package com.example.burpgemini.chat;

import com.example.burpgemini.config.Settings;
import com.example.burpgemini.gemini.GeminiClient;
import com.example.burpgemini.gemini.GeminiModels.Content;
import com.example.burpgemini.gemini.GeminiModels.FunctionCall;
import com.example.burpgemini.gemini.GeminiModels.Part;
import com.example.burpgemini.gemini.SystemPrompt;
import com.example.burpgemini.safety.ActionRequest;
import com.example.burpgemini.safety.ConfirmationManager;
import com.example.burpgemini.safety.ConfirmationManager.Decision;
import com.example.burpgemini.safety.ScopeGuard;
import com.example.burpgemini.tools.RiskTier;
import com.example.burpgemini.tools.ToolExecutor;
import com.example.burpgemini.util.BurpContext;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Orchestrates a chat turn — the agent loop.
 *
 * <p>Per user message: send the whole history + tool declarations to Gemini; if the reply contains
 * function calls, look up each call's {@link RiskTier}, run Tier 0 immediately and route Tier ≥1
 * through {@link ConfirmationManager} + {@link ScopeGuard}; feed every result back as a
 * {@code functionResponse} and loop until the model replies with text only.
 *
 * <p><b>Golden rule:</b> a model tool call is only <em>intent</em>. Nothing target-facing runs
 * without passing the confirmation gate and the scope guard first.
 */
public final class ChatController {

    private static final int MAX_TOOL_STEPS = 16;
    private static final int HISTORY_SOFT_LIMIT = 60;
    private static final int HISTORY_TRIM_TO = 40;

    private final BurpContext ctx;
    private final Settings settings;
    private final GeminiClient gemini;
    private final ToolExecutor executor;
    private final ConfirmationManager confirmations;
    private final ScopeGuard scopeGuard;
    private final ChatTab tab;
    private final com.example.burpgemini.tools.ToolRegistry registry;

    private final Gson pretty = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    /** Full conversation history for the agent loop (excludes the system prompt). */
    private final List<Content> history = new ArrayList<>();

    private final AtomicBoolean turnRunning = new AtomicBoolean(false);
    private volatile boolean cancelled = false;
    private volatile CompletableFuture<Decision> pendingConfirmation;

    public ChatController(BurpContext ctx, Settings settings, GeminiClient gemini,
                          ToolExecutor executor, ConfirmationManager confirmations,
                          ScopeGuard scopeGuard, com.example.burpgemini.tools.ToolRegistry registry,
                          ChatTab tab) {
        this.ctx = ctx;
        this.settings = settings;
        this.gemini = gemini;
        this.executor = executor;
        this.confirmations = confirmations;
        this.scopeGuard = scopeGuard;
        this.registry = registry;
        this.tab = tab;
    }

    // ---- entry points (called from the EDT) --------------------------------

    public void submitUserMessage(String text) {
        if (!settings.hasApiKey()) {
            tab.addNotice("No Gemini API key set. Add one in the Config tab (or set GEMINI_API_KEY).");
            return;
        }
        if (!turnRunning.compareAndSet(false, true)) {
            tab.addNotice("A turn is already running. Cancel it first, or wait for it to finish.");
            return;
        }
        cancelled = false;
        tab.setBusy(true);
        tab.addUserMessage(text);

        final String composed = composeUserMessage(text);
        ctx.executor().submit(() -> {
            try {
                runTurn(composed);
            } catch (Throwable t) {
                ctx.logError("Chat turn failed: " + t, t);
                tab.addNotice("⚠ Internal error: " + t.getMessage());
            } finally {
                tab.setThinking(false);
                tab.setBusy(false);
                turnRunning.set(false);
            }
        });
    }

    public void cancelCurrentTurn() {
        cancelled = true;
        gemini.cancelInFlight();
        CompletableFuture<Decision> pc = pendingConfirmation;
        if (pc != null && !pc.isDone()) {
            pc.complete(Decision.deny("Turn cancelled by operator."));
        }
    }

    public void clearSession() {
        cancelCurrentTurn();
        history.clear();
    }

    // ---- the agent loop ----------------------------------------------------

    private void runTurn(String composedUserText) {
        history.add(Content.userText(composedUserText));
        trimHistory();
        gemini.setApiKey(settings.getApiKey());

        for (int step = 0; step < MAX_TOOL_STEPS; step++) {
            if (cancelled) {
                tab.addNotice("Cancelled.");
                return;
            }

            tab.setThinking(true);
            GeminiClient.GeminiResult res = gemini.sendTurn(
                    SystemPrompt.TEXT, history, registry.geminiTools(),
                    settings.getModel(), settings.getThinkingLevel());
            tab.setThinking(false);

            if (cancelled) {
                tab.addNotice("Cancelled.");
                return;
            }
            if (!res.ok) {
                if (res.cancelled) {
                    tab.addNotice("Cancelled.");
                } else {
                    tab.addNotice("⚠ " + res.errorMessage);
                    ctx.logError("Gemini turn error (HTTP " + res.httpStatus + "): " + res.errorMessage);
                }
                return;
            }

            history.add(res.modelContent);
            if (res.text != null && !res.text.isBlank()) {
                tab.addAssistantMessage(res.text);
            }
            if (res.functionCalls.isEmpty()) {
                return; // text-only reply — turn complete
            }

            // Execute the (possibly parallel) function calls in order, gating each.
            List<Part> responseParts = new ArrayList<>();
            for (FunctionCall fc : res.functionCalls) {
                if (cancelled) {
                    responseParts.add(Part.functionResponse(fc.name, denied("Turn cancelled.")));
                    continue;
                }
                JsonObject response = handleFunctionCall(fc, res.text);
                responseParts.add(Part.functionResponse(fc.name, response));
            }
            history.add(new Content("user", responseParts));

            if (cancelled) {
                tab.addNotice("Cancelled.");
                return;
            }
        }
        tab.addNotice("Stopped after " + MAX_TOOL_STEPS + " tool steps to avoid an endless loop.");
    }

    /**
     * Run one function call through the risk gate and return its {@code functionResponse} payload.
     */
    private JsonObject handleFunctionCall(FunctionCall fc, String rationale) {
        String tool = fc.name;
        JsonObject args = fc.args != null ? fc.args : new JsonObject();
        RiskTier tier = RiskTier.forTool(tool);
        ToolCard card = tab.addToolCard(tool, summarizeArgs(args), tier);

        // Tier 0: read-only, auto-run.
        if (tier == RiskTier.TIER0_AUTO) {
            card.setRunning();
            ctx.logInfo("[tool] " + tool + " (Tier 0) auto-run");
            JsonObject result = executor.execute(tool, args);
            card.setResult(prettyPrint(result));
            return result;
        }

        // Tier >= 1: build the action request and gate it.
        List<String> targets = executor.targetUrlsFor(tool, args);
        ScopeGuard.ScopeDecision scope = executor.isTargetFacing(tool)
                ? scopeGuard.check(targets)
                : permissiveScope();

        // Hard scope block: never even reaches confirmation.
        if (scope.blocked) {
            card.setBlocked(scope.summary);
            ctx.logInfo("[tool] " + tool + " BLOCKED out-of-scope: " + scope.summary);
            return blocked(scope.summary);
        }

        ActionRequest req = new ActionRequest(
                tool, tier, executor.describeAction(tool, args), targets, scope,
                executor.payloadDetailFor(tool, args), executor.countInfoFor(tool, args),
                rationale, null);

        ctx.logInfo("[tool] " + tool + " (Tier " + tier.ordinal() + ") requested; targets=" + targets);

        CompletableFuture<Decision> future = confirmations.request(req, card);
        pendingConfirmation = future;
        Decision decision;
        try {
            decision = future.join();
        } finally {
            pendingConfirmation = null;
        }

        if (!decision.approved) {
            card.setDenied(decision.reason);
            ctx.logInfo("[tool] " + tool + " DENIED: " + decision.reason);
            return denied(decision.reason == null ? "Operator denied the action." : decision.reason);
        }
        // Out-of-scope override must be explicitly confirmed.
        if (scope.requiresOverride && !decision.outOfScopeConfirmed) {
            card.setDenied("Out-of-scope override not confirmed.");
            ctx.logInfo("[tool] " + tool + " DENIED: out-of-scope override not confirmed");
            return denied("Out-of-scope override not confirmed by the operator.");
        }

        card.setRunning();
        ctx.logInfo("[tool] " + tool + " APPROVED; executing");
        JsonObject result = executor.execute(tool, args);
        card.setResult(prettyPrint(result));
        ctx.logInfo("[tool] " + tool + " executed");
        return result;
    }

    // ---- helpers -----------------------------------------------------------

    /** Attach a compact summary of any right-clicked context items to the user's message. */
    private String composeUserMessage(String text) {
        List<HttpRequestResponse> items = ctx.contextItems();
        if (items == null || items.isEmpty()) {
            return text;
        }
        StringBuilder sb = new StringBuilder(text);
        sb.append("\n\n[Attached context: ").append(items.size()).append(" request(s). ")
          .append("Use get_selected_items, then get_request_response(source=\"selection\", id=<index>) ")
          .append("to read them.]");
        for (int i = 0; i < items.size() && i < 10; i++) {
            HttpRequestResponse rr = items.get(i);
            String method = rr.request() != null ? rr.request().method() : "?";
            String url = rr.request() != null ? rr.request().url() : "";
            int status = rr.hasResponse() && rr.response() != null ? rr.response().statusCode() : 0;
            sb.append("\n  - [").append(i).append("] ").append(method).append(' ')
              .append(url).append(status > 0 ? " -> " + status : "");
        }
        return sb.toString();
    }

    private static ScopeGuard.ScopeDecision permissiveScope() {
        ScopeGuard.ScopeDecision d = new ScopeGuard.ScopeDecision();
        d.allowed = true;
        d.summary = "No new target traffic (staging / local action).";
        return d;
    }

    private String summarizeArgs(JsonObject args) {
        if (args == null || args.size() == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        int n = 0;
        for (Map.Entry<String, ?> e : args.entrySet()) {
            if (n++ > 0) {
                sb.append(", ");
            }
            String v = args.get(e.getKey()).toString();
            if (v.length() > 60) {
                v = v.substring(0, 60) + "…";
            }
            sb.append(e.getKey()).append("=").append(v);
            if (n >= 6) {
                sb.append(", …");
                break;
            }
        }
        return sb.toString();
    }

    private String prettyPrint(JsonObject o) {
        String s = pretty.toJson(o);
        return s.length() > 6000 ? s.substring(0, 6000) + "\n…[truncated]" : s;
    }

    private static JsonObject denied(String reason) {
        JsonObject o = new JsonObject();
        o.addProperty("denied", true);
        o.addProperty("reason", reason);
        o.addProperty("note", "The operator declined this action. Propose a safer alternative or "
                + "explain what you would need to proceed.");
        return o;
    }

    private static JsonObject blocked(String reason) {
        JsonObject o = new JsonObject();
        o.addProperty("blocked", true);
        o.addProperty("reason", reason);
        o.addProperty("note", "Blocked as out-of-scope by policy. Do not retry; point the target out "
                + "to the operator and let them decide.");
        return o;
    }

    /** Keep the system prompt + recent turns; drop the oldest content when history grows too large. */
    private void trimHistory() {
        if (history.size() <= HISTORY_SOFT_LIMIT) {
            return;
        }
        int remove = history.size() - HISTORY_TRIM_TO;
        for (int i = 0; i < remove && !history.isEmpty(); i++) {
            history.remove(0);
        }
        // Avoid a leading functionResponse with no preceding functionCall.
        while (!history.isEmpty() && isFunctionResponse(history.get(0))) {
            history.remove(0);
        }
        ctx.logInfo("[history] trimmed to " + history.size() + " messages");
    }

    private static boolean isFunctionResponse(Content c) {
        if (c == null || c.parts == null) {
            return false;
        }
        for (Part p : c.parts) {
            if (p.functionResponse != null) {
                return true;
            }
        }
        return false;
    }
}
