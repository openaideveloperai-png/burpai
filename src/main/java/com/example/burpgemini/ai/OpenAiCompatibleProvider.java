package com.example.burpgemini.ai;

import com.example.burpgemini.ai.Neutral.ChatMessage;
import com.example.burpgemini.ai.Neutral.ToolCallRequest;
import com.example.burpgemini.ai.Neutral.ToolResult;
import com.example.burpgemini.ai.Neutral.ToolSpec;
import com.example.burpgemini.ai.Neutral.TurnResult;
import com.example.burpgemini.ai.OpenAiModels.ChatRequest;
import com.example.burpgemini.ai.OpenAiModels.ChatResponse;
import com.example.burpgemini.ai.OpenAiModels.Choice;
import com.example.burpgemini.ai.OpenAiModels.FunctionDef;
import com.example.burpgemini.ai.OpenAiModels.Message;
import com.example.burpgemini.ai.OpenAiModels.ToolCall;
import com.example.burpgemini.ai.OpenAiModels.ToolDef;
import com.example.burpgemini.config.Settings;
import com.example.burpgemini.util.BurpContext;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Puter AI backend via its OpenAI-compatible Chat Completions endpoint
 * ({@code https://api.puter.com/puterai/openai/v1/chat/completions}, Bearer auth-token).
 *
 * <p>Puter proxies GPT/Claude/Gemini/Grok behind the standard OpenAI wire format, so this provider
 * is a general OpenAI-compatible client. Function calling uses OpenAI's {@code tools} /
 * {@code tool_calls} convention, which this class maps to/from the neutral conversation model.
 */
public final class OpenAiCompatibleProvider implements AiProvider {

    private static final String ENDPOINT = "https://api.puter.com/puterai/openai/v1/chat/completions";

    /** Models offered in the Config dropdown (editable) — Puter's OpenAI line plus a couple of others. */
    public static final String[] MODELS = {
            "gpt-5.3-chat",
            "gpt-5.4-nano",
            "gpt-5.4-mini",
            "gpt-5.4",
            "gpt-5.6-luna",
            "gpt-5.6-terra",
            "gpt-5.6-sol",
            "gpt-5.3-codex",
            "openai/gpt-oss-120b",
            "claude-sonnet-4-latest",
            "google/gemini-2.5-flash",
    };
    public static final String DEFAULT_MODEL = MODELS[0];

    private final BurpContext ctx;
    private final Settings settings;
    private final HttpTransport transport = new HttpTransport();
    private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();

    public OpenAiCompatibleProvider(BurpContext ctx) {
        this.ctx = ctx;
        this.settings = ctx.settings();
    }

    @Override
    public String id() {
        return "puter";
    }

    @Override
    public String displayName() {
        return "Puter AI (OpenAI-compatible)";
    }

    @Override
    public boolean isConfigured() {
        return settings.hasPuterToken();
    }

    @Override
    public String notConfiguredHint() {
        return "No Puter auth token set. Get one at puter.com/dashboard → API tokens → Create token, "
                + "then paste it in the Config tab (or set PUTER_AUTH_TOKEN).";
    }

    @Override
    public void cancelInFlight() {
        transport.cancelInFlight();
    }

    @Override
    public TurnResult sendTurn(String systemPrompt, List<ChatMessage> history, List<ToolSpec> tools) {
        String token = settings.getPuterToken();
        if (token.isBlank()) {
            return TurnResult.error(notConfiguredHint(), 0);
        }
        ChatRequest body = new ChatRequest();
        String model = settings.getPuterModel();
        body.model = model;
        body.messages = toMessages(systemPrompt, history);
        List<ToolDef> toolDefs = toTools(tools);
        // Puter's built-in web_search tool (OpenAI models only) — fetches up-to-date info.
        if (settings.isPuterWebSearch() && isOpenAiModel(model)) {
            if (toolDefs == null) {
                toolDefs = new ArrayList<>();
            }
            toolDefs.add(new ToolDef("web_search"));
        }
        body.tools = toolDefs;
        body.tool_choice = (toolDefs != null && !toolDefs.isEmpty()) ? "auto" : null;
        return call(body, token);
    }

    @Override
    public TurnResult testConnection() {
        String token = settings.getPuterToken();
        if (token.isBlank()) {
            return TurnResult.error(notConfiguredHint(), 0);
        }
        ChatRequest body = new ChatRequest();
        body.model = settings.getPuterModel();
        body.messages.add(Message.of("user", "ping"));
        return call(body, token);
    }

    // ---- HTTP + interpretation ---------------------------------------------

    private TurnResult call(ChatRequest body, String token) {
        Map<String, String> headers = Map.of("Authorization", "Bearer " + token);
        HttpTransport.Response r = transport.postJson(ENDPOINT, headers, gson.toJson(body));
        if (r.cancelled) {
            return TurnResult.cancelled();
        }
        if (r.status == 200) {
            return parse(r.body);
        }
        String apiMsg = extractError(r.body);
        if (r.status == 401 || r.status == 403) {
            return TurnResult.error("Puter rejected the auth token (HTTP " + r.status + "). "
                    + "Create a fresh token at puter.com/dashboard → API tokens. "
                    + (apiMsg == null ? "" : "Details: " + apiMsg), r.status);
        }
        if (r.status == 400 && apiMsg != null && apiMsg.toLowerCase().contains("tool call")) {
            return TurnResult.error("Puter rejected the tool-call format (HTTP 400) for this model. "
                    + "Try a different Puter model in the Config tab (e.g. gpt-5.4-nano or gpt-5.3-chat). "
                    + "Details: " + apiMsg, r.status);
        }
        if (r.status == 429) {
            return TurnResult.error("Rate limited by Puter (HTTP 429). Please retry in a moment. "
                    + (apiMsg == null ? "" : apiMsg), r.status);
        }
        if (r.status == 0) {
            return TurnResult.error("Could not reach Puter: " + r.body, 0);
        }
        return TurnResult.error("Puter request failed (HTTP " + r.status + "). "
                + (apiMsg == null ? "" : apiMsg), r.status);
    }

    private TurnResult parse(String respBody) {
        ChatResponse parsed;
        try {
            parsed = gson.fromJson(respBody, ChatResponse.class);
        } catch (JsonSyntaxException e) {
            return TurnResult.error("Could not parse Puter response: " + e.getMessage(), 200);
        }
        if (parsed == null) {
            return TurnResult.error("Empty Puter response.", 200);
        }
        if (parsed.error != null && parsed.error.message != null) {
            return TurnResult.error("Puter error: " + parsed.error.message, 200);
        }
        if (parsed.choices == null || parsed.choices.isEmpty() || parsed.choices.get(0).message == null) {
            return TurnResult.error("Puter returned no choices.", 200);
        }

        Choice choice = parsed.choices.get(0);
        Message msg = choice.message;

        TurnResult result = new TurnResult();
        result.ok = true;
        result.httpStatus = 200;
        result.text = msg.content == null ? "" : msg.content;

        List<ToolCallRequest> calls = new ArrayList<>();
        if (msg.tool_calls != null) {
            for (ToolCall tc : msg.tool_calls) {
                if (tc.function == null) {
                    continue;
                }
                JsonObject args = parseArgs(tc.function.arguments);
                calls.add(new ToolCallRequest(tc.id, tc.function.name, args, null));
            }
        }
        result.toolCalls = calls;
        result.modelMessage = ChatMessage.model(result.text, calls);
        return result;
    }

    // ---- neutral -> OpenAI wire --------------------------------------------

    /**
     * Build the OpenAI messages array.
     *
     * <p><b>Prior</b> tool exchanges are represented as plain text (not structured
     * {@code tool_calls} / {@code role:"tool"} messages). Puter proxies many models through the
     * OpenAI <em>Responses</em> API, whose bridge mangles the {@code call_id} linkage on resent
     * turns ("No tool call found for function call output with call_id …"). Flattening the history
     * avoids that entirely, while we still advertise {@code tools} in the request so the model can
     * make <em>new</em> tool calls each turn (those are parsed fresh from the response, which is
     * always fine). This keeps multi-turn agent behaviour working across all Puter models, including
     * reasoning models.
     */
    private List<Message> toMessages(String systemPrompt, List<ChatMessage> history) {
        List<Message> messages = new ArrayList<>();
        messages.add(Message.of("system", systemPrompt));

        for (ChatMessage m : history) {
            switch (m.role) {
                case USER:
                    messages.add(Message.of("user", m.text == null ? "" : m.text));
                    break;
                case MODEL: {
                    StringBuilder sb = new StringBuilder();
                    if (m.text != null && !m.text.isEmpty()) {
                        sb.append(m.text);
                    }
                    if (m.toolCalls != null && !m.toolCalls.isEmpty()) {
                        if (sb.length() > 0) {
                            sb.append('\n');
                        }
                        sb.append("[Called tools: ");
                        for (int i = 0; i < m.toolCalls.size(); i++) {
                            ToolCallRequest tc = m.toolCalls.get(i);
                            if (i > 0) {
                                sb.append("; ");
                            }
                            sb.append(tc.name).append('(')
                              .append(tc.args == null ? "{}" : gson.toJson(tc.args)).append(')');
                        }
                        sb.append(']');
                    }
                    messages.add(Message.of("assistant", sb.length() == 0 ? "(thinking)" : sb.toString()));
                    break;
                }
                case TOOL: {
                    StringBuilder sb = new StringBuilder("[Tool results]");
                    if (m.toolResults != null) {
                        for (ToolResult tr : m.toolResults) {
                            sb.append('\n').append(tr.name).append(": ")
                              .append(tr.response == null ? "{}" : gson.toJson(tr.response));
                        }
                    }
                    messages.add(Message.of("user", sb.toString()));
                    break;
                }
                default:
                    break;
            }
        }
        return messages;
    }

    private List<ToolDef> toTools(List<ToolSpec> specs) {
        if (specs == null || specs.isEmpty()) {
            return null;
        }
        List<ToolDef> tools = new ArrayList<>();
        for (ToolSpec s : specs) {
            tools.add(new ToolDef(new FunctionDef(s.name, s.description, s.parameters)));
        }
        return tools;
    }

    private static boolean isOpenAiModel(String model) {
        if (model == null) {
            return false;
        }
        String m = model.toLowerCase();
        return m.contains("gpt") || m.contains("openai") || m.contains("codex")
                || m.contains("o1") || m.contains("o3") || m.contains("oss");
    }

    private JsonObject parseArgs(String arguments) {
        if (arguments == null || arguments.isBlank()) {
            return new JsonObject();
        }
        try {
            JsonObject o = gson.fromJson(arguments, JsonObject.class);
            return o == null ? new JsonObject() : o;
        } catch (RuntimeException e) {
            return new JsonObject();
        }
    }

    private String extractError(String body) {
        if (body == null || body.isBlank()) {
            return null;
        }
        try {
            ChatResponse r = gson.fromJson(body, ChatResponse.class);
            if (r != null && r.error != null && r.error.message != null) {
                return r.error.message;
            }
        } catch (RuntimeException ignored) {
            // fall through
        }
        return body.length() > 300 ? body.substring(0, 300) + "…" : body;
    }
}
