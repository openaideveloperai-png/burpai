package com.example.burpgemini.ai;

import com.example.burpgemini.ai.Neutral.ChatMessage;
import com.example.burpgemini.ai.Neutral.ToolCallRequest;
import com.example.burpgemini.ai.Neutral.ToolResult;
import com.example.burpgemini.ai.Neutral.ToolSpec;
import com.example.burpgemini.ai.Neutral.TurnResult;
import com.example.burpgemini.config.Settings;
import com.example.burpgemini.gemini.GeminiModels.Candidate;
import com.example.burpgemini.gemini.GeminiModels.Content;
import com.example.burpgemini.gemini.GeminiModels.FunctionCall;
import com.example.burpgemini.gemini.GeminiModels.FunctionDeclaration;
import com.example.burpgemini.gemini.GeminiModels.GenerateContentRequest;
import com.example.burpgemini.gemini.GeminiModels.GenerateContentResponse;
import com.example.burpgemini.gemini.GeminiModels.GenerationConfig;
import com.example.burpgemini.gemini.GeminiModels.Part;
import com.example.burpgemini.gemini.GeminiModels.SystemInstruction;
import com.example.burpgemini.gemini.GeminiModels.Tool;
import com.example.burpgemini.util.BurpContext;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Google Gemini backend ({@code generateContent}). Translates the neutral conversation to Gemini
 * contents and back.
 *
 * <p>Two Gemini-specific correctness points are handled here:
 * <ul>
 *   <li><b>thoughtSignature round-trip</b> — Gemini 3 thinking models attach a {@code thoughtSignature}
 *       to each {@code functionCall} part; it must be echoed back verbatim when the model turn is
 *       resent, or the next call fails with HTTP 400. The neutral {@link ToolCallRequest#signature}
 *       carries it through the tool loop.</li>
 *   <li><b>generationConfig fallback</b> — if a model rejects {@code thinkingConfig}, we strip it and
 *       retry once.</li>
 * </ul>
 */
public final class GeminiProvider implements AiProvider {

    private static final String ENDPOINT_TEMPLATE =
            "https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent";

    private final BurpContext ctx;
    private final Settings settings;
    private final HttpTransport transport = new HttpTransport();
    private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();

    public GeminiProvider(BurpContext ctx) {
        this.ctx = ctx;
        this.settings = ctx.settings();
    }

    @Override
    public String id() {
        return "gemini";
    }

    @Override
    public String displayName() {
        return "Google Gemini";
    }

    @Override
    public boolean isConfigured() {
        return settings.hasApiKey();
    }

    @Override
    public String notConfiguredHint() {
        return "No Gemini API key set. Add one in the Config tab (or set GEMINI_API_KEY).";
    }

    @Override
    public void cancelInFlight() {
        transport.cancelInFlight();
    }

    @Override
    public TurnResult sendTurn(String systemPrompt, List<ChatMessage> history, List<ToolSpec> tools) {
        String key = settings.getApiKey();
        if (key.isBlank()) {
            return TurnResult.error(notConfiguredHint(), 0);
        }
        GenerateContentRequest body = new GenerateContentRequest();
        body.systemInstruction = SystemInstruction.of(systemPrompt);
        body.contents = toContents(history);
        body.tools = toTools(tools);
        body.generationConfig = GenerationConfig.thinking(settings.getThinkingLevel());
        return call(body, settings.getModel(), key);
    }

    @Override
    public TurnResult testConnection() {
        String key = settings.getApiKey();
        if (key.isBlank()) {
            return TurnResult.error(notConfiguredHint(), 0);
        }
        GenerateContentRequest body = new GenerateContentRequest();
        body.contents.add(Content.userText("ping"));
        body.generationConfig = GenerationConfig.thinking("low");
        return call(body, settings.getModel(), key);
    }

    // ---- HTTP + interpretation ---------------------------------------------

    private TurnResult call(GenerateContentRequest body, String model, String apiKey) {
        String url = String.format(ENDPOINT_TEMPLATE, model);
        Map<String, String> headers = Map.of("x-goog-api-key", apiKey);

        HttpTransport.Response r = transport.postJson(url, headers, gson.toJson(body));
        if (r.cancelled) {
            return TurnResult.cancelled();
        }
        // Self-healing: strip generationConfig on a schema-400 and retry once.
        if (r.status == 400 && body.generationConfig != null && isGenConfigRejection(r.body)) {
            body.generationConfig = null;
            r = transport.postJson(url, headers, gson.toJson(body));
            if (r.cancelled) {
                return TurnResult.cancelled();
            }
        }

        if (r.status == 200) {
            return parse(r.body);
        }
        String apiMsg = extractError(r.body);
        if (r.status == 401 || r.status == 403) {
            return TurnResult.error("Gemini rejected the API key (HTTP " + r.status
                    + "). Check it in the Config tab — create one at https://aistudio.google.com/apikey. "
                    + (apiMsg == null ? "" : "Details: " + apiMsg), r.status);
        }
        if (r.status == 429) {
            return TurnResult.error("Rate limited by Gemini (HTTP 429). Please retry in a moment. "
                    + (apiMsg == null ? "" : apiMsg), r.status);
        }
        if (r.status == 0) {
            return TurnResult.error("Could not reach Gemini: " + r.body, 0);
        }
        return TurnResult.error("Gemini request failed (HTTP " + r.status + "). "
                + (apiMsg == null ? "" : apiMsg), r.status);
    }

    private TurnResult parse(String respBody) {
        GenerateContentResponse parsed;
        try {
            parsed = gson.fromJson(respBody, GenerateContentResponse.class);
        } catch (JsonSyntaxException e) {
            return TurnResult.error("Could not parse Gemini response: " + e.getMessage(), 200);
        }
        if (parsed == null) {
            return TurnResult.error("Empty Gemini response.", 200);
        }
        if (parsed.error != null) {
            return TurnResult.error("Gemini error: " + parsed.error.message, parsed.error.code);
        }

        TurnResult result = new TurnResult();
        result.ok = true;
        result.httpStatus = 200;
        if (parsed.promptFeedback != null && parsed.promptFeedback.blockReason != null) {
            result.blockReason = parsed.promptFeedback.blockReason;
        }
        if (parsed.candidates == null || parsed.candidates.isEmpty()) {
            result.ok = false;
            result.errorMessage = result.blockReason != null
                    ? "Gemini returned no answer (blocked: " + result.blockReason + ")."
                    : "Gemini returned no candidates.";
            return result;
        }

        Candidate c = parsed.candidates.get(0);
        StringBuilder text = new StringBuilder();
        List<ToolCallRequest> calls = new ArrayList<>();
        if (c.content != null && c.content.parts != null) {
            for (Part p : c.content.parts) {
                if (p.text != null) {
                    text.append(p.text);
                }
                if (p.functionCall != null) {
                    ToolCallRequest call = new ToolCallRequest(
                            null, p.functionCall.name, p.functionCall.args, p.thoughtSignature);
                    calls.add(call);
                }
            }
        }
        result.text = text.toString();
        result.toolCalls = calls;
        result.modelMessage = ChatMessage.model(result.text, calls);
        return result;
    }

    // ---- neutral -> Gemini wire --------------------------------------------

    private List<Content> toContents(List<ChatMessage> history) {
        List<Content> contents = new ArrayList<>();
        for (ChatMessage m : history) {
            switch (m.role) {
                case USER:
                    contents.add(Content.userText(m.text == null ? "" : m.text));
                    break;
                case MODEL: {
                    Content c = new Content();
                    c.role = "model";
                    c.parts = new ArrayList<>();
                    if (m.text != null && !m.text.isEmpty()) {
                        c.parts.add(Part.text(m.text));
                    }
                    if (m.toolCalls != null) {
                        for (ToolCallRequest tc : m.toolCalls) {
                            Part p = new Part();
                            FunctionCall fc = new FunctionCall();
                            fc.name = tc.name;
                            fc.args = tc.args;
                            p.functionCall = fc;
                            p.thoughtSignature = tc.signature; // echo back verbatim (may be null)
                            c.parts.add(p);
                        }
                    }
                    contents.add(c);
                    break;
                }
                case TOOL: {
                    // Function responses are sent as a user-role message in Gemini.
                    Content c = new Content();
                    c.role = "user";
                    c.parts = new ArrayList<>();
                    if (m.toolResults != null) {
                        for (ToolResult tr : m.toolResults) {
                            c.parts.add(Part.functionResponse(tr.name, tr.response));
                        }
                    }
                    contents.add(c);
                    break;
                }
                default:
                    break;
            }
        }
        return contents;
    }

    private List<Tool> toTools(List<ToolSpec> specs) {
        Tool tool = new Tool();
        for (ToolSpec s : specs) {
            tool.functionDeclarations.add(new FunctionDeclaration(s.name, s.description, s.parameters));
        }
        List<Tool> tools = new ArrayList<>();
        tools.add(tool);
        return tools;
    }

    private static boolean isGenConfigRejection(String respBody) {
        if (respBody == null) {
            return false;
        }
        String b = respBody.toLowerCase();
        return b.contains("generation_config") || b.contains("generationconfig")
                || b.contains("thinking") || b.contains("unknown name");
    }

    private String extractError(String body) {
        if (body == null || body.isBlank()) {
            return null;
        }
        try {
            GenerateContentResponse r = gson.fromJson(body, GenerateContentResponse.class);
            if (r != null && r.error != null && r.error.message != null) {
                return r.error.message;
            }
        } catch (RuntimeException ignored) {
            // fall through
        }
        return body.length() > 300 ? body.substring(0, 300) + "…" : body;
    }
}
