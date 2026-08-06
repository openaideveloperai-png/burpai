package com.example.burpgemini.gemini;

import com.example.burpgemini.gemini.GeminiModels.Candidate;
import com.example.burpgemini.gemini.GeminiModels.Content;
import com.example.burpgemini.gemini.GeminiModels.FunctionCall;
import com.example.burpgemini.gemini.GeminiModels.GenerateContentRequest;
import com.example.burpgemini.gemini.GeminiModels.GenerateContentResponse;
import com.example.burpgemini.gemini.GeminiModels.GenerationConfig;
import com.example.burpgemini.gemini.GeminiModels.Part;
import com.example.burpgemini.gemini.GeminiModels.SystemInstruction;
import com.example.burpgemini.gemini.GeminiModels.Tool;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Talks to the Gemini {@code generateContent} REST API with the user's own key.
 *
 * <p>Deliberately swappable: the whole surface is {@link #sendTurn} + {@link #testConnection}, so an
 * alternative backend (e.g. the Interactions API) could implement the same shape.
 *
 * <p>All calls are meant to run off the Swing EDT. An in-flight request can be cancelled via
 * {@link #cancelInFlight()}.
 */
public final class GeminiClient {

    private static final String ENDPOINT_TEMPLATE =
            "https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent";
    private static final int MAX_ATTEMPTS = 4;

    private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(20))
            .build();

    /** Tracks the current async HTTP call so the UI can cancel it. */
    private final AtomicReference<CompletableFuture<HttpResponse<String>>> inFlight = new AtomicReference<>();

    /** Result of one model turn: text and/or function calls, or an error. */
    public static final class GeminiResult {
        public boolean ok;
        public boolean cancelled;
        public String errorMessage; // user-facing, key already redacted upstream
        public int httpStatus;
        public String blockReason;

        /** The raw model turn to append to the conversation history (role=model). */
        public Content modelContent;
        public String text = "";
        public List<FunctionCall> functionCalls = new ArrayList<>();

        static GeminiResult error(String msg, int status) {
            GeminiResult r = new GeminiResult();
            r.ok = false;
            r.errorMessage = msg;
            r.httpStatus = status;
            return r;
        }

        static GeminiResult cancelled() {
            GeminiResult r = new GeminiResult();
            r.ok = false;
            r.cancelled = true;
            r.errorMessage = "Cancelled.";
            return r;
        }
    }

    /**
     * Execute one turn: send the whole {@code history} plus {@code tools}, and return the model's
     * reply. The caller loops (append model content, run tools, append functionResponse, call again)
     * until the reply has no function calls.
     */
    public GeminiResult sendTurn(String systemPrompt,
                                 List<Content> history,
                                 List<Tool> tools,
                                 String model,
                                 String thinkingLevel) {
        GenerateContentRequest body = new GenerateContentRequest();
        body.systemInstruction = SystemInstruction.of(systemPrompt);
        body.contents = history;
        body.tools = tools;
        body.generationConfig = GenerationConfig.thinking(thinkingLevel);
        return post(model, body, /*apiKey*/ currentKey);
    }

    private volatile String currentKey = "";

    /** The key must be set before each turn; never stored beyond the client's lifetime. */
    public void setApiKey(String key) {
        this.currentKey = key == null ? "" : key;
    }

    /** A tiny ping used by "Test connection" in the Config tab. */
    public GeminiResult testConnection(String apiKey, String model) {
        this.currentKey = apiKey == null ? "" : apiKey;
        GenerateContentRequest body = new GenerateContentRequest();
        body.contents.add(Content.userText("ping"));
        body.generationConfig = GenerationConfig.thinking("low");
        return post(model, body, apiKey);
    }

    private GeminiResult post(String model, GenerateContentRequest body, String apiKey) {
        if (apiKey == null || apiKey.isBlank()) {
            return GeminiResult.error("No Gemini API key set. Add one in the Config tab "
                    + "(or set the GEMINI_API_KEY environment variable).", 0);
        }
        String url = String.format(ENDPOINT_TEMPLATE, model);

        long backoffMs = 1000;
        String lastError = "Request failed.";
        int lastStatus = 0;
        boolean strippedGenConfig = false;

        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            String jsonBody = gson.toJson(body);
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(120))
                    .header("x-goog-api-key", apiKey)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build();

            HttpResponse<String> resp;
            try {
                CompletableFuture<HttpResponse<String>> fut =
                        httpClient.sendAsync(req, HttpResponse.BodyHandlers.ofString());
                inFlight.set(fut);
                resp = fut.get();
            } catch (CancellationException ce) {
                return GeminiResult.cancelled();
            } catch (ExecutionException ee) {
                Throwable cause = ee.getCause() == null ? ee : ee.getCause();
                lastError = "Network error contacting Gemini: " + cause.getMessage();
                lastStatus = 0;
                if (attempt < MAX_ATTEMPTS) {
                    if (!sleep(backoffMs)) return GeminiResult.cancelled();
                    backoffMs *= 2;
                    continue;
                }
                return GeminiResult.error(lastError, 0);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                return GeminiResult.cancelled();
            } finally {
                inFlight.set(null);
            }

            int status = resp.statusCode();
            String respBody = resp.body();

            if (status == 200) {
                return parse(respBody);
            }

            // Error handling per status class.
            lastStatus = status;
            String apiMsg = extractApiError(respBody);
            if (status == 401 || status == 403) {
                return GeminiResult.error(
                        "Gemini rejected the API key (HTTP " + status + "). Check the key in the "
                        + "Config tab — create one at https://aistudio.google.com/apikey. "
                        + (apiMsg == null ? "" : "Details: " + apiMsg), status);
            }
            if (status == 429) {
                lastError = "Rate limited by Gemini (HTTP 429). "
                        + (apiMsg == null ? "" : apiMsg);
                if (attempt < MAX_ATTEMPTS) {
                    if (!sleep(backoffMs + jitter())) return GeminiResult.cancelled();
                    backoffMs *= 2;
                    continue;
                }
                return GeminiResult.error(lastError + " Please retry in a moment.", status);
            }
            if (status >= 500) {
                lastError = "Gemini server error (HTTP " + status + "). "
                        + (apiMsg == null ? "" : apiMsg);
                if (attempt < MAX_ATTEMPTS) {
                    if (!sleep(backoffMs + jitter())) return GeminiResult.cancelled();
                    backoffMs *= 2;
                    continue;
                }
                return GeminiResult.error(lastError, status);
            }
            // Self-healing: some models reject generationConfig/thinkingConfig. Strip it and retry
            // once so a turn never hard-fails on the reasoning-depth hint.
            if (status == 400 && !strippedGenConfig && body.generationConfig != null
                    && isGenerationConfigRejection(respBody)) {
                body.generationConfig = null;
                strippedGenConfig = true;
                continue;
            }

            // Other 4xx — not retryable.
            return GeminiResult.error("Gemini request failed (HTTP " + status + "). "
                    + (apiMsg == null ? "" : apiMsg), status);
        }
        return GeminiResult.error(lastError, lastStatus);
    }

    private GeminiResult parse(String respBody) {
        GenerateContentResponse parsed;
        try {
            parsed = gson.fromJson(respBody, GenerateContentResponse.class);
        } catch (JsonSyntaxException e) {
            return GeminiResult.error("Could not parse Gemini response: " + e.getMessage(), 200);
        }
        if (parsed == null) {
            return GeminiResult.error("Empty Gemini response.", 200);
        }
        if (parsed.error != null) {
            return GeminiResult.error("Gemini error: " + parsed.error.message, parsed.error.code);
        }

        GeminiResult result = new GeminiResult();
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
        result.modelContent = c.content;
        if (c.content != null && c.content.parts != null) {
            StringBuilder text = new StringBuilder();
            for (Part p : c.content.parts) {
                if (p.text != null) {
                    text.append(p.text);
                }
                if (p.functionCall != null) {
                    result.functionCalls.add(p.functionCall);
                }
            }
            result.text = text.toString();
        }
        // Ensure a model content object exists so the caller can always append it to history.
        if (result.modelContent == null) {
            result.modelContent = new Content();
            result.modelContent.role = "model";
        } else if (result.modelContent.role == null) {
            result.modelContent.role = "model";
        }
        return result;
    }

    /** Cancel the in-flight HTTP call, if any. */
    public void cancelInFlight() {
        CompletableFuture<HttpResponse<String>> f = inFlight.get();
        if (f != null) {
            f.cancel(true);
        }
    }

    /** True when a 400 looks like a rejection of generationConfig/thinkingConfig fields. */
    private static boolean isGenerationConfigRejection(String respBody) {
        if (respBody == null) {
            return false;
        }
        String b = respBody.toLowerCase();
        return b.contains("generation_config") || b.contains("generationconfig")
                || b.contains("thinking") || b.contains("unknown name");
    }

    private String extractApiError(String body) {
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

    private static boolean sleep(long ms) {
        try {
            Thread.sleep(ms);
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private static long jitter() {
        return (long) (Math.random() * 400);
    }
}
