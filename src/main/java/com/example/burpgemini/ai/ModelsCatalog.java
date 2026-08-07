package com.example.burpgemini.ai;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Predicate;

/**
 * Client for <a href="https://models.dev">models.dev</a> — an open database of AI model specs,
 * pricing and features. Fetches {@code api.json} (provider → models) and exposes model metadata so
 * the Config tab can offer spec-aware, up-to-date model dropdowns instead of hardcoded lists.
 *
 * <p>Parsing is deliberately defensive (nullable fields, unknown keys ignored) so minor schema
 * changes don't break it.
 */
public final class ModelsCatalog {

    private static final String API_URL = "https://models.dev/api.json";

    /** One model's metadata. */
    public static final class ModelInfo {
        public String id;
        public String name;
        public String providerId;
        public String providerName;
        public Integer contextLimit;   // tokens
        public Integer outputLimit;    // tokens
        public Double inputCost;       // USD per 1M tokens
        public Double outputCost;      // USD per 1M tokens
        public boolean toolCall;
        public boolean reasoning;
        public boolean attachment;     // vision / file input

        /** One-line spec summary for the UI. */
        public String summary() {
            StringBuilder sb = new StringBuilder();
            if (contextLimit != null) {
                sb.append(formatTokens(contextLimit)).append(" ctx");
            }
            if (inputCost != null || outputCost != null) {
                if (sb.length() > 0) {
                    sb.append("  ·  ");
                }
                sb.append("in ").append(cost(inputCost)).append(" / out ").append(cost(outputCost))
                  .append(" per 1M");
            }
            if (toolCall) {
                sb.append("  ·  tools ✓");
            }
            if (reasoning) {
                sb.append("  ·  reasoning ✓");
            }
            if (attachment) {
                sb.append("  ·  vision ✓");
            }
            return sb.length() == 0 ? "(no spec data)" : sb.toString();
        }
    }

    /** One provider's metadata (used to offer "pick any provider"). */
    public static final class ProviderInfo {
        public String id;
        public String name;
        public String apiBase;   // base URL, e.g. https://api.openai.com/v1
        public String doc;       // docs URL
        public final List<String> env = new ArrayList<>(); // API-key env var name(s)

        /** Best-effort OpenAI-compatible chat/completions endpoint from the api base. */
        public String chatEndpoint() {
            if (apiBase == null || apiBase.isBlank()) {
                return "";
            }
            String b = apiBase.endsWith("/") ? apiBase.substring(0, apiBase.length() - 1) : apiBase;
            return b.endsWith("/chat/completions") ? b : b + "/chat/completions";
        }
    }

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .build();
    private final Gson gson = new Gson();

    private volatile List<ModelInfo> all = new ArrayList<>();
    private volatile List<ProviderInfo> providers = new ArrayList<>();
    private volatile Map<String, ModelInfo> byId = new LinkedHashMap<>();
    private volatile boolean loaded;

    public boolean isLoaded() {
        return loaded;
    }

    public int size() {
        return all.size();
    }

    /**
     * Fetch and parse the catalog (blocking; call off the EDT).
     *
     * @return null on success, or a user-facing error message.
     */
    public String fetch() {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(API_URL))
                    .timeout(Duration.ofSeconds(30))
                    .header("Accept", "application/json")
                    .GET()
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                return "models.dev returned HTTP " + resp.statusCode();
            }
            parse(resp.body());
            return null;
        } catch (Exception e) {
            return "Could not reach models.dev: " + e.getMessage();
        }
    }

    private void parse(String body) {
        JsonObject root = gson.fromJson(body, JsonObject.class);
        List<ModelInfo> models = new ArrayList<>();
        List<ProviderInfo> provs = new ArrayList<>();
        Map<String, ModelInfo> index = new LinkedHashMap<>();
        if (root != null) {
            for (Map.Entry<String, JsonElement> pe : root.entrySet()) {
                if (!pe.getValue().isJsonObject()) {
                    continue;
                }
                JsonObject provider = pe.getValue().getAsJsonObject();
                String providerId = pe.getKey();
                String providerName = str(provider, "name", providerId);

                ProviderInfo pi = new ProviderInfo();
                pi.id = providerId;
                pi.name = providerName;
                pi.apiBase = str(provider, "api", null);
                pi.doc = str(provider, "doc", null);
                JsonElement envEl = provider.get("env");
                if (envEl != null && envEl.isJsonArray()) {
                    envEl.getAsJsonArray().forEach(x -> {
                        if (x.isJsonPrimitive()) {
                            pi.env.add(x.getAsString());
                        }
                    });
                }
                provs.add(pi);

                JsonElement modelsEl = provider.get("models");
                if (modelsEl == null || !modelsEl.isJsonObject()) {
                    continue;
                }
                for (Map.Entry<String, JsonElement> me : modelsEl.getAsJsonObject().entrySet()) {
                    if (!me.getValue().isJsonObject()) {
                        continue;
                    }
                    ModelInfo mi = toModel(me.getKey(), me.getValue().getAsJsonObject(),
                            providerId, providerName);
                    models.add(mi);
                    index.putIfAbsent(mi.id, mi);
                    index.putIfAbsent(providerId + "/" + mi.id, mi);
                }
            }
        }
        provs.sort((x, y) -> x.name.compareToIgnoreCase(y.name));
        this.all = models;
        this.providers = provs;
        this.byId = index;
        this.loaded = true;
    }

    public List<ProviderInfo> providers() {
        return providers;
    }

    /** Model ids served by a given provider id, sorted. */
    public List<String> modelIdsForProvider(String providerId) {
        List<String> ids = new ArrayList<>();
        for (ModelInfo mi : all) {
            if (mi.providerId != null && mi.providerId.equals(providerId)) {
                ids.add(mi.id);
            }
        }
        ids.sort(String::compareTo);
        return ids;
    }

    private static ModelInfo toModel(String key, JsonObject m, String providerId, String providerName) {
        ModelInfo mi = new ModelInfo();
        mi.id = str(m, "id", key);
        mi.name = str(m, "name", mi.id);
        mi.providerId = providerId;
        mi.providerName = providerName;
        mi.toolCall = bool(m, "tool_call");
        mi.reasoning = bool(m, "reasoning");
        mi.attachment = bool(m, "attachment");
        JsonObject limit = obj(m, "limit");
        if (limit != null) {
            mi.contextLimit = intOrNull(limit, "context");
            mi.outputLimit = intOrNull(limit, "output");
        }
        JsonObject cost = obj(m, "cost");
        if (cost != null) {
            mi.inputCost = dblOrNull(cost, "input");
            mi.outputCost = dblOrNull(cost, "output");
        }
        return mi;
    }

    /** All models whose id matches the predicate (e.g. starts with "gemini"), sorted by id. */
    public List<String> modelIds(Predicate<ModelInfo> filter) {
        List<String> ids = new ArrayList<>();
        for (ModelInfo mi : all) {
            if (filter.test(mi)) {
                ids.add(mi.id);
            }
        }
        ids.sort(String::compareTo);
        return ids;
    }

    /** Look up a model by id, tolerating a {@code provider/} prefix or missing prefix. */
    public ModelInfo lookup(String modelId) {
        if (modelId == null || modelId.isBlank()) {
            return null;
        }
        ModelInfo mi = byId.get(modelId);
        if (mi != null) {
            return mi;
        }
        // Strip a provider prefix like "openai/gpt-4o" → "gpt-4o".
        int slash = modelId.indexOf('/');
        if (slash >= 0) {
            mi = byId.get(modelId.substring(slash + 1));
            if (mi != null) {
                return mi;
            }
        }
        // Last resort: suffix/exact-id match against the bare id.
        for (ModelInfo candidate : all) {
            if (candidate.id.equalsIgnoreCase(modelId)) {
                return candidate;
            }
        }
        return null;
    }

    // ---- small JSON helpers ------------------------------------------------

    private static String str(JsonObject o, String k, String def) {
        JsonElement e = o.get(k);
        return e != null && e.isJsonPrimitive() ? e.getAsString() : def;
    }

    private static boolean bool(JsonObject o, String k) {
        JsonElement e = o.get(k);
        try {
            return e != null && e.isJsonPrimitive() && e.getAsBoolean();
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private static JsonObject obj(JsonObject o, String k) {
        JsonElement e = o.get(k);
        return e != null && e.isJsonObject() ? e.getAsJsonObject() : null;
    }

    private static Integer intOrNull(JsonObject o, String k) {
        JsonElement e = o.get(k);
        try {
            return e != null && e.isJsonPrimitive() ? e.getAsInt() : null;
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private static Double dblOrNull(JsonObject o, String k) {
        JsonElement e = o.get(k);
        try {
            return e != null && e.isJsonPrimitive() ? e.getAsDouble() : null;
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private static String formatTokens(int tokens) {
        if (tokens >= 1_000_000) {
            return (tokens / 1_000_000) + "M";
        }
        if (tokens >= 1000) {
            return (tokens / 1000) + "K";
        }
        return String.valueOf(tokens);
    }

    private static String cost(Double c) {
        if (c == null) {
            return "?";
        }
        return "$" + String.format(Locale.US, c < 1 ? "%.3f" : "%.2f", c);
    }
}
