package com.example.burpgemini.config;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;

/**
 * Typed settings backed by Burp's {@link Preferences} store.
 *
 * <p>All values persist across Burp restarts. The API key can also be supplied via the
 * {@code GEMINI_API_KEY} environment variable so users may avoid persisting the secret at rest
 * (Burp preferences are not strongly encrypted — see README).
 */
public final class Settings {

    // Preference keys (namespaced to avoid collisions with other extensions).
    private static final String K_API_KEY = "burpgemini.apiKey";
    private static final String K_MODEL = "burpgemini.model";
    private static final String K_THINKING = "burpgemini.thinkingLevel";
    private static final String K_REQUIRE_CONFIRM = "burpgemini.requireConfirmActive";
    private static final String K_RESPECT_SCOPE = "burpgemini.respectScope";
    private static final String K_ALLOW_OOS = "burpgemini.allowOutOfScope";
    private static final String K_PERSIST_TRANSCRIPTS = "burpgemini.persistTranscripts";
    private static final String K_AUTO_APPROVE = "burpgemini.autoApprove";
    private static final String K_PASSIVE_SCAN = "burpgemini.passiveScan";
    private static final String K_PASSIVE_IN_SCOPE = "burpgemini.passiveInScopeOnly";
    private static final String K_AI_ENRICH = "burpgemini.aiEnrich";
    private static final String K_PROVIDER = "burpgemini.provider";
    private static final String K_PUTER_TOKEN = "burpgemini.puterToken";
    private static final String K_PUTER_MODEL = "burpgemini.puterModel";
    private static final String K_PUTER_WEBSEARCH = "burpgemini.puterWebSearch";
    private static final String K_CUSTOM_NAME = "burpgemini.customName";
    private static final String K_CUSTOM_ENDPOINT = "burpgemini.customEndpoint";
    private static final String K_CUSTOM_KEY = "burpgemini.customKey";
    private static final String K_CUSTOM_KEY_ENV = "burpgemini.customKeyEnv";
    private static final String K_CUSTOM_MODEL = "burpgemini.customModel";

    /** AI provider ids. */
    public static final String PROVIDER_GEMINI = "gemini";
    public static final String PROVIDER_PUTER = "puter";
    public static final String PROVIDER_CUSTOM = "custom";
    public static final String DEFAULT_PUTER_MODEL = "gpt-5.3-chat";

    /** Models offered in the Config dropdown. First entry is the default. */
    public static final String[] MODELS = {
            "gemini-3.1-pro-preview-customtools", // default: custom-tools variant, best for our tool calls
            "gemini-3.1-pro-preview",
            "gemini-3.6-flash",
            "gemini-3.5-flash",
            "gemini-flash-latest",
            "gemini-3.5-flash-lite",
            "gemini-pro-latest",
    };

    public static final String DEFAULT_MODEL = MODELS[0];
    public static final String THINKING_LOW = "low";
    public static final String THINKING_HIGH = "high";

    private final Preferences prefs;

    public Settings(MontoyaApi api) {
        this.prefs = api.persistence().preferences();
    }

    // ---- API key -----------------------------------------------------------

    /** Effective key: the stored key, or the {@code GEMINI_API_KEY} env var fallback. */
    public String getApiKey() {
        String stored = prefs.getString(K_API_KEY);
        if (stored != null && !stored.isBlank()) {
            return stored.trim();
        }
        String env = System.getenv("GEMINI_API_KEY");
        return env == null ? "" : env.trim();
    }

    public boolean hasApiKey() {
        return !getApiKey().isBlank();
    }

    /** True when the effective key comes from the environment rather than the prefs store. */
    public boolean apiKeyFromEnv() {
        String stored = prefs.getString(K_API_KEY);
        boolean storedBlank = stored == null || stored.isBlank();
        String env = System.getenv("GEMINI_API_KEY");
        return storedBlank && env != null && !env.isBlank();
    }

    public void setApiKey(String key) {
        if (key == null || key.isBlank()) {
            prefs.deleteString(K_API_KEY);
        } else {
            prefs.setString(K_API_KEY, key.trim());
        }
    }

    // ---- provider selection -----------------------------------------------

    public String getProvider() {
        String p = prefs.getString(K_PROVIDER);
        return (p == null || p.isBlank()) ? PROVIDER_GEMINI : p;
    }

    public void setProvider(String provider) {
        prefs.setString(K_PROVIDER, provider);
    }

    // ---- Puter (OpenAI-compatible) ----------------------------------------

    /** Effective Puter token: stored value, or the PUTER_AUTH_TOKEN / PUTER_API_KEY env fallback. */
    public String getPuterToken() {
        String stored = prefs.getString(K_PUTER_TOKEN);
        if (stored != null && !stored.isBlank()) {
            return stored.trim();
        }
        String env = System.getenv("PUTER_AUTH_TOKEN");
        if (env == null || env.isBlank()) {
            env = System.getenv("PUTER_API_KEY");
        }
        return env == null ? "" : env.trim();
    }

    public boolean hasPuterToken() {
        return !getPuterToken().isBlank();
    }

    public boolean puterTokenFromEnv() {
        String stored = prefs.getString(K_PUTER_TOKEN);
        boolean storedBlank = stored == null || stored.isBlank();
        String env = System.getenv("PUTER_AUTH_TOKEN");
        if (env == null || env.isBlank()) {
            env = System.getenv("PUTER_API_KEY");
        }
        return storedBlank && env != null && !env.isBlank();
    }

    public void setPuterToken(String token) {
        if (token == null || token.isBlank()) {
            prefs.deleteString(K_PUTER_TOKEN);
        } else {
            prefs.setString(K_PUTER_TOKEN, token.trim());
        }
    }

    public String getPuterModel() {
        String m = prefs.getString(K_PUTER_MODEL);
        return (m == null || m.isBlank()) ? DEFAULT_PUTER_MODEL : m;
    }

    public void setPuterModel(String model) {
        prefs.setString(K_PUTER_MODEL, model);
    }

    /** Enable Puter's built-in web_search tool for OpenAI models. Default ON. */
    public boolean isPuterWebSearch() {
        return boolOrDefault(K_PUTER_WEBSEARCH, true);
    }

    public void setPuterWebSearch(boolean v) {
        prefs.setBoolean(K_PUTER_WEBSEARCH, v);
    }

    // ---- Custom (any OpenAI-compatible) provider --------------------------

    public String getCustomName() {
        String n = prefs.getString(K_CUSTOM_NAME);
        return (n == null || n.isBlank()) ? "Custom" : n;
    }

    public void setCustomName(String name) {
        prefs.setString(K_CUSTOM_NAME, name == null ? "" : name);
    }

    /** Full chat/completions endpoint URL for the custom provider. */
    public String getCustomEndpoint() {
        String e = prefs.getString(K_CUSTOM_ENDPOINT);
        return e == null ? "" : e.trim();
    }

    public void setCustomEndpoint(String url) {
        prefs.setString(K_CUSTOM_ENDPOINT, url == null ? "" : url.trim());
    }

    public String getCustomModel() {
        String m = prefs.getString(K_CUSTOM_MODEL);
        return m == null ? "" : m.trim();
    }

    public void setCustomModel(String model) {
        prefs.setString(K_CUSTOM_MODEL, model == null ? "" : model.trim());
    }

    /** Optional: the env var name holding the custom key (from models.dev), used as a fallback. */
    public String getCustomKeyEnv() {
        String e = prefs.getString(K_CUSTOM_KEY_ENV);
        return e == null ? "" : e.trim();
    }

    public void setCustomKeyEnv(String envName) {
        prefs.setString(K_CUSTOM_KEY_ENV, envName == null ? "" : envName.trim());
    }

    /** Effective custom key: the stored value, or the configured env var if set. */
    public String getCustomKey() {
        String stored = prefs.getString(K_CUSTOM_KEY);
        if (stored != null && !stored.isBlank()) {
            return stored.trim();
        }
        String envName = getCustomKeyEnv();
        if (!envName.isBlank()) {
            String v = System.getenv(envName);
            if (v != null && !v.isBlank()) {
                return v.trim();
            }
        }
        return "";
    }

    public boolean hasCustomKey() {
        return !getCustomKey().isBlank();
    }

    public boolean customKeyFromEnv() {
        String stored = prefs.getString(K_CUSTOM_KEY);
        return (stored == null || stored.isBlank()) && hasCustomKey();
    }

    public void setCustomKey(String key) {
        if (key == null || key.isBlank()) {
            prefs.deleteString(K_CUSTOM_KEY);
        } else {
            prefs.setString(K_CUSTOM_KEY, key.trim());
        }
    }

    // ---- model & thinking level -------------------------------------------

    public String getModel() {
        String m = prefs.getString(K_MODEL);
        return (m == null || m.isBlank()) ? DEFAULT_MODEL : m;
    }

    public void setModel(String model) {
        prefs.setString(K_MODEL, model);
    }

    public String getThinkingLevel() {
        String t = prefs.getString(K_THINKING);
        return (t == null || t.isBlank()) ? THINKING_HIGH : t;
    }

    public void setThinkingLevel(String level) {
        prefs.setString(K_THINKING, level);
    }

    // ---- safety toggles ----------------------------------------------------

    public boolean isRequireConfirmActive() {
        return boolOrDefault(K_REQUIRE_CONFIRM, true);
    }

    public void setRequireConfirmActive(boolean v) {
        prefs.setBoolean(K_REQUIRE_CONFIRM, v);
    }

    public boolean isRespectScope() {
        return boolOrDefault(K_RESPECT_SCOPE, true);
    }

    public void setRespectScope(boolean v) {
        prefs.setBoolean(K_RESPECT_SCOPE, v);
    }

    public boolean isAllowOutOfScope() {
        return boolOrDefault(K_ALLOW_OOS, false);
    }

    public void setAllowOutOfScope(boolean v) {
        prefs.setBoolean(K_ALLOW_OOS, v);
    }

    public boolean isPersistTranscripts() {
        return boolOrDefault(K_PERSIST_TRANSCRIPTS, false);
    }

    public void setPersistTranscripts(boolean v) {
        prefs.setBoolean(K_PERSIST_TRANSCRIPTS, v);
    }

    /**
     * Agent mode: auto-approve every action the model requests, with no confirmation dialog.
     * Scope still applies — out-of-scope targets remain blocked unless "Allow out-of-scope" is on.
     * Default OFF; this removes the human-in-the-loop gate, so a loud banner is shown when it's ON.
     */
    public boolean isAutoApprove() {
        return boolOrDefault(K_AUTO_APPROVE, false);
    }

    public void setAutoApprove(boolean v) {
        prefs.setBoolean(K_AUTO_APPROVE, v);
    }

    /** Background passive scanner: run local heuristic checks on proxied responses. Default ON. */
    public boolean isPassiveScanEnabled() {
        return boolOrDefault(K_PASSIVE_SCAN, true);
    }

    public void setPassiveScanEnabled(boolean v) {
        prefs.setBoolean(K_PASSIVE_SCAN, v);
    }

    /** Only passively scan in-scope traffic. Default ON. */
    public boolean isPassiveInScopeOnly() {
        return boolOrDefault(K_PASSIVE_IN_SCOPE, true);
    }

    public void setPassiveInScopeOnly(boolean v) {
        prefs.setBoolean(K_PASSIVE_IN_SCOPE, v);
    }

    /** Enrich newly-seen endpoints with an AI pass (uses tokens). Default OFF. */
    public boolean isAiEnrichEnabled() {
        return boolOrDefault(K_AI_ENRICH, false);
    }

    public void setAiEnrichEnabled(boolean v) {
        prefs.setBoolean(K_AI_ENRICH, v);
    }

    private boolean boolOrDefault(String key, boolean def) {
        Boolean b = prefs.getBoolean(key);
        return b == null ? def : b;
    }
}
