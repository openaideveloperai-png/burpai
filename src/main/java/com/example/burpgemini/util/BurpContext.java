package com.example.burpgemini.util;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.example.burpgemini.config.Settings;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Shared context: holds the {@link MontoyaApi}, {@link Settings}, a background executor, and the
 * items the user right-clicked "Send to AI Assistant" on. Also centralises logging with API-key
 * redaction so the secret can never leak into Burp's Output/Error tabs.
 */
public final class BurpContext {

    private final MontoyaApi api;
    private final Settings settings;
    private final ExecutorService executor;

    /** Items attached to the next chat message (from the context-menu action). */
    private volatile List<HttpRequestResponse> contextItems = new ArrayList<>();
    /** Listener notified (on the EDT by convention) when the attached context changes. */
    private volatile Consumer<List<HttpRequestResponse>> contextListener;

    public BurpContext(MontoyaApi api, Settings settings) {
        this.api = api;
        this.settings = settings;
        this.executor = Executors.newFixedThreadPool(3, new NamedThreadFactory("burp-gemini"));
    }

    public MontoyaApi api() {
        return api;
    }

    public Settings settings() {
        return settings;
    }

    public ExecutorService executor() {
        return executor;
    }

    // ---- attached context items -------------------------------------------

    public List<HttpRequestResponse> contextItems() {
        return contextItems;
    }

    public void setContextItems(List<HttpRequestResponse> items) {
        this.contextItems = (items == null) ? new ArrayList<>() : new ArrayList<>(items);
        Consumer<List<HttpRequestResponse>> l = contextListener;
        if (l != null) {
            l.accept(this.contextItems);
        }
    }

    public void clearContextItems() {
        setContextItems(new ArrayList<>());
    }

    public void setContextListener(Consumer<List<HttpRequestResponse>> listener) {
        this.contextListener = listener;
    }

    // ---- logging (key-redacting) ------------------------------------------

    public void logInfo(String message) {
        api.logging().logToOutput(redact(message));
    }

    public void logError(String message) {
        api.logging().logToError(redact(message));
    }

    public void logError(String message, Throwable t) {
        api.logging().logToError(redact(message), t);
    }

    /** Replace any occurrence of the live API key with a masked placeholder. */
    public String redact(String s) {
        if (s == null) {
            return null;
        }
        String key = settings.getApiKey();
        if (key != null && key.length() >= 8 && s.contains(key)) {
            s = s.replace(key, "***REDACTED_API_KEY***");
        }
        return s;
    }

    // ---- lifecycle ---------------------------------------------------------

    public void shutdown() {
        executor.shutdownNow();
        try {
            executor.awaitTermination(2, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static final class NamedThreadFactory implements ThreadFactory {
        private final String prefix;
        private final AtomicInteger n = new AtomicInteger(1);

        NamedThreadFactory(String prefix) {
            this.prefix = prefix;
        }

        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(r, prefix + "-" + n.getAndIncrement());
            t.setDaemon(true);
            return t;
        }
    }
}
