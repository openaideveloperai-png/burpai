package com.example.burpgemini.recon;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;

import com.example.burpgemini.ai.AiProvider;
import com.example.burpgemini.ai.GeminiProvider;
import com.example.burpgemini.ai.Neutral.ChatMessage;
import com.example.burpgemini.ai.Neutral.ToolSpec;
import com.example.burpgemini.ai.Neutral.TurnResult;
import com.example.burpgemini.ai.OpenAiCompatibleProvider;
import com.example.burpgemini.config.Settings;
import com.example.burpgemini.util.BurpContext;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Optional, opt-in, heavily-throttled AI pass over newly-seen endpoints. It uses its <em>own</em>
 * provider instances (separate HTTP transport from the chat) so it never contends with an
 * interactive turn, and it is bounded by a per-session cap and a minimum interval to keep token
 * spend predictable. Off by default.
 */
public final class AiEnricher {

    private static final int MAX_PER_SESSION = 60;
    private static final long MIN_INTERVAL_MS = 3500;
    private static final int QUEUE_CAP = 100;
    private static final int MAX_TEXT = 2500;

    private static final String RECON_PROMPT = """
You are doing passive security reconnaissance inside Burp Suite for an authorized test. You are given
ONE captured HTTP request/response. Report only security-relevant observations that are evident from
what is present: missing/weak security headers, sensitive data exposure, auth/session handling,
injection or access-control hints, and misconfigurations. Be terse — one short bullet each, prefixed
with a severity (Info/Low/Medium/High). Do NOT propose active tests. If nothing is notable, reply
with exactly: nothing notable
""";

    private static final List<ToolSpec> NO_TOOLS = List.of();

    private final BurpContext ctx;
    private final Settings settings;
    private final FindingsStore store;
    private final List<AiProvider> providers;

    private final LinkedBlockingQueue<Item> queue = new LinkedBlockingQueue<>(QUEUE_CAP);
    private final Set<String> queued = ConcurrentHashMap.newKeySet();
    private final AtomicInteger done = new AtomicInteger();
    private volatile boolean running = true;
    private Thread worker;

    private static final class Item {
        final String url;
        final String path;
        final String text;

        Item(String url, String path, String text) {
            this.url = url;
            this.path = path;
            this.text = text;
        }
    }

    public AiEnricher(BurpContext ctx, FindingsStore store) {
        this.ctx = ctx;
        this.settings = ctx.settings();
        this.store = store;
        // Own provider instances → independent HTTP transport from the chat.
        this.providers = List.of(new GeminiProvider(ctx),
                OpenAiCompatibleProvider.puter(ctx), OpenAiCompatibleProvider.custom(ctx));
    }

    public void start() {
        worker = new Thread(this::loop, "burp-gemini-enrich");
        worker.setDaemon(true);
        worker.start();
    }

    public void stop() {
        running = false;
        if (worker != null) {
            worker.interrupt();
        }
        for (AiProvider p : providers) {
            p.cancelInFlight();
        }
    }

    /** Enqueue a newly-seen endpoint for enrichment (deduped, bounded). */
    public void enqueue(HttpRequest req, InterceptedResponse resp) {
        if (done.get() >= MAX_PER_SESSION) {
            return;
        }
        String url = req.url();
        String sig = FindingsStore.endpointSignature(url);
        if (!queued.add(sig)) {
            return; // already queued this endpoint
        }
        String text = "REQUEST:\n" + truncate(req.toString(), MAX_TEXT)
                + "\n\nRESPONSE (headers + start of body):\n"
                + responseHead(resp) + "\n" + truncate(resp.bodyToString(), MAX_TEXT);
        if (!queue.offer(new Item(url, pathOf(url), text))) {
            queued.remove(sig); // queue full; allow a later retry
        }
    }

    private void loop() {
        while (running) {
            Item item;
            try {
                item = queue.poll(1, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            if (item == null) {
                continue;
            }
            if (!settings.isAiEnrichEnabled() || done.get() >= MAX_PER_SESSION) {
                continue;
            }
            AiProvider provider = activeProvider();
            if (provider == null || !provider.isConfigured()) {
                continue;
            }
            try {
                analyze(provider, item);
            } catch (Exception e) {
                ctx.logError("AI enrichment error: " + e);
            }
            done.incrementAndGet();
            sleep(MIN_INTERVAL_MS);
        }
    }

    private void analyze(AiProvider provider, Item item) {
        List<ChatMessage> history = List.of(ChatMessage.user(
                "Passively analyze this single captured exchange.\n\n" + item.text));
        TurnResult res = provider.sendTurn(RECON_PROMPT, history, NO_TOOLS);
        if (!res.ok || res.text == null) {
            return;
        }
        String text = res.text.trim();
        if (text.isEmpty() || text.equalsIgnoreCase("nothing notable")) {
            return;
        }
        String severity = inferSeverity(text);
        store.addFinding(new PassiveFinding(
                "AI recon: " + item.path, severity, "Tentative", item.url,
                truncate(text, 1500), true));
        ctx.logInfo("[passive/ai] " + item.path + " → " + severity);
    }

    private AiProvider activeProvider() {
        String id = settings.getProvider();
        for (AiProvider p : providers) {
            if (p.id().equals(id)) {
                return p;
            }
        }
        return providers.isEmpty() ? null : providers.get(0);
    }

    private static String inferSeverity(String text) {
        String t = text.toLowerCase();
        if (t.contains("high") || t.contains("critical")) {
            return "High";
        }
        if (t.contains("medium")) {
            return "Medium";
        }
        if (t.contains("low")) {
            return "Low";
        }
        return "Info";
    }

    private static String responseHead(InterceptedResponse r) {
        StringBuilder sb = new StringBuilder("HTTP ").append(r.statusCode()).append('\n');
        int n = 0;
        for (HttpHeader h : r.headers()) {
            if (n++ > 25) {
                break;
            }
            sb.append(h.name()).append(": ").append(h.value()).append('\n');
        }
        return sb.toString();
    }

    private static String pathOf(String url) {
        try {
            java.net.URI u = java.net.URI.create(url);
            return (u.getHost() == null ? "" : u.getHost()) + (u.getRawPath() == null ? "" : u.getRawPath());
        } catch (RuntimeException e) {
            return url;
        }
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
