package com.example.burpgemini.ai;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Shared JSON-over-HTTP transport for the AI providers: a cancellable POST with jittered
 * exponential backoff on 429 / 5xx / network errors. Uses the JDK {@link HttpClient} (no extra
 * dependency). Runs off the Swing EDT by contract.
 */
public final class HttpTransport {

    private static final int MAX_ATTEMPTS = 4;

    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(20))
            .build();

    private final AtomicReference<CompletableFuture<HttpResponse<String>>> inFlight = new AtomicReference<>();

    /** A completed HTTP exchange, or a cancellation/terminal-network signal. */
    public static final class Response {
        public final int status;      // 0 when no HTTP response was obtained
        public final String body;     // response body, or a network-error message when status==0
        public final boolean cancelled;

        private Response(int status, String body, boolean cancelled) {
            this.status = status;
            this.body = body;
            this.cancelled = cancelled;
        }

        static Response of(int status, String body) {
            return new Response(status, body, false);
        }

        static Response cancelled() {
            return new Response(0, "Cancelled.", true);
        }

        static Response networkError(String message) {
            return new Response(0, message, false);
        }
    }

    /**
     * POST {@code jsonBody} to {@code url} with the given headers. Retries transient failures. On a
     * non-retryable HTTP status the {@link Response} is returned to the caller to interpret.
     */
    public Response postJson(String url, Map<String, String> headers, String jsonBody) {
        long backoffMs = 1000;
        Response last = Response.networkError("Request failed.");

        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(120))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody));
            for (Map.Entry<String, String> h : headers.entrySet()) {
                b.header(h.getKey(), h.getValue());
            }

            HttpResponse<String> resp;
            try {
                CompletableFuture<HttpResponse<String>> fut =
                        client.sendAsync(b.build(), HttpResponse.BodyHandlers.ofString());
                inFlight.set(fut);
                resp = fut.get();
            } catch (CancellationException ce) {
                return Response.cancelled();
            } catch (ExecutionException ee) {
                Throwable cause = ee.getCause() == null ? ee : ee.getCause();
                last = Response.networkError("Network error: " + cause.getMessage());
                if (attempt < MAX_ATTEMPTS) {
                    if (!sleep(backoffMs)) {
                        return Response.cancelled();
                    }
                    backoffMs *= 2;
                    continue;
                }
                return last;
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                return Response.cancelled();
            } finally {
                inFlight.set(null);
            }

            int status = resp.statusCode();
            if (status == 429 || status >= 500) {
                last = Response.of(status, resp.body());
                if (attempt < MAX_ATTEMPTS) {
                    if (!sleep(backoffMs + jitter())) {
                        return Response.cancelled();
                    }
                    backoffMs *= 2;
                    continue;
                }
                return last;
            }
            return Response.of(status, resp.body());
        }
        return last;
    }

    public void cancelInFlight() {
        CompletableFuture<HttpResponse<String>> f = inFlight.get();
        if (f != null) {
            f.cancel(true);
        }
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
