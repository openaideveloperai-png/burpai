package com.example.burpgemini.recon;

/**
 * A single observation from the background passive scanner. Findings are deduplicated by
 * {@link #dedupKey()} so the same issue on the same endpoint is recorded once, not per request.
 */
public final class PassiveFinding {

    public final String type;        // short label, e.g. "Missing header: Content-Security-Policy"
    public final String severity;    // Info / Low / Medium / High
    public final String confidence;  // Certain / Firm / Tentative
    public final String url;
    public final String evidence;    // short, human-readable
    public final long time;
    public final boolean ai;         // true when produced by AI enrichment rather than a local check
    /** How many times this finding has recurred (repeat requests to the same endpoint). */
    public volatile int occurrences = 1;
    public volatile long lastSeen;

    public PassiveFinding(String type, String severity, String confidence,
                          String url, String evidence, boolean ai) {
        this.type = type;
        this.severity = severity;
        this.confidence = confidence;
        this.url = url;
        this.evidence = evidence;
        this.ai = ai;
        this.time = System.currentTimeMillis();
        this.lastSeen = this.time;
    }

    /** One finding of a given type per endpoint (method-independent path signature). */
    public String dedupKey() {
        return type + "|" + FindingsStore.endpointSignature(url);
    }

    /** Rank used to sort most-severe first. */
    public int severityRank() {
        switch (severity) {
            case "High":
                return 4;
            case "Medium":
                return 3;
            case "Low":
                return 2;
            case "Info":
                return 1;
            default:
                return 0;
        }
    }
}
