package com.example.burpgemini.util;

import com.google.gson.JsonObject;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Response normalization + comparison — the foundation for boolean-based detection, the access-control
 * matrix, and parameter mining. Normalizes out volatile content (CSRF tokens, timestamps, nonces,
 * long hex/UUIDs), then compares two responses by status, length and a shingle-based similarity so
 * "did this response really change?" can be answered reliably.
 */
public final class ResponseDiff {

    private ResponseDiff() {
    }

    private static final Pattern UUID = Pattern.compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    private static final Pattern LONGHEX = Pattern.compile("\\b[0-9a-fA-F]{16,}\\b");
    private static final Pattern TS = Pattern.compile("\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}(:\\d{2})?");
    private static final Pattern TOKENATTR = Pattern.compile(
            "(?i)(csrf|token|nonce|_token|authenticity_token|viewstate)[\"']?\\s*[:=]\\s*[\"']?[A-Za-z0-9_\\-./+]{6,}");
    private static final Pattern NUM = Pattern.compile("\\d{3,}");
    private static final Pattern WS = Pattern.compile("\\s+");

    /** Replace volatile tokens so two structurally-identical pages compare equal. */
    public static String normalize(String body) {
        if (body == null) {
            return "";
        }
        String s = body;
        s = UUID.matcher(s).replaceAll("UUID");
        s = TS.matcher(s).replaceAll("TS");
        s = TOKENATTR.matcher(s).replaceAll("TOK");
        s = LONGHEX.matcher(s).replaceAll("HEX");
        s = NUM.matcher(s).replaceAll("N");
        s = WS.matcher(s).replaceAll(" ");
        return s.trim();
    }

    /** Jaccard similarity over word shingles of the normalized bodies, 0..1. */
    public static double similarity(String a, String b) {
        Set<String> sa = shingles(normalize(a));
        Set<String> sb = shingles(normalize(b));
        if (sa.isEmpty() && sb.isEmpty()) {
            return 1.0;
        }
        Set<String> inter = new HashSet<>(sa);
        inter.retainAll(sb);
        Set<String> union = new HashSet<>(sa);
        union.addAll(sb);
        return union.isEmpty() ? 1.0 : (double) inter.size() / union.size();
    }

    private static Set<String> shingles(String s) {
        Set<String> out = new HashSet<>();
        String[] w = s.split(" ");
        for (int i = 0; i < w.length; i++) {
            if (w[i].isEmpty()) {
                continue;
            }
            // 3-word shingles capture structure; fall back to single words for short bodies.
            if (i + 2 < w.length) {
                out.add(w[i] + " " + w[i + 1] + " " + w[i + 2]);
            } else {
                out.add(w[i]);
            }
        }
        return out;
    }

    /** Structured comparison of two responses. */
    public static JsonObject compare(int statusA, String bodyA, int statusB, String bodyB) {
        double sim = similarity(bodyA == null ? "" : bodyA, bodyB == null ? "" : bodyB);
        int lenA = bodyA == null ? 0 : bodyA.length();
        int lenB = bodyB == null ? 0 : bodyB.length();
        JsonObject o = new JsonObject();
        o.addProperty("status_a", statusA);
        o.addProperty("status_b", statusB);
        o.addProperty("status_same", statusA == statusB);
        o.addProperty("length_a", lenA);
        o.addProperty("length_b", lenB);
        o.addProperty("length_delta", lenB - lenA);
        o.addProperty("similarity", round(sim));
        o.addProperty("likely_same", statusA == statusB && sim >= 0.95);
        o.addProperty("significantly_different", statusA != statusB || sim < 0.6
                || Math.abs(lenB - lenA) > Math.max(50, lenA * 0.15));
        return o;
    }

    private static double round(double v) {
        return Math.round(v * 1000.0) / 1000.0;
    }
}
