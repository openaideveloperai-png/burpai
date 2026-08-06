package com.example.burpgemini.recon;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Thread-safe, bounded store of what the background passive scanner has collected: a deduplicated
 * set of {@link PassiveFinding}s plus an endpoint inventory. The proxy handler writes to it from
 * Burp's proxy threads; the UI and the {@code get_passive_findings} tool read snapshots.
 */
public final class FindingsStore {

    private static final int MAX_FINDINGS = 3000;
    private static final int MAX_ENDPOINTS = 3000;

    /** Aggregated view of one endpoint (method-independent path signature). */
    public static final class EndpointInfo {
        public final String signature;
        public volatile String sampleUrl;
        public final java.util.Set<String> methods = java.util.concurrent.ConcurrentHashMap.newKeySet();
        public final java.util.Set<Integer> statuses = java.util.concurrent.ConcurrentHashMap.newKeySet();
        public final AtomicInteger hits = new AtomicInteger();
        public volatile long lastSeen;

        EndpointInfo(String signature, String sampleUrl) {
            this.signature = signature;
            this.sampleUrl = sampleUrl;
        }
    }

    private final Map<String, PassiveFinding> findings = new ConcurrentHashMap<>();
    private final Map<String, EndpointInfo> endpoints = new ConcurrentHashMap<>();
    private volatile Runnable listener;

    public void setListener(Runnable listener) {
        this.listener = listener;
    }

    /** @return true if this was a new (non-duplicate) finding. */
    public boolean addFinding(PassiveFinding f) {
        if (findings.size() >= MAX_FINDINGS && !findings.containsKey(f.dedupKey())) {
            return false;
        }
        boolean isNew = findings.putIfAbsent(f.dedupKey(), f) == null;
        if (isNew) {
            notifyListener();
        }
        return isNew;
    }

    /** Record an observed endpoint. @return true if this endpoint signature was newly seen. */
    public boolean recordEndpoint(String method, String url, int status) {
        String sig = endpointSignature(url);
        boolean[] created = {false};
        EndpointInfo info = endpoints.computeIfAbsent(sig, k -> {
            created[0] = true;
            return new EndpointInfo(sig, url);
        });
        if (created[0] && endpoints.size() > MAX_ENDPOINTS) {
            // Over cap: drop the just-added entry to keep memory bounded.
            endpoints.remove(sig);
            return false;
        }
        if (method != null) {
            info.methods.add(method);
        }
        if (status > 0) {
            info.statuses.add(status);
        }
        info.hits.incrementAndGet();
        info.lastSeen = System.currentTimeMillis();
        if (created[0]) {
            notifyListener();
        }
        return created[0];
    }

    public List<PassiveFinding> findingsSnapshot() {
        List<PassiveFinding> list = new ArrayList<>(findings.values());
        list.sort(Comparator.comparingInt(PassiveFinding::severityRank).reversed()
                .thenComparing(f -> f.time, Comparator.reverseOrder()));
        return list;
    }

    public List<EndpointInfo> endpointsSnapshot() {
        List<EndpointInfo> list = new ArrayList<>(endpoints.values());
        list.sort(Comparator.comparingLong((EndpointInfo e) -> e.lastSeen).reversed());
        return list;
    }

    public int findingCount() {
        return findings.size();
    }

    public int endpointCount() {
        return endpoints.size();
    }

    public void clear() {
        findings.clear();
        endpoints.clear();
        notifyListener();
    }

    private void notifyListener() {
        Runnable l = listener;
        if (l != null) {
            try {
                l.run();
            } catch (RuntimeException ignored) {
                // UI listener must never break the scanner
            }
        }
    }

    /**
     * Method-independent endpoint signature: {@code host + path-without-query}, with long numeric
     * and hex/UUID path segments collapsed to {@code {id}} so /users/1 and /users/2 group together.
     */
    public static String endpointSignature(String url) {
        if (url == null || url.isBlank()) {
            return "";
        }
        try {
            java.net.URI u = java.net.URI.create(url);
            String host = u.getHost() == null ? "" : u.getHost();
            String path = u.getRawPath() == null ? "" : u.getRawPath();
            String[] segs = path.split("/");
            StringBuilder sb = new StringBuilder();
            for (String s : segs) {
                if (s.isEmpty()) {
                    continue;
                }
                sb.append('/').append(looksLikeId(s) ? "{id}" : s);
            }
            return host + (sb.length() == 0 ? "/" : sb.toString());
        } catch (RuntimeException e) {
            return url;
        }
    }

    private static boolean looksLikeId(String s) {
        if (s.length() >= 8 && s.chars().allMatch(c -> Character.isLetterOrDigit(c) || c == '-')) {
            boolean hasDigit = s.chars().anyMatch(Character::isDigit);
            if (hasDigit && s.matches("[0-9a-fA-F-]{8,}")) {
                return true; // hex / uuid-ish
            }
        }
        return s.matches("\\d+"); // pure number
    }
}
