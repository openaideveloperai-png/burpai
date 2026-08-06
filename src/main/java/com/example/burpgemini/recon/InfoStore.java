package com.example.burpgemini.recon;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Information-gathering aggregator. Unlike {@link FindingsStore} (which deduplicates security
 * findings), this accumulates recon facts from <b>every</b> in-scope request/response: the parameter
 * inventory, discovered secrets/tokens, request/response header names, cookies, technologies, emails
 * and hosts. Repeat requests to the same URL keep contributing new values here.
 *
 * <p>Everything is bounded and value samples are capped so memory stays predictable; secret values
 * are stored masked.
 */
public final class InfoStore {

    private static final int MAX_ENTRIES = 5000;
    private static final int MAX_SAMPLES = 6;
    private static final int MAX_ENDPOINTS = 15;
    private static final int MAX_URLS = 10;

    // ---- aggregate record types -------------------------------------------

    public static final class Param {
        public final String name;
        public final Set<String> types = ConcurrentHashMap.newKeySet();     // URL / BODY / COOKIE / JSON
        public final Set<String> samples = ConcurrentHashMap.newKeySet();   // capped
        public final Set<String> endpoints = ConcurrentHashMap.newKeySet(); // capped
        public final AtomicInteger count = new AtomicInteger();

        Param(String name) {
            this.name = name;
        }
    }

    public static final class Secret {
        public final String kind;   // JWT / Bearer / AWS key / API key / Private key
        public final String masked;
        public final Set<String> urls = ConcurrentHashMap.newKeySet(); // capped
        public final long firstSeen = System.currentTimeMillis();

        Secret(String kind, String masked) {
            this.kind = kind;
            this.masked = masked;
        }
    }

    public static final class NameStat {
        public final String name;
        public final Set<String> samples = ConcurrentHashMap.newKeySet(); // capped
        public final AtomicInteger count = new AtomicInteger();

        NameStat(String name) {
            this.name = name;
        }
    }

    private final Map<String, Param> params = new ConcurrentHashMap<>();
    private final Map<String, Secret> secrets = new ConcurrentHashMap<>();
    private final Map<String, NameStat> reqHeaders = new ConcurrentHashMap<>();
    private final Map<String, NameStat> respHeaders = new ConcurrentHashMap<>();
    private final Map<String, NameStat> cookies = new ConcurrentHashMap<>();
    private final Set<String> technologies = ConcurrentHashMap.newKeySet();
    private final Set<String> emails = ConcurrentHashMap.newKeySet();
    private final Set<String> hosts = ConcurrentHashMap.newKeySet();

    private volatile Runnable listener;

    public void setListener(Runnable listener) {
        this.listener = listener;
    }

    // ---- recording (called from the proxy thread for EVERY request) --------

    public void recordParam(String name, String type, String value, String endpointSig) {
        if (name == null || name.isEmpty()) {
            return;
        }
        if (params.size() >= MAX_ENTRIES && !params.containsKey(name)) {
            return;
        }
        Param p = params.computeIfAbsent(name, Param::new);
        if (type != null) {
            p.types.add(type);
        }
        addBounded(p.samples, truncate(value, 60), MAX_SAMPLES);
        addBounded(p.endpoints, endpointSig, MAX_ENDPOINTS);
        p.count.incrementAndGet();
        touch();
    }

    public void recordSecret(String kind, String value, String url) {
        if (value == null || value.length() < 8) {
            return;
        }
        String key = kind + "|" + value;
        if (secrets.size() >= MAX_ENTRIES && !secrets.containsKey(key)) {
            return;
        }
        Secret s = secrets.computeIfAbsent(key, k -> new Secret(kind, mask(value)));
        addBounded(s.urls, url, MAX_URLS);
        touch();
    }

    public void recordReqHeader(String name, String value) {
        recordName(reqHeaders, name, value);
    }

    public void recordRespHeader(String name, String value) {
        recordName(respHeaders, name, value);
    }

    public void recordCookie(String name, String attrs) {
        recordName(cookies, name, attrs);
    }

    public void addTech(String tech) {
        if (tech != null && !tech.isBlank() && technologies.size() < 500) {
            if (technologies.add(tech.trim())) {
                touch();
            }
        }
    }

    public void addEmail(String email) {
        if (email != null && emails.size() < 1000) {
            if (emails.add(email)) {
                touch();
            }
        }
    }

    public void addHost(String host) {
        if (host != null && !host.isBlank() && hosts.size() < 2000) {
            if (hosts.add(host)) {
                touch();
            }
        }
    }

    private void recordName(Map<String, NameStat> map, String name, String sample) {
        if (name == null || name.isEmpty()) {
            return;
        }
        if (map.size() >= MAX_ENTRIES && !map.containsKey(name)) {
            return;
        }
        NameStat n = map.computeIfAbsent(name, NameStat::new);
        if (sample != null && !sample.isBlank()) {
            addBounded(n.samples, truncate(sample, 80), MAX_SAMPLES);
        }
        n.count.incrementAndGet();
        touch();
    }

    // ---- snapshots ---------------------------------------------------------

    public List<Param> paramsSnapshot() {
        List<Param> l = new ArrayList<>(params.values());
        l.sort(Comparator.comparingInt((Param p) -> p.count.get()).reversed());
        return l;
    }

    public List<Secret> secretsSnapshot() {
        return new ArrayList<>(secrets.values());
    }

    public List<NameStat> reqHeadersSnapshot() {
        return sortedByCount(reqHeaders);
    }

    public List<NameStat> respHeadersSnapshot() {
        return sortedByCount(respHeaders);
    }

    public List<NameStat> cookiesSnapshot() {
        return sortedByCount(cookies);
    }

    public List<String> technologies() {
        return new ArrayList<>(technologies);
    }

    public List<String> emails() {
        return new ArrayList<>(emails);
    }

    public List<String> hosts() {
        return new ArrayList<>(hosts);
    }

    public int paramCount() {
        return params.size();
    }

    public int secretCount() {
        return secrets.size();
    }

    public void clear() {
        params.clear();
        secrets.clear();
        reqHeaders.clear();
        respHeaders.clear();
        cookies.clear();
        technologies.clear();
        emails.clear();
        hosts.clear();
        touch();
    }

    // ---- helpers -----------------------------------------------------------

    private static List<NameStat> sortedByCount(Map<String, NameStat> map) {
        List<NameStat> l = new ArrayList<>(map.values());
        l.sort(Comparator.comparingInt((NameStat n) -> n.count.get()).reversed());
        return l;
    }

    private static void addBounded(Set<String> set, String value, int max) {
        if (value == null || value.isEmpty()) {
            return;
        }
        if (set.size() < max) {
            set.add(value);
        }
    }

    private void touch() {
        Runnable l = listener;
        if (l != null) {
            try {
                l.run();
            } catch (RuntimeException ignored) {
                // never let the UI break the scanner
            }
        }
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }

    /** Mask a secret: keep the shape but not the full value. */
    static String mask(String v) {
        if (v == null) {
            return "";
        }
        if (v.length() <= 12) {
            return v.charAt(0) + "***";
        }
        return v.substring(0, 6) + "…" + v.substring(v.length() - 4) + " (len " + v.length() + ")";
    }
}
