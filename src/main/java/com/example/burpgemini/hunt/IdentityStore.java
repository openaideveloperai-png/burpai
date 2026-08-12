package com.example.burpgemini.hunt;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Holds multiple authentication contexts (session cookies / bearer tokens / API keys) so a captured
 * request can be replayed as different users — the basis of the access-control matrix (IDOR/BOLA).
 * The special identity {@link #UNAUTH} strips all auth headers.
 */
public final class IdentityStore {

    public static final String UNAUTH = "unauthenticated";

    private static final String[] AUTH_HEADERS = {
            "Cookie", "Authorization", "apikey", "x-api-key", "x-auth-token",
            "x-access-token", "x-session-token",
    };

    private final Map<String, Map<String, String>> identities = new LinkedHashMap<>();

    public synchronized void set(String name, Map<String, String> headers) {
        identities.put(name, new LinkedHashMap<>(headers));
    }

    public synchronized Set<String> names() {
        return new LinkedHashSet<>(identities.keySet());
    }

    public synchronized Map<String, String> get(String name) {
        Map<String, String> h = identities.get(name);
        return h == null ? null : new LinkedHashMap<>(h);
    }

    public synchronized boolean has(String name) {
        return UNAUTH.equalsIgnoreCase(name) || identities.containsKey(name);
    }

    /** Return the request rewritten to use the named identity (auth headers swapped cleanly). */
    public HttpRequest apply(HttpRequest req, String name) {
        HttpRequest r = req;
        for (String h : AUTH_HEADERS) {
            if (r.hasHeader(h)) {
                r = r.withRemovedHeader(h);
            }
        }
        if (UNAUTH.equalsIgnoreCase(name)) {
            return r;
        }
        Map<String, String> headers = get(name);
        if (headers != null) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                r = r.withAddedHeader(e.getKey(), e.getValue());
            }
        }
        return r;
    }
}
