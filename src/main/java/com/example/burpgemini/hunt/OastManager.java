package com.example.burpgemini.hunt;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Out-of-band (OAST / Burp Collaborator) manager. Holds one Collaborator client for the session,
 * mints correlatable payloads (via customData labels), and accumulates interactions across polls so
 * blind SSRF / blind XSS / blind SQLi / RCE callbacks become visible.
 */
public final class OastManager {

    private final MontoyaApi api;
    private volatile CollaboratorClient client;
    private final List<Interaction> all = new CopyOnWriteArrayList<>();
    private final Set<String> seenIds = ConcurrentHashMap.newKeySet();

    public OastManager(MontoyaApi api) {
        this.api = api;
    }

    /** @throws RuntimeException if Collaborator is unavailable/disabled. */
    public synchronized CollaboratorClient client() {
        if (client == null) {
            client = api.collaborator().createClient();
        }
        return client;
    }

    /** Mint a payload; {@code label} (customData) lets you correlate later interactions. */
    public CollaboratorPayload generate(String label) {
        return (label == null || label.isBlank())
                ? client().generatePayload()
                : client().generatePayload(label);
    }

    /** Poll the server, accumulate new interactions (deduped by id), and return the full list. */
    public List<Interaction> poll() {
        for (Interaction i : client().getAllInteractions()) {
            if (seenIds.add(i.id().toString())) {
                all.add(i);
            }
        }
        return all;
    }
}
