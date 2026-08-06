package com.example.burpgemini.tools;

import java.awt.Color;
import java.util.HashMap;
import java.util.Map;

/**
 * Risk tiering for every tool the model can request.
 *
 * <p>The tier decides how a tool call is mediated before it can run:
 * <ul>
 *   <li>{@link #TIER0_AUTO} — read-only, runs immediately, no dialog.</li>
 *   <li>{@link #TIER1_CONFIRM} — confirm; stages work in a Burp tool but sends no <em>new</em> traffic.</li>
 *   <li>{@link #TIER2_CONFIRM_WARN} — confirm + warning; sends traffic to the target.</li>
 *   <li>{@link #TIER3_CONFIRM_STRONG} — confirm + strong warning; active / high-volume / stateful.
 *       Always confirmed, even when the global "require confirmation" toggle is off.</li>
 * </ul>
 *
 * <p>The tier of a call is intent-independent: it is a property of the <em>tool</em>, so the model
 * can never talk its way into a lower gate.
 */
public enum RiskTier {
    TIER0_AUTO("Read-only", new Color(0x2E7D32)),
    TIER1_CONFIRM("Confirm", new Color(0xB59A00)),
    TIER2_CONFIRM_WARN("Sends traffic", new Color(0xE65100)),
    TIER3_CONFIRM_STRONG("Active / high-volume", new Color(0xC62828));

    private final String label;
    private final Color color;

    RiskTier(String label, Color color) {
        this.label = label;
        this.color = color;
    }

    public String label() {
        return label;
    }

    /** A saturated badge color that stays legible on both light and dark Burp themes (white text). */
    public Color color() {
        return color;
    }

    public boolean requiresConfirmation() {
        return this != TIER0_AUTO;
    }

    /** Tier 3 is confirmed unconditionally, regardless of the global toggle. */
    public boolean alwaysConfirm() {
        return this == TIER3_CONFIRM_STRONG;
    }

    // ---- tool name -> tier -------------------------------------------------

    private static final Map<String, RiskTier> BY_TOOL = new HashMap<>();

    static {
        // Tier 0 — read-only, auto-run.
        BY_TOOL.put("list_proxy_history", TIER0_AUTO);
        BY_TOOL.put("get_request_response", TIER0_AUTO);
        BY_TOOL.put("get_site_map", TIER0_AUTO);
        BY_TOOL.put("get_selected_items", TIER0_AUTO);
        BY_TOOL.put("search_traffic", TIER0_AUTO);
        BY_TOOL.put("get_scope", TIER0_AUTO);
        BY_TOOL.put("decode_transform", TIER0_AUTO);

        // Tier 1 — confirm, no new target traffic (staging only).
        BY_TOOL.put("send_to_repeater", TIER1_CONFIRM);
        BY_TOOL.put("add_to_scope", TIER1_CONFIRM);
        BY_TOOL.put("remove_from_scope", TIER1_CONFIRM);
        // Montoya exposes no programmatic Intruder *start*, so send_to_intruder can only stage;
        // per the spec it is therefore treated as Tier 1 (confirm + manual start).
        BY_TOOL.put("send_to_intruder", TIER1_CONFIRM);

        // Tier 2 — confirm + warning, sends traffic to the target.
        BY_TOOL.put("send_http_request", TIER2_CONFIRM_WARN);
        BY_TOOL.put("start_passive_audit", TIER2_CONFIRM_WARN);

        // Tier 3 — confirm + strong warning, active / high-volume / stateful.
        BY_TOOL.put("start_active_audit", TIER3_CONFIRM_STRONG);
        BY_TOOL.put("run_request_sequence", TIER3_CONFIRM_STRONG);
    }

    /** Unknown tools default to the strongest gate: fail safe, never fail open. */
    public static RiskTier forTool(String toolName) {
        return BY_TOOL.getOrDefault(toolName, TIER3_CONFIRM_STRONG);
    }
}
