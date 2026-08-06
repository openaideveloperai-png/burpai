package com.example.burpgemini.safety;

import burp.api.montoya.MontoyaApi;
import com.example.burpgemini.config.Settings;

import java.util.ArrayList;
import java.util.List;

/**
 * Enforces Burp scope before any target-facing tool executes.
 *
 * <p>Policy:
 * <ul>
 *   <li>When "Respect Burp scope" is ON (default) and a target URL is out of scope, the action is
 *       blocked — unless "Allow out-of-scope with explicit confirmation" is enabled, in which case
 *       the confirmation dialog adds a mandatory red checkbox.</li>
 *   <li>Every decision is logged by the caller.</li>
 * </ul>
 */
public final class ScopeGuard {

    private final MontoyaApi api;
    private final Settings settings;

    public ScopeGuard(MontoyaApi api, Settings settings) {
        this.api = api;
        this.settings = settings;
    }

    /** Outcome of a scope check for one or more target URLs. */
    public static final class ScopeDecision {
        /** True when the action may proceed without an out-of-scope override checkbox. */
        public boolean allowed;
        /** True when the action is hard-blocked (respect scope ON, override OFF). */
        public boolean blocked;
        /** True when out-of-scope but overridable via an explicit per-action checkbox. */
        public boolean requiresOverride;
        public final List<String> inScopeUrls = new ArrayList<>();
        public final List<String> outOfScopeUrls = new ArrayList<>();
        public String summary = "";
    }

    public ScopeDecision check(List<String> urls) {
        ScopeDecision d = new ScopeDecision();
        for (String url : urls) {
            if (url == null || url.isBlank()) {
                continue;
            }
            boolean in;
            try {
                in = api.scope().isInScope(url);
            } catch (RuntimeException e) {
                in = false;
            }
            if (in) {
                d.inScopeUrls.add(url);
            } else {
                d.outOfScopeUrls.add(url);
            }
        }

        boolean anyOutOfScope = !d.outOfScopeUrls.isEmpty();

        if (!settings.isRespectScope()) {
            // Scope enforcement disabled entirely.
            d.allowed = true;
            d.summary = anyOutOfScope
                    ? "Scope enforcement is OFF; " + d.outOfScopeUrls.size() + " target(s) are out of Burp scope."
                    : "All targets in Burp scope.";
            return d;
        }

        if (!anyOutOfScope) {
            d.allowed = true;
            d.summary = "All target(s) in Burp scope.";
            return d;
        }

        // Out of scope with enforcement ON.
        if (settings.isAllowOutOfScope()) {
            d.requiresOverride = true;
            d.allowed = false; // requires the operator to tick the override checkbox
            d.summary = d.outOfScopeUrls.size() + " target(s) are OUT OF Burp scope. "
                    + "Requires explicit out-of-scope confirmation.";
        } else {
            d.blocked = true;
            d.allowed = false;
            d.summary = d.outOfScopeUrls.size() + " target(s) are OUT OF Burp scope. "
                    + "Blocked by policy (enable 'Allow out-of-scope with explicit confirmation' to override).";
        }
        return d;
    }
}
