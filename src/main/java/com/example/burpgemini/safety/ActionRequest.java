package com.example.burpgemini.safety;

import com.example.burpgemini.tools.RiskTier;

import java.util.List;

/**
 * Everything the confirmation card needs to display for one Tier ≥1 tool call, assembled by the
 * chat controller before the model's intent is allowed to run.
 */
public final class ActionRequest {
    public final String toolName;
    public final RiskTier tier;
    /** Plain-English summary of what the action does. */
    public final String summary;
    public final List<String> targetUrls;
    public final ScopeGuard.ScopeDecision scope;
    /** For send_http_request: a diff vs. the base request. For sequences/Intruder: a sample. May be null. */
    public final String payloadDetail;
    /** For sequences/Intruder: request count / iteration pattern. May be null. */
    public final String countInfo;
    /** The model's one-line rationale (its latest text), shown as "why the AI wants this". */
    public final String rationale;
    /** Expected success vs. failure signal, if the model provided one. May be null. */
    public final String successFailureHint;

    public ActionRequest(String toolName, RiskTier tier, String summary, List<String> targetUrls,
                         ScopeGuard.ScopeDecision scope, String payloadDetail, String countInfo,
                         String rationale, String successFailureHint) {
        this.toolName = toolName;
        this.tier = tier;
        this.summary = summary;
        this.targetUrls = targetUrls;
        this.scope = scope;
        this.payloadDetail = payloadDetail;
        this.countInfo = countInfo;
        this.rationale = rationale;
        this.successFailureHint = successFailureHint;
    }

    /** Tier 3 requires the "authorized & in scope" checkbox. */
    public boolean requiresAuthCheckbox() {
        return tier == RiskTier.TIER3_CONFIRM_STRONG || scope.requiresOverride;
    }

    /** Out-of-scope override needs its own explicit red checkbox. */
    public boolean requiresOutOfScopeCheckbox() {
        return scope.requiresOverride;
    }
}
