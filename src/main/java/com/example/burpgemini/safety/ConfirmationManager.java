package com.example.burpgemini.safety;

import com.example.burpgemini.config.Settings;

import java.util.concurrent.CompletableFuture;

/**
 * Central approval gate. Decides — from the risk tier, the global toggle, and the scope decision —
 * whether an action may run immediately, must be confirmed by the operator, or is blocked outright.
 *
 * <p>The actual Approve/Deny card is rendered by a {@link ConfirmationView} (the chat tab); this
 * class owns only the policy.
 */
public final class ConfirmationManager {

    /** UI that renders a confirmation card and completes the future when the operator decides. */
    public interface ConfirmationView {
        CompletableFuture<Decision> show(ActionRequest request);

        /** Render the action details on the card without asking (auto-approved path). */
        default void showAutoApproved(ActionRequest request, String reason) {
        }
    }

    /** The operator's decision on a confirmation card. */
    public static final class Decision {
        public final boolean approved;
        public final String reason; // optional denial reason, fed back to the model
        public final boolean outOfScopeConfirmed;

        public Decision(boolean approved, String reason, boolean outOfScopeConfirmed) {
            this.approved = approved;
            this.reason = reason;
            this.outOfScopeConfirmed = outOfScopeConfirmed;
        }

        public static Decision approve() {
            return new Decision(true, null, false);
        }

        public static Decision deny(String reason) {
            return new Decision(false, reason, false);
        }
    }

    private final Settings settings;

    public ConfirmationManager(Settings settings) {
        this.settings = settings;
    }

    /**
     * Route an action through policy. The {@code view} is the specific tool card that will render the
     * Approve/Deny controls if confirmation is required.
     *
     * <ul>
     *   <li>Hard-blocked by scope → denied immediately, no dialog.</li>
     *   <li>Tier 3, or an out-of-scope override, or (Tier 1–2 while the global toggle is ON) → show
     *       the confirmation card and await the operator.</li>
     *   <li>Tier 1–2 with the global toggle OFF and in scope → auto-approved.</li>
     * </ul>
     */
    public CompletableFuture<Decision> request(ActionRequest req, ConfirmationView view) {
        // Scope is the one gate agent mode never bypasses: out-of-scope stays blocked.
        if (req.scope.blocked) {
            return CompletableFuture.completedFuture(
                    Decision.deny("Blocked: target is out of Burp scope and out-of-scope override is disabled."));
        }

        // Agent mode: auto-approve everything that isn't scope-blocked (including Tier 3 and an
        // out-of-scope override the operator explicitly enabled). No dialog.
        if (settings.isAutoApprove()) {
            view.showAutoApproved(req, "Agent mode");
            return CompletableFuture.completedFuture(
                    new Decision(true, null, req.scope.requiresOverride));
        }

        boolean mustConfirm = req.tier.alwaysConfirm()
                || req.scope.requiresOverride
                || (req.tier.requiresConfirmation() && settings.isRequireConfirmActive());

        if (!mustConfirm) {
            // Tier 1–2 with confirmation toggle off, and the target is in scope.
            view.showAutoApproved(req, "confirmation off");
            return CompletableFuture.completedFuture(Decision.approve());
        }
        return view.show(req);
    }
}
