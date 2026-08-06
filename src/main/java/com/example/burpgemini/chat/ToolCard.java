package com.example.burpgemini.chat;

import com.example.burpgemini.safety.ActionRequest;
import com.example.burpgemini.safety.ConfirmationManager;
import com.example.burpgemini.tools.RiskTier;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.util.concurrent.CompletableFuture;

/**
 * The visible audit trail for one tool call: a card that moves through
 * pending → (confirm) → running → result / denied / blocked. Implements
 * {@link ConfirmationManager.ConfirmationView} so the same card renders the Approve/Deny controls.
 */
final class ToolCard extends JPanel implements ConfirmationManager.ConfirmationView {

    private final JLabel statusLabel = new JLabel("Pending");
    private final JPanel confirmHolder = new JPanel();
    private final JPanel resultHolder = new JPanel();

    ToolCard(String toolName, String argsSummary, RiskTier tier, Font displayFont) {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setOpaque(true);
        setBackground(MessageViewColors.cardBackground());
        setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 4, 0, 0, tier.color()),
                BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(MessageViewColors.border(), 1, true),
                        BorderFactory.createEmptyBorder(8, 10, 8, 10))));
        setMaximumSize(new Dimension(820, Integer.MAX_VALUE));
        setAlignmentX(Component.LEFT_ALIGNMENT);

        JPanel header = new JPanel();
        header.setOpaque(false);
        header.setLayout(new BoxLayout(header, BoxLayout.X_AXIS));

        JLabel title = new JLabel("🔧 " + toolName);
        title.setFont(title.getFont().deriveFont(Font.BOLD));
        header.add(title);
        header.add(Box.createHorizontalStrut(8));
        header.add(badge(tier));
        header.add(Box.createHorizontalGlue());
        statusLabel.setForeground(MessageViewColors.muted());
        header.add(statusLabel);
        header.setAlignmentX(Component.LEFT_ALIGNMENT);
        add(header);

        if (argsSummary != null && !argsSummary.isBlank()) {
            add(Box.createVerticalStrut(4));
            JLabel args = new JLabel("<html><i>" + escape(argsSummary) + "</i></html>");
            args.setForeground(MessageViewColors.muted());
            args.setAlignmentX(Component.LEFT_ALIGNMENT);
            add(args);
        }

        confirmHolder.setOpaque(false);
        confirmHolder.setLayout(new BoxLayout(confirmHolder, BoxLayout.Y_AXIS));
        confirmHolder.setAlignmentX(Component.LEFT_ALIGNMENT);
        add(confirmHolder);

        resultHolder.setOpaque(false);
        resultHolder.setLayout(new BoxLayout(resultHolder, BoxLayout.Y_AXIS));
        resultHolder.setAlignmentX(Component.LEFT_ALIGNMENT);
        add(resultHolder);
    }

    // ---- state transitions (EDT-safe) --------------------------------------

    void setStatus(String text, Color color) {
        onEdt(() -> {
            statusLabel.setText(text);
            statusLabel.setForeground(color);
        });
    }

    void setRunning() {
        setStatus("Running…", MessageViewColors.muted());
    }

    void setResult(String text) {
        onEdt(() -> {
            statusLabel.setText("Done");
            statusLabel.setForeground(new Color(0x2E7D32));
            resultHolder.removeAll();
            resultHolder.add(scrollableMono(text, 220));
            revalidate();
            repaint();
        });
    }

    void setDenied(String reason) {
        onEdt(() -> {
            confirmHolder.removeAll();
            statusLabel.setText("Denied");
            statusLabel.setForeground(new Color(0xC62828));
            if (reason != null && !reason.isBlank()) {
                resultHolder.removeAll();
                resultHolder.add(note("Denied: " + reason, new Color(0xC62828)));
            }
            revalidate();
            repaint();
        });
    }

    void setBlocked(String reason) {
        onEdt(() -> {
            confirmHolder.removeAll();
            statusLabel.setText("Blocked");
            statusLabel.setForeground(new Color(0xC62828));
            resultHolder.removeAll();
            resultHolder.add(note("Blocked: " + reason, new Color(0xC62828)));
            revalidate();
            repaint();
        });
    }

    // ---- confirmation UI (ConfirmationView) --------------------------------

    @Override
    public CompletableFuture<ConfirmationManager.Decision> show(ActionRequest req) {
        CompletableFuture<ConfirmationManager.Decision> future = new CompletableFuture<>();
        onEdt(() -> buildConfirm(req, future));
        return future;
    }

    private void buildConfirm(ActionRequest req, CompletableFuture<ConfirmationManager.Decision> future) {
        confirmHolder.removeAll();
        statusLabel.setText("Awaiting approval");
        statusLabel.setForeground(new Color(0xE65100));

        confirmHolder.add(note(req.summary, MessageViewColors.foreground()));

        // Targets + scope status.
        String targets = req.targetUrls.isEmpty() ? "(none)" : String.join("\n", req.targetUrls);
        confirmHolder.add(kv("Target(s)", targets));
        Color scopeColor = req.scope.blocked ? new Color(0xC62828)
                : (req.scope.requiresOverride ? new Color(0xE65100) : new Color(0x2E7D32));
        confirmHolder.add(coloredNote("Scope: " + req.scope.summary, scopeColor));

        if (req.countInfo != null) {
            confirmHolder.add(kv("Volume", req.countInfo));
        }
        if (req.payloadDetail != null && !req.payloadDetail.isBlank()) {
            confirmHolder.add(labeled("Payload / modification:"));
            confirmHolder.add(scrollableMono(req.payloadDetail, 200));
        }
        if (req.successFailureHint != null && !req.successFailureHint.isBlank()) {
            confirmHolder.add(kv("Success vs. failure", req.successFailureHint));
        }
        if (req.rationale != null && !req.rationale.isBlank()) {
            confirmHolder.add(coloredNote("Why the AI wants this: " + oneLine(req.rationale),
                    MessageViewColors.muted()));
        }

        // Checkboxes.
        final JCheckBox oosBox = req.requiresOutOfScopeCheckbox()
                ? redCheck("I confirm testing this OUT-OF-SCOPE target is authorized") : null;
        final JCheckBox authBox = req.requiresAuthCheckbox()
                ? redCheck("I confirm this action is authorized and in scope") : null;

        JButton approve = new JButton("Approve");
        JButton deny = new JButton("Deny");

        Runnable refresh = () -> {
            boolean ok = (oosBox == null || oosBox.isSelected()) && (authBox == null || authBox.isSelected());
            approve.setEnabled(ok);
        };
        if (oosBox != null) {
            oosBox.addActionListener(e -> refresh.run());
            confirmHolder.add(oosBox);
        }
        if (authBox != null) {
            authBox.addActionListener(e -> refresh.run());
            confirmHolder.add(authBox);
        }
        refresh.run();

        approve.addActionListener(e -> {
            confirmHolder.removeAll();
            statusLabel.setText("Approved");
            statusLabel.setForeground(new Color(0x2E7D32));
            revalidate();
            repaint();
            future.complete(new ConfirmationManager.Decision(true, null,
                    oosBox != null && oosBox.isSelected()));
        });
        deny.addActionListener(e -> {
            String reason = JOptionPane.showInputDialog(this,
                    "Reason for denying (optional, sent to the AI):", "Deny action",
                    JOptionPane.QUESTION_MESSAGE);
            confirmHolder.removeAll();
            statusLabel.setText("Denied");
            statusLabel.setForeground(new Color(0xC62828));
            revalidate();
            repaint();
            future.complete(ConfirmationManager.Decision.deny(reason));
        });

        JPanel buttons = new JPanel();
        buttons.setOpaque(false);
        buttons.setLayout(new BoxLayout(buttons, BoxLayout.X_AXIS));
        buttons.setAlignmentX(Component.LEFT_ALIGNMENT);
        buttons.add(approve);
        buttons.add(Box.createHorizontalStrut(8));
        buttons.add(deny);
        buttons.add(Box.createHorizontalGlue());
        confirmHolder.add(Box.createVerticalStrut(6));
        confirmHolder.add(buttons);

        revalidate();
        repaint();
    }

    // ---- small component builders ------------------------------------------

    private static JLabel badge(RiskTier tier) {
        JLabel b = new JLabel(" " + tier.label() + " ");
        b.setOpaque(true);
        b.setBackground(tier.color());
        b.setForeground(Color.WHITE);
        b.setFont(b.getFont().deriveFont(Font.BOLD, b.getFont().getSize() - 2f));
        b.setBorder(BorderFactory.createEmptyBorder(1, 4, 1, 4));
        return b;
    }

    private static JComponent note(String text, Color fg) {
        JLabel l = new JLabel("<html><body style='width:520px'>" + escape(text) + "</body></html>");
        l.setForeground(fg);
        l.setAlignmentX(Component.LEFT_ALIGNMENT);
        l.setBorder(BorderFactory.createEmptyBorder(2, 0, 2, 0));
        return l;
    }

    private static JComponent coloredNote(String text, Color fg) {
        return note(text, fg);
    }

    private static JComponent labeled(String text) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(Font.BOLD, l.getFont().getSize() - 1f));
        l.setForeground(MessageViewColors.muted());
        l.setAlignmentX(Component.LEFT_ALIGNMENT);
        l.setBorder(BorderFactory.createEmptyBorder(4, 0, 2, 0));
        return l;
    }

    private static JComponent kv(String key, String value) {
        JPanel p = new JPanel();
        p.setOpaque(false);
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        p.add(labeled(key + ":"));
        JTextArea area = new JTextArea(value);
        area.setEditable(false);
        area.setOpaque(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setFont(area.getFont().deriveFont((float) area.getFont().getSize() - 1));
        area.setAlignmentX(Component.LEFT_ALIGNMENT);
        p.add(area);
        return p;
    }

    private static JComponent scrollableMono(String text, int maxHeight) {
        JTextArea area = MessageView.monoArea(text);
        JScrollPane sp = new JScrollPane(area,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        sp.setAlignmentX(Component.LEFT_ALIGNMENT);
        sp.setPreferredSize(new Dimension(760, Math.min(maxHeight, Math.max(60, text.split("\n").length * 16 + 24))));
        sp.setMaximumSize(new Dimension(780, maxHeight));
        return sp;
    }

    private static JCheckBox redCheck(String text) {
        JCheckBox cb = new JCheckBox(text);
        cb.setOpaque(false);
        cb.setForeground(new Color(0xC62828));
        cb.setFont(cb.getFont().deriveFont(Font.BOLD));
        cb.setAlignmentX(Component.LEFT_ALIGNMENT);
        return cb;
    }

    private static String oneLine(String s) {
        String t = s.replace("\r", " ").replace("\n", " ").trim();
        return t.length() > 200 ? t.substring(0, 200) + "…" : t;
    }

    private static String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static void onEdt(Runnable r) {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            SwingUtilities.invokeLater(r);
        }
    }
}
