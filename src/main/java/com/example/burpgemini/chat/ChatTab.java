package com.example.burpgemini.chat;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.example.burpgemini.config.Settings;
import com.example.burpgemini.tools.RiskTier;
import com.example.burpgemini.util.BurpContext;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.KeyStroke;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * The "AI Assistant" suite tab: a scrollable conversation view plus an input area. All mutation
 * methods are safe to call from any thread — they marshal onto the Swing EDT.
 */
public final class ChatTab extends JPanel {

    private final BurpContext ctx;
    private final Settings settings;
    private final Font displayFont;

    private final JPanel conversation = new JPanel();
    private final JScrollPane conversationScroll;
    private final JTextArea input = new JTextArea(3, 60);
    private final JButton sendButton = new JButton("Send");
    private final JButton cancelButton = new JButton("Cancel");
    private final JButton clearButton = new JButton("Clear chat");

    private final JPanel contextChip = new JPanel();
    private final JLabel contextChipLabel = new JLabel();
    private final JLabel banner = new JLabel();
    private final JLabel thinking = new JLabel("AI is thinking…");

    private ChatController controller;

    public ChatTab(BurpContext ctx, Settings settings) {
        this.ctx = ctx;
        this.settings = settings;
        Font f = ctx.api().userInterface().currentDisplayFont();
        this.displayFont = f != null ? f : new Font(Font.SANS_SERIF, Font.PLAIN, 13);

        setLayout(new BorderLayout());

        // ---- top: banner + context chip -----------------------------------
        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        banner.setOpaque(true);
        banner.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
        banner.setAlignmentX(Component.LEFT_ALIGNMENT);
        top.add(banner);

        contextChip.setLayout(new BoxLayout(contextChip, BoxLayout.X_AXIS));
        contextChip.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 8));
        contextChip.setAlignmentX(Component.LEFT_ALIGNMENT);
        JButton removeChip = new JButton("✕");
        removeChip.setMargin(new java.awt.Insets(0, 4, 0, 4));
        removeChip.addActionListener(e -> ctx.clearContextItems());
        contextChip.add(contextChipLabel);
        contextChip.add(Box.createHorizontalStrut(6));
        contextChip.add(removeChip);
        contextChip.setVisible(false);
        top.add(contextChip);
        add(top, BorderLayout.NORTH);

        // ---- center: conversation -----------------------------------------
        conversation.setLayout(new BoxLayout(conversation, BoxLayout.Y_AXIS));
        conversation.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        JPanel convWrapper = new JPanel(new BorderLayout());
        convWrapper.add(conversation, BorderLayout.NORTH);
        conversationScroll = new JScrollPane(convWrapper,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        conversationScroll.getVerticalScrollBar().setUnitIncrement(16);
        add(conversationScroll, BorderLayout.CENTER);

        // ---- bottom: input ------------------------------------------------
        add(buildInputPanel(), BorderLayout.SOUTH);

        thinking.setForeground(MessageViewColors.muted());
        thinking.setBorder(BorderFactory.createEmptyBorder(2, 10, 2, 10));

        ctx.setContextListener(items -> SwingUtilities.invokeLater(() -> updateContextChip(items)));
        refreshBanner();
        addNotice("Ready. Set your Gemini API key in the Config tab, then right-click a request "
                + "and choose 'Send to AI Assistant', or just ask a question here. "
                + "For authorized, in-scope testing only.");
    }

    public void setController(ChatController controller) {
        this.controller = controller;
    }

    private JComponent buildInputPanel() {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.setBorder(BorderFactory.createEmptyBorder(4, 8, 8, 8));

        panel.add(buildQuickActions(), BorderLayout.NORTH);

        input.setLineWrap(true);
        input.setWrapStyleWord(true);
        input.setFont(displayFont);
        JScrollPane inputScroll = new JScrollPane(input);
        inputScroll.setPreferredSize(new Dimension(600, 70));

        // Ctrl/Cmd+Enter to send.
        KeyStroke send = KeyStroke.getKeyStroke(KeyEvent.VK_ENTER,
                java.awt.Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx());
        input.getInputMap().put(send, "send");
        input.getActionMap().put("send", new javax.swing.AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                onSend();
            }
        });
        // Plain Ctrl+Enter fallback.
        input.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, InputEvent.CTRL_DOWN_MASK), "send");

        JPanel buttons = new JPanel();
        buttons.setLayout(new BoxLayout(buttons, BoxLayout.Y_AXIS));
        sendButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        cancelButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        clearButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        cancelButton.setEnabled(false);
        sendButton.addActionListener(e -> onSend());
        cancelButton.addActionListener(e -> {
            if (controller != null) {
                controller.cancelCurrentTurn();
            }
        });
        clearButton.addActionListener(e -> {
            if (controller != null) {
                controller.clearSession();
            }
            clearConversation();
        });
        buttons.add(sendButton);
        buttons.add(Box.createVerticalStrut(4));
        buttons.add(cancelButton);
        buttons.add(Box.createVerticalStrut(4));
        buttons.add(clearButton);

        panel.add(inputScroll, BorderLayout.CENTER);
        panel.add(buttons, BorderLayout.EAST);
        return panel;
    }

    private JComponent buildQuickActions() {
        JPanel bar = new JPanel();
        bar.setLayout(new BoxLayout(bar, BoxLayout.X_AXIS));
        bar.setBorder(BorderFactory.createEmptyBorder(0, 0, 4, 0));

        bar.add(new JLabel("Quick actions: "));
        bar.add(quickButton("🔍 Passive recon",
                "Do passive reconnaissance on the in-scope target(s): call list_proxy_history and "
                + "get_site_map to map endpoints, search_traffic for interesting keywords (token, "
                + "admin, password, key, debug), and run start_passive_audit on the most relevant "
                + "captured items. Then summarize the attack surface and any findings with confidence "
                + "and severity."));
        bar.add(Box.createHorizontalStrut(4));
        bar.add(quickButton("🎯 Analyze selection",
                "Analyze the attached/selected request(s) for vulnerabilities. If there is no captured "
                + "response, use send_http_request to fetch it first. Ground every finding in evidence "
                + "with a confidence and severity, then propose and run the smallest safe active test "
                + "to confirm the most promising issue."));
        bar.add(Box.createHorizontalStrut(4));
        bar.add(quickButton("🛡 Security headers",
                "Check the selected/most-recent response for missing or weak security headers "
                + "(CSP, HSTS, X-Content-Type-Options, X-Frame-Options, CORS Access-Control-* , "
                + "cookie flags). Fetch the response with send_http_request if needed. Report each "
                + "gap with severity."));
        bar.add(Box.createHorizontalGlue());
        return bar;
    }

    private JButton quickButton(String label, String prompt) {
        JButton b = new JButton(label);
        b.setMargin(new java.awt.Insets(2, 6, 2, 6));
        b.setFont(b.getFont().deriveFont(b.getFont().getSize() - 1f));
        b.addActionListener(e -> {
            if (controller != null) {
                controller.submitUserMessage(prompt);
            }
        });
        return b;
    }

    private void onSend() {
        if (controller == null) {
            return;
        }
        String text = input.getText().trim();
        if (text.isEmpty()) {
            return;
        }
        input.setText("");
        controller.submitUserMessage(text);
    }

    // ---- public API used by the controller (thread-safe) -------------------

    public void addUserMessage(String text) {
        addRow(() -> MessageView.user(text, displayFont));
    }

    public void addAssistantMessage(String text) {
        addRow(() -> MessageView.assistant(text, displayFont));
    }

    public void addNotice(String text) {
        addRow(() -> MessageView.notice(text, displayFont));
    }

    /** Create and append a tool card, returning the handle for later state updates. */
    public ToolCard addToolCard(String tool, String argsSummary, RiskTier tier) {
        return runEdtGet(() -> {
            ToolCard card = new ToolCard(tool, argsSummary, tier, displayFont);
            card.setAlignmentX(Component.LEFT_ALIGNMENT);
            conversation.add(card);
            conversation.add(Box.createVerticalStrut(6));
            conversation.revalidate();
            scrollToBottom();
            return card;
        });
    }

    public void setThinking(boolean on) {
        SwingUtilities.invokeLater(() -> {
            if (on) {
                if (thinking.getParent() == null) {
                    conversation.add(thinking);
                    conversation.revalidate();
                    scrollToBottom();
                }
            } else {
                if (thinking.getParent() != null) {
                    conversation.remove(thinking);
                    conversation.revalidate();
                    conversation.repaint();
                }
            }
        });
    }

    public void setBusy(boolean busy) {
        SwingUtilities.invokeLater(() -> {
            sendButton.setEnabled(!busy);
            cancelButton.setEnabled(busy);
        });
    }

    public void clearConversation() {
        SwingUtilities.invokeLater(() -> {
            conversation.removeAll();
            conversation.revalidate();
            conversation.repaint();
            addNotice("New session.");
        });
    }

    public void refreshBanner() {
        SwingUtilities.invokeLater(() -> {
            if (settings.isAutoApprove()) {
                banner.setText("⚡ AGENT MODE — every action is auto-approved with NO confirmation. "
                        + (settings.isRespectScope()
                            ? "Out-of-scope targets are still blocked." : "Scope is OFF too — nothing is blocked."));
                banner.setBackground(new Color(0xC62828));
                banner.setForeground(Color.WHITE);
                banner.setVisible(true);
            } else if (!settings.isRequireConfirmActive()) {
                banner.setText("⚠ 'Require confirmation before active actions' is OFF — "
                        + "Tier 1–2 actions run automatically (Tier 3 still always confirms).");
                banner.setBackground(new Color(0xC62828));
                banner.setForeground(Color.WHITE);
                banner.setVisible(true);
            } else if (!settings.isRespectScope()) {
                banner.setText("⚠ 'Respect Burp scope' is OFF — out-of-scope targets are NOT blocked.");
                banner.setBackground(new Color(0xE65100));
                banner.setForeground(Color.WHITE);
                banner.setVisible(true);
            } else {
                banner.setVisible(false);
            }
        });
    }

    // ---- helpers -----------------------------------------------------------

    private void updateContextChip(List<HttpRequestResponse> items) {
        if (items == null || items.isEmpty()) {
            contextChip.setVisible(false);
            return;
        }
        String label;
        if (items.size() == 1) {
            HttpRequestResponse only = items.get(0);
            String url = only.request() != null ? only.request().url() : "(request)";
            label = "📎 context attached: " + url;
        } else {
            label = "📎 context attached: " + items.size() + " requests";
        }
        contextChipLabel.setText(label);
        contextChip.setVisible(true);
    }

    private void addRow(Supplier<Component> factory) {
        SwingUtilities.invokeLater(() -> {
            Component row = factory.get();
            if (row instanceof JComponent) {
                ((JComponent) row).setAlignmentX(Component.LEFT_ALIGNMENT);
            }
            // Insert before the thinking indicator if present.
            if (thinking.getParent() == conversation) {
                conversation.remove(thinking);
                conversation.add(row);
                conversation.add(thinking);
            } else {
                conversation.add(row);
            }
            conversation.revalidate();
            scrollToBottom();
        });
    }

    private void scrollToBottom() {
        Timer t = new Timer(30, e -> {
            conversationScroll.getVerticalScrollBar()
                    .setValue(conversationScroll.getVerticalScrollBar().getMaximum());
        });
        t.setRepeats(false);
        t.start();
    }

    private <T> T runEdtGet(Supplier<T> supplier) {
        if (SwingUtilities.isEventDispatchThread()) {
            return supplier.get();
        }
        AtomicReference<T> ref = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> ref.set(supplier.get()));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (InvocationTargetException e) {
            ctx.logError("EDT task failed: " + e.getCause(), e.getCause());
        }
        return ref.get();
    }
}
