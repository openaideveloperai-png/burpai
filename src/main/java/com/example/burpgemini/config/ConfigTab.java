package com.example.burpgemini.config;

import com.example.burpgemini.chat.ChatTab;
import com.example.burpgemini.gemini.GeminiClient;
import com.example.burpgemini.util.BurpContext;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.SwingUtilities;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

/**
 * The settings UI. Everything here persists via {@link Settings} (Burp preferences). The API key is
 * masked, never echoed in full, and never logged.
 */
public final class ConfigTab extends JPanel {

    private final BurpContext ctx;
    private final Settings settings;
    private final GeminiClient gemini;
    private ChatTab chatTab; // set after construction to refresh its banner

    private final JPasswordField apiKeyField = new JPasswordField(36);
    private final JComboBox<String> modelBox = new JComboBox<>(Settings.MODELS);
    private final JComboBox<String> thinkingBox =
            new JComboBox<>(new String[]{Settings.THINKING_HIGH, Settings.THINKING_LOW});
    private final JCheckBox requireConfirm = new JCheckBox("Require confirmation before active actions (Tier 1–2)");
    private final JCheckBox respectScope = new JCheckBox("Respect Burp scope (block out-of-scope target traffic)");
    private final JCheckBox allowOutOfScope = new JCheckBox("Allow out-of-scope with explicit confirmation");
    private final JCheckBox persistTranscripts = new JCheckBox("Persist chat transcripts (never includes the API key)");
    private final JLabel statusLabel = new JLabel(" ");

    public ConfigTab(BurpContext ctx, Settings settings, GeminiClient gemini) {
        this.ctx = ctx;
        this.settings = settings;
        this.gemini = gemini;

        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(BorderFactory.createEmptyBorder(14, 16, 14, 16));

        add(title("Burp Gemini Assistant — Settings"));
        add(Box.createVerticalStrut(4));
        add(reminder("For authorized, in-scope penetration testing only. The AI proposes actions; "
                + "you confirm; the extension executes. Nothing target-facing runs without your approval."));
        add(Box.createVerticalStrut(12));

        add(buildForm());
        add(Box.createVerticalStrut(12));
        add(buildButtons());
        add(Box.createVerticalStrut(8));
        statusLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        add(statusLabel);
        add(Box.createVerticalGlue());

        loadFromSettings();
    }

    public void setChatTab(ChatTab chatTab) {
        this.chatTab = chatTab;
    }

    private JComponent buildForm() {
        JPanel form = new JPanel(new GridBagLayout());
        form.setAlignmentX(Component.LEFT_ALIGNMENT);
        form.setMaximumSize(new Dimension(760, Integer.MAX_VALUE));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 8);
        c.anchor = GridBagConstraints.WEST;

        int row = 0;

        c.gridx = 0;
        c.gridy = row;
        form.add(new JLabel("Gemini API key:"), c);
        c.gridx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        form.add(apiKeyField, c);
        c.weightx = 0;
        c.fill = GridBagConstraints.NONE;
        row++;

        c.gridx = 1;
        c.gridy = row;
        JLabel keyHint = new JLabel("Create one at https://aistudio.google.com/apikey. "
                + "Or set the GEMINI_API_KEY environment variable.");
        keyHint.setFont(keyHint.getFont().deriveFont(Font.ITALIC, keyHint.getFont().getSize() - 1f));
        form.add(keyHint, c);
        row++;

        c.gridx = 0;
        c.gridy = row;
        form.add(new JLabel("Model:"), c);
        c.gridx = 1;
        form.add(modelBox, c);
        row++;

        c.gridx = 0;
        c.gridy = row;
        form.add(new JLabel("Thinking level:"), c);
        c.gridx = 1;
        form.add(thinkingBox, c);
        row++;

        // Safety toggles.
        requireConfirm.setAlignmentX(Component.LEFT_ALIGNMENT);
        respectScope.setAlignmentX(Component.LEFT_ALIGNMENT);
        allowOutOfScope.setAlignmentX(Component.LEFT_ALIGNMENT);
        persistTranscripts.setAlignmentX(Component.LEFT_ALIGNMENT);

        c.gridx = 0;
        c.gridy = row;
        c.gridwidth = 2;
        form.add(sectionLabel("Safety"), c);
        row++;
        c.gridy = row++;
        form.add(requireConfirm, c);
        c.gridy = row++;
        form.add(respectScope, c);
        c.gridy = row++;
        form.add(allowOutOfScope, c);
        c.gridy = row++;
        form.add(persistTranscripts, c);

        return form;
    }

    private JComponent buildButtons() {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.X_AXIS));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);

        JButton save = new JButton("Save");
        save.addActionListener(e -> onSave());
        JButton test = new JButton("Test connection");
        test.addActionListener(e -> onTest());

        p.add(save);
        p.add(Box.createHorizontalStrut(8));
        p.add(test);
        p.add(Box.createHorizontalGlue());
        return p;
    }

    private void loadFromSettings() {
        // Show a placeholder rather than the real key so it is never echoed back in full.
        if (settings.apiKeyFromEnv()) {
            apiKeyField.setText("");
            apiKeyField.putClientProperty("JTextField.placeholderText", "(using GEMINI_API_KEY env var)");
        } else if (settings.hasApiKey()) {
            apiKeyField.setText("");
            apiKeyField.putClientProperty("JTextField.placeholderText", "(saved — leave blank to keep)");
        }
        modelBox.setSelectedItem(settings.getModel());
        thinkingBox.setSelectedItem(settings.getThinkingLevel());
        requireConfirm.setSelected(settings.isRequireConfirmActive());
        respectScope.setSelected(settings.isRespectScope());
        allowOutOfScope.setSelected(settings.isAllowOutOfScope());
        persistTranscripts.setSelected(settings.isPersistTranscripts());
    }

    private void onSave() {
        char[] pw = apiKeyField.getPassword();
        String key = new String(pw).trim();
        java.util.Arrays.fill(pw, '\0');
        if (!key.isEmpty()) {
            settings.setApiKey(key);
            apiKeyField.setText("");
            apiKeyField.putClientProperty("JTextField.placeholderText", "(saved — leave blank to keep)");
        }
        settings.setModel((String) modelBox.getSelectedItem());
        settings.setThinkingLevel((String) thinkingBox.getSelectedItem());
        settings.setRequireConfirmActive(requireConfirm.isSelected());
        settings.setRespectScope(respectScope.isSelected());
        settings.setAllowOutOfScope(allowOutOfScope.isSelected());
        settings.setPersistTranscripts(persistTranscripts.isSelected());
        setStatus("Settings saved.", new Color(0x2E7D32));
        ctx.logInfo("Settings saved (model=" + settings.getModel()
                + ", thinking=" + settings.getThinkingLevel()
                + ", requireConfirm=" + settings.isRequireConfirmActive()
                + ", respectScope=" + settings.isRespectScope()
                + ", allowOOS=" + settings.isAllowOutOfScope() + ")");
        if (chatTab != null) {
            chatTab.refreshBanner();
        }
    }

    private void onTest() {
        // Prefer the value typed in the field; otherwise use the saved/effective key.
        char[] pw = apiKeyField.getPassword();
        String typed = new String(pw).trim();
        java.util.Arrays.fill(pw, '\0');
        String key = typed.isEmpty() ? settings.getApiKey() : typed;
        String model = (String) modelBox.getSelectedItem();

        if (key.isEmpty()) {
            setStatus("No API key to test. Enter one first.", new Color(0xC62828));
            return;
        }
        setStatus("Testing…", null);
        ctx.executor().submit(() -> {
            GeminiClient.GeminiResult r = gemini.testConnection(key, model);
            SwingUtilities.invokeLater(() -> {
                if (r.ok) {
                    setStatus("OK — Gemini responded successfully (model " + model + ").",
                            new Color(0x2E7D32));
                } else {
                    setStatus("Failed: " + r.errorMessage, new Color(0xC62828));
                }
            });
        });
    }

    private void setStatus(String text, Color color) {
        statusLabel.setText(text);
        statusLabel.setForeground(color != null ? color : statusLabel.getForeground());
    }

    private static JComponent title(String text) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(Font.BOLD, l.getFont().getSize() + 3f));
        l.setAlignmentX(Component.LEFT_ALIGNMENT);
        return l;
    }

    private static JComponent sectionLabel(String text) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(Font.BOLD, l.getFont().getSize() + 1f));
        l.setBorder(BorderFactory.createEmptyBorder(8, 0, 2, 0));
        return l;
    }

    private static JComponent reminder(String text) {
        JLabel l = new JLabel("<html><body style='width:700px'>" + text + "</body></html>");
        l.setAlignmentX(Component.LEFT_ALIGNMENT);
        l.setForeground(new Color(0xE65100));
        return l;
    }
}
