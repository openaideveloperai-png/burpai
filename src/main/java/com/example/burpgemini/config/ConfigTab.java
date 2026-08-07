package com.example.burpgemini.config;

import com.example.burpgemini.ai.AiProvider;
import com.example.burpgemini.ai.ModelsCatalog;
import com.example.burpgemini.ai.OpenAiCompatibleProvider;
import com.example.burpgemini.chat.ChatTab;
import com.example.burpgemini.util.BurpContext;

import java.util.LinkedHashSet;
import java.util.Set;

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
import java.util.List;

/**
 * The settings UI. Everything persists via {@link Settings} (Burp preferences). Secrets (the Gemini
 * API key and the Puter auth token) are masked, never echoed in full, and never logged.
 */
public final class ConfigTab extends JPanel {

    private final BurpContext ctx;
    private final Settings settings;
    private final List<AiProvider> providers;
    private final ModelsCatalog catalog;
    private ChatTab chatTab;

    private final JComboBox<String> providerBox = new JComboBox<>();
    private final JLabel modelInfo = new JLabel(" ");

    // Gemini
    private final JPasswordField apiKeyField = new JPasswordField(36);
    private final JComboBox<String> modelBox = new JComboBox<>(Settings.MODELS);
    private final JComboBox<String> thinkingBox =
            new JComboBox<>(new String[]{Settings.THINKING_HIGH, Settings.THINKING_LOW});

    // Puter
    private final JPasswordField puterTokenField = new JPasswordField(36);
    private final JComboBox<String> puterModelBox = new JComboBox<>(OpenAiCompatibleProvider.MODELS);
    private final JCheckBox puterWebSearch = new JCheckBox("Enable web search (OpenAI models — real-time info)");

    // Safety
    private final JCheckBox autoApprove = new JCheckBox(
            "⚡ Agent mode: auto-approve ALL actions (no confirmation; scope still applies)");
    private final JCheckBox requireConfirm = new JCheckBox("Require confirmation before active actions (Tier 1–2)");
    private final JCheckBox respectScope = new JCheckBox("Respect Burp scope (block out-of-scope target traffic)");
    private final JCheckBox allowOutOfScope = new JCheckBox("Allow out-of-scope with explicit confirmation");
    private final JCheckBox persistTranscripts = new JCheckBox("Persist chat transcripts (never includes secrets)");

    // Background passive recon
    private final JCheckBox passiveScan = new JCheckBox("Background passive scan (local heuristics on proxied responses)");
    private final JCheckBox passiveInScope = new JCheckBox("Passive scan in-scope traffic only");
    private final JCheckBox aiEnrich = new JCheckBox("AI-enrich new endpoints (uses tokens; throttled, opt-in)");
    private final JLabel statusLabel = new JLabel(" ");

    // Field group labels, so we can grey out the inactive provider's section.
    private JLabel geminiHeader;
    private JLabel puterHeader;

    public ConfigTab(BurpContext ctx, Settings settings, List<AiProvider> providers, ModelsCatalog catalog) {
        this.ctx = ctx;
        this.settings = settings;
        this.providers = providers;
        this.catalog = catalog;

        for (AiProvider p : providers) {
            providerBox.addItem(p.displayName());
        }
        puterModelBox.setEditable(true);

        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(BorderFactory.createEmptyBorder(14, 16, 14, 16));

        add(title("Burp AI Assistant — Settings"));
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

        providerBox.addActionListener(e -> {
            updateEnabledState();
            updateModelInfo();
        });
        modelBox.addActionListener(e -> updateModelInfo());
        puterModelBox.addActionListener(e -> updateModelInfo());
        loadFromSettings();
        updateEnabledState();
        updateModelInfo();
        // Best-effort: load model specs from models.dev in the background.
        ctx.executor().submit(() -> loadCatalog(false));
    }

    public void setChatTab(ChatTab chatTab) {
        this.chatTab = chatTab;
    }

    private JComponent buildForm() {
        JPanel form = new JPanel(new GridBagLayout());
        form.setAlignmentX(Component.LEFT_ALIGNMENT);
        form.setMaximumSize(new Dimension(780, Integer.MAX_VALUE));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 8);
        c.anchor = GridBagConstraints.WEST;
        int row = 0;

        c.gridx = 0;
        c.gridy = row;
        form.add(new JLabel("AI provider:"), c);
        c.gridx = 1;
        form.add(providerBox, c);
        row++;

        c.gridx = 1;
        c.gridy = row;
        modelInfo.setFont(modelInfo.getFont().deriveFont(Font.ITALIC, modelInfo.getFont().getSize() - 1f));
        form.add(modelInfo, c);
        row++;

        // ---- Gemini ----
        geminiHeader = sectionLabel("Google Gemini");
        c.gridx = 0;
        c.gridy = row;
        c.gridwidth = 2;
        form.add(geminiHeader, c);
        c.gridwidth = 1;
        row++;

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
        form.add(hint("Create one at https://aistudio.google.com/apikey, or set GEMINI_API_KEY."), c);
        row++;

        c.gridx = 0;
        c.gridy = row;
        form.add(new JLabel("Gemini model:"), c);
        c.gridx = 1;
        form.add(modelBox, c);
        row++;

        c.gridx = 0;
        c.gridy = row;
        form.add(new JLabel("Thinking level:"), c);
        c.gridx = 1;
        form.add(thinkingBox, c);
        row++;

        // ---- Puter ----
        puterHeader = sectionLabel("Puter AI (OpenAI-compatible)");
        c.gridx = 0;
        c.gridy = row;
        c.gridwidth = 2;
        form.add(puterHeader, c);
        c.gridwidth = 1;
        row++;

        c.gridx = 0;
        c.gridy = row;
        form.add(new JLabel("Puter auth token:"), c);
        c.gridx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        form.add(puterTokenField, c);
        c.weightx = 0;
        c.fill = GridBagConstraints.NONE;
        row++;

        c.gridx = 1;
        c.gridy = row;
        form.add(hint("Get one at puter.com/dashboard → API tokens → Create token, "
                + "or set PUTER_AUTH_TOKEN. Puter proxies GPT/Claude/Gemini/Grok."), c);
        row++;

        c.gridx = 0;
        c.gridy = row;
        form.add(new JLabel("Puter model:"), c);
        c.gridx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        form.add(puterModelBox, c);
        c.fill = GridBagConstraints.NONE;
        row++;

        c.gridx = 1;
        c.gridy = row;
        puterWebSearch.setAlignmentX(Component.LEFT_ALIGNMENT);
        form.add(puterWebSearch, c);
        row++;

        // ---- Safety ----
        c.gridx = 0;
        c.gridy = row;
        c.gridwidth = 2;
        form.add(sectionLabel("Safety"), c);
        row++;
        autoApprove.setAlignmentX(Component.LEFT_ALIGNMENT);
        autoApprove.setForeground(new Color(0xC62828));
        requireConfirm.setAlignmentX(Component.LEFT_ALIGNMENT);
        respectScope.setAlignmentX(Component.LEFT_ALIGNMENT);
        allowOutOfScope.setAlignmentX(Component.LEFT_ALIGNMENT);
        persistTranscripts.setAlignmentX(Component.LEFT_ALIGNMENT);
        c.gridy = row++;
        form.add(autoApprove, c);
        c.gridy = row++;
        form.add(requireConfirm, c);
        c.gridy = row++;
        form.add(respectScope, c);
        c.gridy = row++;
        form.add(allowOutOfScope, c);
        c.gridy = row++;
        form.add(persistTranscripts, c);

        // ---- Background passive recon ----
        passiveScan.setAlignmentX(Component.LEFT_ALIGNMENT);
        passiveInScope.setAlignmentX(Component.LEFT_ALIGNMENT);
        aiEnrich.setAlignmentX(Component.LEFT_ALIGNMENT);
        c.gridy = row++;
        form.add(sectionLabel("Background passive recon"), c);
        c.gridy = row++;
        form.add(passiveScan, c);
        c.gridy = row++;
        form.add(passiveInScope, c);
        c.gridy = row++;
        form.add(aiEnrich, c);

        return form;
    }

    private JComponent buildButtons() {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.X_AXIS));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        JButton save = new JButton("Save");
        save.addActionListener(e -> {
            persist();
            setStatus("Settings saved.", new Color(0x2E7D32));
            if (chatTab != null) {
                chatTab.refreshBanner();
            }
        });
        JButton test = new JButton("Test connection");
        test.addActionListener(e -> onTest());
        JButton refreshModels = new JButton("Refresh models (models.dev)");
        refreshModels.setToolTipText("Load up-to-date model specs & pricing from models.dev.");
        refreshModels.addActionListener(e -> {
            setStatus("Loading model specs from models.dev…", null);
            ctx.executor().submit(() -> loadCatalog(true));
        });
        p.add(save);
        p.add(Box.createHorizontalStrut(8));
        p.add(test);
        p.add(Box.createHorizontalStrut(8));
        p.add(refreshModels);
        p.add(Box.createHorizontalGlue());
        return p;
    }

    /** Fetch the models.dev catalog (off the EDT) and repopulate the dropdowns + info label. */
    private void loadCatalog(boolean report) {
        String err = catalog.fetch();
        SwingUtilities.invokeLater(() -> {
            if (err != null) {
                if (report) {
                    setStatus(err, new Color(0xC62828));
                }
                return;
            }
            repopulateModelBoxes();
            updateModelInfo();
            if (report) {
                setStatus("Loaded specs for " + catalog.size() + " models from models.dev.",
                        new Color(0x2E7D32));
            }
        });
    }

    private void repopulateModelBoxes() {
        // Gemini dropdown: hardcoded defaults + any "gemini*" models from the catalog.
        Set<String> gemini = new LinkedHashSet<>(java.util.Arrays.asList(Settings.MODELS));
        gemini.addAll(catalog.modelIds(mi -> mi.id.toLowerCase().startsWith("gemini")));
        rebuildCombo(modelBox, gemini, settings.getModel());

        // Puter dropdown: hardcoded defaults + OpenAI/GPT models from the catalog.
        Set<String> puter = new LinkedHashSet<>(java.util.Arrays.asList(OpenAiCompatibleProvider.MODELS));
        puter.addAll(catalog.modelIds(mi -> mi.id.toLowerCase().startsWith("gpt")
                || "openai".equalsIgnoreCase(mi.providerId)));
        rebuildCombo(puterModelBox, puter, settings.getPuterModel());
    }

    private static void rebuildCombo(JComboBox<String> box, Set<String> items, String preferred) {
        Object current = box.getSelectedItem();
        box.removeAllItems();
        for (String i : items) {
            box.addItem(i);
        }
        Object want = current != null && !String.valueOf(current).isBlank() ? current : preferred;
        if (want != null) {
            box.setSelectedItem(want);
        }
    }

    private void updateModelInfo() {
        if (!catalog.isLoaded()) {
            modelInfo.setText("Model specs: click 'Refresh models (models.dev)'.");
            return;
        }
        boolean gemini = Settings.PROVIDER_GEMINI.equals(selectedProviderId());
        Object sel = gemini ? modelBox.getSelectedItem() : puterModelBox.getSelectedItem();
        String model = sel == null ? "" : sel.toString().trim();
        if (model.isEmpty()) {
            modelInfo.setText(" ");
            return;
        }
        ModelsCatalog.ModelInfo mi = catalog.lookup(model);
        modelInfo.setText(mi == null
                ? model + " — not found on models.dev"
                : model + " — " + mi.summary());
    }

    private void loadFromSettings() {
        // Show placeholders rather than the real secrets so they are never echoed back in full.
        apiKeyField.setText("");
        apiKeyField.putClientProperty("JTextField.placeholderText",
                settings.apiKeyFromEnv() ? "(using GEMINI_API_KEY env var)"
                        : settings.hasApiKey() ? "(saved — leave blank to keep)" : "");
        puterTokenField.setText("");
        puterTokenField.putClientProperty("JTextField.placeholderText",
                settings.puterTokenFromEnv() ? "(using PUTER_AUTH_TOKEN env var)"
                        : settings.hasPuterToken() ? "(saved — leave blank to keep)" : "");

        selectProvider(settings.getProvider());
        modelBox.setSelectedItem(settings.getModel());
        thinkingBox.setSelectedItem(settings.getThinkingLevel());
        puterModelBox.setSelectedItem(settings.getPuterModel());
        puterWebSearch.setSelected(settings.isPuterWebSearch());
        autoApprove.setSelected(settings.isAutoApprove());
        requireConfirm.setSelected(settings.isRequireConfirmActive());
        respectScope.setSelected(settings.isRespectScope());
        allowOutOfScope.setSelected(settings.isAllowOutOfScope());
        persistTranscripts.setSelected(settings.isPersistTranscripts());
        passiveScan.setSelected(settings.isPassiveScanEnabled());
        passiveInScope.setSelected(settings.isPassiveInScopeOnly());
        aiEnrich.setSelected(settings.isAiEnrichEnabled());
    }

    private void persist() {
        char[] gk = apiKeyField.getPassword();
        String key = new String(gk).trim();
        java.util.Arrays.fill(gk, '\0');
        if (!key.isEmpty()) {
            settings.setApiKey(key);
            apiKeyField.setText("");
            apiKeyField.putClientProperty("JTextField.placeholderText", "(saved — leave blank to keep)");
        }
        char[] pk = puterTokenField.getPassword();
        String token = new String(pk).trim();
        java.util.Arrays.fill(pk, '\0');
        if (!token.isEmpty()) {
            settings.setPuterToken(token);
            puterTokenField.setText("");
            puterTokenField.putClientProperty("JTextField.placeholderText", "(saved — leave blank to keep)");
        }

        settings.setProvider(selectedProviderId());
        settings.setModel((String) modelBox.getSelectedItem());
        settings.setThinkingLevel((String) thinkingBox.getSelectedItem());
        Object pm = puterModelBox.getSelectedItem();
        if (pm != null && !pm.toString().isBlank()) {
            settings.setPuterModel(pm.toString().trim());
        }
        settings.setPuterWebSearch(puterWebSearch.isSelected());
        settings.setAutoApprove(autoApprove.isSelected());
        settings.setRequireConfirmActive(requireConfirm.isSelected());
        settings.setRespectScope(respectScope.isSelected());
        settings.setAllowOutOfScope(allowOutOfScope.isSelected());
        settings.setPersistTranscripts(persistTranscripts.isSelected());
        settings.setPassiveScanEnabled(passiveScan.isSelected());
        settings.setPassiveInScopeOnly(passiveInScope.isSelected());
        settings.setAiEnrichEnabled(aiEnrich.isSelected());
        ctx.logInfo("Settings saved (provider=" + settings.getProvider()
                + ", geminiModel=" + settings.getModel()
                + ", puterModel=" + settings.getPuterModel()
                + ", requireConfirm=" + settings.isRequireConfirmActive()
                + ", respectScope=" + settings.isRespectScope()
                + ", allowOOS=" + settings.isAllowOutOfScope() + ")");
    }

    private void onTest() {
        // Persist first so the test uses exactly what's in the form.
        persist();
        AiProvider provider = providers.get(Math.max(0, providerBox.getSelectedIndex()));
        if (!provider.isConfigured()) {
            setStatus(provider.notConfiguredHint(), new Color(0xC62828));
            return;
        }
        setStatus("Testing " + provider.displayName() + "…", null);
        ctx.executor().submit(() -> {
            com.example.burpgemini.ai.Neutral.TurnResult r = provider.testConnection();
            SwingUtilities.invokeLater(() -> {
                if (r.ok) {
                    setStatus("OK — " + provider.displayName() + " responded successfully.",
                            new Color(0x2E7D32));
                } else {
                    setStatus("Failed: " + r.errorMessage, new Color(0xC62828));
                }
            });
        });
    }

    private void updateEnabledState() {
        String id = selectedProviderId();
        boolean gemini = Settings.PROVIDER_GEMINI.equals(id);
        setGroupEnabled(gemini, geminiHeader, apiKeyField, modelBox, thinkingBox);
        setGroupEnabled(!gemini, puterHeader, puterTokenField, puterModelBox);
    }

    private void setGroupEnabled(boolean enabled, JComponent... comps) {
        for (JComponent comp : comps) {
            comp.setEnabled(enabled);
        }
    }

    private void selectProvider(String id) {
        for (int i = 0; i < providers.size(); i++) {
            if (providers.get(i).id().equals(id)) {
                providerBox.setSelectedIndex(i);
                return;
            }
        }
        providerBox.setSelectedIndex(0);
    }

    private String selectedProviderId() {
        int idx = Math.max(0, providerBox.getSelectedIndex());
        return providers.get(idx).id();
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

    private static JLabel sectionLabel(String text) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(Font.BOLD, l.getFont().getSize() + 1f));
        l.setBorder(BorderFactory.createEmptyBorder(8, 0, 2, 0));
        return l;
    }

    private static JComponent hint(String text) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(Font.ITALIC, l.getFont().getSize() - 1f));
        return l;
    }

    private static JComponent reminder(String text) {
        JLabel l = new JLabel("<html><body style='width:720px'>" + text + "</body></html>");
        l.setAlignmentX(Component.LEFT_ALIGNMENT);
        l.setForeground(new Color(0xE65100));
        return l;
    }
}
