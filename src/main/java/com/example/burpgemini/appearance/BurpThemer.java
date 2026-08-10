package com.example.burpgemini.appearance;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.plaf.ColorUIResource;
import java.awt.Color;
import java.awt.Window;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Re-themes the whole Burp UI (all windows) to a palette derived from the chosen background, keeping
 * text readable by always pairing a background with a contrast-computed foreground. Fully reversible:
 * the original UIManager values are captured on first apply and restored by {@link #reset()}.
 */
public final class BurpThemer {

    // Background-role keys (get the derived surface colors).
    private static final String[] BG_KEYS = {
            "control", "Panel.background", "background", "Viewport.background", "ScrollPane.background",
            "SplitPane.background", "TabbedPane.background", "TabbedPane.contentAreaColor",
            "MenuBar.background", "ToolBar.background", "Tree.background", "OptionPane.background",
    };
    private static final String[] FIELD_KEYS = {
            "TextField.background", "FormattedTextField.background", "PasswordField.background",
            "TextArea.background", "TextPane.background", "EditorPane.background", "ComboBox.background",
            "Spinner.background", "List.background", "Table.background", "TableHeader.background",
    };
    // Foreground-role keys (get the contrast color).
    private static final String[] FG_KEYS = {
            "text", "controlText", "textText", "infoText", "Label.foreground", "TabbedPane.foreground",
            "Table.foreground", "TableHeader.foreground", "List.foreground", "Tree.foreground",
            "TextField.foreground", "TextArea.foreground", "TextPane.foreground", "EditorPane.foreground",
            "ComboBox.foreground", "Button.foreground", "CheckBox.foreground", "RadioButton.foreground",
            "MenuItem.foreground", "Menu.foreground", "TitledBorder.titleColor",
    };
    // Accent / selection keys.
    private static final String[] ACCENT_KEYS = {
            "TabbedPane.underlineColor", "TabbedPane.focusColor", "Component.focusColor",
            "List.selectionBackground", "Table.selectionBackground", "textHighlight",
    };

    private Map<String, Object> saved; // original values, captured lazily
    private boolean applied;

    public boolean isApplied() {
        return applied;
    }

    /** Apply a palette derived from {@code dominant}; {@code dark} chooses the contrast direction. */
    public void apply(Color dominant, boolean dark) {
        captureIfNeeded();

        Color panelBg = dominant;
        Color fieldBg = dark ? lighten(dominant, 0.10f) : darken(dominant, 0.06f);
        Color fg = dark ? new Color(0xEDEDED) : new Color(0x15181C);
        Color accent = dark ? new Color(0x4EA8FF) : new Color(0x1666C7);
        Color selBg = dark ? lighten(dominant, 0.22f) : darken(dominant, 0.14f);

        for (String k : BG_KEYS) {
            UIManager.put(k, new ColorUIResource(panelBg));
        }
        for (String k : FIELD_KEYS) {
            UIManager.put(k, new ColorUIResource(fieldBg));
        }
        for (String k : FG_KEYS) {
            UIManager.put(k, new ColorUIResource(fg));
        }
        for (String k : ACCENT_KEYS) {
            UIManager.put(k, new ColorUIResource(k.contains("selection") || k.equals("textHighlight")
                    ? selBg : accent));
        }
        // Selection text stays readable on the selection background.
        UIManager.put("List.selectionForeground", new ColorUIResource(contrast(selBg)));
        UIManager.put("Table.selectionForeground", new ColorUIResource(contrast(selBg)));

        applied = true;
        refreshAllWindows();
    }

    /** Restore Burp's original theme. */
    public void reset() {
        if (saved != null) {
            for (Map.Entry<String, Object> e : saved.entrySet()) {
                UIManager.put(e.getKey(), e.getValue());
            }
        }
        applied = false;
        refreshAllWindows();
    }

    private void captureIfNeeded() {
        if (saved != null) {
            return;
        }
        saved = new LinkedHashMap<>();
        for (String k : allKeys()) {
            saved.put(k, UIManager.get(k));
        }
        // Also remember the two selection-foreground keys we override.
        saved.put("List.selectionForeground", UIManager.get("List.selectionForeground"));
        saved.put("Table.selectionForeground", UIManager.get("Table.selectionForeground"));
    }

    private static String[] allKeys() {
        String[] all = new String[BG_KEYS.length + FIELD_KEYS.length + FG_KEYS.length + ACCENT_KEYS.length];
        int i = 0;
        for (String[] arr : new String[][]{BG_KEYS, FIELD_KEYS, FG_KEYS, ACCENT_KEYS}) {
            System.arraycopy(arr, 0, all, i, arr.length);
            i += arr.length;
        }
        return all;
    }

    private void refreshAllWindows() {
        SwingUtilities.invokeLater(() -> {
            for (Window w : Window.getWindows()) {
                if (w.isDisplayable()) {
                    SwingUtilities.updateComponentTreeUI(w);
                    w.revalidate();
                    w.repaint();
                }
            }
        });
    }

    // ---- color helpers -----------------------------------------------------

    static Color contrast(Color bg) {
        int lum = (int) (0.299 * bg.getRed() + 0.587 * bg.getGreen() + 0.114 * bg.getBlue());
        return lum < 140 ? new Color(0xEDEDED) : new Color(0x15181C);
    }

    static Color lighten(Color c, float f) {
        return new Color(
                clamp((int) (c.getRed() + (255 - c.getRed()) * f)),
                clamp((int) (c.getGreen() + (255 - c.getGreen()) * f)),
                clamp((int) (c.getBlue() + (255 - c.getBlue()) * f)));
    }

    static Color darken(Color c, float f) {
        return new Color(
                clamp((int) (c.getRed() * (1 - f))),
                clamp((int) (c.getGreen() * (1 - f))),
                clamp((int) (c.getBlue() * (1 - f))));
    }

    private static int clamp(int v) {
        return Math.max(0, Math.min(255, v));
    }
}
