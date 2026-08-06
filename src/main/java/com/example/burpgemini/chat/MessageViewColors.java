package com.example.burpgemini.chat;

import javax.swing.UIManager;
import java.awt.Color;

/**
 * Theme-aware colours derived from the active Look-and-Feel so cards look right in both Burp's
 * light and dark themes. Never hardcode a background/foreground that only works in one theme.
 */
final class MessageViewColors {

    private MessageViewColors() {
    }

    static Color panelBackground() {
        Color c = UIManager.getColor("Panel.background");
        return c != null ? c : new Color(0x2B2B2B);
    }

    static boolean isDark() {
        Color bg = panelBackground();
        double lum = 0.299 * bg.getRed() + 0.587 * bg.getGreen() + 0.114 * bg.getBlue();
        return lum < 128;
    }

    static Color cardBackground() {
        Color bg = panelBackground();
        int d = 12;
        if (isDark()) {
            return new Color(clamp(bg.getRed() + d), clamp(bg.getGreen() + d), clamp(bg.getBlue() + d));
        }
        return new Color(clamp(bg.getRed() - 8), clamp(bg.getGreen() - 8), clamp(bg.getBlue() - 8));
    }

    static Color border() {
        Color c = UIManager.getColor("Component.borderColor");
        return c != null ? c : (isDark() ? new Color(0x4A4A4A) : new Color(0xCCCCCC));
    }

    static Color foreground() {
        Color c = UIManager.getColor("Label.foreground");
        return c != null ? c : (isDark() ? Color.LIGHT_GRAY : Color.DARK_GRAY);
    }

    static Color muted() {
        Color fg = foreground();
        return new Color(fg.getRed(), fg.getGreen(), fg.getBlue(), 170);
    }

    private static int clamp(int v) {
        return Math.max(0, Math.min(255, v));
    }
}
