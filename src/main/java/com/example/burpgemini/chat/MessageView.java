package com.example.burpgemini.chat;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextPane;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;

/**
 * Builds the styled message bubbles shown in the conversation view (user / assistant / notice).
 * Colours are derived from the current Look-and-Feel so the extension respects Burp's light/dark
 * theme instead of hardcoding values that break in one of them.
 */
final class MessageView {

    private MessageView() {
    }

    static JComponentRow user(String text, Font displayFont) {
        return bubble("You", text, displayFont, accent(true), true);
    }

    static JComponentRow assistant(String text, Font displayFont) {
        return bubble("AI Assistant", text, displayFont, accent(false), false);
    }

    static JComponentRow notice(String text, Font displayFont) {
        JComponentRow row = bubble("System", text, displayFont, softBackground(0.10f), false);
        return row;
    }

    /** A row wrapping a bubble, aligned left or right. */
    static final class JComponentRow extends JPanel {
        JComponentRow(Component bubble, boolean alignRight) {
            setLayout(new BoxLayout(this, BoxLayout.X_AXIS));
            setOpaque(false);
            setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));
            if (alignRight) {
                add(Box.createHorizontalGlue());
                add(bubble);
            } else {
                add(bubble);
                add(Box.createHorizontalGlue());
            }
        }
    }

    private static JComponentRow bubble(String role, String text, Font displayFont,
                                        Color bg, boolean alignRight) {
        JPanel bubble = new JPanel();
        bubble.setLayout(new BoxLayout(bubble, BoxLayout.Y_AXIS));
        bubble.setOpaque(true);
        bubble.setBackground(bg);
        bubble.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(borderColor(), 1, true),
                BorderFactory.createEmptyBorder(8, 10, 8, 10)));
        bubble.setMaximumSize(new Dimension(760, Integer.MAX_VALUE));

        JLabel header = new JLabel(role);
        header.setFont(header.getFont().deriveFont(Font.BOLD, header.getFont().getSize() - 1f));
        header.setForeground(mutedForeground());
        header.setAlignmentX(Component.LEFT_ALIGNMENT);
        bubble.add(header);
        bubble.add(Box.createVerticalStrut(4));

        JTextPane content = markdownish(text, displayFont);
        content.setAlignmentX(Component.LEFT_ALIGNMENT);
        bubble.add(content);

        return new JComponentRow(bubble, alignRight);
    }

    /**
     * Render text with light markdown-ish handling: fenced code blocks (```), and inline monospace
     * for anything that looks like a request/payload, get a monospaced font; everything else uses the
     * display font. Kept intentionally simple and robust.
     */
    static JTextPane markdownish(String text, Font displayFont) {
        JTextPane pane = new JTextPane();
        pane.setEditable(false);
        pane.setOpaque(false);
        pane.setBorder(null);
        StyledDocument doc = pane.getStyledDocument();

        SimpleAttributeSet normal = new SimpleAttributeSet();
        StyleConstants.setFontFamily(normal, displayFont.getFamily());
        StyleConstants.setFontSize(normal, displayFont.getSize());

        SimpleAttributeSet mono = new SimpleAttributeSet();
        StyleConstants.setFontFamily(mono, Font.MONOSPACED);
        StyleConstants.setFontSize(mono, displayFont.getSize() - 1);
        StyleConstants.setForeground(mono, codeForeground());

        try {
            String[] segments = text.split("```", -1);
            for (int i = 0; i < segments.length; i++) {
                boolean code = (i % 2 == 1);
                String seg = segments[i];
                if (code) {
                    // Drop an optional language hint on the first line.
                    int nl = seg.indexOf('\n');
                    if (nl >= 0 && nl < 20 && !seg.substring(0, nl).contains(" ")) {
                        seg = seg.substring(nl + 1);
                    }
                }
                doc.insertString(doc.getLength(), seg, code ? mono : normal);
            }
        } catch (Exception e) {
            try {
                doc.insertString(0, text, normal);
            } catch (Exception ignored) {
                // give up on styling
            }
        }
        pane.setMaximumSize(new Dimension(740, Integer.MAX_VALUE));
        return pane;
    }

    /** A read-only monospace area for diffs, payloads, and tool results. */
    static JTextArea monoArea(String text) {
        JTextArea area = new JTextArea(text);
        area.setEditable(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        area.setLineWrap(false);
        area.setBackground(softBackground(0.06f));
        area.setForeground(codeForeground());
        area.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));
        return area;
    }

    // ---- theme-aware colour helpers ----------------------------------------

    private static Color panelBackground() {
        Color c = javax.swing.UIManager.getColor("Panel.background");
        return c != null ? c : new Color(0x2B2B2B);
    }

    private static boolean isDark() {
        Color bg = panelBackground();
        double lum = (0.299 * bg.getRed() + 0.587 * bg.getGreen() + 0.114 * bg.getBlue());
        return lum < 128;
    }

    private static Color accent(boolean user) {
        // Subtle tint that reads on both themes.
        if (isDark()) {
            return user ? new Color(0x2F3B4C) : new Color(0x30392F);
        }
        return user ? new Color(0xE8F0FE) : new Color(0xEDF6EC);
    }

    private static Color softBackground(float amount) {
        Color bg = panelBackground();
        int delta = (int) (255 * amount);
        if (isDark()) {
            return new Color(clamp(bg.getRed() + delta), clamp(bg.getGreen() + delta), clamp(bg.getBlue() + delta));
        }
        return new Color(clamp(bg.getRed() - delta), clamp(bg.getGreen() - delta), clamp(bg.getBlue() - delta));
    }

    private static Color borderColor() {
        Color c = javax.swing.UIManager.getColor("Component.borderColor");
        return c != null ? c : (isDark() ? new Color(0x4A4A4A) : new Color(0xCCCCCC));
    }

    private static Color mutedForeground() {
        Color fg = javax.swing.UIManager.getColor("Label.foreground");
        if (fg == null) {
            fg = isDark() ? Color.LIGHT_GRAY : Color.DARK_GRAY;
        }
        return new Color(fg.getRed(), fg.getGreen(), fg.getBlue(), 180);
    }

    private static Color codeForeground() {
        return isDark() ? new Color(0xD7BA7D) : new Color(0x7A3E00);
    }

    private static int clamp(int v) {
        return Math.max(0, Math.min(255, v));
    }
}
