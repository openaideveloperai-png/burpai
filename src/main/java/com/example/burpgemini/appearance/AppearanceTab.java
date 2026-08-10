package com.example.burpgemini.appearance;

import com.example.burpgemini.config.Settings;
import com.example.burpgemini.util.BurpContext;

import javax.imageio.ImageIO;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JColorChooser;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSlider;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * "AI Appearance" tab: a live animated background with a readable, translucent control card. Lets
 * you pick a background style (including moving ones) or a custom image, and optionally re-theme all
 * of Burp to match — always with contrast-checked text so nothing is unreadable — plus a
 * <b>Reset to normal Burp</b> button.
 */
public final class AppearanceTab extends JPanel {

    private final BurpContext ctx;
    private final Settings settings;
    private final BurpThemer themer;

    private final AnimatedBackground bg = new AnimatedBackground();
    private final ControlCard card = new ControlCard();

    private final JComboBox<AnimatedBackground.Style> styleBox =
            new JComboBox<>(AnimatedBackground.Style.values());
    private final JSlider speed = new JSlider(1, 40, 10);
    private final JButton baseBtn = new JButton("Base color");
    private final JButton accentBtn = new JButton("Accent color");
    private final JButton loadImg = new JButton("Load image…");
    private final JButton applyBtn = new JButton("Apply colors to Burp");
    private final JButton resetBtn = new JButton("Reset to normal Burp");
    private final JLabel note = new JLabel(" ");
    private final List<JLabel> tintLabels = new ArrayList<>();

    private boolean loading;

    public AppearanceTab(BurpContext ctx, Settings settings, BurpThemer themer) {
        this.ctx = ctx;
        this.settings = settings;
        this.themer = themer;

        setLayout(new BorderLayout());
        bg.setLayout(new GridBagLayout());
        buildCard();

        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.anchor = GridBagConstraints.NORTHWEST;
        c.insets = new Insets(16, 16, 16, 16);
        c.weightx = 1;
        c.weighty = 1;
        bg.add(card, c);
        add(bg, BorderLayout.CENTER);

        loadFromSettings();
        wire();
        refreshContrast();

        // Re-apply the Burp theme on startup if it was applied before (after windows exist).
        if (settings.isAppearanceApplied()) {
            SwingUtilities.invokeLater(() -> themer.apply(bg.dominantColor(), bg.isDark()));
        }
    }

    private void buildCard() {
        card.setOpaque(false);
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBorder(BorderFactory.createEmptyBorder(14, 16, 14, 16));

        JLabel title = tinted("🎨 Appearance — custom backgrounds");
        title.setFont(title.getFont().deriveFont(java.awt.Font.BOLD, title.getFont().getSize() + 4f));
        card.add(title);
        card.add(Box.createVerticalStrut(10));

        card.add(row(tinted("Style:"), styleBox));
        card.add(row(tinted("Speed:"), speed));
        card.add(row(baseBtn, accentBtn, loadImg));
        card.add(Box.createVerticalStrut(8));
        card.add(row(applyBtn, resetBtn));
        card.add(Box.createVerticalStrut(6));
        note.setForeground(Color.WHITE);
        JPanel noteRow = row(note);
        card.add(noteRow);

        JLabel hint = tinted("Text stays readable on any background; \"Apply colors to Burp\" recolors "
                + "every tab to match, and \"Reset to normal Burp\" restores the default theme.");
        hint.setFont(hint.getFont().deriveFont(java.awt.Font.ITALIC, hint.getFont().getSize() - 1f));
        card.add(row(hint));
    }

    private JPanel row(JComponent... comps) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        p.setOpaque(false);
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        for (JComponent comp : comps) {
            p.add(comp);
        }
        return p;
    }

    private JLabel tinted(String text) {
        JLabel l = new JLabel("<html><body style='width:520px'>" + text.replace("<", "&lt;") + "</body></html>");
        tintLabels.add(l);
        return l;
    }

    private void wire() {
        styleBox.addActionListener(e -> {
            if (loading) {
                return;
            }
            bg.setStyle((AnimatedBackground.Style) styleBox.getSelectedItem());
            persist();
            refreshContrast();
        });
        speed.addChangeListener(e -> {
            bg.setSpeed(speed.getValue() / 10f);
            if (!speed.getValueIsAdjusting()) {
                persist();
            }
        });
        baseBtn.addActionListener(e -> pickColor(true));
        accentBtn.addActionListener(e -> pickColor(false));
        loadImg.addActionListener(e -> loadImage());
        applyBtn.addActionListener(e -> {
            themer.apply(bg.dominantColor(), bg.isDark());
            settings.setAppearanceApplied(true);
            note.setText("Applied — Burp recolored to match (text kept readable).");
        });
        resetBtn.addActionListener(e -> {
            themer.reset();
            settings.setAppearanceApplied(false);
            note.setText("Reset — back to the default Burp theme.");
        });
    }

    private void pickColor(boolean baseColor) {
        Color initial = baseColor ? bg.getBase() : bg.getAccent();
        Color picked = JColorChooser.showDialog(this, baseColor ? "Base color" : "Accent color", initial);
        if (picked != null) {
            if (baseColor) {
                bg.setColors(picked, null);
            } else {
                bg.setColors(null, picked);
            }
            swatches();
            persist();
            refreshContrast();
        }
    }

    private void loadImage() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Choose a background image");
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File f = chooser.getSelectedFile();
        try {
            BufferedImage img = ImageIO.read(f);
            if (img == null) {
                throw new java.io.IOException("Unsupported image format.");
            }
            bg.setImage(img);
            loading = true;
            styleBox.setSelectedItem(AnimatedBackground.Style.IMAGE);
            loading = false;
            bg.setStyle(AnimatedBackground.Style.IMAGE);
            persist();
            refreshContrast();
            note.setText("Loaded image: " + f.getName());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Could not load image:\n" + ex.getMessage(),
                    "Image error", JOptionPane.ERROR_MESSAGE);
        }
    }

    /** Recolor overlay text/swatches so nothing blends into the current background. */
    private void refreshContrast() {
        boolean dark = bg.isDark();
        Color fg = dark ? new Color(0xF2F2F2) : new Color(0x141414);
        for (JLabel l : tintLabels) {
            l.setForeground(fg);
        }
        note.setForeground(fg);
        card.setDark(dark);
        swatches();
        card.repaint();
    }

    private void swatches() {
        baseBtn.setBackground(bg.getBase());
        baseBtn.setForeground(BurpThemer.contrast(bg.getBase()));
        accentBtn.setBackground(bg.getAccent());
        accentBtn.setForeground(BurpThemer.contrast(bg.getAccent()));
        baseBtn.setOpaque(true);
        accentBtn.setOpaque(true);
    }

    private void loadFromSettings() {
        loading = true;
        try {
            bg.setColors(new Color(settings.getAppearanceBaseRgb()), new Color(settings.getAppearanceAccentRgb()));
            bg.setSpeed(settings.getAppearanceSpeedX10() / 10f);
            speed.setValue(settings.getAppearanceSpeedX10());
            AnimatedBackground.Style st;
            try {
                st = AnimatedBackground.Style.valueOf(settings.getAppearanceStyle());
            } catch (IllegalArgumentException ex) {
                st = AnimatedBackground.Style.AURORA;
            }
            bg.setStyle(st);
            styleBox.setSelectedItem(st);
        } finally {
            loading = false;
        }
    }

    private void persist() {
        settings.setAppearanceStyle(bg.getStyle().name());
        settings.setAppearanceBaseRgb(bg.getBase().getRGB());
        settings.setAppearanceAccentRgb(bg.getAccent().getRGB());
        settings.setAppearanceSpeedX10(speed.getValue());
    }

    /** Translucent, rounded control card with a scrim so its contents stay readable. */
    private static final class ControlCard extends JPanel {
        private boolean dark = true;

        void setDark(boolean dark) {
            this.dark = dark;
        }

        @Override
        protected void paintComponent(Graphics g0) {
            Graphics2D g = (Graphics2D) g0.create();
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.setColor(dark ? new Color(0, 0, 0, 165) : new Color(255, 255, 255, 185));
            g.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 18, 18);
            g.setColor(dark ? new Color(255, 255, 255, 40) : new Color(0, 0, 0, 40));
            g.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 18, 18);
            g.dispose();
            super.paintComponent(g0);
        }
    }
}
