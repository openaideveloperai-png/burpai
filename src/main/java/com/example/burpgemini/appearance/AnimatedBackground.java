package com.example.burpgemini.appearance;

import javax.swing.JPanel;
import javax.swing.Timer;
import java.awt.AlphaComposite;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GradientPaint;
import java.awt.RadialGradientPaint;
import java.awt.RenderingHints;
import java.awt.geom.Point2D;
import java.awt.image.BufferedImage;
import java.util.Random;

/**
 * A live, animated background canvas. Draws a selected style (aurora, starfield, matrix rain,
 * bubbles, gradient, a custom image, or none) via a Swing {@link Timer}. The timer only runs while
 * the panel is showing, so it costs nothing when the tab isn't visible.
 *
 * <p>{@link #isDark()} reports whether the current background is dark, so callers can choose a
 * contrasting text color and nothing blends in.
 */
public final class AnimatedBackground extends JPanel {

    public enum Style {
        AURORA("Aurora (moving)"),
        STARFIELD("Starfield (moving)"),
        MATRIX("Matrix rain (moving)"),
        BUBBLES("Bubbles (moving)"),
        PLASMA("Plasma (moving)"),
        GRADIENT("Gradient (static)"),
        IMAGE("Custom image"),
        NONE("None (default Burp)");

        public final String label;

        Style(String label) {
            this.label = label;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    private Style style = Style.AURORA;
    private Color base = new Color(0x0B1E3B);   // primary color
    private Color accent = new Color(0x3AA0FF); // secondary/accent color
    private float speed = 1.0f;
    private BufferedImage image;

    private final Timer timer;
    private long startNanos = System.nanoTime();

    // Starfield / bubbles state.
    private final Random rnd = new Random(42);
    private float[][] stars; // x,y,z
    private float[][] bubbles; // x,y,r,vy,alpha
    private int[] matrixY; // per-column head position
    private final BufferedImage plasmaBuf = new BufferedImage(160, 100, BufferedImage.TYPE_INT_RGB);

    public AnimatedBackground() {
        setOpaque(true);
        // ~25 fps; only repaint while actually showing.
        timer = new Timer(40, e -> {
            if (isShowing()) {
                repaint();
            }
        });
        timer.setCoalesce(true);
    }

    @Override
    public void addNotify() {
        super.addNotify();
        timer.start();
    }

    @Override
    public void removeNotify() {
        timer.stop();
        super.removeNotify();
    }

    // ---- configuration -----------------------------------------------------

    public void setStyle(Style s) {
        this.style = s == null ? Style.NONE : s;
        repaint();
    }

    public Style getStyle() {
        return style;
    }

    public void setColors(Color base, Color accent) {
        if (base != null) {
            this.base = base;
        }
        if (accent != null) {
            this.accent = accent;
        }
        repaint();
    }

    public Color getBase() {
        return base;
    }

    public Color getAccent() {
        return accent;
    }

    public void setSpeed(float s) {
        this.speed = Math.max(0.1f, Math.min(4f, s));
    }

    public float getSpeed() {
        return speed;
    }

    public void setImage(BufferedImage img) {
        this.image = img;
        repaint();
    }

    /** True when the effective background is dark (so overlay text should be light). */
    public boolean isDark() {
        switch (style) {
            case STARFIELD:
            case MATRIX:
                return true;
            case NONE: {
                Color c = getBackground();
                return c == null || luminance(c) < 128;
            }
            case IMAGE:
                return image == null || imageLuminance() < 128;
            default:
                return luminance(base) < 140;
        }
    }

    /** A representative color for deriving a matching Burp palette. */
    public Color dominantColor() {
        switch (style) {
            case STARFIELD:
            case MATRIX:
                return new Color(0x0A0A12);
            case NONE:
                return getBackground() == null ? new Color(0x2B2B2B) : getBackground();
            case IMAGE:
                return image == null ? base : averageImageColor();
            default:
                return blend(base, accent, 0.35f);
        }
    }

    // ---- painting ----------------------------------------------------------

    @Override
    protected void paintComponent(Graphics g0) {
        Graphics2D g = (Graphics2D) g0.create();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        int w = getWidth();
        int h = getHeight();
        double t = (System.nanoTime() - startNanos) / 1_000_000_000.0 * speed;

        switch (style) {
            case AURORA:
                paintAurora(g, w, h, t);
                break;
            case STARFIELD:
                paintStarfield(g, w, h, t);
                break;
            case MATRIX:
                paintMatrix(g, w, h, t);
                break;
            case BUBBLES:
                paintBubbles(g, w, h, t);
                break;
            case PLASMA:
                paintPlasma(g, w, h, t);
                break;
            case GRADIENT:
                paintGradient(g, w, h);
                break;
            case IMAGE:
                paintImage(g, w, h, t);
                break;
            case NONE:
            default:
                g.setColor(getBackground());
                g.fillRect(0, 0, w, h);
                break;
        }
        g.dispose();
    }

    private void paintAurora(Graphics2D g, int w, int h, double t) {
        g.setColor(base);
        g.fillRect(0, 0, w, h);
        Color[] cols = {accent, blend(accent, Color.MAGENTA, 0.4f), blend(base, accent, 0.6f)};
        for (int i = 0; i < 3; i++) {
            double phase = t * 0.6 + i * 2.1;
            float cx = (float) (w * (0.5 + 0.35 * Math.sin(phase)));
            float cy = (float) (h * (0.5 + 0.35 * Math.cos(phase * 0.8 + i)));
            float radius = Math.max(60, Math.min(w, h) * (0.55f + 0.15f * (float) Math.sin(phase * 1.3)));
            Color c = cols[i];
            RadialGradientPaint paint = new RadialGradientPaint(
                    new Point2D.Float(cx, cy), radius,
                    new float[]{0f, 1f},
                    new Color[]{new Color(c.getRed(), c.getGreen(), c.getBlue(), 150),
                            new Color(c.getRed(), c.getGreen(), c.getBlue(), 0)});
            g.setPaint(paint);
            g.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 0.9f));
            g.fillRect(0, 0, w, h);
        }
        g.setComposite(AlphaComposite.SrcOver);
    }

    private void paintStarfield(Graphics2D g, int w, int h, double t) {
        g.setColor(new Color(0x05060A));
        g.fillRect(0, 0, w, h);
        int n = 220;
        if (stars == null || stars.length != n) {
            stars = new float[n][3];
            for (int i = 0; i < n; i++) {
                stars[i][0] = rnd.nextFloat() * 2 - 1;
                stars[i][1] = rnd.nextFloat() * 2 - 1;
                stars[i][2] = rnd.nextFloat();
            }
        }
        int cx = w / 2;
        int cy = h / 2;
        for (float[] s : stars) {
            s[2] -= 0.006f * speed;
            if (s[2] <= 0.01f) {
                s[0] = rnd.nextFloat() * 2 - 1;
                s[1] = rnd.nextFloat() * 2 - 1;
                s[2] = 1f;
            }
            float k = 1f / s[2];
            int x = (int) (cx + s[0] * k * cx);
            int y = (int) (cy + s[1] * k * cy);
            if (x < 0 || x >= w || y < 0 || y >= h) {
                continue;
            }
            int b = Math.min(255, (int) (60 + 195 * (1 - s[2])));
            int size = s[2] < 0.3f ? 2 : 1;
            g.setColor(new Color(b, b, Math.min(255, b + 20)));
            g.fillRect(x, y, size, size);
        }
    }

    private void paintMatrix(Graphics2D g, int w, int h, double t) {
        g.setColor(new Color(0x03060A));
        g.fillRect(0, 0, w, h);
        int cell = 14;
        int cols = Math.max(1, w / cell);
        if (matrixY == null || matrixY.length != cols) {
            matrixY = new int[cols];
            for (int i = 0; i < cols; i++) {
                matrixY[i] = rnd.nextInt(Math.max(1, h));
            }
        }
        g.setFont(new Font(Font.MONOSPACED, Font.BOLD, cell));
        for (int i = 0; i < cols; i++) {
            int x = i * cell;
            int head = matrixY[i];
            for (int j = 0; j < 12; j++) {
                int y = head - j * cell;
                if (y < 0 || y > h) {
                    continue;
                }
                int alpha = Math.max(0, 255 - j * 22);
                char ch = (char) (0x30A0 + rnd.nextInt(80));
                g.setColor(new Color(0x33, 0xFF, 0x66, j == 0 ? 255 : alpha));
                g.drawString(String.valueOf(ch), x, y);
            }
            matrixY[i] += (int) (cell * (0.6 + 0.6 * speed));
            if (matrixY[i] > h + rnd.nextInt(200)) {
                matrixY[i] = 0;
            }
        }
    }

    private void paintBubbles(Graphics2D g, int w, int h, double t) {
        GradientPaint bg = new GradientPaint(0, 0, base, 0, h, blend(base, accent, 0.3f));
        g.setPaint(bg);
        g.fillRect(0, 0, w, h);
        int n = 36;
        if (bubbles == null || bubbles.length != n) {
            bubbles = new float[n][5];
            for (int i = 0; i < n; i++) {
                resetBubble(bubbles[i], w, h, true);
            }
        }
        for (float[] b : bubbles) {
            b[1] -= b[3] * speed;
            if (b[1] + b[2] < 0) {
                resetBubble(b, w, h, false);
            }
            int a = (int) (b[4] * 120);
            g.setColor(new Color(accent.getRed(), accent.getGreen(), accent.getBlue(), Math.max(20, a)));
            int d = (int) (b[2] * 2);
            g.fillOval((int) (b[0] - b[2]), (int) (b[1] - b[2]), d, d);
        }
    }

    private void resetBubble(float[] b, int w, int h, boolean anywhere) {
        b[0] = rnd.nextFloat() * Math.max(1, w);
        b[1] = anywhere ? rnd.nextFloat() * Math.max(1, h) : h + rnd.nextInt(60);
        b[2] = 6 + rnd.nextFloat() * 30;
        b[3] = 0.3f + rnd.nextFloat() * 1.2f;
        b[4] = 0.3f + rnd.nextFloat() * 0.7f;
    }

    private void paintPlasma(Graphics2D g, int w, int h, double t) {
        int pw = plasmaBuf.getWidth();
        int ph = plasmaBuf.getHeight();
        float br = base.getRed() / 255f;
        float bg = base.getGreen() / 255f;
        float bb = base.getBlue() / 255f;
        for (int y = 0; y < ph; y++) {
            for (int x = 0; x < pw; x++) {
                double v = Math.sin(x * 0.06 + t) + Math.sin(y * 0.06 + t * 1.1)
                        + Math.sin((x + y) * 0.05 + t * 0.7)
                        + Math.sin(Math.hypot(x - pw / 2.0, y - ph / 2.0) * 0.07 - t);
                float hue = (float) ((v + 4) / 8.0);
                int rgb = Color.HSBtoRGB((hue + base.getRGB() / 1.0e7f) % 1f, 0.55f, 0.85f);
                plasmaBuf.setRGB(x, y, rgb);
            }
        }
        g.drawImage(plasmaBuf, 0, 0, w, h, null);
    }

    private void paintGradient(Graphics2D g, int w, int h) {
        g.setPaint(new GradientPaint(0, 0, base, w, h, accent));
        g.fillRect(0, 0, w, h);
    }

    private void paintImage(Graphics2D g, int w, int h, double t) {
        g.setColor(base);
        g.fillRect(0, 0, w, h);
        if (image == null) {
            return;
        }
        // Scale to cover, then slowly pan for a subtle "moving" feel.
        double scale = Math.max((double) w / image.getWidth(), (double) h / image.getHeight()) * 1.08;
        int iw = (int) (image.getWidth() * scale);
        int ih = (int) (image.getHeight() * scale);
        int panX = (int) (Math.sin(t * 0.2) * (iw - w) * 0.5);
        int panY = (int) (Math.cos(t * 0.15) * (ih - h) * 0.5);
        int x = (w - iw) / 2 + panX;
        int y = (h - ih) / 2 + panY;
        g.drawImage(image, x, y, iw, ih, null);
    }

    // ---- helpers -----------------------------------------------------------

    private int imageLuminance() {
        return luminance(averageImageColor());
    }

    private Color averageImageColor() {
        if (image == null) {
            return base;
        }
        long r = 0;
        long gg = 0;
        long b = 0;
        int step = Math.max(1, image.getWidth() / 40);
        int count = 0;
        for (int y = 0; y < image.getHeight(); y += step) {
            for (int x = 0; x < image.getWidth(); x += step) {
                int rgb = image.getRGB(x, y);
                r += (rgb >> 16) & 0xFF;
                gg += (rgb >> 8) & 0xFF;
                b += rgb & 0xFF;
                count++;
            }
        }
        if (count == 0) {
            return base;
        }
        return new Color((int) (r / count), (int) (gg / count), (int) (b / count));
    }

    static int luminance(Color c) {
        return (int) (0.299 * c.getRed() + 0.587 * c.getGreen() + 0.114 * c.getBlue());
    }

    static Color blend(Color a, Color b, float f) {
        f = Math.max(0, Math.min(1, f));
        return new Color(
                (int) (a.getRed() * (1 - f) + b.getRed() * f),
                (int) (a.getGreen() * (1 - f) + b.getGreen() * f),
                (int) (a.getBlue() * (1 - f) + b.getBlue() * f));
    }
}
