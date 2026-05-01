package com.phishing;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

/**
 * Centralized design system for the Phishing Detector UI.
 * All color constants, gradients, and factory methods live here.
 */
public final class UITheme {

    // ── Core Palette ──
    public static final Color BG_DARK       = new Color(15, 17, 21);
    public static final Color BG_PANEL      = new Color(22, 25, 30);
    public static final Color BG_CARD       = new Color(30, 34, 40);
    public static final Color BG_INPUT      = new Color(36, 40, 48);
    public static final Color BORDER        = new Color(50, 56, 66);

    // ── Accent Palette (Green) ──
    public static final Color GREEN_BRIGHT  = new Color(0, 230, 118);   // #00E676
    public static final Color GREEN_PRIMARY = new Color(46, 204, 113);  // #2ECC71
    public static final Color GREEN_DARK    = new Color(14, 80, 52);
    public static final Color GREEN_DEEPEST = new Color(8, 45, 30);

    // ── Semantic Colors ──
    public static final Color RED           = new Color(255, 82, 82);
    public static final Color AMBER         = new Color(255, 196, 0);
    public static final Color BLUE          = new Color(64, 169, 255);
    public static final Color TEXT_PRIMARY  = new Color(230, 237, 243);
    public static final Color TEXT_SECONDARY= new Color(140, 150, 165);
    public static final Color TEXT_MUTED    = new Color(90, 100, 115);

    // ── Fonts ──
    public static final Font TITLE = new Font("Segoe UI", Font.BOLD, 22);
    public static final Font SUBTITLE = new Font("Segoe UI", Font.PLAIN, 14);
    public static final Font BODY = new Font("Segoe UI", Font.PLAIN, 13);
    public static final Font MONO = new Font("Consolas", Font.PLAIN, 13);
    public static final Font LABEL_BOLD = new Font("Segoe UI", Font.BOLD, 14);
    public static final Font SMALL = new Font("Segoe UI", Font.PLAIN, 11);
    public static final Font NAV = new Font("Segoe UI", Font.BOLD, 13);

    private UITheme() {} // no instances

    // ═══════════════════════════════════════════════
    // ── Hover Effect Engine ──
    // ═══════════════════════════════════════════════

    /**
     * Adds a hover effect to any JButton: changes BG/FG on enter, 
     * restores on exit, and applies a pressed dimming effect.
     */
    private static void addHover(JButton btn, Color normalBg, Color hoverBg,
                                  Color normalFg, Color hoverFg,
                                  Border normalBorder, Border hoverBorder) {
        btn.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                btn.setBackground(hoverBg);
                btn.setForeground(hoverFg);
                if (hoverBorder != null) btn.setBorder(hoverBorder);
            }
            @Override
            public void mouseExited(MouseEvent e) {
                btn.setBackground(normalBg);
                btn.setForeground(normalFg);
                if (normalBorder != null) btn.setBorder(normalBorder);
            }
            @Override
            public void mousePressed(MouseEvent e) {
                btn.setBackground(darker(hoverBg, 0.8f));
            }
            @Override
            public void mouseReleased(MouseEvent e) {
                btn.setBackground(hoverBg);
            }
        });
    }

    /** Darken a color by a given factor (0.0 = black, 1.0 = original) */
    private static Color darker(Color c, float factor) {
        return new Color(
            Math.max((int)(c.getRed() * factor), 0),
            Math.max((int)(c.getGreen() * factor), 0),
            Math.max((int)(c.getBlue() * factor), 0),
            c.getAlpha()
        );
    }

    /** Lighten a color by mixing towards white */
    private static Color lighter(Color c, float factor) {
        return new Color(
            Math.min((int)(c.getRed() + (255 - c.getRed()) * factor), 255),
            Math.min((int)(c.getGreen() + (255 - c.getGreen()) * factor), 255),
            Math.min((int)(c.getBlue() + (255 - c.getBlue()) * factor), 255),
            c.getAlpha()
        );
    }

    // ═══════════════════════════════════════════════
    // ── Button Factories ──
    // ═══════════════════════════════════════════════

    // ── Factory: Accent Button (green filled, dark text) ──
    public static JButton accentButton(String text) {
        JButton btn = new JButton(text);
        btn.setFont(LABEL_BOLD);
        btn.setForeground(BG_DARK);
        btn.setBackground(GREEN_PRIMARY);
        btn.putClientProperty("JButton.buttonType", "roundRect");
        btn.setFocusPainted(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        Color hoverBg = GREEN_BRIGHT;
        addHover(btn, GREEN_PRIMARY, hoverBg, BG_DARK, BG_DARK, null, null);
        return btn;
    }

    // ── Factory: Ghost/Outline Button (dark bg, light text, outline on hover) ──
    public static JButton ghostButton(String text) {
        JButton btn = new JButton(text);
        btn.setFont(BODY);
        btn.setForeground(TEXT_PRIMARY);
        btn.setBackground(BG_CARD);
        btn.putClientProperty("JButton.buttonType", "roundRect");
        btn.setFocusPainted(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        Border normal = BorderFactory.createLineBorder(BORDER, 1, true);
        Border hover  = BorderFactory.createLineBorder(GREEN_PRIMARY, 1, true);
        btn.setBorder(BorderFactory.createCompoundBorder(normal, BorderFactory.createEmptyBorder(5, 12, 5, 12)));

        btn.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                btn.setBackground(lighter(BG_CARD, 0.15f));
                btn.setForeground(GREEN_BRIGHT);
                btn.setBorder(BorderFactory.createCompoundBorder(hover, BorderFactory.createEmptyBorder(5, 12, 5, 12)));
            }
            @Override
            public void mouseExited(MouseEvent e) {
                btn.setBackground(BG_CARD);
                btn.setForeground(TEXT_PRIMARY);
                btn.setBorder(BorderFactory.createCompoundBorder(normal, BorderFactory.createEmptyBorder(5, 12, 5, 12)));
            }
            @Override
            public void mousePressed(MouseEvent e) {
                btn.setBackground(darker(BG_CARD, 0.7f));
            }
            @Override
            public void mouseReleased(MouseEvent e) {
                btn.setBackground(lighter(BG_CARD, 0.15f));
            }
        });
        return btn;
    }

    // ── Factory: Danger Button (dark bg, red text, red outline on hover) ──
    public static JButton dangerButton(String text) {
        JButton btn = new JButton(text);
        btn.setFont(BODY);
        btn.setForeground(RED);
        btn.setBackground(BG_CARD);
        btn.putClientProperty("JButton.buttonType", "roundRect");
        btn.setFocusPainted(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        Border normal = BorderFactory.createLineBorder(BORDER, 1, true);
        Border hover  = BorderFactory.createLineBorder(RED, 1, true);
        btn.setBorder(BorderFactory.createCompoundBorder(normal, BorderFactory.createEmptyBorder(5, 12, 5, 12)));

        btn.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                btn.setBackground(new Color(255, 82, 82, 25));
                btn.setForeground(new Color(255, 120, 120));
                btn.setBorder(BorderFactory.createCompoundBorder(hover, BorderFactory.createEmptyBorder(5, 12, 5, 12)));
            }
            @Override
            public void mouseExited(MouseEvent e) {
                btn.setBackground(BG_CARD);
                btn.setForeground(RED);
                btn.setBorder(BorderFactory.createCompoundBorder(normal, BorderFactory.createEmptyBorder(5, 12, 5, 12)));
            }
            @Override
            public void mousePressed(MouseEvent e) {
                btn.setBackground(new Color(255, 82, 82, 50));
            }
            @Override
            public void mouseReleased(MouseEvent e) {
                btn.setBackground(new Color(255, 82, 82, 25));
            }
        });
        return btn;
    }

    // ── Factory: Rounded card border ──
    public static Border cardBorder() {
        return BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(BORDER, 1, true),
            BorderFactory.createEmptyBorder(15, 15, 15, 15)
        );
    }

    // ── Gradient Panel (top-down) ──
    public static JPanel gradientPanel(Color top, Color bottom) {
        return new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
                g2.setPaint(new GradientPaint(0, 0, top, 0, getHeight(), bottom));
                g2.fillRect(0, 0, getWidth(), getHeight());
            }
        };
    }

    /** Returns a color for the given AnalysisResult */
    public static Color resultColor(AnalysisResult result) {
        switch (result) {
            case MALICIOUS:  return RED;
            case SUSPICIOUS: return AMBER;
            default:         return GREEN_BRIGHT;
        }
    }
}
