package com.phishing;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class NotificationPopup extends JWindow {
    
    private final int WINDOW_WIDTH = 340;
    private final int WINDOW_HEIGHT = 105;
    private final int ANIMATION_SPEED = 12;
    private int currentY;
    private int targetY;
    private float opacity = 1f;
    private Timer animationTimer;
    private Timer displayTimer;
    private boolean supportsOpacity = true;

    public NotificationPopup(final String url, final RiskReport report) {
        setSize(WINDOW_WIDTH, WINDOW_HEIGHT);
        setAlwaysOnTop(true);

        // Test if per-pixel translucency is supported
        try {
            GraphicsDevice gd = GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice();
            supportsOpacity = gd.isWindowTranslucencySupported(GraphicsDevice.WindowTranslucency.TRANSLUCENT);
        } catch (Exception e) {
            supportsOpacity = false;
        }

        // Only set rounded shape if translucency is supported
        try {
            setShape(new java.awt.geom.RoundRectangle2D.Double(0, 0, WINDOW_WIDTH, WINDOW_HEIGHT, 16, 16));
        } catch (Exception ignored) {}

        JPanel panel = new JPanel(new BorderLayout()) {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setPaint(new GradientPaint(0, 0, UITheme.BG_CARD, getWidth(), 0, UITheme.BG_DARK));
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 16, 16);
                // Left accent stripe
                Color accent = UITheme.resultColor(report.getResult());
                g2.setColor(accent);
                g2.fillRoundRect(0, 0, 4, getHeight(), 4, 4);
            }
        };
        panel.setOpaque(false);
        panel.setBorder(BorderFactory.createEmptyBorder(14, 18, 14, 18));

        Color titleColor = UITheme.resultColor(report.getResult());
        String titleText;
        switch (report.getResult()) {
            case MALICIOUS:  titleText = "[!] MALICIOUS LINK DETECTED"; break;
            case SUSPICIOUS: titleText = "[!] SUSPICIOUS LINK"; break;
            default:         titleText = "[OK] Link Appears Safe"; break;
        }

        // ── Title row with close button ──
        JPanel titleRow = new JPanel(new BorderLayout());
        titleRow.setOpaque(false);

        JLabel titleLabel = new JLabel(titleText);
        titleLabel.setForeground(titleColor);
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));

        JLabel closeBtn = new JLabel("X");
        closeBtn.setForeground(UITheme.TEXT_MUTED);
        closeBtn.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        closeBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        closeBtn.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 0));
        closeBtn.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (displayTimer != null) displayTimer.stop();
                dispose();
            }
            @Override
            public void mouseEntered(java.awt.event.MouseEvent e) {
                closeBtn.setForeground(UITheme.RED);
            }
            @Override
            public void mouseExited(java.awt.event.MouseEvent e) {
                closeBtn.setForeground(UITheme.TEXT_MUTED);
            }
        });

        titleRow.add(titleLabel, BorderLayout.CENTER);
        titleRow.add(closeBtn, BorderLayout.EAST);

        String displayUrl = url.length() > 38 ? url.substring(0, 38) + "..." : url;
        JLabel urlLabel = new JLabel("Copied: " + SecurityUtils.sanitizeForUI(SecurityUtils.defangUrl(displayUrl)));
        urlLabel.setForeground(UITheme.TEXT_SECONDARY);
        urlLabel.setFont(UITheme.BODY);
        
        JLabel hintLabel = new JLabel("Click for details");
        hintLabel.setForeground(UITheme.TEXT_MUTED);
        hintLabel.setFont(UITheme.SMALL);

        panel.add(titleRow, BorderLayout.NORTH);
        panel.add(urlLabel, BorderLayout.CENTER);
        panel.add(hintLabel, BorderLayout.SOUTH);
        
        setContentPane(panel);

        addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                DetailsWindow detailsWin = new DetailsWindow(url, report);
                detailsWin.setVisible(true);
                if(displayTimer != null) displayTimer.stop();
                dispose();
            }
        });
        
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
    }

    private void safeSetOpacity(float val) {
        if (!supportsOpacity) return;
        try {
            setOpacity(Math.max(0f, Math.min(1f, val)));
        } catch (Exception ignored) {}
    }

    public void showNotification() {
        GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();
        Rectangle bounds = ge.getMaximumWindowBounds();

        int x = bounds.width - WINDOW_WIDTH - 20;
        targetY = bounds.height - WINDOW_HEIGHT - 20;
        currentY = bounds.height; // start below screen

        setLocation(x, currentY);
        opacity = 0f;
        safeSetOpacity(0f);
        setVisible(true);

        // If opacity isn't supported, just show immediately at full opacity
        if (!supportsOpacity) {
            opacity = 1f;
        }

        animationTimer = new Timer(ANIMATION_SPEED, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (currentY > targetY) {
                    currentY -= 5;
                    if (supportsOpacity) {
                        opacity = Math.min(1f, opacity + 0.05f);
                        safeSetOpacity(opacity);
                    }
                    if (currentY < targetY) currentY = targetY;
                    setLocation(x, currentY);
                } else {
                    animationTimer.stop();
                    startDisplayTimer();
                }
            }
        });
        animationTimer.start();
    }

    private void startDisplayTimer() {
        displayTimer = new Timer(5000, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                displayTimer.stop();
                startFadeOut();
            }
        });
        displayTimer.start();
    }

    private void startFadeOut() {
        if (!supportsOpacity) {
            // No fade support, just close after display time
            dispose();
            return;
        }
        Timer fadeOutTimer = new Timer(ANIMATION_SPEED, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (opacity > 0) {
                    opacity -= 0.05f;
                    if (opacity < 0) opacity = 0f;
                    safeSetOpacity(opacity);
                } else {
                    ((Timer) e.getSource()).stop();
                    dispose();
                }
            }
        });
        fadeOutTimer.start();
    }
}
