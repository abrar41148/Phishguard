package com.phishing;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

/**
 * A live-updating notification popup shown when multiple URLs are detected
 * from the clipboard at once. Displays scan progress and a counter.
 * Clicking the popup opens the DashboardWindow to the Batch Scanner tab.
 */
public class BatchNotificationPopup extends JWindow {

    private final int WINDOW_WIDTH = 370;
    private final int WINDOW_HEIGHT = 115;
    private final int ANIMATION_SPEED = 12;
    private int currentY;
    private int targetY;
    private float opacity = 1f;
    private Timer animationTimer;
    private Timer displayTimer;
    private boolean supportsOpacity = true;

    // UI elements we update live
    private final JLabel titleLabel;
    private final JLabel counterLabel;
    private final JLabel hintLabel;
    private final JProgressBar miniProgress;
    private final JPanel accentStripe;

    private final int totalUrls;
    private int scannedCount = 0;
    private int safeCount = 0;
    private int suspiciousCount = 0;
    private int maliciousCount = 0;
    private boolean scanComplete = false;

    private Runnable onClickAction;

    public BatchNotificationPopup(int totalUrls) {
        this.totalUrls = totalUrls;
        setSize(WINDOW_WIDTH, WINDOW_HEIGHT);
        setAlwaysOnTop(true);

        // Test translucency support
        try {
            GraphicsDevice gd = GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice();
            supportsOpacity = gd.isWindowTranslucencySupported(GraphicsDevice.WindowTranslucency.TRANSLUCENT);
        } catch (Exception e) {
            supportsOpacity = false;
        }

        try {
            setShape(new java.awt.geom.RoundRectangle2D.Double(0, 0, WINDOW_WIDTH, WINDOW_HEIGHT, 16, 16));
        } catch (Exception ignored) {}

        // Main panel with gradient background
        JPanel panel = new JPanel(new BorderLayout(0, 0)) {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setPaint(new GradientPaint(0, 0, UITheme.BG_CARD, getWidth(), 0, UITheme.BG_DARK));
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 16, 16);
            }
        };
        panel.setOpaque(false);

        // Left accent stripe (changes color as scan progresses)
        accentStripe = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                Color stripeColor = getAccentColor();
                g2.setColor(stripeColor);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 4, 4);
            }
        };
        accentStripe.setOpaque(false);
        accentStripe.setPreferredSize(new Dimension(4, 0));

        // Content area
        JPanel content = new JPanel();
        content.setOpaque(false);
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBorder(BorderFactory.createEmptyBorder(12, 14, 10, 14));

        // Title row with close button
        JPanel titleRow = new JPanel(new BorderLayout());
        titleRow.setOpaque(false);
        titleRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        titleRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 22));

        // Title
        titleLabel = new JLabel("Batch Scan - Scanning " + totalUrls + " links...");
        titleLabel.setForeground(UITheme.GREEN_BRIGHT);
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 13));

        JLabel closeBtn = new JLabel("X");
        closeBtn.setForeground(UITheme.TEXT_MUTED);
        closeBtn.setFont(new Font("Segoe UI", Font.PLAIN, 13));
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

        // Counter label
        counterLabel = new JLabel("Progress: 0 / " + totalUrls);
        counterLabel.setForeground(UITheme.TEXT_SECONDARY);
        counterLabel.setFont(UITheme.BODY);
        counterLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Mini progress bar
        miniProgress = new JProgressBar(0, totalUrls);
        miniProgress.setValue(0);
        miniProgress.setStringPainted(false);
        miniProgress.setForeground(UITheme.GREEN_PRIMARY);
        miniProgress.setBackground(UITheme.BG_INPUT);
        miniProgress.setMaximumSize(new Dimension(Integer.MAX_VALUE, 6));
        miniProgress.setPreferredSize(new Dimension(300, 6));
        miniProgress.setBorder(null);
        miniProgress.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Hint
        hintLabel = new JLabel("Click to open Batch Scanner");
        hintLabel.setForeground(UITheme.TEXT_MUTED);
        hintLabel.setFont(UITheme.SMALL);
        hintLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        content.add(titleRow);
        content.add(Box.createVerticalStrut(4));
        content.add(counterLabel);
        content.add(Box.createVerticalStrut(6));
        content.add(miniProgress);
        content.add(Box.createVerticalStrut(6));
        content.add(hintLabel);

        panel.add(accentStripe, BorderLayout.WEST);
        panel.add(content, BorderLayout.CENTER);

        setContentPane(panel);

        // Click handler
        addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                if (onClickAction != null) {
                    onClickAction.run();
                }
                if (displayTimer != null) displayTimer.stop();
                dispose();
            }
        });

        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
    }

    /** Set the callback for when the notification is clicked. */
    public void setOnClickAction(Runnable action) {
        this.onClickAction = action;
    }

    /** Update the progress from background scan threads. Thread-safe (runs on EDT). */
    public void updateProgress(int scanned, int safe, int suspicious, int malicious) {
        SwingUtilities.invokeLater(() -> {
            this.scannedCount = scanned;
            this.safeCount = safe;
            this.suspiciousCount = suspicious;
            this.maliciousCount = malicious;

            miniProgress.setValue(scanned);

            if (scanned >= totalUrls) {
                scanComplete = true;
                titleLabel.setText("Batch Scan Complete!");
                counterLabel.setText("Safe: " + safe + "  Suspicious: " + suspicious + "  Malicious: " + malicious);
                titleLabel.setForeground(getAccentColor());

                // Change progress bar color to final result
                if (malicious > 0) {
                    miniProgress.setForeground(UITheme.RED);
                } else if (suspicious > 0) {
                    miniProgress.setForeground(UITheme.AMBER);
                } else {
                    miniProgress.setForeground(UITheme.GREEN_BRIGHT);
                }

                hintLabel.setText("Click to view all results");

                // Auto-dismiss after 6 seconds
                startDisplayTimer();
            } else {
                titleLabel.setText("Batch Scan - Scanning " + totalUrls + " links...");
                counterLabel.setText("Progress: " + scanned + " / " + totalUrls);
            }

            accentStripe.repaint();
        });
    }

    private Color getAccentColor() {
        if (scanComplete) {
            if (maliciousCount > 0) return UITheme.RED;
            if (suspiciousCount > 0) return UITheme.AMBER;
            return UITheme.GREEN_BRIGHT;
        }
        return UITheme.GREEN_PRIMARY;
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
                    // Don't start display timer here — wait for scan completion
                }
            }
        });
        animationTimer.start();
    }

    private void startDisplayTimer() {
        if (displayTimer != null) return; // already started
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
