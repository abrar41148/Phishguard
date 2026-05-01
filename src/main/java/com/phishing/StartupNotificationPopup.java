package com.phishing;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * A startup notification that slides up to inform the user PhishGuard
 * has started. Clicking it opens the main dashboard window.
 */
public class StartupNotificationPopup extends JWindow {

    private final int WINDOW_WIDTH = 360;
    private final int WINDOW_HEIGHT = 110;
    private final int ANIMATION_SPEED = 12;
    private int currentY;
    private int targetY;
    private float opacity = 1f;
    private Timer animationTimer;
    private Timer displayTimer;
    private boolean supportsOpacity = true;

    private final Runnable onClickAction;

    public StartupNotificationPopup(Runnable onClickAction) {
        this.onClickAction = onClickAction;
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

        // Main panel - gradient background with green accent
        JPanel panel = new JPanel(new BorderLayout(0, 0)) {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                // Dark card gradient
                g2.setPaint(new GradientPaint(0, 0, UITheme.BG_CARD, getWidth(), 0, UITheme.BG_DARK));
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 16, 16);
                // Green accent stripe on left
                g2.setColor(UITheme.GREEN_BRIGHT);
                g2.fillRoundRect(0, 0, 4, getHeight(), 4, 4);
                // Subtle green glow top-left
                g2.setPaint(new RadialGradientPaint(
                    new java.awt.geom.Point2D.Float(30, 20), 100f,
                    new float[]{0f, 1f},
                    new Color[]{new Color(0, 230, 118, 25), new Color(0, 230, 118, 0)}
                ));
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 16, 16);
            }
        };
        panel.setOpaque(false);
        panel.setBorder(BorderFactory.createEmptyBorder(14, 18, 14, 18));


        // Text content
        JPanel textPanel = new JPanel();
        textPanel.setOpaque(false);
        textPanel.setLayout(new BoxLayout(textPanel, BoxLayout.Y_AXIS));

        // Title row with close button
        JPanel titleRow = new JPanel(new BorderLayout());
        titleRow.setOpaque(false);
        titleRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        titleRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 22));

        JLabel titleLabel = new JLabel("PhishGuard is Running");
        titleLabel.setForeground(UITheme.GREEN_BRIGHT);
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));

        JLabel closeBtn = new JLabel("\u2715");
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

        JLabel descLabel = new JLabel("Clipboard monitoring is active. You're protected.");
        descLabel.setForeground(UITheme.TEXT_SECONDARY);
        descLabel.setFont(UITheme.BODY);
        descLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel trayHint = new JLabel("Double-click the system tray icon to open.");
        trayHint.setForeground(UITheme.TEXT_MUTED);
        trayHint.setFont(UITheme.SMALL);
        trayHint.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel clickHint = new JLabel("Click here to open dashboard");
        clickHint.setForeground(new Color(0, 230, 118, 160));
        clickHint.setFont(new Font("Segoe UI", Font.ITALIC, 11));
        clickHint.setAlignmentX(Component.LEFT_ALIGNMENT);

        textPanel.add(titleRow);
        textPanel.add(Box.createVerticalStrut(4));
        textPanel.add(descLabel);
        textPanel.add(Box.createVerticalStrut(3));
        textPanel.add(trayHint);
        textPanel.add(Box.createVerticalStrut(3));
        textPanel.add(clickHint);

        // Assemble layout
        panel.add(textPanel, BorderLayout.CENTER);
        setContentPane(panel);

        // Click to open dashboard
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
