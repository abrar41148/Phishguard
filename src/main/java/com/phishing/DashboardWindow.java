package com.phishing;

import javax.swing.*;
import java.awt.*;

public class DashboardWindow extends JFrame {

    private static volatile DashboardWindow instance;

    private JPanel contentPanel;
    private CardLayout cardLayout;
    private JButton activeNavBtn;
    private JButton btnBatch; // reference for programmatic nav
    private BatchPanel batchPanel;

    // Accent color for the active nav highlight bar
    private static final Color NAV_ACTIVE_ACCENT = UITheme.GREEN_PRIMARY;

    public DashboardWindow() {
        instance = this;

        setTitle("Phishing Link Detector");
        setSize(960, 780);
        setMinimumSize(new Dimension(820, 560));
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
        setLayout(new BorderLayout());

        // ═══════ Sidebar (Green-to-Black Gradient) ═══════
        JPanel sidebar = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
                g2.setPaint(new GradientPaint(0, 0, new Color(12, 72, 48), 0, getHeight(), UITheme.BG_DARK));
                g2.fillRect(0, 0, getWidth(), getHeight());
            }
        };
        sidebar.setLayout(new BoxLayout(sidebar, BoxLayout.Y_AXIS));
        sidebar.setPreferredSize(new Dimension(200, 0));
        sidebar.setOpaque(false);
        sidebar.setBorder(BorderFactory.createEmptyBorder(20, 12, 20, 12));

        // ── Logo / Title Area ──
        JLabel brandLabel = new JLabel("PhishGuard");
        brandLabel.setForeground(UITheme.GREEN_BRIGHT);
        brandLabel.setFont(new Font("Segoe UI", Font.BOLD, 20));
        brandLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel tagLabel = new JLabel("Security Dashboard");
        tagLabel.setForeground(UITheme.TEXT_SECONDARY);
        tagLabel.setFont(UITheme.SMALL);
        tagLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        sidebar.add(brandLabel);
        sidebar.add(Box.createVerticalStrut(2));
        sidebar.add(tagLabel);
        sidebar.add(Box.createVerticalStrut(30));

        // ── Separator ──
        JSeparator sep = new JSeparator();
        sep.setMaximumSize(new Dimension(Integer.MAX_VALUE, 1));
        sep.setForeground(new Color(255, 255, 255, 30));
        sidebar.add(sep);
        sidebar.add(Box.createVerticalStrut(20));

        // ── Nav Buttons ──
        JButton btnHome     = createNavButton("Home");
        btnBatch    = createNavButton("Batch Scan");
        JButton btnHistory  = createNavButton("History");
        JButton btnSettings = createNavButton("Settings");

        sidebar.add(btnHome);
        sidebar.add(Box.createVerticalStrut(4));
        sidebar.add(btnBatch);
        sidebar.add(Box.createVerticalStrut(4));
        sidebar.add(btnHistory);
        sidebar.add(Box.createVerticalStrut(4));
        sidebar.add(btnSettings);
        sidebar.add(Box.createVerticalGlue());

        // ── Version label ──
        JLabel versionLabel = new JLabel("v1.0 - Enterprise");
        versionLabel.setForeground(UITheme.TEXT_MUTED);
        versionLabel.setFont(new Font("Segoe UI", Font.ITALIC, 10));
        versionLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        sidebar.add(versionLabel);

        add(sidebar, BorderLayout.WEST);

        // ═══════ Content Area ═══════
        cardLayout = new CardLayout();
        contentPanel = new JPanel(cardLayout);
        contentPanel.setBackground(UITheme.BG_DARK);

        batchPanel = new BatchPanel();

        contentPanel.add(new HomePanel(), "Home");
        contentPanel.add(batchPanel, "Batch");
        contentPanel.add(new HistoryPanel(), "History");
        contentPanel.add(new SettingsPanel(), "Settings");

        add(contentPanel, BorderLayout.CENTER);

        // ── Nav Actions ──
        btnHome.addActionListener(e -> { setActiveNav(btnHome); cardLayout.show(contentPanel, "Home"); });
        btnBatch.addActionListener(e -> { setActiveNav(btnBatch); cardLayout.show(contentPanel, "Batch"); });
        btnHistory.addActionListener(e -> { setActiveNav(btnHistory); refreshHistoryPanel(); cardLayout.show(contentPanel, "History"); });
        btnSettings.addActionListener(e -> { setActiveNav(btnSettings); cardLayout.show(contentPanel, "Settings"); });

        // Set default active
        setActiveNav(btnHome);
    }

    /** Returns the singleton instance of DashboardWindow */
    public static DashboardWindow getInstance() {
        return instance;
    }

    /**
     * Opens the dashboard and navigates to the Batch Scan tab.
     */
    public void showBatchScanTab() {
        SwingUtilities.invokeLater(() -> {
            setVisible(true);
            setExtendedState(JFrame.NORMAL);
            toFront();
            requestFocus();
            setActiveNav(btnBatch);
            cardLayout.show(contentPanel, "Batch");
        });
    }

    /**
     * Opens the dashboard, navigates to the Batch Scan tab,
     * and pre-populates the URL input with the given text.
     * Accepts an optional BatchNotificationPopup to receive live progress updates.
     */
    public void showBatchScanWithUrls(String urlText) {
        showBatchScanWithUrls(urlText, null);
    }

    public void showBatchScanWithUrls(String urlText, BatchNotificationPopup popup) {
        // Single invokeLater to guarantee ordering: tab switch THEN scan start
        SwingUtilities.invokeLater(() -> {
            setVisible(true);
            setExtendedState(JFrame.NORMAL);
            toFront();
            requestFocus();
            setActiveNav(btnBatch);
            cardLayout.show(contentPanel, "Batch");
            batchPanel.loadUrlsAndScan(urlText, popup);
        });
    }

    /** Replaces the History panel with a fresh instance so data is up-to-date */
    private void refreshHistoryPanel() {
        contentPanel.add(new HistoryPanel(), "History");
    }

    private void setActiveNav(JButton btn) {
        if (activeNavBtn != null) {
            activeNavBtn.setBackground(new Color(255, 255, 255, 8));
            activeNavBtn.setForeground(UITheme.TEXT_SECONDARY);
            activeNavBtn.setBorder(BorderFactory.createEmptyBorder(8, 14, 8, 14));
        }
        activeNavBtn = btn;
        btn.setBackground(new Color(0, 230, 118, 25));
        btn.setForeground(Color.WHITE);
        btn.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 3, 0, 0, UITheme.GREEN_BRIGHT),
            BorderFactory.createEmptyBorder(8, 11, 8, 14)
        ));
    }

    private JButton createNavButton(String text) {
        JButton btn = new JButton(text);
        btn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 38));
        btn.setAlignmentX(Component.LEFT_ALIGNMENT);
        btn.setHorizontalAlignment(SwingConstants.LEFT);
        btn.setForeground(UITheme.TEXT_SECONDARY);
        btn.setBackground(new Color(255, 255, 255, 8));
        btn.putClientProperty("JButton.buttonType", "roundRect");
        btn.setFocusPainted(false);
        btn.setFont(UITheme.NAV);
        btn.setBorder(BorderFactory.createEmptyBorder(8, 14, 8, 14));
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        // ── Hover effect (only when not active) ──
        btn.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseEntered(java.awt.event.MouseEvent e) {
                if (btn != activeNavBtn) {
                    btn.setBackground(new Color(255, 255, 255, 18));
                    btn.setForeground(UITheme.TEXT_PRIMARY);
                    btn.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createMatteBorder(0, 3, 0, 0, UITheme.GREEN_PRIMARY),
                        BorderFactory.createEmptyBorder(8, 11, 8, 14)
                    ));
                }
            }
            @Override
            public void mouseExited(java.awt.event.MouseEvent e) {
                if (btn != activeNavBtn) {
                    btn.setBackground(new Color(255, 255, 255, 8));
                    btn.setForeground(UITheme.TEXT_SECONDARY);
                    btn.setBorder(BorderFactory.createEmptyBorder(8, 14, 8, 14));
                }
            }
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                btn.setBackground(new Color(0, 230, 118, 15));
            }
        });
        return btn;
    }
}
