package com.phishing;

import javax.swing.*;
import java.awt.*;
import java.util.List;

public class HomePanel extends JPanel {
    private final DetectionEngine engine;

    public HomePanel() {
        engine = DetectionEngine.getInstance();
        setBackground(UITheme.BG_DARK);
        setLayout(new BorderLayout(0, 18));
        setBorder(BorderFactory.createEmptyBorder(25, 35, 25, 35));

        // ═══ TOP: Welcome Banner — deep green gradient with glow ═══
        JPanel banner = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                // Multi-stop gradient: deep emerald -> teal -> dark card
                g2.setPaint(new GradientPaint(0, 0, new Color(6, 95, 70), getWidth(), getHeight(), new Color(18, 30, 45)));
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 18, 18);
                // Subtle green glow in top-left corner
                g2.setPaint(new RadialGradientPaint(
                    new java.awt.geom.Point2D.Float(60, 30), 180f,
                    new float[]{0f, 1f},
                    new Color[]{new Color(0, 230, 118, 40), new Color(0, 230, 118, 0)}
                ));
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 18, 18);
                // Bottom edge accent line
                g2.setColor(UITheme.GREEN_BRIGHT);
                g2.fillRect(0, getHeight() - 2, getWidth(), 2);
            }
        };
        banner.setOpaque(false);
        banner.setLayout(new BoxLayout(banner, BoxLayout.Y_AXIS));
        banner.setBorder(BorderFactory.createEmptyBorder(24, 28, 24, 28));

        JLabel titleLabel = new JLabel("Welcome to PhishGuard");
        titleLabel.setForeground(new Color(180, 255, 210));
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 26));
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // removed subtitle for more space

        // ── Toggle ──
        SettingsManager sm = SettingsManager.getInstance();
        boolean isScanning = "true".equals(sm.getProperty("CLIPBOARD_SCAN_ENABLED", "true"));

        JToggleButton toggleBtn = new JToggleButton(isScanning ? "Clipboard Monitoring: ACTIVE" : "Clipboard Monitoring: PAUSED", isScanning);
        toggleBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        toggleBtn.setForeground(isScanning ? UITheme.GREEN_BRIGHT : UITheme.TEXT_MUTED);
        toggleBtn.setBackground(isScanning ? new Color(0, 230, 118, 30) : UITheme.BG_INPUT);
        toggleBtn.putClientProperty("JButton.buttonType", "roundRect");
        toggleBtn.setFocusPainted(false);
        toggleBtn.setAlignmentX(Component.LEFT_ALIGNMENT);
        toggleBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        toggleBtn.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(isScanning ? UITheme.GREEN_PRIMARY : UITheme.BORDER, 1, true),
            BorderFactory.createEmptyBorder(6, 14, 6, 14)
        ));

        toggleBtn.addActionListener(e -> {
            boolean active = toggleBtn.isSelected();
            toggleBtn.setText(active ? "Clipboard Monitoring: ACTIVE" : "Clipboard Monitoring: PAUSED");
            toggleBtn.setForeground(active ? UITheme.GREEN_BRIGHT : UITheme.TEXT_MUTED);
            toggleBtn.setBackground(active ? new Color(0, 230, 118, 30) : UITheme.BG_INPUT);
            toggleBtn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(active ? UITheme.GREEN_PRIMARY : UITheme.BORDER, 1, true),
                BorderFactory.createEmptyBorder(6, 14, 6, 14)
            ));
            sm.setProperty("CLIPBOARD_SCAN_ENABLED", active ? "true" : "false");
            sm.saveSettings();
        });

        banner.add(titleLabel);
        banner.add(Box.createVerticalStrut(12));
        banner.add(toggleBtn);

        add(banner, BorderLayout.NORTH);

        // ═══ CENTER: Quick Scan Card ═══
        JPanel scanCard = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(UITheme.BG_PANEL);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 14, 14);
                // Left accent
                g2.setColor(UITheme.GREEN_PRIMARY);
                g2.fillRoundRect(0, 0, 3, getHeight(), 3, 3);
            }
        };
        scanCard.setOpaque(false);
        scanCard.setLayout(new BoxLayout(scanCard, BoxLayout.Y_AXIS));
        scanCard.setBorder(BorderFactory.createEmptyBorder(18, 20, 18, 20));

        JLabel scanTitle = new JLabel("Quick Scan");
        scanTitle.setForeground(UITheme.TEXT_PRIMARY);
        scanTitle.setFont(UITheme.LABEL_BOLD);
        scanTitle.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel scanSub = new JLabel("Paste a URL, multiple links, or an email body to extract and scan links.");
        scanSub.setForeground(UITheme.TEXT_MUTED);
        scanSub.setFont(UITheme.SMALL);
        scanSub.setAlignmentX(Component.LEFT_ALIGNMENT);

        // URL extraction regex (same as ClipboardMonitor)
        final java.util.regex.Pattern URL_PATTERN = java.util.regex.Pattern.compile(
            "((?:https?://)?(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{2,6}\\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&//=]*))"
        );

        // Input area (supports multi-line pasting of email bodies, etc.)
        JTextArea linkArea = new JTextArea(3, 40);
        linkArea.setFont(UITheme.MONO);
        linkArea.setBackground(UITheme.BG_INPUT);
        linkArea.setForeground(UITheme.TEXT_PRIMARY);
        linkArea.setCaretColor(UITheme.GREEN_BRIGHT);
        linkArea.setLineWrap(true);
        linkArea.setWrapStyleWord(true);
        linkArea.setMargin(new java.awt.Insets(8, 10, 8, 10));
        linkArea.putClientProperty("JTextArea.placeholderText", "Paste a URL, multiple links, or an entire email body...");

        JScrollPane inputScroll = new JScrollPane(linkArea);
        inputScroll.setBorder(BorderFactory.createLineBorder(UITheme.BORDER, 1, true));
        inputScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        inputScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, 60));

        // Button + extracted link count
        JPanel btnRow = new JPanel(new BorderLayout(10, 0));
        btnRow.setOpaque(false);
        btnRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 38));
        btnRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel linkCountLabel = new JLabel("");
        linkCountLabel.setForeground(UITheme.TEXT_MUTED);
        linkCountLabel.setFont(UITheme.SMALL);

        JButton scanBtn = UITheme.accentButton("Scan");
        scanBtn.setPreferredSize(new Dimension(170, 34));

        btnRow.add(linkCountLabel, BorderLayout.CENTER);
        btnRow.add(scanBtn, BorderLayout.EAST);

        // ── Results Panel (visual checklist) ──
        JPanel resultsPanel = new JPanel();
        resultsPanel.setOpaque(false);
        resultsPanel.setLayout(new BoxLayout(resultsPanel, BoxLayout.Y_AXIS));

        // Status header row
        JLabel statusHeader = new JLabel("Results will appear here...");
        statusHeader.setForeground(UITheme.TEXT_MUTED);
        statusHeader.setFont(UITheme.LABEL_BOLD);
        statusHeader.setAlignmentX(Component.LEFT_ALIGNMENT);
        statusHeader.setBorder(BorderFactory.createEmptyBorder(4, 4, 8, 0));

        // Container for check items
        JPanel checksContainer = new JPanel();
        checksContainer.setOpaque(false);
        checksContainer.setLayout(new BoxLayout(checksContainer, BoxLayout.Y_AXIS));
        checksContainer.setAlignmentX(Component.LEFT_ALIGNMENT);

        resultsPanel.add(statusHeader);
        // Expand vertically automatically
        JScrollPane resultScroll = new JScrollPane(checksContainer);
        resultScroll.setBorder(BorderFactory.createLineBorder(UITheme.BORDER, 1, true));
        resultScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        resultScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
        resultScroll.setPreferredSize(new Dimension(800, 350));
        resultScroll.getViewport().setBackground(UITheme.BG_CARD);
        resultsPanel.setBackground(UITheme.BG_INPUT);

        // ── Dynamic button switching based on extracted URL count ──
        final java.util.function.Supplier<java.util.List<String>> extractUrls = () -> {
            String text = linkArea.getText();
            if (text == null || text.trim().isEmpty()) return java.util.Collections.emptyList();

            java.util.LinkedHashSet<String> urls = new java.util.LinkedHashSet<>();
            java.util.regex.Matcher m = URL_PATTERN.matcher(text);
            while (m.find()) {
                String url = m.group(1).trim();
                if (!url.isEmpty()) urls.add(url);
            }
            return new java.util.ArrayList<>(urls);
        };

        // Update button text when input changes
        javax.swing.event.DocumentListener docListener = new javax.swing.event.DocumentListener() {
            private void update() {
                SwingUtilities.invokeLater(() -> {
                    java.util.List<String> urls = extractUrls.get();
                    int count = urls.size();
                    if (count == 0) {
                        scanBtn.setText("Scan");
                        linkCountLabel.setText("");
                    } else if (count == 1) {
                        scanBtn.setText("Scan");
                        linkCountLabel.setText("1 link detected");
                        linkCountLabel.setForeground(UITheme.GREEN_PRIMARY);
                    } else {
                        scanBtn.setText("Batch Scan (" + count + " links)");
                        linkCountLabel.setText(count + " links extracted");
                        linkCountLabel.setForeground(UITheme.AMBER);
                    }
                });
            }
            public void insertUpdate(javax.swing.event.DocumentEvent e) { update(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { update(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { update(); }
        };
        linkArea.getDocument().addDocumentListener(docListener);

        // ── Scan / Batch Scan action ──
        scanBtn.addActionListener(e -> {
            java.util.List<String> urls = extractUrls.get();
            if (urls.isEmpty()) {
                checksContainer.removeAll();
                statusHeader.setText("No valid URLs detected");
                statusHeader.setForeground(UITheme.AMBER);
                checksContainer.add(createTableRow("Input", "Failed", UITheme.AMBER, "No URLs found. Paste a link or email body containing links."));
                checksContainer.revalidate();
                checksContainer.repaint();
                return;
            }

            if (urls.size() == 1) {
                // Single URL — scan inline
                String url = urls.get(0);
                checksContainer.removeAll();
                statusHeader.setText("Analyzing...");
                statusHeader.setForeground(UITheme.TEXT_SECONDARY);
                checksContainer.add(createTableRow("Status", "Running", UITheme.TEXT_MUTED, "Scan started for: " + SecurityUtils.defangUrl(url)));
                checksContainer.revalidate();
                checksContainer.repaint();
                scanBtn.setEnabled(false);

                SwingWorker<RiskReport, Void> worker = new SwingWorker<>() {
                    @Override
                    protected RiskReport doInBackground() throws Exception {
                        RiskReport report = engine.analyze(url);
                        HistoryManager.logScan(url, report);
                        return report;
                    }

                    @Override
                    protected void done() {
                        scanBtn.setEnabled(true);
                        try {
                            RiskReport report = get();
                            Color resultColor = UITheme.resultColor(report.getResult());

                            // Status header
                            statusHeader.setText(report.getResult().name() + "  |  Risk Score: " + report.getScore());
                            statusHeader.setForeground(resultColor);
                            resultScroll.setBorder(BorderFactory.createLineBorder(resultColor, 1, true));

                            // Build checklist from report details
                            checksContainer.removeAll();

                            // Define the checks to display
                            String[][] analyzerChecks = {
                                {"Local DB Entries", "[Local DB Entries]"},
                                {"URL Shortener", "[UnshortenAnalyzer]"},
                                {"URL Length", "[LengthAnalyzer]"},
                                {"Suspicious Characters", "[CharacterAnalyzer]"},
                                {"Phishing Keywords", "[KeywordAnalyzer]"},
                                {"Typosquatting", "[TyposquattingAnalyzer]"},
                                {"Domain Age (WHOIS)", "[WhoisAnalyzer]"},
                                {"Reputation API", "[VirusTotal]", "[Google Safe Browsing]", "[PhishTank]"},
                            };

                            java.util.List<String> details = report.getDetails();

                            for (String[] check : analyzerChecks) {
                                String label = check[0];
                                boolean flagged = false;
                                String flagDetail = null;

                                boolean isReputation = label.equals("Reputation API");
                                boolean isShortener = label.equals("URL Shortener");

                                // Check if any of the prefixes for this analyzer appeared in details
                                for (int p = 1; p < check.length; p++) {
                                    for (String detail : details) {
                                        if (detail.contains(check[p])) {
                                            flagged = true;
                                            flagDetail = detail;
                                            break;
                                        }
                                    }
                                    if (flagged) break;
                                }

                                String statusText;
                                Color statusColor;
                                String detailText = "";

                                if (isReputation) {
                                    if (flagged) {
                                        int bEnd = flagDetail.indexOf("] ");
                                        detailText = bEnd > 0 ? flagDetail.substring(bEnd + 2) : flagDetail;

                                        String lowerDetail = detailText.toLowerCase();
                                        if (lowerDetail.startsWith("0/") || lowerDetail.contains("0 security vendors") || lowerDetail.contains("not found in") || lowerDetail.contains("no vendors flagged")) {
                                            statusText = "Secure";
                                            statusColor = UITheme.GREEN_BRIGHT;
                                        } else if (lowerDetail.contains("below threshold") || lowerDetail.contains("suspicious")) {
                                            statusText = "Suspicious";
                                            statusColor = UITheme.AMBER;
                                        } else {
                                            statusText = "Flagged";
                                            statusColor = UITheme.RED;
                                        }
                                    } else {
                                        statusText = "Secure";
                                        statusColor = UITheme.GREEN_BRIGHT;
                                        detailText = "No vendors flagged";
                                    }
                                } else if (isShortener) {
                                    if (flagged) {
                                        int bEnd = flagDetail.indexOf("] ");
                                        detailText = bEnd > 0 ? flagDetail.substring(bEnd + 2) : flagDetail;
                                        
                                        if (detailText.contains("Long url, shortening not required")) {
                                            statusText = "Not shortened";
                                            statusColor = UITheme.GREEN_BRIGHT;
                                            detailText = "No shortening used";
                                        } else {
                                            statusText = "Shortened";
                                            statusColor = UITheme.AMBER;
                                        }
                                    } else {
                                        statusText = "Not shortened";
                                        statusColor = UITheme.GREEN_BRIGHT;
                                        detailText = "No shortening used";
                                    }
                                } else {
                                    if (flagged) {
                                        statusText = "Failed";
                                        statusColor = UITheme.RED;
                                        int bEnd = flagDetail.indexOf("] ");
                                        detailText = bEnd > 0 ? flagDetail.substring(bEnd + 2) : flagDetail;
                                    } else {
                                        statusText = "Secure";
                                        statusColor = UITheme.GREEN_BRIGHT;
                                        detailText = "No issues detected";
                                    }
                                }

                                checksContainer.add(createTableRow(label, statusText, statusColor, detailText));
                            }

                            // Add overall severity at the bottom
                            checksContainer.add(Box.createVerticalStrut(6));
                            String severity;
                            if (report.getScore() >= 75) severity = "HIGH RISK";
                            else if (report.getScore() >= 40) severity = "MODERATE RISK";
                            else severity = "LOW RISK";
                            JLabel severityLabel = new JLabel("    OVERALL: " + severity + " (Score: " + report.getScore() + ")");
                            severityLabel.setForeground(resultColor);
                            severityLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
                            severityLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
                            checksContainer.add(severityLabel);

                            checksContainer.revalidate();
                            checksContainer.repaint();
                        } catch (Exception ex) {
                            statusHeader.setText("Error occurred during scan");
                            statusHeader.setForeground(UITheme.RED);
                            resultScroll.setBorder(BorderFactory.createLineBorder(UITheme.RED, 1, true));
                        }
                    }
                };
                worker.execute();
            } else {
                // Multiple URLs — send to batch scanner
                String urlText = String.join("\n", urls);
                checksContainer.removeAll();
                statusHeader.setText("Batch Scan");
                statusHeader.setForeground(UITheme.GREEN_PRIMARY);
                checksContainer.add(createTableRow("Batch", "Started", UITheme.GREEN_PRIMARY, "Extracted " + urls.size() + " links, navigating to Batch Scanner..."));
                checksContainer.revalidate();
                checksContainer.repaint();

                DashboardWindow dashboard = DashboardWindow.getInstance();
                if (dashboard != null) {
                    dashboard.showBatchScanWithUrls(urlText);
                }
            }
        });

        scanCard.add(scanTitle);
        scanCard.add(Box.createVerticalStrut(4));
        scanCard.add(scanSub);
        scanCard.add(Box.createVerticalStrut(10));
        scanCard.add(inputScroll);
        scanCard.add(Box.createVerticalStrut(8));
        scanCard.add(btnRow);
        scanCard.add(Box.createVerticalStrut(10));
        scanCard.add(resultScroll);

        add(scanCard, BorderLayout.CENTER);

        // ═══ BOTTOM: Stats Cards with colored glow ═══
        List<String[]> history = HistoryManager.getHistory();
        int totalScanned = history.size();
        long threatsFound = history.stream().filter(row -> row[2].equals("MALICIOUS") || row[2].equals("SUSPICIOUS")).count();
        long safeCount = totalScanned - threatsFound;

        JPanel statsRow = new JPanel(new FlowLayout(FlowLayout.CENTER, 35, 8));
        statsRow.setOpaque(false);
        statsRow.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, UITheme.BORDER));

        int dbCount = 0;
        try { dbCount = ThreatDatabase.getInstance().getThreatCount(); } catch (Exception ignored) {}

        JLabel lTotal = new JLabel("Total Scanned: " + totalScanned);
        lTotal.setForeground(UITheme.TEXT_SECONDARY);
        lTotal.setFont(UITheme.BODY);

        JLabel lClean = new JLabel("Clean: " + safeCount);
        lClean.setForeground(UITheme.GREEN_BRIGHT);
        lClean.setFont(UITheme.BODY);

        JLabel lThreats = new JLabel("Threats Caught: " + threatsFound);
        lThreats.setForeground(UITheme.RED);
        lThreats.setFont(UITheme.BODY);

        JLabel lDb = new JLabel("Local DB Entries: " + dbCount);
        lDb.setForeground(UITheme.AMBER);
        lDb.setFont(UITheme.BODY);

        statsRow.add(lTotal);
        statsRow.add(lClean);
        statsRow.add(lThreats);
        statsRow.add(lDb);

        add(statsRow, BorderLayout.SOUTH);
    }

    /**
     * Creates a single table row with category, status, and detail.
     */
    private JPanel createTableRow(String category, String status, Color statusColor, String detail) {
        JPanel row = new JPanel(new BorderLayout(15, 0));
        row.setOpaque(false);
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));
        row.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, UITheme.BORDER),
            BorderFactory.createEmptyBorder(6, 10, 6, 10)
        ));
        
        // Left side: Category name
        JLabel catLabel = new JLabel(category);
        catLabel.setForeground(UITheme.TEXT_PRIMARY);
        catLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
        catLabel.setPreferredSize(new Dimension(150, 20));
        
        // Right side: Status and detail wrapping
        JPanel rightPanel = new JPanel(new BorderLayout(10, 0));
        rightPanel.setOpaque(false);
        
        JLabel statusLabel = new JLabel(status);
        statusLabel.setForeground(statusColor);
        statusLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
        statusLabel.setPreferredSize(new Dimension(80, 20));
        
        JLabel detailLabel = new JLabel(SecurityUtils.sanitizeForUI(detail));
        detailLabel.setForeground(UITheme.TEXT_SECONDARY);
        detailLabel.setFont(UITheme.BODY);
        
        rightPanel.add(statusLabel, BorderLayout.WEST);
        rightPanel.add(detailLabel, BorderLayout.CENTER);
        
        row.add(catLabel, BorderLayout.WEST);
        row.add(rightPanel, BorderLayout.CENTER);
        
        return row;
    }
}
