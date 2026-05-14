package com.phishing;

import javax.swing.*;
import java.awt.*;

public class DetailsWindow extends JFrame {

    public DetailsWindow(String url, RiskReport report) {
        setTitle("Scan Details — PhishGuard");
        setSize(700, 450);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setResizable(true);
        setMinimumSize(new Dimension(500, 300));

        getContentPane().setBackground(UITheme.BG_DARK);
        setLayout(new BorderLayout(10, 10));

        // ═══ Header Strip ═══
        JPanel header = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g;
                Color accent = UITheme.resultColor(report.getResult());
                g2.setPaint(new GradientPaint(0, 0, accent, getWidth(), 0, UITheme.BG_CARD));
                g2.fillRect(0, 0, getWidth(), getHeight());
            }
        };
        header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));
        header.setBorder(BorderFactory.createEmptyBorder(18, 22, 18, 22));
        header.setOpaque(false);

        JLabel statusLabel = new JLabel("Status: " + report.getResult().name());
        statusLabel.setFont(new Font("Segoe UI", Font.BOLD, 20));
        statusLabel.setForeground(Color.WHITE);

        String displayUrl = SecurityUtils.defangUrl(url.length() > 50 ? url.substring(0, 50) + "..." : url);
        JLabel urlLabel = new JLabel(SecurityUtils.sanitizeForUI(displayUrl));
        urlLabel.setForeground(new Color(255, 255, 255, 180));
        urlLabel.setFont(UITheme.BODY);

        JLabel sourceLabel = new JLabel("Source: " + report.getSource());
        sourceLabel.setForeground(new Color(255, 255, 255, 140));
        sourceLabel.setFont(UITheme.SMALL);

        header.add(statusLabel);
        header.add(Box.createVerticalStrut(4));
        header.add(urlLabel);
        header.add(Box.createVerticalStrut(2));
        header.add(sourceLabel);

        add(header, BorderLayout.NORTH);

        // ═══ Details Body ═══
        JPanel detailsPanel = new JPanel();
        detailsPanel.setOpaque(false);
        detailsPanel.setLayout(new BoxLayout(detailsPanel, BoxLayout.Y_AXIS));

        // Define the checks to display
        String[][] analyzerChecks = {
            {"Local DB Entries", "[Local DB Entries]"},
            {"Redirect Chain", "[RedirectAnalyzer]"},
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
            boolean isRedirect = label.equals("Redirect Chain");

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
            } else if (isRedirect) {
                if (flagged) {
                    int bEnd = flagDetail.indexOf("] ");
                    detailText = bEnd > 0 ? flagDetail.substring(bEnd + 2) : flagDetail;
                    
                    if (detailText.contains("No redirects") || detailText.contains("No issues detected")) {
                        statusText = "Secure";
                        statusColor = UITheme.GREEN_BRIGHT;
                        detailText = "No redirects";
                    } else {
                        statusText = "Flagged";
                        statusColor = UITheme.AMBER;
                    }
                } else {
                    statusText = "Secure";
                    statusColor = UITheme.GREEN_BRIGHT;
                    detailText = "No redirects";
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

            detailsPanel.add(createTableRow(label, statusText, statusColor, detailText));
        }

        detailsPanel.add(Box.createVerticalStrut(10));
        // Add overall severity at the bottom
        JLabel overallLabel = new JLabel("    OVERALL SEVERITY: " + report.getResult().name() + " (Risk Score: " + report.getScore() + ")");
        overallLabel.setForeground(UITheme.resultColor(report.getResult()));
        overallLabel.setFont(new Font("Segoe UI", Font.BOLD, 13));
        overallLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        overallLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
        detailsPanel.add(overallLabel);

        JScrollPane scrollPane = new JScrollPane(detailsPanel);
        scrollPane.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createEmptyBorder(10, 20, 10, 20),
            BorderFactory.createLineBorder(UITheme.BORDER, 1, true)
        ));
        scrollPane.getViewport().setBackground(UITheme.BG_PANEL);
        detailsPanel.setBackground(UITheme.BG_PANEL);

        add(scrollPane, BorderLayout.CENTER);

        // ═══ Close ═══
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 20, 8));
        btnPanel.setOpaque(false);
        JButton closeBtn = UITheme.ghostButton("Close");
        closeBtn.addActionListener(e -> dispose());
        btnPanel.add(closeBtn);
        add(btnPanel, BorderLayout.SOUTH);
    }

    private JPanel createTableRow(String category, String status, Color statusColor, String detail) {
        JPanel row = new JPanel(new BorderLayout(15, 0));
        row.setOpaque(false);
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));
        row.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, UITheme.BORDER),
            BorderFactory.createEmptyBorder(4, 4, 4, 4)
        ));
        
        // Left side: Category name
        JLabel catLabel = new JLabel(category);
        catLabel.setForeground(UITheme.TEXT_PRIMARY);
        catLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
        catLabel.setPreferredSize(new Dimension(120, 20));
        
        // Right side: Status and detail wrapping
        JPanel rightPanel = new JPanel(new BorderLayout(10, 0));
        rightPanel.setOpaque(false);
        
        JLabel statusLabel = new JLabel(status);
        statusLabel.setForeground(statusColor);
        statusLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
        statusLabel.setPreferredSize(new Dimension(80, 20));
        
        // Using HTML to support basic wrapping for long details on narrower window
        String safeDetail = SecurityUtils.sanitizeForUI(detail);
        JLabel detailLabel = new JLabel("<html><body style='width: 380px'>" + safeDetail + "</body></html>");
        detailLabel.setForeground(UITheme.TEXT_SECONDARY);
        detailLabel.setFont(UITheme.BODY);
        
        rightPanel.add(statusLabel, BorderLayout.WEST);
        rightPanel.add(detailLabel, BorderLayout.CENTER);
        
        row.add(catLabel, BorderLayout.WEST);
        row.add(rightPanel, BorderLayout.CENTER);
        
        return row;
    }
}
