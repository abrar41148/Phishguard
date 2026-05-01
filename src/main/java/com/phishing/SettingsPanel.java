package com.phishing;

import javax.swing.*;
import java.awt.*;

public class SettingsPanel extends JPanel {

    public SettingsPanel() {
        setBackground(UITheme.BG_DARK);
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(BorderFactory.createEmptyBorder(25, 40, 25, 40));

        // ═══ Title ═══
        JLabel titleLabel = new JLabel("Configuration");
        titleLabel.setForeground(UITheme.TEXT_PRIMARY);
        titleLabel.setFont(UITheme.TITLE);
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel subLabel = new JLabel("Manage API keys, scan preferences, and data.");
        subLabel.setForeground(UITheme.TEXT_MUTED);
        subLabel.setFont(UITheme.SMALL);
        subLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        SettingsManager sm = SettingsManager.getInstance();

        // ═══ API Config Card ═══
        JPanel apiCard = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(UITheme.BG_PANEL);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 14, 14);
                // Top green accent
                g2.setColor(UITheme.GREEN_PRIMARY);
                g2.fillRoundRect(0, 0, getWidth(), 3, 3, 3);
                // Subtle border
                g2.setColor(new Color(UITheme.GREEN_DARK.getRed(), UITheme.GREEN_DARK.getGreen(), UITheme.GREEN_DARK.getBlue(), 50));
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 14, 14);
            }
        };
        apiCard.setOpaque(false);
        apiCard.setLayout(new GridLayout(4, 1, 8, 12));
        apiCard.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        apiCard.setMaximumSize(new Dimension(650, 280));
        apiCard.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel cardTitle = new JLabel("API Providers");
        cardTitle.setForeground(UITheme.GREEN_PRIMARY);
        cardTitle.setFont(UITheme.LABEL_BOLD);
        cardTitle.setAlignmentX(Component.LEFT_ALIGNMENT);

        apiCard.add(createFieldRow("Active Provider", createProviderBox(sm)));
        apiCard.add(createPasswordRow("VirusTotal Key", sm.getProperty("VIRUS_TOTAL_KEY")));
        apiCard.add(createPasswordRow("Google Safe Browsing", sm.getProperty("GOOGLE_SAFE_BROWSING_KEY")));
        apiCard.add(createPasswordRow("PhishTank Key (Opt)", sm.getProperty("PHISHTANK_KEY")));

        // ═══ Danger Zone Card ═══
        JPanel dangerCard = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(UITheme.BG_PANEL);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 14, 14);
                // Top red accent
                g2.setColor(UITheme.RED);
                g2.fillRoundRect(0, 0, getWidth(), 3, 3, 3);
                // Subtle red border
                g2.setColor(new Color(255, 82, 82, 30));
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 14, 14);
            }
        };
        dangerCard.setOpaque(false);
        dangerCard.setLayout(new BoxLayout(dangerCard, BoxLayout.Y_AXIS));
        dangerCard.setBorder(BorderFactory.createEmptyBorder(18, 20, 18, 20));
        dangerCard.setMaximumSize(new Dimension(650, 100));
        dangerCard.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel dangerTitle = new JLabel("Danger Zone");
        dangerTitle.setForeground(UITheme.RED);
        dangerTitle.setFont(UITheme.LABEL_BOLD);
        dangerTitle.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel dangerSub = new JLabel("Clearing history is irreversible.");
        dangerSub.setForeground(UITheme.TEXT_MUTED);
        dangerSub.setFont(UITheme.SMALL);
        dangerSub.setAlignmentX(Component.LEFT_ALIGNMENT);

        JButton clearBtn = UITheme.dangerButton("Clear All History");
        clearBtn.setAlignmentX(Component.LEFT_ALIGNMENT);
        clearBtn.setMaximumSize(new Dimension(180, 34));
        clearBtn.addActionListener(e -> {
            int result = JOptionPane.showConfirmDialog(this, "Are you sure you want to clear all scan history?", "Clear History", JOptionPane.YES_NO_OPTION);
            if (result == JOptionPane.YES_OPTION) {
                HistoryManager.clearHistory();
                JOptionPane.showMessageDialog(this, "History cleared.\nReopen the History tab to see the change.", "Done", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        dangerCard.add(dangerTitle);
        dangerCard.add(Box.createVerticalStrut(4));
        dangerCard.add(dangerSub);
        dangerCard.add(Box.createVerticalStrut(10));
        dangerCard.add(clearBtn);

        // ═══ Save Button ═══
        JButton saveBtn = UITheme.accentButton("Save Configurations");
        saveBtn.setAlignmentX(Component.LEFT_ALIGNMENT);
        saveBtn.setMaximumSize(new Dimension(220, 38));
        saveBtn.addActionListener(e -> {
            Container card = apiCard;
            JComboBox<?> providerBox = (JComboBox<?>) findComponentByName(card, "providerBox");
            JPasswordField vtField = (JPasswordField) findComponentByName(card, "VirusTotal Key");
            JPasswordField gsbField = (JPasswordField) findComponentByName(card, "Google Safe Browsing");
            JPasswordField ptField = (JPasswordField) findComponentByName(card, "PhishTank Key (Opt)");

            if (providerBox != null) sm.setProperty("ACTIVE_PROVIDER", (String) providerBox.getSelectedItem());
            if (vtField != null) sm.setProperty("VIRUS_TOTAL_KEY", new String(vtField.getPassword()).trim());
            if (gsbField != null) sm.setProperty("GOOGLE_SAFE_BROWSING_KEY", new String(gsbField.getPassword()).trim());
            if (ptField != null) sm.setProperty("PHISHTANK_KEY", new String(ptField.getPassword()).trim());
            sm.saveSettings();
            JOptionPane.showMessageDialog(this, "Settings saved successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
        });

        add(titleLabel);
        add(Box.createVerticalStrut(4));
        add(subLabel);
        add(Box.createVerticalStrut(18));
        add(cardTitle);
        add(Box.createVerticalStrut(8));
        add(apiCard);
        add(Box.createVerticalStrut(14));
        add(saveBtn);
        add(Box.createVerticalStrut(24));
        add(dangerCard);
    }

    private JPanel createFieldRow(String label, JComponent field) {
        JPanel row = new JPanel(new BorderLayout(14, 0));
        row.setOpaque(false);
        JLabel lbl = new JLabel(label);
        lbl.setForeground(UITheme.TEXT_SECONDARY);
        lbl.setFont(UITheme.BODY);
        lbl.setPreferredSize(new Dimension(170, 30));
        row.add(lbl, BorderLayout.WEST);
        row.add(field, BorderLayout.CENTER);
        return row;
    }

    private JPanel createPasswordRow(String label, String value) {
        JPasswordField field = new JPasswordField(value);
        field.setEchoChar('*');
        field.setName(label);
        field.setBackground(UITheme.BG_INPUT);
        field.setForeground(UITheme.TEXT_PRIMARY);
        field.setCaretColor(UITheme.GREEN_BRIGHT);
        return createFieldRow(label, field);
    }

    private JComboBox<String> createProviderBox(SettingsManager sm) {
        String[] providers = {"VirusTotal", "Google Safe Browsing", "PhishTank"};
        JComboBox<String> box = new JComboBox<>(providers);
        box.setSelectedItem(sm.getProperty("ACTIVE_PROVIDER"));
        box.setName("providerBox");
        return box;
    }

    /** Recursively find a component by name */
    private Component findComponentByName(Container parent, String name) {
        for (Component c : parent.getComponents()) {
            if (name.equals(c.getName())) return c;
            if (c instanceof Container) {
                Component found = findComponentByName((Container) c, name);
                if (found != null) return found;
            }
        }
        return null;
    }
}
