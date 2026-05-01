package com.phishing;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.util.List;

public class HistoryPanel extends JPanel {

    public HistoryPanel() {
        setBackground(UITheme.BG_DARK);
        setLayout(new BorderLayout(0, 14));
        setBorder(BorderFactory.createEmptyBorder(25, 35, 25, 35));

        // ═══ Top Bar ═══
        JPanel topPanel = new JPanel(new BorderLayout(10, 0));
        topPanel.setOpaque(false);

        JLabel titleLabel = new JLabel("Scan History");
        titleLabel.setForeground(UITheme.TEXT_PRIMARY);
        titleLabel.setFont(UITheme.TITLE);
        topPanel.add(titleLabel, BorderLayout.WEST);

        // ── Filter & Export ──
        JPanel controlRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        controlRow.setOpaque(false);

        JLabel filterLabel = new JLabel("Source:");
        filterLabel.setForeground(UITheme.TEXT_MUTED);
        filterLabel.setFont(UITheme.BODY);

        JComboBox<String> sourceFilter = new JComboBox<>(new String[]{"All", "Clipboard", "Manual", "API"});

        JButton exportBtn = UITheme.ghostButton("Export CSV");

        controlRow.add(filterLabel);
        controlRow.add(sourceFilter);
        controlRow.add(Box.createHorizontalStrut(6));
        controlRow.add(exportBtn);
        topPanel.add(controlRow, BorderLayout.EAST);

        add(topPanel, BorderLayout.NORTH);

        // ═══ Table ═══
        String[] columns = {"Timestamp", "URL", "Result", "Score", "Source"};
        DefaultTableModel model = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };

        List<String[]> history = HistoryManager.getHistory();
        // Store full data (including details at index 5) for lookup
        java.util.List<String[]> fullData = new java.util.ArrayList<>();
        for (int i = history.size() - 1; i >= 0; i--) {
            String[] row = history.get(i);
            fullData.add(row);
            // Only add first 5 columns to the visible table
            model.addRow(new String[]{row[0], SecurityUtils.defangUrl(row[1]), row[2], row[3], row[4]});
        }

        JTable table = new JTable(model);
        table.setFillsViewportHeight(true);
        table.setFont(UITheme.BODY);
        table.setRowHeight(34);
        table.setShowGrid(false);
        table.setIntercellSpacing(new Dimension(0, 2));
        table.setBackground(UITheme.BG_DARK);
        table.setForeground(UITheme.TEXT_PRIMARY);
        table.setSelectionBackground(new Color(0, 230, 118, 30));
        table.setSelectionForeground(UITheme.GREEN_BRIGHT);

        // ── Double-click to view stored detailed analysis (instant) ──
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int viewRow = table.getSelectedRow();
                    if (viewRow < 0) return;
                    int modelRow = table.convertRowIndexToModel(viewRow);

                    String url = fullData.get(modelRow)[1]; // Use original URL, not defanged
                    String resultStr = (String) model.getValueAt(modelRow, 2);
                    String scoreStr = (String) model.getValueAt(modelRow, 3);
                    String source = (String) model.getValueAt(modelRow, 4);
                    String detailsRaw = fullData.get(modelRow).length > 5 ? fullData.get(modelRow)[5] : "";

                    AnalysisResult ar = AnalysisResult.SAFE;
                    if ("MALICIOUS".equals(resultStr)) ar = AnalysisResult.MALICIOUS;
                    else if ("SUSPICIOUS".equals(resultStr)) ar = AnalysisResult.SUSPICIOUS;

                    RiskReport report = new RiskReport(ar, source);
                    try { report.addScore(Integer.parseInt(scoreStr)); } catch (Exception ignored) {}

                    // Restore detail lines from pipe-delimited string
                    if (!detailsRaw.isEmpty()) {
                        for (String detail : detailsRaw.split("\\|")) {
                            if (!detail.trim().isEmpty()) report.addDetail(detail.trim());
                        }
                    } else {
                        report.addDetail("Result: " + resultStr + "  |  Score: " + scoreStr);
                        report.addDetail("(Detailed breakdown not available for legacy scans)");
                    }

                    new DetailsWindow(url, report).setVisible(true);
                }
            }
        });

        // ── Styled Header ──
        JTableHeader header = table.getTableHeader();
        header.setFont(UITheme.LABEL_BOLD);
        header.setBackground(UITheme.BG_PANEL);
        header.setForeground(UITheme.GREEN_PRIMARY);
        header.setBorder(BorderFactory.createMatteBorder(0, 0, 2, 0, UITheme.GREEN_DARK));
        header.setPreferredSize(new Dimension(0, 36));

        // ── Sorter ──
        javax.swing.table.TableRowSorter<DefaultTableModel> sorter = new javax.swing.table.TableRowSorter<>(model);
        table.setRowSorter(sorter);

        // ── Filter Action ──
        sourceFilter.addActionListener(e -> {
            String selected = (String) sourceFilter.getSelectedItem();
            if ("All".equals(selected)) {
                sorter.setRowFilter(null);
            } else {
                sorter.setRowFilter(javax.swing.RowFilter.regexFilter(
                    "^" + java.util.regex.Pattern.quote(selected) + "$", 4));
            }
        });

        // ── Export Action ──
        exportBtn.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Export History CSV");
            String ts = java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss"));
            fileChooser.setSelectedFile(new java.io.File("phishing_history_" + ts + ".csv"));
            int userSelection = fileChooser.showSaveDialog(this);
            if (userSelection == JFileChooser.APPROVE_OPTION) {
                java.io.File fileToSave = fileChooser.getSelectedFile();
                try {
                    java.nio.file.Files.copy(
                        new java.io.File("history.csv").toPath(),
                        fileToSave.toPath(),
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING
                    );
                    JOptionPane.showMessageDialog(this, "Exported to:\n" + fileToSave.getAbsolutePath(), "Export Successful", JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(this, "Export failed. " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        // ── Row renderer: tint entire row by severity ──
        DefaultTableCellRenderer rowRenderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                
                // Get the result value for this row
                int modelRow = table.convertRowIndexToModel(row);
                String result = (String) model.getValueAt(modelRow, 2);

                if (!isSelected) {
                    // Tint entire row background based on severity
                    if ("MALICIOUS".equals(result)) {
                        c.setBackground(new Color(255, 50, 50, 18));
                    } else if ("SUSPICIOUS".equals(result)) {
                        c.setBackground(new Color(255, 196, 0, 14));
                    } else {
                        // Alternate between two dark shades for readability
                        c.setBackground(row % 2 == 0 ? UITheme.BG_DARK : UITheme.BG_PANEL);
                    }
                }

                // Color the result column text specifically
                if (column == 2) {
                    if ("MALICIOUS".equals(value)) c.setForeground(UITheme.RED);
                    else if ("SUSPICIOUS".equals(value)) c.setForeground(UITheme.AMBER);
                    else c.setForeground(UITheme.GREEN_BRIGHT);
                    c.setFont(new Font("Segoe UI", Font.BOLD, 12));
                } else if (column == 3) {
                    // Score column - color by value
                    try {
                        int score = Integer.parseInt(value.toString());
                        if (score >= 75) c.setForeground(UITheme.RED);
                        else if (score >= 40) c.setForeground(UITheme.AMBER);
                        else c.setForeground(UITheme.GREEN_PRIMARY);
                    } catch (Exception ex) {
                        c.setForeground(UITheme.TEXT_MUTED);
                    }
                    c.setFont(new Font("Segoe UI", Font.BOLD, 12));
                } else {
                    c.setForeground(isSelected ? UITheme.GREEN_BRIGHT : UITheme.TEXT_PRIMARY);
                    c.setFont(UITheme.BODY);
                }

                // Pad cells
                ((JLabel) c).setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));
                return c;
            }
        };

        // Apply to all columns
        for (int i = 0; i < table.getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setCellRenderer(rowRenderer);
        }

        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.setBorder(BorderFactory.createLineBorder(UITheme.BORDER, 1, true));
        scrollPane.getViewport().setBackground(UITheme.BG_DARK);
        add(scrollPane, BorderLayout.CENTER);

        // ═══ Bottom Summary Bar ═══
        long totalCount = history.size();
        long malCount = history.stream().filter(r -> "MALICIOUS".equals(r[2])).count();
        long susCount = history.stream().filter(r -> "SUSPICIOUS".equals(r[2])).count();
        long safeCount = totalCount - malCount - susCount;

        JPanel summaryBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 24, 6));
        summaryBar.setOpaque(false);
        summaryBar.add(createSummaryChip("Total: " + totalCount, UITheme.TEXT_SECONDARY));
        summaryBar.add(createSummaryChip("Safe: " + safeCount, UITheme.GREEN_BRIGHT));
        summaryBar.add(createSummaryChip("Suspicious: " + susCount, UITheme.AMBER));
        summaryBar.add(createSummaryChip("Malicious: " + malCount, UITheme.RED));
        add(summaryBar, BorderLayout.SOUTH);
    }

    private JLabel createSummaryChip(String text, Color color) {
        JLabel chip = new JLabel(text);
        chip.setForeground(color);
        chip.setFont(new Font("Segoe UI", Font.BOLD, 12));
        return chip;
    }
}
