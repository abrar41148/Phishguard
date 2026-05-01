package com.phishing;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class BatchPanel extends JPanel {

    private JTextArea inputArea;
    private JProgressBar progressBar;
    private JButton startButton;
    private JButton pauseButton;
    private JLabel statusLabel;
    private DetectionEngine analyzer;
    private DefaultTableModel resultsModel;
    private JPanel resultsCard;
    private final Map<Integer, RiskReport> batchReports = new ConcurrentHashMap<>();
    private String[] currentUrls;
    private BatchNotificationPopup currentPopup;

    // Scan control state
    private SwingWorker<Void, int[]> activeWorker;
    private volatile boolean cancelled = false;
    private volatile boolean paused = false;
    private final Object pauseLock = new Object();

    public BatchPanel() {
        analyzer = DetectionEngine.getInstance();
        setBackground(UITheme.BG_DARK);
        setLayout(new BorderLayout(0, 12));
        setBorder(BorderFactory.createEmptyBorder(20, 30, 20, 30));

        // ═══ Header ═══
        JPanel headerPanel = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g;
                g2.setColor(UITheme.GREEN_DARK);
                g2.fillRect(0, getHeight() - 1, getWidth(), 1);
            }
        };
        headerPanel.setOpaque(false);
        headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.Y_AXIS));
        headerPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));

        JLabel titleLabel = new JLabel("Batch Link Scanner");
        titleLabel.setForeground(UITheme.TEXT_PRIMARY);
        titleLabel.setFont(UITheme.TITLE);

        JLabel subLabel = new JLabel("Paste multiple URLs below, separated by spaces or newlines. Results appear live.");
        subLabel.setForeground(UITheme.TEXT_MUTED);
        subLabel.setFont(UITheme.SMALL);

        headerPanel.add(titleLabel);
        headerPanel.add(Box.createVerticalStrut(4));
        headerPanel.add(subLabel);
        add(headerPanel, BorderLayout.NORTH);

        // ═══ Split: Input (top) + Results (bottom) ═══
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.35);
        splitPane.setDividerSize(6);
        splitPane.setBorder(null);
        splitPane.setBackground(UITheme.BG_DARK);

        // ── Input Card ──
        JPanel inputCard = new JPanel(new BorderLayout()) {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(UITheme.BG_PANEL);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 12, 12);
                g2.setColor(UITheme.GREEN_PRIMARY);
                g2.fillRoundRect(0, 0, 3, getHeight(), 3, 3);
            }
        };
        inputCard.setOpaque(false);
        inputCard.setBorder(BorderFactory.createEmptyBorder(10, 16, 10, 10));

        JLabel inputLabel = new JLabel("URLs to scan:");
        inputLabel.setForeground(UITheme.TEXT_SECONDARY);
        inputLabel.setFont(UITheme.LABEL_BOLD);
        inputLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));

        inputArea = new JTextArea();
        inputArea.setFont(UITheme.MONO);
        inputArea.setBackground(UITheme.BG_INPUT);
        inputArea.setForeground(UITheme.TEXT_PRIMARY);
        inputArea.setCaretColor(UITheme.GREEN_BRIGHT);
        inputArea.setMargin(new Insets(10, 10, 10, 10));

        JScrollPane inputScroll = new JScrollPane(inputArea);
        inputScroll.setBorder(BorderFactory.createLineBorder(UITheme.BORDER, 1, true));

        inputCard.add(inputLabel, BorderLayout.NORTH);
        inputCard.add(inputScroll, BorderLayout.CENTER);

        // ── Results Card ──
        resultsCard = new JPanel(new BorderLayout()) {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(UITheme.BG_PANEL);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 12, 12);
            }
        };
        resultsCard.setOpaque(false);
        resultsCard.setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));

        JLabel resultsLabel = new JLabel("Scan Results");
        resultsLabel.setForeground(UITheme.TEXT_SECONDARY);
        resultsLabel.setFont(UITheme.LABEL_BOLD);
        resultsLabel.setBorder(BorderFactory.createEmptyBorder(0, 4, 6, 0));

        String[] cols = {"#", "URL", "Result", "Score"};
        resultsModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) { return false; }
        };

        JTable resultsTable = new JTable(resultsModel);
        resultsTable.setFillsViewportHeight(true);
        resultsTable.setFont(UITheme.BODY);
        resultsTable.setRowHeight(30);
        resultsTable.setShowGrid(false);
        resultsTable.setIntercellSpacing(new Dimension(0, 2));
        resultsTable.setBackground(UITheme.BG_DARK);
        resultsTable.setForeground(UITheme.TEXT_PRIMARY);
        resultsTable.setSelectionBackground(new Color(0, 230, 118, 30));
        resultsTable.setSelectionForeground(UITheme.GREEN_BRIGHT);

        // Column widths
        resultsTable.getColumnModel().getColumn(0).setMaxWidth(40);
        resultsTable.getColumnModel().getColumn(2).setPreferredWidth(90);
        resultsTable.getColumnModel().getColumn(2).setMaxWidth(120);
        resultsTable.getColumnModel().getColumn(3).setPreferredWidth(60);
        resultsTable.getColumnModel().getColumn(3).setMaxWidth(80);

        // Styled header
        JTableHeader tableHeader = resultsTable.getTableHeader();
        tableHeader.setFont(UITheme.LABEL_BOLD);
        tableHeader.setBackground(UITheme.BG_PANEL);
        tableHeader.setForeground(UITheme.GREEN_PRIMARY);
        tableHeader.setBorder(BorderFactory.createMatteBorder(0, 0, 2, 0, UITheme.GREEN_DARK));

        // Row renderer with severity coloring
        DefaultTableCellRenderer cellRenderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object value,
                    boolean isSelected, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(t, value, isSelected, hasFocus, row, col);
                int modelRow = t.convertRowIndexToModel(row);
                String result = (String) resultsModel.getValueAt(modelRow, 2);

                if (!isSelected) {
                    if ("MALICIOUS".equals(result)) c.setBackground(new Color(255, 50, 50, 18));
                    else if ("SUSPICIOUS".equals(result)) c.setBackground(new Color(255, 196, 0, 14));
                    else if ("SAFE".equals(result)) c.setBackground(row % 2 == 0 ? UITheme.BG_DARK : UITheme.BG_PANEL);
                    else c.setBackground(UITheme.BG_DARK); // scanning row
                }

                if (col == 2) {
                    if ("MALICIOUS".equals(value)) c.setForeground(UITheme.RED);
                    else if ("SUSPICIOUS".equals(value)) c.setForeground(UITheme.AMBER);
                    else if ("SAFE".equals(value)) c.setForeground(UITheme.GREEN_BRIGHT);
                    else if ("STOPPED".equals(value)) c.setForeground(UITheme.TEXT_MUTED);
                    else c.setForeground(UITheme.TEXT_MUTED);
                    c.setFont(new Font("Segoe UI", Font.BOLD, 12));
                } else if (col == 3) {
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
                ((JLabel) c).setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
                return c;
            }
        };
        for (int i = 0; i < resultsTable.getColumnCount(); i++) {
            resultsTable.getColumnModel().getColumn(i).setCellRenderer(cellRenderer);
        }

        // Double-click to view details
        resultsTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int viewRow = resultsTable.getSelectedRow();
                    if (viewRow < 0) return;
                    int modelRow = resultsTable.convertRowIndexToModel(viewRow);
                    String resultStr = (String) resultsModel.getValueAt(modelRow, 2);
                    if ("...".equals(resultStr)) return; // still scanning

                    RiskReport report = batchReports.get(modelRow);
                    if (report != null && currentUrls != null && modelRow < currentUrls.length) {
                        new DetailsWindow(currentUrls[modelRow], report).setVisible(true);
                    }
                }
            }
        });

        JScrollPane resultsScroll = new JScrollPane(resultsTable);
        resultsScroll.setBorder(BorderFactory.createLineBorder(UITheme.BORDER, 1, true));
        resultsScroll.getViewport().setBackground(UITheme.BG_DARK);

        resultsCard.add(resultsLabel, BorderLayout.NORTH);
        resultsCard.add(resultsScroll, BorderLayout.CENTER);

        splitPane.setTopComponent(inputCard);
        splitPane.setBottomComponent(resultsCard);
        add(splitPane, BorderLayout.CENTER);

        // ═══ Footer Controls ═══
        JPanel footerPanel = new JPanel(new BorderLayout(12, 0));
        footerPanel.setOpaque(false);
        footerPanel.setBorder(BorderFactory.createEmptyBorder(8, 0, 0, 0));

        // Left side: status + progress
        JPanel leftFooter = new JPanel();
        leftFooter.setOpaque(false);
        leftFooter.setLayout(new BoxLayout(leftFooter, BoxLayout.Y_AXIS));

        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setForeground(UITheme.GREEN_PRIMARY);
        progressBar.setBackground(UITheme.BG_INPUT);
        progressBar.setVisible(false);
        progressBar.setMaximumSize(new Dimension(Integer.MAX_VALUE, 18));
        progressBar.setBorder(BorderFactory.createLineBorder(UITheme.GREEN_DARK, 1, true));

        statusLabel = new JLabel("Ready");
        statusLabel.setForeground(UITheme.TEXT_MUTED);
        statusLabel.setFont(new Font("Segoe UI", Font.ITALIC, 12));
        statusLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        leftFooter.add(progressBar);
        leftFooter.add(Box.createVerticalStrut(4));
        leftFooter.add(statusLabel);

        // Right side: buttons
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        btnPanel.setOpaque(false);

        pauseButton = UITheme.ghostButton("Pause");
        pauseButton.setPreferredSize(new Dimension(100, 36));
        pauseButton.setVisible(false);
        pauseButton.addActionListener(e -> togglePause());

        startButton = UITheme.accentButton("Start Batch Scan");
        startButton.setPreferredSize(new Dimension(180, 36));
        startButton.addActionListener(e -> handleStartStopClick());

        btnPanel.add(pauseButton);
        btnPanel.add(startButton);

        footerPanel.add(leftFooter, BorderLayout.CENTER);
        footerPanel.add(btnPanel, BorderLayout.EAST);
        add(footerPanel, BorderLayout.SOUTH);
    }

    /** Handles start button click — starts scan or stops it depending on state */
    private void handleStartStopClick() {
        if (activeWorker != null && !activeWorker.isDone()) {
            // Currently scanning → stop
            stopScan();
        } else {
            this.currentPopup = null;
            startBatchScan();
        }
    }

    /** Toggle pause/resume */
    private void togglePause() {
        if (paused) {
            // Resume
            paused = false;
            pauseButton.setText("Pause");
            pauseButton.setForeground(UITheme.AMBER);
            statusLabel.setForeground(UITheme.GREEN_PRIMARY);
            progressBar.setForeground(UITheme.GREEN_PRIMARY);
            synchronized (pauseLock) {
                pauseLock.notifyAll();
            }
        } else {
            // Pause
            paused = true;
            pauseButton.setText("Resume");
            pauseButton.setForeground(UITheme.GREEN_BRIGHT);
            statusLabel.setForeground(UITheme.AMBER);
            progressBar.setForeground(UITheme.AMBER);
            String currentText = statusLabel.getText();
            statusLabel.setText("PAUSED  |  " + currentText);
        }
    }

    /** Stop the scan entirely */
    private void stopScan() {
        cancelled = true;
        paused = false;
        synchronized (pauseLock) {
            pauseLock.notifyAll(); // unblock if paused
        }
        if (activeWorker != null) {
            activeWorker.cancel(false);
        }
        // Clear stale popup reference so the next scan doesn't update a dead popup
        if (currentPopup != null) {
            currentPopup.dispose();
            currentPopup = null;
        }
    }

    /** Reset UI to idle state */
    private void resetToIdle() {
        activeWorker = null;
        cancelled = false;
        paused = false;

        startButton.setText("Start Batch Scan");
        startButton.setForeground(UITheme.BG_DARK);
        startButton.setBackground(UITheme.GREEN_PRIMARY);
        startButton.setEnabled(true);

        pauseButton.setVisible(false);
        pauseButton.setText("Pause");

        inputArea.setEditable(true);
        progressBar.setVisible(false);
        progressBar.setForeground(UITheme.GREEN_PRIMARY);
    }

    private void startBatchScan() {
        String text = inputArea.getText();
        if (text == null || text.trim().isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please paste at least one link.", "Empty Input", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String[] urls = text.trim().split("\\s+");
        if (urls.length == 0) return;

        // Reset state
        cancelled = false;
        paused = false;

        // Clear previous results and pre-populate rows
        batchReports.clear();
        currentUrls = urls;
        resultsModel.setRowCount(0);
        for (int i = 0; i < urls.length; i++) {
            String displayUrl = urls[i].length() > 60 ? urls[i].substring(0, 60) + "..." : urls[i];
            resultsModel.addRow(new Object[]{String.valueOf(i + 1), SecurityUtils.defangUrl(displayUrl), "...", ""});
        }

        // Switch to scanning UI
        startButton.setText("Stop Scan");
        startButton.setForeground(UITheme.RED);
        startButton.setBackground(UITheme.BG_CARD);

        pauseButton.setVisible(true);
        pauseButton.setText("Pause");
        pauseButton.setForeground(UITheme.AMBER);

        inputArea.setEditable(false);
        progressBar.setVisible(true);
        progressBar.setValue(0);
        progressBar.setForeground(UITheme.GREEN_PRIMARY);
        statusLabel.setText("Scanning 0 / " + urls.length + "...");
        statusLabel.setForeground(UITheme.GREEN_PRIMARY);

        activeWorker = new SwingWorker<Void, int[]>() {
            int safe = 0, suspicious = 0, malicious = 0;

            @Override
            protected Void doInBackground() {
                for (int i = 0; i < urls.length; i++) {
                    // Check for stop
                    if (cancelled || isCancelled()) {
                        // Mark remaining rows as STOPPED
                        for (int j = i; j < urls.length; j++) {
                            publish(new int[]{j, -1, 0, safe, suspicious, malicious});
                        }
                        break;
                    }

                    // Check for pause
                    while (paused && !cancelled) {
                        synchronized (pauseLock) {
                            try {
                                pauseLock.wait(500);
                            } catch (InterruptedException e) {
                                break;
                            }
                        }
                    }
                    if (cancelled || isCancelled()) {
                        for (int j = i; j < urls.length; j++) {
                            publish(new int[]{j, -1, 0, safe, suspicious, malicious});
                        }
                        break;
                    }

                    String url = urls[i];
                    RiskReport report = analyzer.analyze(url);
                    HistoryManager.logScan(url, report);
                    batchReports.put(i, report);

                    switch (report.getResult()) {
                        case SAFE: safe++; break;
                        case SUSPICIOUS: suspicious++; break;
                        case MALICIOUS: malicious++; break;
                    }

                    int progress = (int) (((i + 1) / (float) urls.length) * 100);
                    setProgress(progress);
                    // Include running totals in published data so EDT can read them safely
                    publish(new int[]{i, report.getResult().ordinal(), report.getScore(), safe, suspicious, malicious});
                }
                return null;
            }

            @Override
            protected void process(List<int[]> chunks) {
                // Use the LAST chunk's totals (most up-to-date)
                int latestSafe = 0, latestSuspicious = 0, latestMalicious = 0;
                for (int[] data : chunks) {
                    int row = data[0];
                    if (data[1] == -1) {
                        // Stopped
                        resultsModel.setValueAt("STOPPED", row, 2);
                        resultsModel.setValueAt("-", row, 3);
                    } else {
                        String resultText;
                        switch (data[1]) {
                            case 0: resultText = "SAFE"; break;
                            case 1: resultText = "SUSPICIOUS"; break;
                            case 2: resultText = "MALICIOUS"; break;
                            default: resultText = "UNKNOWN";
                        }
                        resultsModel.setValueAt(resultText, row, 2);
                        resultsModel.setValueAt(String.valueOf(data[2]), row, 3);
                    }
                    // Extract running totals from payload
                    latestSafe = data[3];
                    latestSuspicious = data[4];
                    latestMalicious = data[5];
                }
                int scanned = latestSafe + latestSuspicious + latestMalicious;
                if (!paused) {
                    progressBar.setValue(getProgress());
                    statusLabel.setText("Scanning " + scanned + " / " + urls.length + 
                        "  |  Safe: " + latestSafe + "  Suspicious: " + latestSuspicious + "  Malicious: " + latestMalicious);
                    if (currentPopup != null) {
                        currentPopup.updateProgress(scanned, latestSafe, latestSuspicious, latestMalicious);
                    }
                }
            }

            @Override
            protected void done() {
                // safe/suspicious/malicious are guaranteed visible here (happens-before from doInBackground -> done)
                int scanned = safe + suspicious + malicious;
                if (currentPopup != null) {
                    if (cancelled) {
                        currentPopup.dispose();
                    } else {
                        // Force final update with correct totals
                        currentPopup.updateProgress(urls.length, safe, suspicious, malicious);
                    }
                    currentPopup = null;
                }
                resetToIdle();

                if (cancelled) {
                    statusLabel.setForeground(UITheme.AMBER);
                    statusLabel.setText("Stopped at " + scanned + " / " + urls.length +
                        "  |  Safe: " + safe + "  Suspicious: " + suspicious + "  Malicious: " + malicious);
                } else {
                    statusLabel.setForeground(UITheme.GREEN_BRIGHT);
                    statusLabel.setText("Complete  |  Safe: " + safe + 
                        "  Suspicious: " + suspicious + "  Malicious: " + malicious +
                        "  |  Total: " + urls.length);
                }
            }
        };
        activeWorker.execute();
    }

    /**
     * Externally load URLs into the input area and auto-start scanning.
     * Called from DashboardWindow when batch notification is clicked.
     * NOTE: This method expects to be called on the EDT already.
     */
    public void loadUrlsAndScan(String urlText) {
        loadUrlsAndScan(urlText, null);
    }

    public void loadUrlsAndScan(String urlText, BatchNotificationPopup popup) {
        // If a scan is already running, stop it first
        if (activeWorker != null && !activeWorker.isDone()) {
            stopScan();
            // Small delay to let the worker finish, then start new scan
            Timer delay = new Timer(300, e -> {
                ((Timer) e.getSource()).stop();
                inputArea.setText(urlText);
                this.currentPopup = popup;
                startBatchScan();
            });
            delay.setRepeats(false);
            delay.start();
        } else {
            inputArea.setText(urlText);
            this.currentPopup = popup;
            startBatchScan();
        }
    }
}

