package com.phishing;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ClipboardMonitor implements Runnable {

    // Clipboard polling interval in milliseconds
    private static final int POLL_INTERVAL_MS = ConfigConstants.CLIPBOARD_POLL_INTERVAL_MS;

    private String lastClipboardHash = "";
    private final DetectionEngine analyzer;
    
    // Matches URLs including those without http:// — supports Unicode letters for IDN domains
    private static final Pattern URL_PATTERN = Pattern.compile(
        "((?:https?://)?(?:www\\.)?[-\\p{L}0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{2,6}\\b(?:[-\\p{L}0-9()@:%_\\+.~#?&//=]*))"
    );

    public ClipboardMonitor() {
        this.analyzer = DetectionEngine.getInstance();
    }

    private void log(String msg) {
        String ts = java.time.LocalTime.now().toString() + " - " + msg;
        System.out.println("[ClipboardMonitor] " + ts);
        try {
            java.nio.file.Path logPath = java.nio.file.Paths.get("clipboard_debug.log");
            
            // Implement log rotation: if file exceeds max size, rotate it
            if (java.nio.file.Files.exists(logPath)) {
                long fileSize = java.nio.file.Files.size(logPath);
                if (fileSize > ConfigConstants.CLIPBOARD_LOG_MAX_SIZE) {
                    java.nio.file.Path backup = java.nio.file.Paths.get("clipboard_debug.log.1");
                    java.nio.file.Files.move(logPath, backup, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                }
            }
            
            java.nio.file.Files.writeString(
                logPath, 
                ts + "\n", 
                java.nio.file.StandardOpenOption.CREATE, 
                java.nio.file.StandardOpenOption.APPEND
            );
        } catch(Exception ignored) {}
    }

    /** Produces a hex SHA-256 digest of the input string to avoid hashCode collisions */
    private String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(64);
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            // Fallback to hashCode if SHA-256 unavailable (shouldn't happen)
            return Integer.toHexString(input.hashCode());
        }
    }

    @Override
    public void run() {
        log("Started listening for URLs...");

        // Pre-hash initial clipboard contents to avoid scanning links copied prior to startup
        try {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            if (clipboard.isDataFlavorAvailable(DataFlavor.stringFlavor)) {
                String rawData = (String) clipboard.getData(DataFlavor.stringFlavor);
                if (rawData != null && !rawData.trim().isEmpty()) {
                    lastClipboardHash = sha256Hex(rawData.trim());
                }
            }
        } catch (Exception e) {
            // Ignore if clipboard is locked during startup
        }

        while (true) {
            try {
                Thread.sleep(POLL_INTERVAL_MS);

                // Respect toggle setting
                String isEnabled = SettingsManager.getInstance().getProperty("CLIPBOARD_SCAN_ENABLED", "true");
                if (!"true".equals(isEnabled)) {
                    continue;
                }

                // Get clipboard on each iteration (safer across LAF changes)
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();

                if (!clipboard.isDataFlavorAvailable(DataFlavor.stringFlavor)) {
                    continue;
                }

                String rawData = (String) clipboard.getData(DataFlavor.stringFlavor);
                if (rawData == null || rawData.trim().isEmpty()) {
                    continue;
                }

                String copiedData = rawData.trim();

                // Hash clipboard content to avoid reprocessing same copy
                String clipHash = sha256Hex(copiedData);
                if (clipHash.equals(lastClipboardHash)) {
                    continue;
                }

                // Extract ALL URLs from clipboard text
                Matcher matcher = URL_PATTERN.matcher(copiedData);
                Set<String> urlSet = new LinkedHashSet<>(); // preserve order, deduplicate
                while (matcher.find()) {
                    String url = matcher.group(1);
                    if (!url.toLowerCase().startsWith("http")) {
                        url = "http://" + url;
                    }
                    urlSet.add(url);
                }

                if (urlSet.isEmpty()) {
                    continue; // no URLs found
                }

                // Mark as processed
                lastClipboardHash = clipHash;

                List<String> urls = new ArrayList<>(urlSet);
                log("Detected " + urls.size() + " URL(s) from clipboard");

                if (urls.size() == 1) {
                    // ── Single URL: existing behavior ──
                    handleSingleUrl(urls.get(0));
                } else {
                    // ── Multiple URLs: batch analysis with live notification ──
                    handleBatchUrls(urls);
                }

            } catch (IllegalStateException e) {
                // Clipboard locked by another app — normal, ignore
            } catch (Exception e) {
                log("Exception: " + e.getMessage());
            }
        }
    }

    /** Original single-URL handling with individual notification popup. */
    private void handleSingleUrl(String url) {
        log("Single URL detected: " + url);
        new Thread(() -> {
            try {
                log("Analyzing: " + url);
                final RiskReport report = analyzer.analyze(url);
                HistoryManager.logScan(url, report);
                log("Result: " + report.getResult().name() + " (Score: " + report.getScore() + ")");

                // Trigger Notification on EDT
                javax.swing.SwingUtilities.invokeLater(() -> {
                    try {
                        NotificationPopup popup = new NotificationPopup(url, report);
                        popup.showNotification();
                        log("Notification shown for: " + url);
                    } catch (Exception ex) {
                        log("ERROR showing notification: " + ex.getMessage());
                        ex.printStackTrace();
                    }
                });
            } catch (Exception ex) {
                log("ERROR during analysis: " + ex.getMessage());
                ex.printStackTrace();
            }
        }).start();
    }

    /**
     * Handles multiple URLs detected at once. Shows a BatchNotificationPopup
     * with the link count, and clicking it opens the Batch Scanner which
     * performs the actual analysis (no duplicate scanning).
     */
    private void handleBatchUrls(List<String> urls) {
        log("Batch mode: " + urls.size() + " URLs detected");

        // Build the URL text to pass to BatchPanel
        final String urlText = String.join("\n", urls);
        final int total = urls.size();

        // Create and show the batch notification on EDT
        javax.swing.SwingUtilities.invokeLater(() -> {
            BatchNotificationPopup popup = new BatchNotificationPopup(total);

            // On click: open dashboard to Batch Scan tab (do not restart scan)
            popup.setOnClickAction(() -> {
                DashboardWindow dashboard = DashboardWindow.getInstance();
                if (dashboard != null) {
                    dashboard.showBatchScanTab();
                }
            });

            popup.showNotification();
            log("Batch notification shown for " + total + " URLs");

            // Auto-open the batch scanner immediately so scanning starts right away,
            // passing the popup so it receives live updates.
            DashboardWindow dashboard = DashboardWindow.getInstance();
            if (dashboard != null) {
                dashboard.showBatchScanWithUrls(urlText, popup);
            }
        });
    }
}

