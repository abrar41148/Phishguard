package com.phishing;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.RandomAccessFile;
import java.nio.channels.FileLock;

public class Main {

    // Hold references so GC doesn't release the lock
    private static RandomAccessFile lockFile;
    private static FileLock lock;

    public static void main(String[] args) {
        // ── Single-instance enforcement ──
        if (!acquireLock()) {
            JOptionPane.showMessageDialog(null,
                "PhishGuard is already running.\nCheck the system tray.",
                "Already Running", JOptionPane.WARNING_MESSAGE);
            System.exit(0);
        }

        // Set modern FlatDarkLaf natively
        try {
            com.formdev.flatlaf.FlatDarkLaf.setup();
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Start the clipboard monitoring thread
        ClipboardMonitor monitor = new ClipboardMonitor();
        Thread monitorThread = new Thread(monitor);
        monitorThread.setDaemon(true);
        monitorThread.start();

        System.out.println("Phishing Link Detector started in background.");

        // Setup System Tray
        if (SystemTray.isSupported()) {
            setupSystemTray();
        } else {
            System.out.println("System tray not supported. Running purely headless.");
            // Prevent the main thread from exiting
            try {
                Thread.currentThread().join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    private static void setupSystemTray() {
        SystemTray tray = SystemTray.getSystemTray();
        
        // Generate a simple shield icon in memory
        Image icon = createShieldIcon();

        // Dashboard Instance
        DashboardWindow dashboard = new DashboardWindow();

        PopupMenu popup = new PopupMenu();
        
        MenuItem openItem = new MenuItem("Open Dashboard");
        openItem.addActionListener(e -> {
            dashboard.setVisible(true);
            dashboard.toFront();
        });

        MenuItem aboutItem = new MenuItem("About");
        aboutItem.addActionListener(e -> {
            JOptionPane.showMessageDialog(null, 
                "Phishing Link Detector\nActively monitoring clipboard for URLs.", 
                "About", JOptionPane.INFORMATION_MESSAGE);
        });
        
        MenuItem testItem = new MenuItem("Test Notification");
        testItem.addActionListener(e -> {
            RiskReport mockReport = new RiskReport(AnalysisResult.SUSPICIOUS, "Local Heuristic Engine");
            mockReport.addDetail("Suspicious keyword found in domain structure.");
            mockReport.addDetail("Unusually long domain (45 chars).");
            NotificationPopup fakePopup = new NotificationPopup("http://test-notification.com/secure", mockReport);
            fakePopup.showNotification();
        });

        MenuItem exitItem = new MenuItem("Exit");
        exitItem.addActionListener(e -> System.exit(0));

        popup.add(openItem);
        popup.add(aboutItem);
        popup.add(testItem);
        popup.addSeparator();
        popup.add(exitItem);

        TrayIcon trayIcon = new TrayIcon(icon, "Phishing Link Detector", popup);
        trayIcon.setImageAutoSize(true);
        
        // Double-click opens dashboard
        trayIcon.addActionListener(e -> {
            dashboard.setVisible(true);
            dashboard.toFront();
        });

        try {
            tray.add(trayIcon);

            // Show startup notification after DB/dashboard init completes
            Timer startupDelay = new Timer(ConfigConstants.STARTUP_NOTIFICATION_DELAY_MS, evt -> {
                ((Timer) evt.getSource()).stop();
                StartupNotificationPopup startupPopup = new StartupNotificationPopup(() -> {
                    dashboard.setVisible(true);
                    dashboard.toFront();
                });
                startupPopup.showNotification();
            });
            startupDelay.setRepeats(false);
            startupDelay.start();

        } catch (AWTException e) {
            System.out.println("TrayIcon could not be added.");
        }
    }

    private static Image createShieldIcon() {
        BufferedImage img = new BufferedImage(16, 16, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g2d = img.createGraphics();
        // Enable anti-aliasing
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        
        g2d.setColor(new Color(46, 204, 113)); // Safe green
        g2d.fillPolygon(new int[]{8, 14, 14, 8, 2, 2}, new int[]{1, 3, 10, 15, 10, 3}, 6);
        
        g2d.setColor(Color.WHITE);
        g2d.fillOval(7, 4, 2, 6);
        g2d.fillOval(7, 11, 2, 2);
        
        g2d.dispose();
        return img;
    }

    /**
     * Attempts to acquire an exclusive file lock.
     * Returns true if this is the only instance, false if another is running.
     */
    private static boolean acquireLock() {
        try {
            File file = new File(ConfigConstants.LOCK_FILE);
            lockFile = new RandomAccessFile(file, "rw");
            lock = lockFile.getChannel().tryLock();
            if (lock == null) {
                lockFile.close();
                return false;
            }
            // Delete lock file on JVM shutdown
            file.deleteOnExit();
            return true;
        } catch (Exception e) {
            // Ensure lockFile is closed if exception occurs
            if (lockFile != null) {
                try {
                    lockFile.close();
                } catch (Exception ex) {
                    System.err.println("Error closing lock file: " + ex.getMessage());
                }
            }
            System.err.println("Failed to acquire application lock: " + e.getMessage());
            return false;
        }
    }
}
