package com.phishing;

/**
 * Centralized configuration constants for the Phishing Detector.
 * All magic numbers and configuration values are defined here for easy maintenance.
 */
public class ConfigConstants {
    
    // ═══ Risk Scoring Thresholds ═══
    /** Score threshold above which a URL is classified as MALICIOUS */
    public static final int RISK_THRESHOLD_MALICIOUS = 75;
    
    /** Score threshold above which a URL is classified as SUSPICIOUS */
    public static final int RISK_THRESHOLD_SUSPICIOUS = 40;
    
    // ═══ VirusTotal API Thresholds ═══
    /** Number of vendors that must flag as malicious for MALICIOUS verdict */
    public static final int VT_MALICIOUS_THRESHOLD = 3;
    
    /** Number of vendors that must flag as suspicious for SUSPICIOUS verdict */
    public static final int VT_SUSPICIOUS_THRESHOLD = 2;
    
    // ═══ Notification UI Settings ═══
    /** Notification popup window width in pixels */
    public static final int NOTIFICATION_WINDOW_WIDTH = 340;
    
    /** Notification popup window height in pixels */
    public static final int NOTIFICATION_WINDOW_HEIGHT = 105;
    
    /** Initial animation delay for notifications in milliseconds */
    public static final int NOTIFICATION_ANIMATION_DELAY_MS = 12;
    
    /** Timeout before notification automatically closes (milliseconds) */
    public static final int NOTIFICATION_TIMEOUT_MS = 8000;
    
    // ═══ Clipboard Monitor Settings ═══
    /** Clipboard polling interval in milliseconds */
    public static final int CLIPBOARD_POLL_INTERVAL_MS = 500;
    
    /** Maximum size of clipboard debug log file before rotation (5MB) */
    public static final long CLIPBOARD_LOG_MAX_SIZE = 5_242_880L;
    
    // ═══ Database Settings ═══
    /** SQLite database file name */
    public static final String DATABASE_FILE = "threat_database.db";
    
    /** Lock file for single-instance enforcement */
    public static final String LOCK_FILE = "phishguard.lock";
    
    // ═══ Analyzer Scoring Adjustments ═══
    /** Score increase for IP address detection in CharacterAnalyzer */
    public static final int SCORE_IP_ADDRESS = 45;
    
    /** Score increase for unusually long domain in LengthAnalyzer */
    public static final int SCORE_LONG_DOMAIN = 15;
    
    /** Score increase for typosquatting detection in TyposquattingAnalyzer */
    public static final int SCORE_TYPOSQUATTING = 40;

    /** Score increase for 3+ redirects in RedirectAnalyzer */
    public static final int SCORE_EXCESSIVE_REDIRECTS = 30;

    /** Score increase for cross-domain redirects in RedirectAnalyzer */
    public static final int SCORE_CROSS_DOMAIN_REDIRECT = 25;

    /** Score increase for redirect to an IP address */
    public static final int SCORE_REDIRECT_TO_IP = 50;
    
    // ═══ System Tray Settings ═══
    /** Initial delay before showing startup notification (milliseconds) */
    public static final int STARTUP_NOTIFICATION_DELAY_MS = 1500;
    
    // ═══ Batch Scanning Settings ═══
    /** Maximum length of URL to display in results table before truncation */
    public static final int BATCH_RESULTS_URL_MAX_LENGTH = 60;
}
