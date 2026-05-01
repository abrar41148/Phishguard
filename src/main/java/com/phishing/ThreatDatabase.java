package com.phishing;

import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Manages the local SQLite threat database.
 * Stores known malicious/phishing domains and URLs for offline checking.
 * Pre-seeded with publicly known phishing domains on first launch.
 */
public class ThreatDatabase {

    private static final String DB_FILE = ConfigConstants.DATABASE_FILE;
    private static ThreatDatabase instance;
    private Connection connection;

    private ThreatDatabase() {
        try {
            // Load SQLite JDBC driver
            Class.forName("org.sqlite.JDBC");
            connection = DriverManager.getConnection("jdbc:sqlite:" + DB_FILE);
            connection.setAutoCommit(true);
            initTables();
            seedIfEmpty();
            
            // Ensure connection is closed on JVM shutdown
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try {
                    if (connection != null && !connection.isClosed()) {
                        connection.close();
                        System.out.println("[ThreatDatabase] Connection closed on shutdown.");
                    }
                } catch (SQLException e) {
                    System.err.println("[ThreatDatabase] Error closing connection: " + e.getMessage());
                }
            }));
        } catch (Exception e) {
            System.out.println("[ThreatDatabase] Failed to initialize: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static synchronized ThreatDatabase getInstance() {
        if (instance == null) {
            instance = new ThreatDatabase();
        }
        return instance;
    }

    /** Create tables if they don't exist */
    private void initTables() throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.executeUpdate(
                "CREATE TABLE IF NOT EXISTS known_threats (" +
                "  id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "  domain TEXT NOT NULL," +
                "  threat_type TEXT NOT NULL DEFAULT 'PHISHING'," +
                "  source TEXT DEFAULT 'seed'," +
                "  date_added TEXT NOT NULL," +
                "  active INTEGER DEFAULT 1" +
                ")"
            );
            // Index on domain for fast lookups
            stmt.executeUpdate(
                "CREATE INDEX IF NOT EXISTS idx_domain ON known_threats(domain)"
            );

            // Scan cache: avoids re-scanning the same URL within a time window
            stmt.executeUpdate(
                "CREATE TABLE IF NOT EXISTS scan_cache (" +
                "  url TEXT PRIMARY KEY," +
                "  result TEXT NOT NULL," +
                "  score INTEGER NOT NULL," +
                "  details TEXT," +
                "  scanned_at TEXT NOT NULL" +
                ")"
            );
        }
        System.out.println("[ThreatDatabase] Tables initialized.");
    }

    /**
     * Check if a domain or any of its parent domains exist in the threat database.
     * Returns the threat type ("PHISHING", "MALWARE", "SCAM") or null if not found.
     */
    public String checkDomain(String host) {
        if (host == null || host.isEmpty()) return null;
        host = host.toLowerCase().replaceAll("^www\\.", "");

        try {
            // Check exact domain
            String result = queryDomain(host);
            if (result != null) return result;

            // Check parent domains (e.g., evil.phishing-site.com → phishing-site.com)
            String[] parts = host.split("\\.");
            if (parts.length > 2) {
                for (int i = 1; i < parts.length - 1; i++) {
                    StringBuilder parentDomain = new StringBuilder();
                    for (int j = i; j < parts.length; j++) {
                        if (parentDomain.length() > 0) parentDomain.append(".");
                        parentDomain.append(parts[j]);
                    }
                    result = queryDomain(parentDomain.toString());
                    if (result != null) return result;
                }
            }
        } catch (Exception e) {
            System.out.println("[ThreatDatabase] Error checking domain: " + e.getMessage());
        }
        return null;
    }

    private String queryDomain(String domain) throws SQLException {
        String sql = "SELECT threat_type FROM known_threats WHERE domain = ? AND active = 1 LIMIT 1";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, domain);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                return rs.getString("threat_type");
            }
        }
        return null;
    }

    /** Add a threat domain to the database */
    public void addThreat(String domain, String threatType, String source) {
        domain = domain.toLowerCase().replaceAll("^www\\.", "").trim();
        if (domain.isEmpty()) return;

        String sql = "INSERT OR IGNORE INTO known_threats (domain, threat_type, source, date_added) VALUES (?, ?, ?, ?)";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, domain);
            ps.setString(2, threatType);
            ps.setString(3, source);
            ps.setString(4, LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            ps.executeUpdate();
        } catch (SQLException e) {
            System.out.println("[ThreatDatabase] Error adding threat: " + e.getMessage());
        }
    }

    /** Remove a domain from the threat database */
    public void removeThreat(String domain) {
        domain = domain.toLowerCase().replaceAll("^www\\.", "").trim();
        String sql = "DELETE FROM known_threats WHERE domain = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, domain);
            ps.executeUpdate();
        } catch (SQLException e) {
            System.out.println("[ThreatDatabase] Error removing threat: " + e.getMessage());
        }
    }

    /** Get total count of threats in the database */
    public int getThreatCount() {
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM known_threats WHERE active = 1")) {
            if (rs.next()) return rs.getInt(1);
        } catch (SQLException e) {
            System.out.println("[ThreatDatabase] Error counting: " + e.getMessage());
        }
        return 0;
    }

    // ═══════════════════════════════════════════════════════
    // ── Scan Cache ──
    // ═══════════════════════════════════════════════════════

    /** Cache a scan result for a URL */
    public void cacheResult(String url, String result, int score, String details) {
        String sql = "INSERT OR REPLACE INTO scan_cache (url, result, score, details, scanned_at) VALUES (?, ?, ?, ?, ?)";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, url);
            ps.setString(2, result);
            ps.setInt(3, score);
            ps.setString(4, details);
            ps.setString(5, LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            ps.executeUpdate();
        } catch (SQLException e) {
            System.out.println("[ThreatDatabase] Error caching result: " + e.getMessage());
        }
    }

    /**
     * Get a cached result for a URL, if it was scanned within the given hours.
     * Returns a String[] {result, score, details} or null if not cached/expired.
     */
    public String[] getCachedResult(String url, int maxAgeHours) {
        String sql = "SELECT result, score, details, scanned_at FROM scan_cache WHERE url = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, url);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                String scannedAt = rs.getString("scanned_at");
                LocalDateTime scannedTime = LocalDateTime.parse(scannedAt, DateTimeFormatter.ISO_LOCAL_DATE_TIME);
                LocalDateTime cutoff = LocalDateTime.now().minusHours(maxAgeHours);

                if (scannedTime.isAfter(cutoff)) {
                    return new String[]{
                        rs.getString("result"),
                        String.valueOf(rs.getInt("score")),
                        rs.getString("details")
                    };
                }
            }
        } catch (Exception e) {
            System.out.println("[ThreatDatabase] Error reading cache: " + e.getMessage());
        }
        return null;
    }

    // ═══════════════════════════════════════════════════════
    // ── Seed Database with Known Threats ──
    // ═══════════════════════════════════════════════════════

    /** Seed the database with commonly known phishing/malicious domains on first run */
    private void seedIfEmpty() {
        if (getThreatCount() > 0) {
            System.out.println("[ThreatDatabase] Database already seeded (" + getThreatCount() + " entries).");
            return;
        }

        System.out.println("[ThreatDatabase] Seeding database with known threats...");

        // ── Known Phishing Domains ──
        String[] phishingDomains = {
            // PayPal impersonation
            "paypa1.com", "paypal-secure.com", "paypal-login.com", "paypal-verify.net",
            "paypal-update.com", "secure-paypal.com", "login-paypal.com", "paypal-resolution.com",
            "paypal-confirm.com", "paypal-account.net",
            // Google impersonation
            "g00gle.com", "gooogle.com", "googel.com", "google-security.com",
            "accounts-google.com", "google-verify.com", "google-login.net",
            // Apple impersonation
            "apple-id-verify.com", "appleid-secure.com", "appie.com",
            "apple-support-verify.com", "icloud-verify.com", "apple-login.net",
            // Microsoft impersonation
            "microsft.com", "microsoft-verify.com", "microsoft-login.com",
            "office365-login.com", "outlook-verify.com", "microsoft-account.net",
            // Amazon impersonation
            "amaz0n.com", "amazon-verify.com", "amazon-login.com",
            "amazon-security.com", "amazon-update.net",
            // Facebook impersonation
            "faceb00k.com", "facebook-login.com", "facebook-verify.com",
            "fb-login.com", "facebook-security.net",
            // Banking phishing
            "chase-verify.com", "chase-login.com", "bankofamerica-verify.com",
            "wellsfargo-login.com", "citibank-verify.com",
            // Cryptocurrency scams
            "binance-giveaway.com", "coinbase-airdrop.com", "crypto-bonus.net",
            "ethereum-giveaway.com", "bitcoin-double.com",
            // Streaming phishing
            "netflix-renew.com", "netflix-billing.com", "spotify-verify.com",
            "disney-plus-verify.com", "hulu-billing.com",
            // Social media phishing
            "instagram-verify.com", "twitter-verify.com", "tiktok-verify.com",
            "snapchat-login.com", "linkedin-verify.com",
            // Generic phishing patterns
            "secure-login-verify.com", "account-update-banking.com",
            "verify-your-account.com", "update-your-information.com",
            "confirm-identity.com", "security-alert-notification.com",
            "urgent-account-action.com", "suspended-account-restore.com",
            // Known malware distribution
            "free-virus-scan.com", "your-pc-is-infected.com",
            "download-free-antivirus.com", "system-alert-warning.com",
            // Test domains
            "testsafebrowsing.appspot.com", "malware.testing.google.test"
        };

        String[] malwareDomains = {
            "free-virus-scan.com", "your-pc-is-infected.com",
            "download-free-antivirus.com", "system-alert-warning.com",
            "free-software-download.net", "crack-software-free.com",
            "keygen-download.com", "serial-key-free.com"
        };

        String[] scamDomains = {
            "bitcoin-double.com", "crypto-bonus.net", "ethereum-giveaway.com",
            "free-iphone-winner.com", "congratulations-you-won.com",
            "claim-your-prize.com", "lottery-winner-notification.com",
            "inheritance-claim.com", "nigerian-prince-fund.com"
        };

        // Insert phishing domains
        for (String domain : phishingDomains) {
            addThreat(domain, "PHISHING", "seed");
        }
        // Insert malware domains
        for (String domain : malwareDomains) {
            addThreat(domain, "MALWARE", "seed");
        }
        // Insert scam domains
        for (String domain : scamDomains) {
            addThreat(domain, "SCAM", "seed");
        }

        System.out.println("[ThreatDatabase] Seeded " + getThreatCount() + " threat entries.");
    }
}
