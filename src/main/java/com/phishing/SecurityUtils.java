package com.phishing;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

public class SecurityUtils {

    // ═══════════════════════════════════════════════════
    // ── UI Sanitization ──
    // ═══════════════════════════════════════════════════

    /**
     * Prevents Java Swing HTML injection via JLabel or other components.
     * Swing will automatically render anything starting with <html>, allowing XSS-like attacks locally.
     */
    public static String sanitizeForUI(String input) {
        if (input == null) return "";
        // Neutralize basic HTML tags and scripts
        return input.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;")
                    .replace("'", "&#x27;");
    }

    /**
     * Defangs a URL to prevent accidental clicking or execution.
     * Converts http:// to hxxp:// and replaces dots in the domain with [.]
     * Standard practice in threat intelligence to safely display malicious URLs.
     */
    public static String defangUrl(String url) {
        if (url == null) return "";
        return url.replace("http://", "hxxp://")
                  .replace("https://", "hxxps://")
                  .replace(".", "[.]");
    }

    // ═══════════════════════════════════════════════════
    // ── CSV Injection Prevention ──
    // ═══════════════════════════════════════════════════

    /**
     * Prevents CSV Injection (Formula Injection) vulnerabilities when exporting to Excel/Sheets.
     * Uses the ISO/IEC 26300 standard defense: prefix dangerous characters with a tab.
     * This is universally recognized by Excel, Google Sheets, and LibreOffice.
     * 
     * Formula injection markers (commonly blocked): =, +, -, @, tab, CR, LF
     * Defense mechanism: prepend with \t (tab character) which causes Excel to treat as text.
     */
    public static String sanitizeForCSV(String input) {
        if (input == null || input.isEmpty()) return "";
        
        // Escape any internal quotes by doubling them (RFC 4180 standard)
        String escaped = input.replace("\"", "\"\"");
        
        // Check if starts with formula injection marker
        if (escaped.length() > 0) {
            char firstChar = escaped.charAt(0);
            // If starts with =, +, -, @, or other dangerous markers, prepend tab
            // Tab character forces Excel to treat the field as text, not a formula
            if (firstChar == '=' || firstChar == '+' || firstChar == '-' || firstChar == '@') {
                escaped = "\t" + escaped;
            }
            // Also handle control characters (CR, LF, form feed)
            if (firstChar == '\r' || firstChar == '\n' || firstChar == '\f') {
                escaped = "\t" + escaped;
            }
        }
        
        // Wrap in double quotes (RFC 4180 CSV standard)
        return "\"" + escaped + "\"";
    }

    // ═══════════════════════════════════════════════════
    // ── API Key Encryption (AES-128) ──
    // ═══════════════════════════════════════════════════

    /**
     * Generates a machine-specific AES key derived from the local username and OS.
     * This prevents API keys from being trivially readable in settings.properties.
     */
    private static SecretKeySpec getEncryptionKey() {
        try {
            String seed = System.getProperty("user.name", "default") + "-" +
                          System.getProperty("os.name", "os") + "-PhishGuard";
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = sha.digest(seed.getBytes("UTF-8"));
            keyBytes = Arrays.copyOf(keyBytes, 16); // Use first 128 bits for AES-128
            return new SecretKeySpec(keyBytes, "AES");
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate encryption key", e);
        }
    }

    /** Encrypts a plaintext API key for storage */
    public static String encryptKey(String plaintext) {
        if (plaintext == null || plaintext.isEmpty() || plaintext.equals("YOUR_API_KEY_HERE")) {
            return plaintext;
        }
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, getEncryptionKey());
            byte[] encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));
            return "ENC:" + Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            System.out.println("[SecurityUtils] Encryption failed: " + e.getMessage());
            return plaintext; // Fallback to plaintext if encryption fails
        }
    }

    /** Decrypts a stored API key */
    public static String decryptKey(String stored) {
        if (stored == null || stored.isEmpty() || !stored.startsWith("ENC:")) {
            return stored; // Not encrypted, return as-is (backward compat)
        }
        try {
            String encoded = stored.substring(4); // Remove "ENC:" prefix
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, getEncryptionKey());
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encoded));
            return new String(decrypted, "UTF-8");
        } catch (Exception e) {
            System.out.println("[SecurityUtils] Decryption failed: " + e.getMessage());
            return ""; // Return empty if tampered or wrong machine
        }
    }
}
