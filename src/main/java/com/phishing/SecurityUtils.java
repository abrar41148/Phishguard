package com.phishing;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
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
    // ── API Key Encryption (AES-128-GCM) ──
    // ═══════════════════════════════════════════════════

    /** GCM IV size in bytes (96 bits — NIST recommended) */
    private static final int GCM_IV_LENGTH = 12;

    /** GCM authentication tag length in bits */
    private static final int GCM_TAG_LENGTH = 128;

    /** Prefix for AES-GCM encrypted values (v2) */
    private static final String ENC_V2_PREFIX = "ENC2:";

    /** Legacy prefix for AES-ECB encrypted values (v1, read-only for migration) */
    private static final String ENC_V1_PREFIX = "ENC:";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

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

    /**
     * Encrypts a plaintext API key for storage using AES-128-GCM.
     * A random 12-byte IV is generated and prepended to the ciphertext before Base64 encoding.
     * Output format: "ENC2:" + Base64(IV || ciphertext+tag)
     */
    public static String encryptKey(String plaintext) {
        if (plaintext == null || plaintext.isEmpty() || plaintext.equals("YOUR_API_KEY_HERE")) {
            return plaintext;
        }
        try {
            // Generate random IV for each encryption (critical for GCM security)
            byte[] iv = new byte[GCM_IV_LENGTH];
            SECURE_RANDOM.nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, getEncryptionKey(), spec);
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));

            // Prepend IV to ciphertext: [12-byte IV][ciphertext+GCM tag]
            byte[] combined = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);

            return ENC_V2_PREFIX + Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            System.out.println("[SecurityUtils] Encryption failed: " + e.getMessage());
            return plaintext; // Fallback to plaintext if encryption fails
        }
    }

    /**
     * Decrypts a stored API key.
     * Supports both AES-GCM (ENC2: prefix) and legacy AES-ECB (ENC: prefix) for migration.
     * Legacy ECB values will be re-encrypted as GCM on next save automatically.
     */
    public static String decryptKey(String stored) {
        if (stored == null || stored.isEmpty()) {
            return stored;
        }

        // ── AES-GCM decryption (current format) ──
        if (stored.startsWith(ENC_V2_PREFIX)) {
            try {
                byte[] combined = Base64.getDecoder().decode(stored.substring(ENC_V2_PREFIX.length()));

                // Extract IV (first 12 bytes) and ciphertext (remainder)
                byte[] iv = Arrays.copyOfRange(combined, 0, GCM_IV_LENGTH);
                byte[] ciphertext = Arrays.copyOfRange(combined, GCM_IV_LENGTH, combined.length);

                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
                cipher.init(Cipher.DECRYPT_MODE, getEncryptionKey(), spec);
                byte[] decrypted = cipher.doFinal(ciphertext);
                return new String(decrypted, "UTF-8");
            } catch (Exception e) {
                System.out.println("[SecurityUtils] GCM decryption failed: " + e.getMessage());
                return ""; // Return empty if tampered or wrong machine
            }
        }

        // ── Legacy AES-ECB decryption (backward compat for migration) ──
        if (stored.startsWith(ENC_V1_PREFIX)) {
            try {
                String encoded = stored.substring(ENC_V1_PREFIX.length());
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, getEncryptionKey());
                byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encoded));
                return new String(decrypted, "UTF-8");
            } catch (Exception e) {
                System.out.println("[SecurityUtils] Legacy ECB decryption failed: " + e.getMessage());
                return ""; // Return empty if tampered or wrong machine
            }
        }

        // Not encrypted — return as-is (plaintext backward compat)
        return stored;
    }
}

