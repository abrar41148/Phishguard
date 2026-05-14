package com.phishing;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for SecurityUtils AES-GCM encryption upgrade.
 * Covers: encrypt/decrypt roundtrip, randomness, edge cases, tamper detection,
 * and backward compatibility with legacy AES-ECB (ENC:) format.
 */
class SecurityUtilsTest {

    // ═══════════════════════════════════════════════════
    // ── AES-GCM Core Tests ──
    // ═══════════════════════════════════════════════════

    @Test
    @DisplayName("Encrypt then decrypt returns original plaintext")
    void testEncryptDecryptRoundtrip() {
        String original = "abc123-test-api-key";
        String encrypted = SecurityUtils.encryptKey(original);
        String decrypted = SecurityUtils.decryptKey(encrypted);

        assertEquals(original, decrypted);
    }

    @Test
    @DisplayName("Encrypted output uses ENC2: prefix (GCM format)")
    void testEncryptedPrefixIsV2() {
        String encrypted = SecurityUtils.encryptKey("my-secret-key");

        assertTrue(encrypted.startsWith("ENC2:"),
            "Expected ENC2: prefix, got: " + encrypted);
    }

    @Test
    @DisplayName("Two encryptions of same plaintext produce different ciphertext (random IV)")
    void testNonDeterministicEncryption() {
        String plaintext = "same-key-encrypted-twice";
        String enc1 = SecurityUtils.encryptKey(plaintext);
        String enc2 = SecurityUtils.encryptKey(plaintext);

        assertNotEquals(enc1, enc2,
            "GCM should produce different ciphertext each time due to random IV");

        // Both should still decrypt to same value
        assertEquals(plaintext, SecurityUtils.decryptKey(enc1));
        assertEquals(plaintext, SecurityUtils.decryptKey(enc2));
    }

    @Test
    @DisplayName("Long API key encrypts and decrypts correctly")
    void testLongKey() {
        String longKey = "a".repeat(256); // 256-char key
        String encrypted = SecurityUtils.encryptKey(longKey);
        String decrypted = SecurityUtils.decryptKey(encrypted);

        assertEquals(longKey, decrypted);
    }

    @Test
    @DisplayName("Special characters in key survive encryption roundtrip")
    void testSpecialCharacters() {
        String specialKey = "key+with/special=chars&more!@#$%^*()";
        String encrypted = SecurityUtils.encryptKey(specialKey);
        String decrypted = SecurityUtils.decryptKey(encrypted);

        assertEquals(specialKey, decrypted);
    }

    @Test
    @DisplayName("Unicode characters survive encryption roundtrip")
    void testUnicodeKey() {
        String unicodeKey = "キー-clé-Schlüssel-密钥";
        String encrypted = SecurityUtils.encryptKey(unicodeKey);
        String decrypted = SecurityUtils.decryptKey(encrypted);

        assertEquals(unicodeKey, decrypted);
    }

    // ═══════════════════════════════════════════════════
    // ── Edge Cases ──
    // ═══════════════════════════════════════════════════

    @Test
    @DisplayName("Null input returns null (no encryption)")
    void testNullInput() {
        assertNull(SecurityUtils.encryptKey(null));
        assertNull(SecurityUtils.decryptKey(null));
    }

    @Test
    @DisplayName("Empty string returns empty (no encryption)")
    void testEmptyInput() {
        assertEquals("", SecurityUtils.encryptKey(""));
        assertEquals("", SecurityUtils.decryptKey(""));
    }

    @Test
    @DisplayName("Placeholder 'YOUR_API_KEY_HERE' passes through unchanged")
    void testPlaceholderPassthrough() {
        String placeholder = "YOUR_API_KEY_HERE";
        assertEquals(placeholder, SecurityUtils.encryptKey(placeholder));
    }

    @Test
    @DisplayName("Unencrypted plaintext returned as-is by decryptKey (backward compat)")
    void testPlaintextPassthrough() {
        String plain = "not-encrypted-at-all";
        assertEquals(plain, SecurityUtils.decryptKey(plain));
    }

    // ═══════════════════════════════════════════════════
    // ── Tamper Detection (GCM Auth Tag) ──
    // ═══════════════════════════════════════════════════

    @Test
    @DisplayName("Tampered ciphertext returns empty string (GCM integrity check)")
    void testTamperedCiphertext() {
        String encrypted = SecurityUtils.encryptKey("sensitive-key");
        assertTrue(encrypted.startsWith("ENC2:"));

        // Flip a character in the Base64 payload to simulate tampering
        char[] chars = encrypted.toCharArray();
        int tamperIndex = 6; // somewhere in Base64 payload
        chars[tamperIndex] = (chars[tamperIndex] == 'A') ? 'B' : 'A';
        String tampered = new String(chars);

        String result = SecurityUtils.decryptKey(tampered);
        assertEquals("", result, "Tampered ciphertext should fail GCM auth and return empty");
    }

    // ═══════════════════════════════════════════════════
    // ── Legacy ECB Backward Compatibility ──
    // ═══════════════════════════════════════════════════

    @Test
    @DisplayName("Legacy ENC: (ECB) values still decrypt correctly")
    void testLegacyEcbDecryption() {
        // Encrypt using the old ECB method to simulate a legacy stored value
        String plaintext = "legacy-api-key-12345";
        String legacyEncrypted = legacyEcbEncrypt(plaintext);

        assertTrue(legacyEncrypted.startsWith("ENC:"));

        // New decryptKey should handle legacy format
        String decrypted = SecurityUtils.decryptKey(legacyEncrypted);
        assertEquals(plaintext, decrypted,
            "Legacy ECB-encrypted values should still decrypt via fallback");
    }

    /**
     * Helper: encrypts using the old AES-ECB method to produce legacy "ENC:" values for testing.
     */
    private String legacyEcbEncrypt(String plaintext) {
        try {
            java.security.MessageDigest sha = java.security.MessageDigest.getInstance("SHA-256");
            String seed = System.getProperty("user.name", "default") + "-" +
                          System.getProperty("os.name", "os") + "-PhishGuard";
            byte[] keyBytes = sha.digest(seed.getBytes("UTF-8"));
            keyBytes = java.util.Arrays.copyOf(keyBytes, 16);
            javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(keyBytes, "AES");

            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keySpec);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));
            return "ENC:" + java.util.Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new RuntimeException("Legacy ECB encrypt failed in test", e);
        }
    }
}
