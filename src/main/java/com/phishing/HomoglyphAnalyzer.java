package com.phishing;

import java.net.IDN;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Detects Internationalized Domain Name (IDN) homograph attacks.
 * These attacks use Unicode characters that visually resemble ASCII letters
 * (e.g., Cyrillic "а" vs Latin "a") to impersonate legitimate domains.
 *
 * Detection strategy:
 * 1. Identify punycode domains (xn-- prefix) which indicate Unicode chars
 * 2. Decode punycode to Unicode and normalize confusable characters to ASCII
 * 3. Check if the normalized form closely matches a high-value brand domain
 * 4. Also detect mixed-script domains (e.g., Latin + Cyrillic in the same label)
 */
public class HomoglyphAnalyzer implements Analyzer {

    /**
     * High-value brand domains that are commonly targeted by IDN homograph attacks.
     */
    private static final List<String> HIGH_VALUE_TARGETS = Arrays.asList(
        "paypal.com", "google.com", "apple.com", "microsoft.com",
        "facebook.com", "amazon.com", "chase.com", "bankofamerica.com",
        "netflix.com", "instagram.com", "twitter.com", "discord.com",
        "wellsfargo.com", "citibank.com", "dropbox.com", "linkedin.com",
        "coinbase.com", "binance.com", "github.com", "outlook.com",
        "icloud.com", "spotify.com", "steam.com", "whatsapp.com",
        "kaggle.com", "patreon.com", "twitch.tv", "reddit.com",
        "zoom.us", "slack.com", "adobe.com", "stripe.com",
        "shopify.com", "ebay.com", "walmart.com", "target.com",
        "youtube.com", "yahoo.com", "tiktok.com", "snapchat.com",
        "uber.com", "airbnb.com", "tesla.com", "robinhood.com"
    );

    /**
     * Mapping of Unicode confusable characters to their ASCII equivalents.
     * Covers Cyrillic, Greek, and other common homoglyphs used in phishing.
     * Source: Unicode Confusables (https://unicode.org/cldr/utility/confusables.jsp)
     */
    private static final Map<Character, Character> CONFUSABLES = new HashMap<>();
    static {
        // Cyrillic → Latin
        CONFUSABLES.put('\u0430', 'a'); // а → a
        CONFUSABLES.put('\u0435', 'e'); // е → e
        CONFUSABLES.put('\u043E', 'o'); // о → o
        CONFUSABLES.put('\u0440', 'p'); // р → p
        CONFUSABLES.put('\u0441', 'c'); // с → c
        CONFUSABLES.put('\u0443', 'y'); // у → y
        CONFUSABLES.put('\u0445', 'x'); // х → x
        CONFUSABLES.put('\u043D', 'h'); // н → h  (less common but used)
        CONFUSABLES.put('\u0456', 'i'); // і → i  (Ukrainian i)
        CONFUSABLES.put('\u0458', 'j'); // ј → j  (Serbian je)
        CONFUSABLES.put('\u04BB', 'h'); // һ → h  (Bashkir)
        CONFUSABLES.put('\u0455', 's'); // ѕ → s  (Macedonian)
        CONFUSABLES.put('\u044C', 'b'); // ь → b  (visual similarity)
        CONFUSABLES.put('\u0432', 'b'); // в → b  (visual similarity in some fonts)
        CONFUSABLES.put('\u0433', 'r'); // г → r  (Cyrillic Ge, some fonts)
        CONFUSABLES.put('\u043A', 'k'); // к → k
        CONFUSABLES.put('\u043C', 'm'); // м → m
        CONFUSABLES.put('\u0442', 't'); // т → t  (Cyrillic Te, some fonts)

        // Cyrillic uppercase → Latin lowercase (for case-insensitive matching)
        CONFUSABLES.put('\u0410', 'a'); // А → a
        CONFUSABLES.put('\u0415', 'e'); // Е → e
        CONFUSABLES.put('\u041E', 'o'); // О → o
        CONFUSABLES.put('\u0420', 'p'); // Р → p
        CONFUSABLES.put('\u0421', 'c'); // С → c
        CONFUSABLES.put('\u0423', 'y'); // У → y
        CONFUSABLES.put('\u0425', 'x'); // Х → x

        // Greek → Latin
        CONFUSABLES.put('\u03B1', 'a'); // α → a
        CONFUSABLES.put('\u03BF', 'o'); // ο → o
        CONFUSABLES.put('\u03C1', 'p'); // ρ → p
        CONFUSABLES.put('\u03B5', 'e'); // ε → e
        CONFUSABLES.put('\u03BA', 'k'); // κ → k
        CONFUSABLES.put('\u03BD', 'v'); // ν → v
        CONFUSABLES.put('\u03C4', 't'); // τ → t
        CONFUSABLES.put('\u03B9', 'i'); // ι → i

        // Latin-like extended
        CONFUSABLES.put('\u0131', 'i'); // ı → i  (Turkish dotless i)
        CONFUSABLES.put('\u00E0', 'a'); // à → a
        CONFUSABLES.put('\u00E1', 'a'); // á → a
        CONFUSABLES.put('\u00E2', 'a'); // â → a
        CONFUSABLES.put('\u00E3', 'a'); // ã → a
        CONFUSABLES.put('\u00E4', 'a'); // ä → a
        CONFUSABLES.put('\u00E8', 'e'); // è → e
        CONFUSABLES.put('\u00E9', 'e'); // é → e
        CONFUSABLES.put('\u00EC', 'i'); // ì → i
        CONFUSABLES.put('\u00ED', 'i'); // í → i
        CONFUSABLES.put('\u00F2', 'o'); // ò → o
        CONFUSABLES.put('\u00F3', 'o'); // ó → o
        CONFUSABLES.put('\u00F4', 'o'); // ô → o
        CONFUSABLES.put('\u00F6', 'o'); // ö → o
        CONFUSABLES.put('\u00F9', 'u'); // ù → u
        CONFUSABLES.put('\u00FA', 'u'); // ú → u

        // Other common confusables
        CONFUSABLES.put('\u0261', 'g'); // ɡ → g  (Latin small letter script g)
        CONFUSABLES.put('\u026A', 'i'); // ɪ → i  (Latin letter small capital I)
        CONFUSABLES.put('\u1D00', 'a'); // ᴀ → a  (Latin letter small capital A)
        CONFUSABLES.put('\u1D04', 'c'); // ᴄ → c  (Latin letter small capital C)
    }

    @Override
    public void analyze(UrlTarget target, RiskReport report) {
        // Use getUnicodeHost() to get the original Unicode hostname (not punycode)
        // so we can detect confusable characters like Cyrillic а vs Latin a
        String host = target.getUnicodeHost().toLowerCase();
        if (host.isEmpty()) return;

        // Extract root domain (e.g., login.аpple.com → аpple.com)
        String[] parts = host.split("\\.");
        String rootDomain = host;
        if (parts.length >= 2) {
            rootDomain = parts[parts.length - 2] + "." + parts[parts.length - 1];
        }

        // ── Check 1: Punycode detection (xn-- prefix) ──
        boolean isPunycode = false;
        String decodedDomain = rootDomain;
        for (String part : parts) {
            if (part.startsWith("xn--")) {
                isPunycode = true;
                break;
            }
        }

        if (isPunycode) {
            try {
                // Decode punycode to Unicode
                decodedDomain = IDN.toUnicode(rootDomain);
                System.out.println("[HomoglyphAnalyzer] Punycode detected: " + rootDomain + " → " + decodedDomain);
            } catch (Exception e) {
                // If decoding fails, it's suspicious in itself
                report.addScore(30);
                report.addDetail("[HomoglyphAnalyzer] Malformed punycode domain detected: " + rootDomain + " (+30 risk)");
                return;
            }
        }

        // ── Check 2: Normalize confusable characters to ASCII ──
        String normalized = normalizeConfusables(decodedDomain);
        boolean hasConfusables = !normalized.equals(decodedDomain);

        // ── Check 3: Mixed-script detection ──
        boolean hasMixedScripts = detectMixedScripts(decodedDomain);

        // ── Check 4: Compare normalized domain against targets ──
        if (hasConfusables || isPunycode) {
            for (String targetDomain : HIGH_VALUE_TARGETS) {
                // Exact match with the target after normalization = homograph attack
                if (normalized.equals(targetDomain)) {
                    report.addScore(50);
                    report.addDetail("[HomoglyphAnalyzer] IDN Homograph Attack! Domain '" + decodedDomain
                        + "' uses lookalike characters to impersonate '" + targetDomain + "'. (+50 risk)");
                    return;
                }

                // Close match (distance 1-2 after normalization) — could be combined attack
                String normalizedBase = normalized.contains(".") 
                    ? normalized.substring(0, normalized.lastIndexOf('.'))
                    : normalized;
                String targetBase = targetDomain.contains(".")
                    ? targetDomain.substring(0, targetDomain.lastIndexOf('.'))
                    : targetDomain;

                if (normalizedBase.length() > 2 && targetBase.length() > 2) {
                    int dist = levenshtein(normalizedBase, targetBase);
                    if (dist > 0 && dist <= 2) {
                        report.addScore(45);
                        report.addDetail("[HomoglyphAnalyzer] Possible homograph + typosquatting attack on '"
                            + targetDomain + "'. Normalized domain: '" + normalized + "'. (+45 risk)");
                        return;
                    }
                }
            }

            // Confusable characters found but doesn't match a known target — still flag it
            if (hasConfusables) {
                report.addScore(25);
                report.addDetail("[HomoglyphAnalyzer] Domain contains Unicode lookalike characters: '"
                    + decodedDomain + "' → normalized to '" + normalized + "'. (+25 risk)");
            }
        }

        // ── Check 5: Mixed scripts without punycode — also suspicious ──
        if (hasMixedScripts && !hasConfusables) {
            report.addScore(20);
            report.addDetail("[HomoglyphAnalyzer] Mixed Unicode scripts detected in domain '"
                + decodedDomain + "'. This is a common IDN attack technique. (+20 risk)");
        }
    }

    /**
     * Replaces all known confusable Unicode characters with their ASCII equivalents.
     */
    private String normalizeConfusables(String input) {
        StringBuilder sb = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            Character replacement = CONFUSABLES.get(c);
            sb.append(replacement != null ? replacement : c);
        }
        return sb.toString();
    }

    /**
     * Detects if a domain label uses characters from multiple Unicode scripts.
     * Legitimate domains almost never mix Cyrillic with Latin, for example.
     * Checks only the domain labels, not the TLD.
     */
    private boolean detectMixedScripts(String domain) {
        // Only check the part before the TLD
        int lastDot = domain.lastIndexOf('.');
        String label = lastDot > 0 ? domain.substring(0, lastDot) : domain;

        boolean hasLatin = false;
        boolean hasCyrillic = false;
        boolean hasGreek = false;

        for (int i = 0; i < label.length(); i++) {
            char c = label.charAt(i);
            if (c == '.' || c == '-') continue; // separators are neutral

            Character.UnicodeBlock block = Character.UnicodeBlock.of(c);
            if (block == Character.UnicodeBlock.BASIC_LATIN || 
                block == Character.UnicodeBlock.LATIN_1_SUPPLEMENT ||
                block == Character.UnicodeBlock.LATIN_EXTENDED_A ||
                block == Character.UnicodeBlock.LATIN_EXTENDED_B) {
                hasLatin = true;
            } else if (block == Character.UnicodeBlock.CYRILLIC ||
                       block == Character.UnicodeBlock.CYRILLIC_SUPPLEMENTARY) {
                hasCyrillic = true;
            } else if (block == Character.UnicodeBlock.GREEK) {
                hasGreek = true;
            }
        }

        int scriptCount = 0;
        if (hasLatin) scriptCount++;
        if (hasCyrillic) scriptCount++;
        if (hasGreek) scriptCount++;

        return scriptCount > 1;
    }

    /** Simple Levenshtein distance for close-match detection */
    private int levenshtein(String a, String b) {
        int[][] dp = new int[a.length() + 1][b.length() + 1];
        for (int i = 0; i <= a.length(); i++) {
            for (int j = 0; j <= b.length(); j++) {
                if (i == 0) dp[i][j] = j;
                else if (j == 0) dp[i][j] = i;
                else {
                    int cost = (a.charAt(i - 1) == b.charAt(j - 1)) ? 0 : 1;
                    dp[i][j] = Math.min(Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1), dp[i - 1][j - 1] + cost);
                }
            }
        }
        return dp[a.length()][b.length()];
    }
}
