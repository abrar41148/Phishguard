package com.phishing;

import java.util.Arrays;
import java.util.List;

public class TyposquattingAnalyzer implements Analyzer {
    private static final List<String> HIGH_VALUE_TARGETS = Arrays.asList(
            "paypal.com", "google.com", "apple.com", "microsoft.com", 
            "facebook.com", "chase.com", "bankofamerica.com", "amazon.com"
    );

    @Override
    public void analyze(UrlTarget target, RiskReport report) {
        String host = target.getHost().toLowerCase();
        if (host.isEmpty()) return;

        // Strip subdomains to get the root domain roughly (e.g. login.paypal.com -> paypal.com)
        String[] parts = host.split("\\.");
        String rootDomain = host;
        if (parts.length >= 2) {
            rootDomain = parts[parts.length - 2] + "." + parts[parts.length - 1];
        }

        for (String targetDomain : HIGH_VALUE_TARGETS) {
            // Exact match is not typosquatting! It could be legit.
            if (rootDomain.equals(targetDomain)) continue;

            int dist = calculateLevenshtein(rootDomain, targetDomain);
            // If the distance is exactly 1 or 2, it's highly suspicious (e.g., paypol.com, g00gle.com)
            if (dist > 0 && dist <= 2) {
                report.addScore(40);
                report.addDetail("[TyposquattingAnalyzer] Possible typosquatting of '" + targetDomain + "'. (+40 risk)");
                break; // One match is enough
            }
        }
    }

    private int calculateLevenshtein(String a, String b) {
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
