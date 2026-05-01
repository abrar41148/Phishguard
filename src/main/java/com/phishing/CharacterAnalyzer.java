package com.phishing;

import java.util.regex.Pattern;

public class CharacterAnalyzer implements Analyzer {
    private static final Pattern IP_PATTERN = Pattern.compile("^(?:http|https)://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
    // Matches @ in the authority section (before the host), the actual attack pattern
    // e.g. http://legit.com@evil.com — NOT youtube.com/@channel
    private static final Pattern AUTHORITY_AT = Pattern.compile("^https?://[^/]*@");

    @Override
    public void analyze(UrlTarget target, RiskReport report) {
        String url = target.getResolvedUrl();

        if (IP_PATTERN.matcher(url).find()) {
            report.addScore(45);
            report.addDetail("[CharacterAnalyzer] IP address used instead of domain. (+45 risk)");
        }

        // Only flag @ if it's in the authority portion (credential stuffing)
        // e.g. http://paypal.com@evil.com — NOT youtube.com/@channel
        if (AUTHORITY_AT.matcher(url).find()) {
            report.addScore(50);
            report.addDetail("[CharacterAnalyzer] '@' symbol in authority section (credential stuffing obfuscation). (+50 risk)");
        }
        
        if (target.isMalformed()) {
            report.addScore(30);
            report.addDetail("[CharacterAnalyzer] Malformed URI syntax detected. (+30 risk)");
        }
    }
}
