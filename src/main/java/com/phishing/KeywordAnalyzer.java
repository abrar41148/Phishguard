package com.phishing;

import java.util.regex.Pattern;

public class KeywordAnalyzer implements Analyzer {
    private static final Pattern SUSPICIOUS_WORDS = Pattern.compile("(?i)(login|secure|account|update|verify|banking|paypal|service)");

    @Override
    public void analyze(UrlTarget target, RiskReport report) {
        String host = target.getHost();
        String path = target.getPath();

        if (SUSPICIOUS_WORDS.matcher(host).find()) {
            report.addScore(25);
            report.addDetail("[KeywordAnalyzer] Suspicious keyword found in domain structure. (+25 risk)");
        }
        
        if (SUSPICIOUS_WORDS.matcher(path).find()) {
            report.addScore(15);
            report.addDetail("[KeywordAnalyzer] Suspicious keyword found in URI path. (+15 risk)");
        }
    }
}
