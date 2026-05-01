package com.phishing;

public class LengthAnalyzer implements Analyzer {
    @Override
    public void analyze(UrlTarget target, RiskReport report) {
        String host = target.getHost();
        String url = target.getResolvedUrl();

        if (host.length() > 40) {
            report.addScore(15);
            report.addDetail("[LengthAnalyzer] Unusually long domain (" + host.length() + " chars). (+15 risk)");
        }

        if (url.length() > 100) {
            report.addScore(10);
            report.addDetail("[LengthAnalyzer] Overly long URL (" + url.length() + " chars). (+10 risk)");
        }
        
        long dotCount = host.chars().filter(ch -> ch == '.').count();
        if (dotCount > 3) {
            report.addScore(20);
            report.addDetail("[LengthAnalyzer] High number of subdomains (" + dotCount + "). (+20 risk)");
        }
    }
}
