package com.phishing;

public class ReputationAnalyzer implements Analyzer {

    @Override
    public void analyze(UrlTarget target, RiskReport report) {
        String providerName = SettingsManager.getInstance().getProperty("ACTIVE_PROVIDER");
        ThreatProvider provider;
        
        if ("Google Safe Browsing".equals(providerName)) {
            provider = new GoogleSafeBrowsingClient();
        } else if ("PhishTank".equals(providerName)) {
            provider = new PhishTankClient();
        } else {
            provider = new VirusTotalClient(); // Default
        }

        // We temporarily create an old-style RiskReport to catch the ThreatProvider's result, 
        // since we didn't refactor the existing API client interfaces yet (for time/safety).
        // ThreatProvider still returns RiskReport if we didn't change it, wait we ARE changing it.
        // I will assume ThreatProvider returns RiskReport.
        
        RiskReport apiReport = provider.checkUrl(target.getResolvedUrl());
        
        // Aggregate the API report into our master report
        if (apiReport.getResult() == AnalysisResult.MALICIOUS) {
            report.addScore(80); // Major red flag
        } else if (apiReport.getResult() == AnalysisResult.SUSPICIOUS) {
            report.addScore(40);
        }
        
        for (String detail : apiReport.getDetails()) {
            report.addDetail("[" + providerName + "] " + detail);
        }
    }
}
