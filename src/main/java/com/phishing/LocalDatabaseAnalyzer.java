package com.phishing;

/**
 * Analyzer that checks URLs against the local SQLite threat database.
 * Runs offline — no internet required. Checks the domain (and parent domains)
 * against known phishing, malware, and scam entries.
 */
public class LocalDatabaseAnalyzer implements Analyzer {

    @Override
    public void analyze(UrlTarget target, RiskReport report) {
        String host = target.getHost();
        if (host == null || host.isEmpty()) return;

        try {
            ThreatDatabase db = ThreatDatabase.getInstance();
            String threatType = db.checkDomain(host);

            if (threatType != null) {
                switch (threatType) {
                    case "PHISHING":
                        report.addScore(70);
                        report.addDetail("[Local DB Entries] Domain '" + host + "' found in local phishing database! (+70 risk)");
                        break;
                    case "MALWARE":
                        report.addScore(80);
                        report.addDetail("[Local DB Entries] Domain '" + host + "' flagged as malware distribution! (+80 risk)");
                        break;
                    case "SCAM":
                        report.addScore(60);
                        report.addDetail("[Local DB Entries] Domain '" + host + "' flagged as known scam! (+60 risk)");
                        break;
                    default:
                        report.addScore(50);
                        report.addDetail("[Local DB Entries] Domain '" + host + "' found in local threat database (" + threatType + "). (+50 risk)");
                }
            }
        } catch (Exception e) {
            System.out.println("[LocalDatabaseAnalyzer] Error: " + e.getMessage());
            // Fail silently — don't block the scan if DB is unavailable
        }
    }
}
