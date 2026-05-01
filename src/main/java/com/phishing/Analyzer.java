package com.phishing;

public interface Analyzer {
    /**
     * Analyzes the target URL and appropriately adds risk score and details to the report.
     */
    void analyze(UrlTarget target, RiskReport report);
}
