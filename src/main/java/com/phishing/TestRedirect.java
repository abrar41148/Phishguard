package com.phishing;

public class TestRedirect {
    public static void main(String[] args) {
        UrlTarget target = new UrlTarget("bit.ly/3uH6hO6");
        RiskReport report = new RiskReport(AnalysisResult.SAFE, "Test");
        RedirectAnalyzer analyzer = new RedirectAnalyzer();
        analyzer.analyze(target, report);
        
        System.out.println("Details: " + report.getDetails());
    }
}
