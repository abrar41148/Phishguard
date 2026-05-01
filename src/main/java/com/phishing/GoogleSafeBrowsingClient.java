package com.phishing;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class GoogleSafeBrowsingClient implements ThreatProvider {
    // Requires an API key via Google Cloud Developer Console
    private static final String API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=";
    private final HttpClient httpClient;

    public GoogleSafeBrowsingClient() {
        this.httpClient = NetworkClient.getInstance();
    }

    @Override
    public RiskReport checkUrl(String url) {
        String apiKey = SettingsManager.getInstance().getProperty("GOOGLE_SAFE_BROWSING_KEY");
        if (apiKey.isEmpty() || apiKey.equals("YOUR_API_KEY_HERE")) {
            RiskReport report = new RiskReport(AnalysisResult.SAFE, "Google Safe Browsing (Placeholder)");
            report.addDetail("No Google Safe Browsing API Key configured. Passed through as SAFE.");
            return report;
        }

        try {
            // Manual JSON building to avoid external dependencies like Gson or Jackson
            String safeUrl = url.replace("\"", "\\\""); // escape quotes
            String payload = "{"
              + "\"client\": {\"clientId\": \"phishing-detector\", \"clientVersion\": \"1.0\"},"
              + "\"threatInfo\": {"
              + "\"threatTypes\": [\"MALWARE\", \"SOCIAL_ENGINEERING\", \"UNWANTED_SOFTWARE\"],"
              + "\"platformTypes\": [\"ANY_PLATFORM\"],"
              + "\"threatEntryTypes\": [\"URL\"],"
              + "\"threatEntries\": [{\"url\": \"" + safeUrl + "\"}]"
              + "}}";

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(API_URL + apiKey))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(payload))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                String body = response.body();
                // A clean response is just an empty JSON object {}
                if (body.contains("matches")) {
                    RiskReport report = new RiskReport(AnalysisResult.MALICIOUS, "Google Safe Browsing API");
                    report.addDetail("Detected as Malicious by Google Safe Browsing.");
                    if(body.contains("SOCIAL_ENGINEERING")) report.addDetail("Flagged explicitly as Social Engineering (Phishing).");
                    if(body.contains("MALWARE")) report.addDetail("Flagged explicitly as Malware Distribution.");
                    return report;
                } else {
                    RiskReport report = new RiskReport(AnalysisResult.SAFE, "Google Safe Browsing API");
                    report.addDetail("URL not found in Google's threat databases.");
                    return report;
                }
            } else {
                 RiskReport errorReport = new RiskReport(AnalysisResult.SUSPICIOUS, "Google Safe Browsing API (Error)");
                 errorReport.addDetail("API Error: HTTP Status " + response.statusCode());
                 return errorReport;
            }

        } catch (Exception e) {
            System.out.println("Error with Google Safe Browsing API: " + e.getMessage());
        }

        RiskReport failReport = new RiskReport(AnalysisResult.SUSPICIOUS, "Google Safe Browsing API (Fail)");
        failReport.addDetail("Failed to scan due to network exception. Defaulting to SUSPICIOUS for safety.");
        return failReport;
    }
}
