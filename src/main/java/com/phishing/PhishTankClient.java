package com.phishing;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

public class PhishTankClient implements ThreatProvider {
    private final HttpClient httpClient;

    public PhishTankClient() {
        this.httpClient = NetworkClient.getInstance();
    }

    @Override
    public RiskReport checkUrl(String url) {
        String apiKey = SettingsManager.getInstance().getProperty("PHISHTANK_KEY"); // Optional on PhishTank but recommended
        
        try {
            String encodedUrl = URLEncoder.encode(url, StandardCharsets.UTF_8.toString());
            String payload = "url=" + encodedUrl + "&format=json";
            if (!apiKey.isEmpty() && !apiKey.equals("YOUR_API_KEY_HERE")) {
                payload += "&app_key=" + apiKey;
            }

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://checkurl.phishtank.com/checkurl/"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("User-Agent", "phishtank/")
                    .POST(HttpRequest.BodyPublishers.ofString(payload))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                String body = response.body();
                // We use simple String manipulation to check if it's explicitly identified as a phish
                if (body.contains("\"in_database\":true") && body.contains("\"valid\":true")) {
                    RiskReport report = new RiskReport(AnalysisResult.MALICIOUS, "PhishTank API");
                    report.addDetail("Actively verified as a Phishing Link in PhishTank database.");
                    return report;
                } else {
                    RiskReport report = new RiskReport(AnalysisResult.SAFE, "PhishTank API");
                    if (body.contains("\"in_database\":false")) {
                        report.addDetail("URL not found in PhishTank database.");
                    } else if (body.contains("\"valid\":false")) {
                        report.addDetail("URL exists but is currently flagged as inactive or invalid.");
                    }
                    return report;
                }
            } else {
                 RiskReport errorReport = new RiskReport(AnalysisResult.SUSPICIOUS, "PhishTank API (Error)");
                 errorReport.addDetail("API request failed. HTTP Status " + response.statusCode());
                 return errorReport;
            }

        } catch (Exception e) {
            System.out.println("Error communicating with PhishTank API: " + e.getMessage());
        }

        RiskReport failReport = new RiskReport(AnalysisResult.SUSPICIOUS, "PhishTank API (Fail)");
        failReport.addDetail("Failed to scan due to network exception. Defaulting to SUSPICIOUS for safety.");
        return failReport;
    }
}
