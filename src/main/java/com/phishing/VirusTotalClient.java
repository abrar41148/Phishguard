package com.phishing;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VirusTotalClient implements ThreatProvider {
    private static final String API_URL = "https://www.virustotal.com/api/v3/urls/";
    private final HttpClient httpClient;

    // Thresholds: how many vendors must flag a URL before we consider it malicious/suspicious
    private static final int MALICIOUS_THRESHOLD = ConfigConstants.VT_MALICIOUS_THRESHOLD;   // 3+ vendors = MALICIOUS
    private static final int SUSPICIOUS_THRESHOLD = ConfigConstants.VT_SUSPICIOUS_THRESHOLD;   // 2 vendors = SUSPICIOUS (1 alone is noise)

    public VirusTotalClient() {
        this.httpClient = NetworkClient.getInstance();
    }

    @Override
    public RiskReport checkUrl(String url) {
        String apiKey = SettingsManager.getInstance().getProperty("VIRUS_TOTAL_KEY");
        if (apiKey.isEmpty() || apiKey.equals("YOUR_API_KEY_HERE")) {
            RiskReport report = new RiskReport(AnalysisResult.SAFE, "VirusTotal API (Placeholder)");
            report.addDetail("No API Key configured in Settings. Passed through as SAFE.");
            return report;
        }

        try {
            String encodedUrl = Base64.getUrlEncoder().withoutPadding().encodeToString(url.getBytes());
            
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(API_URL + encodedUrl))
                    .header("accept", "application/json")
                    .header("x-apikey", apiKey)
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                String body = response.body();
                return parseVtResponse(body);
            } else if (response.statusCode() == 404) {
                 RiskReport report = new RiskReport(AnalysisResult.SAFE, "VirusTotal API");
                 report.addDetail("URL not found in threat database (Likely clean or un-analyzed).");
                 return report;
            } else {
                System.out.println("API Request failed with status code " + response.statusCode());
                RiskReport errorReport = new RiskReport(AnalysisResult.SUSPICIOUS, "VirusTotal API (Error)");
                errorReport.addDetail("API Error: HTTP Status " + response.statusCode());
                return errorReport;
            }

        } catch (Exception e) {
            System.out.println("Error communicating with VirusTotal API: " + e.getMessage());
        }
        
        RiskReport report = new RiskReport(AnalysisResult.SUSPICIOUS, "VirusTotal API (Error)");
        report.addDetail("Failed to scan URL due to network exception. Defaulting to SUSPICIOUS for safety.");
        return report;
    }

    /**
     * Parses the VirusTotal API v3 response using regex to extract
     * last_analysis_stats counts. Uses vendor count thresholds instead
     * of naive string matching to avoid false positives from rogue vendors.
     */
    private RiskReport parseVtResponse(String body) {
        try {
            // Extract the last_analysis_stats block
            // Format: "last_analysis_stats": {"malicious": N, "suspicious": N, ...}
            int statsIdx = body.indexOf("\"last_analysis_stats\"");
            if (statsIdx == -1) {
                RiskReport report = new RiskReport(AnalysisResult.SAFE, "VirusTotal API");
                report.addDetail("Could not find analysis stats in response.");
                return report;
            }

            // Extract a substring around the stats block
            int braceStart = body.indexOf("{", statsIdx);
            int braceEnd = body.indexOf("}", braceStart);
            if (braceStart == -1 || braceEnd == -1) {
                RiskReport report = new RiskReport(AnalysisResult.SAFE, "VirusTotal API");
                report.addDetail("Malformed analysis stats in API response.");
                return report;
            }
            String statsBlock = body.substring(braceStart, braceEnd + 1);

            int maliciousCount = extractStatValue(statsBlock, "malicious");
            int suspiciousCount = extractStatValue(statsBlock, "suspicious");
            int harmlessCount = extractStatValue(statsBlock, "harmless");
            int undetectedCount = extractStatValue(statsBlock, "undetected");
            int timeoutCount = extractStatValue(statsBlock, "timeout");
            int totalEngines = maliciousCount + suspiciousCount + harmlessCount + undetectedCount + timeoutCount;

            System.out.println("[VirusTotal] Stats: malicious=" + maliciousCount + 
                " suspicious=" + suspiciousCount + " harmless=" + harmlessCount + 
                " undetected=" + undetectedCount + " total=" + totalEngines);

            // Combined threat count
            int threatCount = maliciousCount + suspiciousCount;

            AnalysisResult result;
            if (maliciousCount >= MALICIOUS_THRESHOLD) {
                result = AnalysisResult.MALICIOUS;
            } else if (threatCount >= SUSPICIOUS_THRESHOLD && maliciousCount > 0) {
                result = AnalysisResult.SUSPICIOUS;
            } else {
                result = AnalysisResult.SAFE;
            }

            RiskReport report = new RiskReport(result, "VirusTotal API");

            // Build informative detail string
            report.addDetail(maliciousCount + "/" + totalEngines + " security vendors flagged this URL.");

            if (result == AnalysisResult.MALICIOUS) {
                report.addDetail("Confirmed malicious by " + maliciousCount + " vendors (threshold: " + MALICIOUS_THRESHOLD + "+).");
                if (body.contains("phishing")) report.addDetail("Categorized as: Phishing");
                if (body.contains("malware")) report.addDetail("Categorized as: Malware Downloader");
            } else if (result == AnalysisResult.SUSPICIOUS) {
                report.addDetail("Low-confidence threat: only " + threatCount + " vendor(s) flagged this URL.");
            } else {
                if (maliciousCount == 0 && suspiciousCount == 0) {
                    report.addDetail("0 security vendors flagged this URL as malicious.");
                } else {
                    report.addDetail("Below threshold (" + threatCount + " flag(s), need " + MALICIOUS_THRESHOLD + "+ for malicious). Likely a false positive.");
                }
            }

            return report;

        } catch (Exception e) {
            System.out.println("Error parsing VirusTotal response: " + e.getMessage());
            RiskReport report = new RiskReport(AnalysisResult.SAFE, "VirusTotal API (Parse Error)");
            report.addDetail("Could not parse API response. Defaulting to SAFE.");
            return report;
        }
    }

    /**
     * Extracts an integer value for a given key from a JSON-like stats block.
     * Handles both "key": N and "key" : N formats.
     */
    private int extractStatValue(String statsBlock, String key) {
        // Match: "key" : N  or  "key":N  (with optional whitespace)
        Pattern p = Pattern.compile("\"" + key + "\"\\s*:\\s*(\\d+)");
        Matcher m = p.matcher(statsBlock);
        if (m.find()) {
            return Integer.parseInt(m.group(1));
        }
        return 0;
    }
}
