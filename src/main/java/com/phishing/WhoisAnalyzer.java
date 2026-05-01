package com.phishing;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

public class WhoisAnalyzer implements Analyzer {

    private final HttpClient httpClient;

    public WhoisAnalyzer() {
        this.httpClient = NetworkClient.getInstance();
    }

    @Override
    public void analyze(UrlTarget target, RiskReport report) {
        String host = target.getHost().toLowerCase();
        if (host.isEmpty() || isIpAddress(host)) return;

        // Strip subdomains to get the root domain roughly (e.g. login.paypal.com -> paypal.com)
        String[] parts = host.split("\\.");
        String rootDomain = host;
        if (parts.length >= 2) {
            rootDomain = parts[parts.length - 2] + "." + parts[parts.length - 1];
        }

        try {
            // RDAP (Registration Data Access Protocol) is the modern REST standard replacing WHOIS
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://rdap.org/domain/" + rootDomain))
                    .header("Accept", "application/rdap+json")
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                String body = response.body();
                // Extremely lightweight JSON parsing without imposing external dependencies like Gson mapping
                
                // We look for: "eventAction": "registration", "eventDate": "1999-07-14T04:00:00Z"
                int regIdx = body.indexOf("\"eventAction\":\"registration\"");
                if (regIdx == -1) regIdx = body.indexOf("\"eventAction\": \"registration\"");
                if (regIdx == -1) regIdx = body.indexOf("\"eventAction\" : \"registration\"");

                if (regIdx != -1) {
                    // Start looking for the eventDate around the registration block
                    int dateStart = body.indexOf("\"eventDate\"", regIdx);
                    if (dateStart != -1) {
                        int quote1 = body.indexOf("\"", dateStart + 11);
                        int quote2 = body.indexOf("\"", quote1 + 1);
                        
                        if (quote1 != -1 && quote2 != -1) {
                            String dateStr = body.substring(quote1 + 1, quote2);
                            
                            Instant regDate = Instant.parse(dateStr);
                            Instant now = Instant.now();
                            long daysOld = ChronoUnit.DAYS.between(regDate, now);
                            
                            if (daysOld < 30) {
                                report.addScore(55);
                                report.addDetail("[WhoisAnalyzer] Critical Warning! Domain '" + rootDomain + "' was registered only " + daysOld + " days ago! (+55 risk)");
                            } else if (daysOld < 90) {
                                report.addScore(30);
                                report.addDetail("[WhoisAnalyzer] High Warning! Domain '" + rootDomain + "' is less than 3 months old (" + daysOld + " days). (+30 risk)");
                            }
                        }
                    }
                }
            } else if (response.statusCode() == 404) {
                 report.addScore(25);
                 report.addDetail("[WhoisAnalyzer] Domain RDAP record not found. Could be an unregistered or private spoofed TLD. (+25 risk)");
            }
            
        } catch (Exception e) {
            // Fails gracefully if no internet or RDAP server is unreachable. Just move along.
        }
    }

    private boolean isIpAddress(String host) {
        return host.matches("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$");
    }
}
