package com.phishing;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class UnshortenAnalyzer implements Analyzer {

    private final HttpClient httpClient;

    public UnshortenAnalyzer() {
        this.httpClient = NetworkClient.getUnshortenerInstance();
    }

    @Override
    public void analyze(UrlTarget target, RiskReport report) {
        String originalUrl = target.getOriginalUrl();
        
        boolean isLikelyShortener = false;
        String host = target.getHost().toLowerCase();
        
        if (host.contains("bit.ly") || host.contains("tinyurl.com") || host.contains("t.co") 
            || host.contains("goo.gl") || host.contains("is.gd") || host.contains("ow.ly")) {
            isLikelyShortener = true;
        } else if (host.length() <= 15 && target.getPath().length() > 1) {
            isLikelyShortener = true;
        }

        if (!isLikelyShortener) return;

        String currentUrl = originalUrl;
        try {
            int redirectCount = 0;
            
            while (redirectCount < 5) {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(currentUrl))
                        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                        .GET()
                        .build();

                HttpResponse<Void> response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
                int status = response.statusCode();
                
                if (status >= 300 && status <= 399) {
                    String location = response.headers().firstValue("Location").orElse(null);
                    if (location != null && !location.isEmpty()) {
                        if (location.startsWith("http")) {
                            currentUrl = location;
                        } else if (location.startsWith("/")) {
                            URI currentUri = URI.create(currentUrl);
                            currentUrl = currentUri.getScheme() + "://" + currentUri.getHost() + location;
                        } else {
                            break;
                        }
                        redirectCount++;
                        continue;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            
            if (!currentUrl.equals(originalUrl)) {
                target.setResolvedUrl(currentUrl);
                String unshortenedHost = URI.create(currentUrl).getHost();
                report.addDetail("[UnshortenAnalyzer] Unshortened to: " + unshortenedHost);
            }
            
        } catch (Exception e) {
            if (!currentUrl.equals(originalUrl)) {
                target.setResolvedUrl(currentUrl);
                try {
                    String unshortenedHost = URI.create(currentUrl).getHost();
                    report.addDetail("[UnshortenAnalyzer] Traced to masked destination before connection died: " + unshortenedHost);
                } catch (Exception parseEx) {
                    report.addDetail("[UnshortenAnalyzer] Traced to masked destination (malformed): " + currentUrl);
                }
            } else {
                report.addDetail("[UnshortenAnalyzer] Long url, shortening not required.");
            }
        }
    }
}
