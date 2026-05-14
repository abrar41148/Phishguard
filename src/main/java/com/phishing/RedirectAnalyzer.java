package com.phishing;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashSet;
import java.util.Set;

/**
 * Analyzes the HTTP redirect chain of a URL.
 * Flags excessive hops, cross-domain redirects, and redirects to IP addresses.
 * Also resolves the final destination URL for subsequent analyzers.
 */
public class RedirectAnalyzer implements Analyzer {

    private final HttpClient httpClient;
    private static final int MAX_HOPS = 10;

    public RedirectAnalyzer() {
        this.httpClient = NetworkClient.getUnshortenerInstance();
    }

    @Override
    public void analyze(UrlTarget target, RiskReport report) {
        String currentUrl = target.getOriginalUrl();
        if (!currentUrl.startsWith("http://") && !currentUrl.startsWith("https://")) {
            currentUrl = "http://" + currentUrl;
        }
        String originalHost = target.getHost();
        
        Set<String> visitedUrls = new HashSet<>();
        visitedUrls.add(currentUrl);

        int redirectCount = 0;
        int meaningfulRedirectCount = 0;
        boolean crossDomainDetected = false;
        boolean ipRedirectDetected = false;

        try {
            while (redirectCount < MAX_HOPS) {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(currentUrl))
                        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                        .timeout(Duration.ofSeconds(5))
                        .GET()
                        .build();

                HttpResponse<Void> response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
                int status = response.statusCode();

                // 3xx status codes indicate redirects
                if (status >= 300 && status <= 399) {
                    String location = response.headers().firstValue("Location").orElse(null);
                    if (location == null || location.isEmpty()) {
                        break;
                    }

                    // Handle relative redirects
                    if (!location.startsWith("http")) {
                        URI currentUri = URI.create(currentUrl);
                        if (location.startsWith("/")) {
                            location = currentUri.getScheme() + "://" + currentUri.getAuthority() + location;
                        } else {
                            // Simple relative path
                            String path = currentUri.getPath();
                            int lastSlash = path.lastIndexOf('/');
                            String base = path.substring(0, lastSlash + 1);
                            location = currentUri.getScheme() + "://" + currentUri.getAuthority() + base + location;
                        }
                    }

                    // Detect circular redirects
                    if (visitedUrls.contains(location)) {
                        report.addDetail("[RedirectAnalyzer] Circular redirect detected at: " + location);
                        report.addScore(20); // Suspicious behavior
                        break;
                    }
                    visitedUrls.add(location);

                    URI nextUri = new URI(location);
                    String nextHost = nextUri.getHost();

                    // Check for cross-domain redirect
                    if (nextHost != null && !isSameRegisteredDomain(originalHost, nextHost)) {
                        crossDomainDetected = true;
                    }

                    // Check for redirect to IP address
                    if (nextHost != null && isIpAddress(nextHost)) {
                        ipRedirectDetected = true;
                    }

                    if (!isBenignRedirect(currentUrl, location)) {
                        meaningfulRedirectCount++;
                    }

                    currentUrl = location;
                    redirectCount++;
                } else {
                    // Not a redirect status
                    break;
                }
            }

            // Record findings
            target.setResolvedUrl(currentUrl); // Always set resolved URL, even if only benign redirects occurred

            if (meaningfulRedirectCount > 0) {
                report.addDetail("[RedirectAnalyzer] Followed " + meaningfulRedirectCount + " redirect(s). Final destination: " + currentUrl);
                
                if (meaningfulRedirectCount >= 3) {
                    report.addScore(ConfigConstants.SCORE_EXCESSIVE_REDIRECTS);
                    report.addDetail("[RedirectAnalyzer] Excessive redirect chain length: " + meaningfulRedirectCount + " hops.");
                }

                if (crossDomainDetected) {
                    report.addScore(ConfigConstants.SCORE_CROSS_DOMAIN_REDIRECT);
                    report.addDetail("[RedirectAnalyzer] Cross-domain redirect detected (potential evasion/phishing).");
                }

                if (ipRedirectDetected) {
                    report.addScore(ConfigConstants.SCORE_REDIRECT_TO_IP);
                    report.addDetail("[RedirectAnalyzer] Redirect to raw IP address detected: " + currentUrl);
                }
            } else {
                report.addDetail("[RedirectAnalyzer] No redirects detected.");
            }

        } catch (Exception e) {
            // If it fails mid-way, we still update the resolved URL to the last successful one
            String orig = target.getOriginalUrl();
            if (!currentUrl.equals(orig) && !currentUrl.equals("http://" + orig) && !currentUrl.equals("https://" + orig)) {
                target.setResolvedUrl(currentUrl);
                report.addDetail("[RedirectAnalyzer] Trace interrupted: " + e.getMessage());
            } else {
                report.addDetail("[RedirectAnalyzer] No redirects detected. (Trace failed: " + e.getMessage() + ")");
            }
        }
    }

    /**
     * Crude check for same registered domain (e.g., mail.google.com and google.com are same).
     * This is a simplified version; for production, a Public Suffix List should be used.
     */
    private boolean isSameRegisteredDomain(String host1, String host2) {
        if (host1 == null || host2 == null) return false;
        if (host1.equalsIgnoreCase(host2)) return true;

        String[] parts1 = host1.split("\\.");
        String[] parts2 = host2.split("\\.");

        if (parts1.length < 2 || parts2.length < 2) return false;

        // Compare last two parts (e.g., example.com)
        String domain1 = parts1[parts1.length - 2] + "." + parts1[parts1.length - 1];
        String domain2 = parts2[parts2.length - 2] + "." + parts2[parts2.length - 1];

        return domain1.equalsIgnoreCase(domain2);
    }

    private boolean isIpAddress(String host) {
        if (host == null) return false;
        // Basic IPv4 check
        return host.matches("^(\\d{1,3}\\.){3}\\d{1,3}$") || host.contains(":"); // Simple IPv6 check
    }

    /**
     * Determines if a redirect is benign (e.g., http -> https, adding www., trailing slash).
     */
    private boolean isBenignRedirect(String fromUrl, String toUrl) {
        if (fromUrl == null || toUrl == null) return false;

        // Normalize trailing slashes
        String from = fromUrl.endsWith("/") ? fromUrl.substring(0, fromUrl.length() - 1) : fromUrl;
        String to = toUrl.endsWith("/") ? toUrl.substring(0, toUrl.length() - 1) : toUrl;

        if (from.equalsIgnoreCase(to)) return true;

        String fromScheme = from.startsWith("https://") ? "https://" : (from.startsWith("http://") ? "http://" : "");
        String toScheme = to.startsWith("https://") ? "https://" : (to.startsWith("http://") ? "http://" : "");
        
        String fromRest = from.substring(fromScheme.length());
        String toRest = to.substring(toScheme.length());

        // Ignore www. addition/removal
        fromRest = fromRest.replaceFirst("^www\\.", "");
        toRest = toRest.replaceFirst("^www\\.", "");

        // If the remaining URL is exactly the same, it's just a protocol or www upgrade
        if (fromRest.equalsIgnoreCase(toRest)) {
            // Only allow http -> https upgrade or keeping the same protocol. 
            // A downgrade (https -> http) is NOT benign.
            return !fromScheme.equals("https://") || toScheme.equals("https://");
        }

        return false;
    }
}
