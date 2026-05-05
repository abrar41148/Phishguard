package com.phishing;

import java.net.IDN;
import java.net.URI;
import java.net.URISyntaxException;

public class UrlTarget {
    private final String originalUrl;
    private URI originalUri;

    // Mutably tracks the end-destination URL if hidden behind redirectors
    private String resolvedUrl;
    private URI resolvedUri;

    /**
     * Stores the original Unicode hostname for IDN/homoglyph analysis.
     * For normal ASCII domains, this equals getHost().
     * For IDN domains like "kаggle.com" (Cyrillic а), this preserves the
     * Unicode form while getHost() returns the punycode form (xn--...).
     */
    private String unicodeHost;
    
    private boolean isMalformed;

    public UrlTarget(String originalUrl) {
        this.originalUrl = originalUrl == null ? "" : originalUrl.trim();
        this.resolvedUrl = this.originalUrl;

        // Try to handle IDN domains with non-ASCII characters.
        // java.net.URI rejects non-ASCII hostnames, so we convert to punycode first.
        String processedUrl = this.resolvedUrl;
        try {
            String rawHost = extractHostFromUrl(processedUrl);
            if (rawHost != null && !isAscii(rawHost)) {
                this.unicodeHost = rawHost.toLowerCase();
                String punycodeHost = IDN.toASCII(rawHost);
                processedUrl = processedUrl.replace(rawHost, punycodeHost);
            }
        } catch (Exception e) {
            // IDN conversion failed — will fall through to regular parsing
        }

        try {
            this.originalUri = new URI(processedUrl);
            this.resolvedUri = this.originalUri;
        } catch (URISyntaxException e) {
            this.isMalformed = true;
            // Last resort: try to extract host from the raw URL string
            if (this.unicodeHost == null) {
                String fallback = extractHostFromUrl(this.originalUrl);
                if (fallback != null) this.unicodeHost = fallback.toLowerCase();
            }
        }

        // For normal ASCII domains, unicodeHost defaults to parsed host
        if (this.unicodeHost == null) {
            this.unicodeHost = getHost();
        }
    }

    public void setResolvedUrl(String target) {
        this.resolvedUrl = target;

        // Apply the same IDN handling for resolved URLs
        String processedUrl = target;
        try {
            String rawHost = extractHostFromUrl(processedUrl);
            if (rawHost != null && !isAscii(rawHost)) {
                this.unicodeHost = rawHost.toLowerCase();
                String punycodeHost = IDN.toASCII(rawHost);
                processedUrl = processedUrl.replace(rawHost, punycodeHost);
            }
        } catch (Exception ignored) {}

        try {
            this.resolvedUri = new URI(processedUrl);
            this.isMalformed = false;
        } catch (URISyntaxException e) {
            this.isMalformed = true;
        }

        if (this.unicodeHost == null) {
            this.unicodeHost = getHost();
        }
    }

    public String getOriginalUrl() { return originalUrl; }
    
    public String getResolvedUrl() { return resolvedUrl; }

    public URI getResolvedUri() { return resolvedUri; }
    
    public boolean isMalformed() { return isMalformed; }

    public String getHost() {
        return resolvedUri != null && resolvedUri.getHost() != null ? resolvedUri.getHost() : "";
    }
    
    public String getPath() {
        return resolvedUri != null && resolvedUri.getPath() != null ? resolvedUri.getPath() : "";
    }

    /**
     * Returns the original Unicode hostname, preserving non-ASCII characters.
     * Use this for homoglyph/IDN analysis instead of getHost() which returns punycode.
     * For normal ASCII domains, this is identical to getHost().
     */
    public String getUnicodeHost() {
        return unicodeHost != null ? unicodeHost : getHost();
    }

    /**
     * Extracts the hostname from a URL string using basic string parsing.
     * Handles: protocol, userinfo, port, path, query.
     * Used as fallback when java.net.URI can't parse non-ASCII domains.
     */
    private String extractHostFromUrl(String url) {
        if (url == null || url.isEmpty()) return null;
        String work = url;

        // Remove protocol (http://, https://)
        int protoEnd = work.indexOf("://");
        if (protoEnd >= 0) {
            work = work.substring(protoEnd + 3);
        }

        // Remove userinfo (user:pass@)
        int atSign = work.indexOf('@');
        if (atSign >= 0) {
            work = work.substring(atSign + 1);
        }

        // Remove path and query
        int pathStart = work.indexOf('/');
        if (pathStart >= 0) work = work.substring(0, pathStart);
        int queryStart = work.indexOf('?');
        if (queryStart >= 0) work = work.substring(0, queryStart);
        int fragStart = work.indexOf('#');
        if (fragStart >= 0) work = work.substring(0, fragStart);

        // Remove port (:8080)
        int portStart = work.lastIndexOf(':');
        if (portStart >= 0) {
            // Make sure everything after : is digits (not part of IPv6)
            String afterColon = work.substring(portStart + 1);
            if (afterColon.matches("\\d+")) {
                work = work.substring(0, portStart);
            }
        }

        return work.isEmpty() ? null : work;
    }

    /** Returns true if the string contains only ASCII characters (0-127) */
    private boolean isAscii(String str) {
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) > 127) return false;
        }
        return true;
    }
}
