package com.phishing;

import java.net.URI;
import java.net.URISyntaxException;

public class UrlTarget {
    private final String originalUrl;
    private URI originalUri;

    // Mutably tracks the end-destination URL if hidden behind redirectors
    private String resolvedUrl;
    private URI resolvedUri;
    
    private boolean isMalformed;

    public UrlTarget(String originalUrl) {
        this.originalUrl = originalUrl == null ? "" : originalUrl.trim();
        this.resolvedUrl = this.originalUrl;
        try {
            this.originalUri = new URI(this.originalUrl);
            this.resolvedUri = this.originalUri;
        } catch (URISyntaxException e) {
            this.isMalformed = true;
        }
    }

    public void setResolvedUrl(String target) {
        this.resolvedUrl = target;
        try {
            this.resolvedUri = new URI(target);
            this.isMalformed = false;
        } catch (URISyntaxException e) {
            this.isMalformed = true;
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
}
