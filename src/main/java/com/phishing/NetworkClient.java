package com.phishing;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.http.HttpClient;
import java.time.Duration;

public class NetworkClient {
    private static volatile HttpClient instance;
    private static volatile HttpClient unshortenerInstance;

    private NetworkClient() {}

    /**
     * Gets the standard, globally pooled HttpClient used for API queries 
     * (VirusTotal, Google Safe Browsing, PhishTank, Whois).
     */
    public static HttpClient getInstance() {
        if (instance == null) {
            synchronized (NetworkClient.class) {
                if (instance == null) {
                    instance = HttpClient.newBuilder()
                            .connectTimeout(Duration.ofSeconds(10))
                            .followRedirects(HttpClient.Redirect.NORMAL)
                            .build();
                }
            }
        }
        return instance;
    }

    /**
     * Gets a specialized HttpClient built exclusively for the Unshortener Analyzer.
     * It prevents auto-redirects so we can manually inspect Location headers.
     * It also includes a CookieManager to emulate basic browser handshakes.
     */
    public static HttpClient getUnshortenerInstance() {
        if (unshortenerInstance == null) {
            synchronized (NetworkClient.class) {
                if (unshortenerInstance == null) {
                    CookieManager cookieManager = new CookieManager();
                    cookieManager.setCookiePolicy(CookiePolicy.ACCEPT_ALL);
                    
                    unshortenerInstance = HttpClient.newBuilder()
                            .connectTimeout(Duration.ofSeconds(6))
                            .followRedirects(HttpClient.Redirect.NEVER)
                            .cookieHandler(cookieManager)
                            .build();
                }
            }
        }
        return unshortenerInstance;
    }
}
