package com.phishing;

public interface ThreatProvider {
    RiskReport checkUrl(String url);
}
