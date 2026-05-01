package com.phishing;

import java.util.ArrayList;
import java.util.List;

public class RiskReport {
    private volatile AnalysisResult result;
    private String source;
    private java.util.concurrent.CopyOnWriteArrayList<String> details;
    private java.util.concurrent.atomic.AtomicInteger score;

    public RiskReport(AnalysisResult result, String source) {
        this.result = result;
        this.source = source;
        this.details = new java.util.concurrent.CopyOnWriteArrayList<>();
        this.score = new java.util.concurrent.atomic.AtomicInteger(0);
    }

    public void addDetail(String detail) {
        details.add(detail);
    }
    
    public void addScore(int delta) {
        this.score.addAndGet(delta);
    }

    public void setResult(AnalysisResult result) {
        this.result = result;
    }

    public AnalysisResult getResult() {
        return result;
    }

    public String getSource() {
        return source;
    }

    public List<String> getDetails() {
        return details;
    }
    
    public int getScore() {
        return score.get();
    }
}
