package com.phishing;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class DetectionEngine {
    private final List<Analyzer> analyzers;
    private static volatile DetectionEngine instance;

    /**
     * Well-known trusted root domains. When matched, heuristic analyzers
     * are skipped entirely — only the API reputation check runs.
     * This prevents false positives on legit sites like YouTube, Google, etc.
     */
    private static final Set<String> TRUSTED_DOMAINS = new HashSet<>(Arrays.asList(
        "google.com", "youtube.com", "youtu.be", "gmail.com",
        "microsoft.com", "live.com", "outlook.com", "bing.com", "office.com",
        "apple.com", "icloud.com",
        "amazon.com", "aws.amazon.com",
        "facebook.com", "instagram.com", "whatsapp.com", "meta.com",
        "twitter.com", "x.com",
        "linkedin.com",
        "reddit.com",
        "github.com", "gitlab.com",
        "stackoverflow.com",
        "wikipedia.org", "wikimedia.org",
        "netflix.com", "spotify.com", "discord.com", "twitch.tv",
        "zoom.us", "slack.com", "dropbox.com",
        "cloudflare.com", "wordpress.com", "medium.com"
    ));

    private DetectionEngine() {
        this.analyzers = new ArrayList<>();
        // Registering our polymorphic modules (Order matters: Resolvers first!)
        analyzers.add(new UnshortenAnalyzer());
        
        analyzers.add(new LocalDatabaseAnalyzer()); // Local threat DB (offline, instant)
        analyzers.add(new LengthAnalyzer());
        analyzers.add(new CharacterAnalyzer());
        analyzers.add(new KeywordAnalyzer());
        analyzers.add(new TyposquattingAnalyzer());
        analyzers.add(new HomoglyphAnalyzer());
        analyzers.add(new WhoisAnalyzer());
        analyzers.add(new ReputationAnalyzer());
    }

    /**
     * Returns the singleton instance of the DetectionEngine.
     * Lazy initialization with double-checked locking pattern.
     */
    public static DetectionEngine getInstance() {
        if (instance == null) {
            synchronized (DetectionEngine.class) {
                if (instance == null) {
                    instance = new DetectionEngine();
                }
            }
        }
        return instance;
    }

    public RiskReport analyze(String rawUrl) {
        UrlTarget target = new UrlTarget(rawUrl);
        RiskReport report = new RiskReport(AnalysisResult.SAFE, "Aggregated Engine");

        // Execute UnshortenAnalyzer first because other analyzers depend on its resolved URL
        long start1 = System.currentTimeMillis();
        analyzers.get(0).analyze(target, report);
        long end1 = System.currentTimeMillis();
        System.out.println("[Benchmark] UnshortenAnalyzer took " + (end1 - start1) + "ms");

        // Check if the resolved domain is trusted
        boolean isTrusted = isTrustedDomain(target.getHost());
        if (isTrusted) {
            System.out.println("[DetectionEngine] Trusted domain detected: " + target.getHost() + " — skipping heuristics.");
            report.addDetail("[TrustedDomain] '" + target.getHost() + "' is a known trusted domain. Heuristic checks skipped.");
            
            // Only run ReputationAnalyzer (API check) for trusted domains
            long stRep = System.currentTimeMillis();
            analyzers.get(analyzers.size() - 1).analyze(target, report); // Last one = ReputationAnalyzer
            System.out.println("[Benchmark] ReputationAnalyzer took " + (System.currentTimeMillis() - stRep) + "ms");
        } else {
            // Execute the rest in parallel
            long start2 = System.currentTimeMillis();
            analyzers.stream()
                    .skip(1)
                    .parallel()
                    .forEach(analyzer -> {
                        long st = System.currentTimeMillis();
                        analyzer.analyze(target, report);
                        System.out.println("[Benchmark] " + analyzer.getClass().getSimpleName() + " took " + (System.currentTimeMillis() - st) + "ms");
                    });
            System.out.println("[Benchmark] Parallel heuristics took " + (System.currentTimeMillis() - start2) + "ms");
        }

        // Resolve risk score into severity threshold
        int score = report.getScore();
        if (score >= ConfigConstants.RISK_THRESHOLD_MALICIOUS) {
            report.setResult(AnalysisResult.MALICIOUS);
            report.addDetail("OVERALL SEVERITY: MALICIOUS (Risk Score: " + score + " / Threshold: " + ConfigConstants.RISK_THRESHOLD_MALICIOUS + "+)");
        } else if (score >= ConfigConstants.RISK_THRESHOLD_SUSPICIOUS) {
            report.setResult(AnalysisResult.SUSPICIOUS);
            report.addDetail("OVERALL SEVERITY: SUSPICIOUS (Risk Score: " + score + " / Threshold: " + ConfigConstants.RISK_THRESHOLD_SUSPICIOUS + "-" + (ConfigConstants.RISK_THRESHOLD_MALICIOUS - 1) + ")");
        } else {
            report.setResult(AnalysisResult.SAFE);
            report.addDetail("OVERALL SEVERITY: SAFE (Risk Score: " + score + " / Threshold: < " + ConfigConstants.RISK_THRESHOLD_SUSPICIOUS + ")");
        }

        return report;
    }

    /**
     * Checks if the given host belongs to a trusted root domain.
     * Handles subdomains (e.g. www.youtube.com, music.youtube.com).
     */
    private boolean isTrustedDomain(String host) {
        if (host == null || host.isEmpty()) return false;
        host = host.toLowerCase();
        // Direct match
        if (TRUSTED_DOMAINS.contains(host)) return true;
        // Subdomain match (e.g., www.youtube.com → youtube.com)
        for (String trusted : TRUSTED_DOMAINS) {
            if (host.endsWith("." + trusted)) return true;
        }
        return false;
    }
}

