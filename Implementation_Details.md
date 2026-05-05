# Architecture & Implementation Details

Technical reference for contributors and the curious. For usage, see [README.md](README.md).

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Java 11 |
| UI Framework | Swing + [FlatLaf 3.4](https://www.formdev.com/flatlaf/) (dark theme) |
| Build | Maven, packaged as a fat JAR via `maven-shade-plugin` |
| Local Database | SQLite (via JDBC, file-based -- no server needed) |
| Encryption | `javax.crypto` AES-128 |
| External APIs | VirusTotal, Google Safe Browsing, PhishTank (all optional except VT) |

---

## High-Level Flow

```
Clipboard Copy
     |
     v
ClipboardMonitor (daemon thread, polls every 500ms)
     |
     |-- extracts URLs via regex (Unicode-aware for IDN support)
     |-- deduplicates + hashes to skip already-seen content
     |
     v
DetectionEngine (singleton)
     |
     |-- 1. UnshortenAnalyzer runs first (resolves redirects)
     |-- 2. Trusted domain check -- if matched, skip heuristics
     |-- 3. Remaining 8 analyzers run in parallel via Stream.parallel()
     |
     v
RiskReport (thread-safe accumulator)
     |
     |-- score (AtomicInteger) aggregated from all analyzers
     |-- thresholded -> SAFE / SUSPICIOUS / MALICIOUS
     |
     v
NotificationPopup (shown on EDT)
```

---

## Package Overview

All classes live under `com.phishing`. There are no sub-packages -- it's a flat structure.

### Core Engine

| Class | Role |
|---|---|
| `DetectionEngine` | Singleton orchestrator. Registers analyzers, runs the pipeline, applies thresholds. |
| `Analyzer` | Interface -- single method: `void analyze(UrlTarget, RiskReport)` |
| `UrlTarget` | Mutable wrapper around a URL. Tracks original vs. resolved (unshortened) URL, parsed host/path. Handles IDN domains by converting Unicode hostnames to punycode for URI parsing while preserving the original Unicode form for homoglyph analysis. |
| `RiskReport` | Thread-safe result accumulator. Uses `CopyOnWriteArrayList` for details and `AtomicInteger` for score. |
| `AnalysisResult` | Enum: `SAFE`, `SUSPICIOUS`, `MALICIOUS` |
| `ConfigConstants` | All magic numbers centralized -- thresholds, intervals, sizes. |

### Analyzers (all implement `Analyzer`)

| Analyzer | Score Weight | Notes |
|---|---|---|
| `UnshortenAnalyzer` | -- | Runs **sequentially first**. Follows HTTP redirects to resolve the final URL for downstream analyzers. |
| `LocalDatabaseAnalyzer` | 100 | Checks against a pre-seeded SQLite database of ~90 known phishing/malware/scam domains. |
| `LengthAnalyzer` | 15 | Flags domains > 30 chars. |
| `CharacterAnalyzer` | 45 | Detects IP-based URLs and malformed URIs. |
| `KeywordAnalyzer` | 10/keyword | Scans for phishing-associated terms (`login`, `verify`, `secure`, etc.) in the URL. |
| `TyposquattingAnalyzer` | 40 | Levenshtein distance comparison against major brand domains. |
| `HomoglyphAnalyzer` | 50 | Detects IDN homograph attacks where Unicode lookalike characters impersonate ASCII letters (e.g., Cyrillic "a" in `apple.com`). Includes 70+ confusable character mappings across Cyrillic, Greek, and Latin-extended scripts. Checks against 40+ high-value brand domains. Also detects mixed-script domains and punycode-encoded URLs. |
| `WhoisAnalyzer` | 30 | RDAP lookup -- flags domains registered within the last 30 days. |
| `ReputationAnalyzer` | varies | Delegates to API clients. Also runs for trusted domains. |

### Risk Thresholds

Defined in `ConfigConstants`:

| Verdict | Score Range |
|---|---|
| Safe | 0 -- 39 |
| Suspicious | 40 -- 74 |
| Malicious | 75+ |

### API Clients

| Class | API | Auth |
|---|---|---|
| `VirusTotalClient` | VirusTotal v3 | API key (required) |
| `GoogleSafeBrowsingClient` | Safe Browsing v4 | API key (optional) |
| `PhishTankClient` | PhishTank | API key (optional) |

All clients extend/use `NetworkClient` for shared HTTP logic.

### UI

| Class | Description |
|---|---|
| `DashboardWindow` | Main `JFrame` with a tabbed pane (Home, Batch, History, Settings). Singleton -- tray icon opens this. Includes a real-time protection status indicator in the sidebar with animated pulsing for active state. |
| `HomePanel` | Manual URL input + scan trigger + inline result display. |
| `BatchPanel` | Textarea for multiple URLs, parallel scanning with progress bar. |
| `HistoryPanel` | Table of past scans. Supports live text search across URL and result columns, source filtering via dropdown, and CSV export. Both filters combine via `RowFilter.andFilter()`. |
| `SettingsPanel` | API key entry, clipboard toggle, active provider selector. |
| `NotificationPopup` | Slide-in popup for single-URL clipboard results. |
| `BatchNotificationPopup` | Compact popup for multi-URL clipboard detections. |
| `StartupNotificationPopup` | One-time "PhishGuard is running" toast on launch. |
| `DetailsWindow` | Expanded risk breakdown view per scan. |
| `UITheme` | Centralized color palette, fonts, and styled component factory methods. |

### Infrastructure

| Class | Role |
|---|---|
| `Main` | Entry point. Acquires single-instance file lock, starts clipboard thread, sets up system tray. |
| `SecurityUtils` | AES-128 key encryption/decryption, UI sanitization (anti-Swing HTML injection), URL defanging, CSV injection prevention. |
| `SettingsManager` | Reads/writes `settings.properties`. Auto-encrypts API keys on save. |
| `HistoryManager` | Appends scan results to `scan_history.csv`. |
| `ThreatDatabase` | SQLite singleton. Manages `known_threats` table + `scan_cache` table with TTL-based expiry. |

---

## URL Regex & IDN Support

The URL extraction regex in both `HomePanel` and `ClipboardMonitor` uses `\p{L}` (Unicode letter property) instead of `[a-zA-Z]` in the domain character class. This ensures URLs containing non-ASCII characters (e.g., Cyrillic, Greek) are correctly extracted and passed to the detection pipeline.

`UrlTarget` handles IDN domains by:
1. Extracting the hostname from the raw URL string
2. Detecting non-ASCII characters in the hostname
3. Converting to punycode via `IDN.toASCII()` for `java.net.URI` compatibility
4. Preserving the original Unicode hostname via `getUnicodeHost()` for `HomoglyphAnalyzer`

This two-layer approach ensures network-facing analyzers (WHOIS, Reputation) use the standards-compliant punycode form, while the homoglyph analyzer can compare against the original Unicode characters.

---

## Key Design Decisions

### Why clipboard polling instead of a listener?
Java's `ClipboardOwner` / `FlavorListener` approach is fragile across platforms and LAF changes. Polling at 500ms is reliable and has negligible CPU cost. Content is SHA-256 hashed to avoid reprocessing.

### Why a flat package structure?
For a project of this size (~35 classes), sub-packages add navigation overhead without meaningful separation. The naming convention (`*Analyzer`, `*Panel`, `*Client`) provides enough grouping.

### Why `Stream.parallel()` instead of an executor pool?
The common fork-join pool is sufficient here -- analyzers are I/O-bound (network calls) and short-lived. A custom pool would be warranted if we needed backpressure or priority scheduling, but we don't.

### Why AES-ECB for key encryption?
This is obfuscation-grade protection, not vault-grade. The threat model is "someone reads the properties file on the same machine." The key is derived from `user.name + os.name`, so the encrypted value is useless on another machine. ECB is fine for single-block payloads (API keys are < 16 bytes of entropy after hashing).

### Why SQLite for the threat database?
Zero-config, file-based, no server process, ships with the JAR. The dataset is small (~100 entries) and read-heavy -- SQLite handles this trivially with indexed lookups.

---

## File Artifacts (Runtime)

These are created at runtime in the working directory and are all gitignored:

| File | Purpose |
|---|---|
| `settings.properties` | User configuration + encrypted API keys |
| `threat_database.db` | SQLite threat DB (auto-seeded on first run) |
| `scan_history.csv` | Persistent scan log |
| `clipboard_debug.log` | Debug log with 5MB rotation |
| `phishguard.lock` | Single-instance file lock |
