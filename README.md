# 🛡️ PhishGuard — Real-Time Phishing Link Detector

A Java Swing desktop application that silently monitors your clipboard for URLs and instantly analyzes them for phishing, malware, and other threats using a multi-layered detection engine.

## How It Works

PhishGuard runs in the **system tray** and watches your clipboard. When you copy a URL, it automatically runs it through **8 detection modules** in parallel and shows a popup notification with the verdict: **Safe**, **Suspicious**, or **Malicious**.

## Features

- **Clipboard Monitoring** — Automatic real-time URL detection from clipboard
- **Multi-Engine Analysis** — 8 analyzers run in parallel for comprehensive detection:
  | Analyzer | What It Does |
  |---|---|
  | `UnshortenAnalyzer` | Resolves shortened URLs (bit.ly, tinyurl, etc.) |
  | `LocalDatabaseAnalyzer` | Checks against a local SQLite threat database |
  | `LengthAnalyzer` | Flags abnormally long URLs/domains |
  | `CharacterAnalyzer` | Detects IP-based URLs and malformed URIs |
  | `KeywordAnalyzer` | Scans for phishing keywords (login, secure, verify, etc.) |
  | `TyposquattingAnalyzer` | Detects lookalike domains (g00gle.com, paypa1.com) |
  | `WhoisAnalyzer` | RDAP/WHOIS domain registration lookups |
  | `ReputationAnalyzer` | VirusTotal, Google Safe Browsing, PhishTank API checks |
- **Batch URL Analysis** — Paste multiple URLs at once for bulk scanning
- **Scan History** — Full CSV-exportable history with filtering
- **Trusted Domain Whitelist** — Skips heuristics for known-good domains (Google, YouTube, etc.)
- **Popup Notifications** — Non-intrusive desktop alerts with risk breakdowns
- **API Key Encryption** — Keys encrypted at rest with AES-128 (machine-specific)
- **Single Instance Lock** — Prevents duplicate processes
- **Dark Mode UI** — FlatLaf dark theme

## Prerequisites

- **Java 11+** (JDK or JRE)
- **Maven** (for building)
- **VirusTotal API Key** (free tier) — [Get one here](https://www.virustotal.com/gui/join-us)
- Google Safe Browsing / PhishTank keys are optional

## Setup

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/phishing-detector.git
cd phishing-detector

# 2. Build with Maven
mvn clean package

# 3. Copy the example config and add your API key
cp settings.properties.example settings.properties
# Edit settings.properties and replace YOUR_API_KEY_HERE with your VirusTotal key

# 4. Run
java -jar target/phishing-detector-1.0-SNAPSHOT.jar
```

The app will start in the system tray. Right-click the tray icon to open the dashboard.

## Configuration

Edit `settings.properties` (created from the example template):

| Key | Description |
|---|---|
| `VIRUS_TOTAL_KEY` | Your VirusTotal API key (required for full detection) |
| `GOOGLE_SAFE_BROWSING_KEY` | Google Safe Browsing API key (optional) |
| `PHISHTANK_KEY` | PhishTank API key (optional) |
| `ACTIVE_PROVIDER` | Primary API provider (`VirusTotal` by default) |
| `CLIPBOARD_SCAN_ENABLED` | Toggle clipboard monitoring (`true`/`false`) |

> **Note:** API keys are automatically encrypted on first save using AES-128 with a machine-specific seed. The `settings.properties` file is gitignored and never committed.

## Project Structure

```
phishing-detector/
├── src/main/java/com/phishing/
│   ├── Main.java                  # Entry point, system tray setup
│   ├── DetectionEngine.java       # Orchestrates all analyzers
│   ├── ClipboardMonitor.java      # Clipboard polling thread
│   ├── *Analyzer.java             # 8 detection modules
│   ├── VirusTotalClient.java      # VirusTotal API integration
│   ├── GoogleSafeBrowsingClient.java
│   ├── PhishTankClient.java
│   ├── SecurityUtils.java         # Encryption, sanitization, defanging
│   ├── DashboardWindow.java       # Main UI window
│   ├── HomePanel.java             # Manual URL scan panel
│   ├── BatchPanel.java            # Bulk URL analysis
│   ├── HistoryPanel.java          # Scan history with export
│   └── SettingsPanel.java         # API key configuration
├── pom.xml                        # Maven build config
├── settings.properties.example    # Config template
├── test_urls.txt                  # Sample URLs for testing
└── .gitignore
```

## Security Notes

- API keys are **encrypted at rest** (AES-128) in `settings.properties`
- UI inputs are **sanitized** against Swing HTML injection
- CSV exports are protected against **formula injection**
- Malicious URLs are **defanged** (`hxxp://`, `[.]`) in displays
- `settings.properties` is **gitignored** — never committed

