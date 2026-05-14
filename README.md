# PhishGuard - Real-Time Phishing Link Detector

**Copy a link. Get an instant verdict.** PhishGuard is a lightweight desktop app that silently watches your clipboard and alerts you the moment you copy a dangerous URL - before you ever click it.

---

## What It Does

1. **You copy a link** - from an email, message, browser, anywhere.
2. **PhishGuard scans it instantly** - running 9 checks in parallel behind the scenes.
3. **A popup tells you the verdict** - Safe, Suspicious, or Malicious - with a risk breakdown.

---

## Getting Started

### Prerequisites

| Requirement | Details |
|---|---|
| **Java 11+** | JDK or JRE - [Download](https://adoptium.net/) |
| **Maven** | For building from source - [Download](https://maven.apache.org/download.cgi) |
| **VirusTotal API Key** | Free tier is enough - [Sign up here](https://www.virustotal.com/gui/join-us) |

### Quick Start

```bash
# Clone and build
git clone https://github.com/YOUR_USERNAME/phishing-detector.git
cd phishing-detector
mvn clean package

# Run
java -jar target/phishing-detector-1.0-SNAPSHOT.jar
```

On first launch, PhishGuard will ask you to enter your VirusTotal API key in the **Settings** tab. Once configured, it minimizes to the **system tray** and starts protecting you immediately.

> **Windows users:** You can also double-click `Run_Phishing_Detector.bat` to launch silently.

---

## Using PhishGuard

### System Tray

PhishGuard lives in your system tray. Right-click the tray icon to open the full dashboard. It runs quietly in the background - you'll only see it when a copied URL needs your attention.

### Protection Status

A live status indicator at the bottom of the sidebar shows whether real-time clipboard monitoring is active:

- **Green pulsing dot** - Protection is active and monitoring your clipboard.
- **Red dot** - Protection is paused. You can toggle it from the Home tab.

### Dashboard

The dashboard has four tabs:

| Tab | What You Can Do |
|---|---|
| **Home** | Manually paste and scan any URL on demand |
| **Batch Scan** | Paste a list of URLs to scan them all at once |
| **History** | Browse past scans, search and filter results, export to CSV |
| **Settings** | Add or update your API keys, toggle clipboard monitoring |

### Searching Your History

The History tab includes a **live search bar** that filters results as you type. You can search by URL or scan result, and combine it with the source filter (Clipboard, Manual, API) to narrow down past scans.

### Notifications

When you copy a URL, a non-intrusive popup slides in with:
- The **verdict** (Safe / Suspicious / Malicious)
- A **risk score** breakdown showing which checks flagged it
- The option to **view full details** for a deeper look

---

## What Gets Checked

Every URL is run through **9 independent checks** simultaneously:

| Check | What It Catches |
|---|---|
| **Link Unshortening** | Reveals the real URL hidden behind bit.ly, tinyurl, etc. |
| **Known Threat Database** | Matches against a local database of known malicious sites |
| **URL Length Analysis** | Flags abnormally long URLs often used in phishing |
| **Suspicious Characters** | Detects IP-based URLs and oddly structured links |
| **Phishing Keywords** | Catches terms like "login", "verify", "secure" in suspicious contexts |
| **Lookalike Detection** | Spots typosquatting like `g00gle.com` or `paypa1.com` |
| **IDN Homograph Detection** | Catches Unicode lookalike attacks - e.g., a Cyrillic "a" impersonating a Latin "a" in brand domains |
| **Domain Age Lookup** | Checks WHOIS/RDAP data - brand-new domains are riskier |
| **Reputation APIs** | Cross-references VirusTotal, Google Safe Browsing, and PhishTank |

Results are combined into a single risk score so you get one clear answer.

---

## Configuration

All settings are managed from the **Settings** tab inside the app. You can also edit `settings.properties` directly:

| Setting | Description | Required? |
|---|---|---|
| `VIRUS_TOTAL_KEY` | Your VirusTotal API key | Choose an API of your preference |
| `GOOGLE_SAFE_BROWSING_KEY` | Google Safe Browsing key | Choose an API of your preference |
| `PHISHTANK_KEY` | PhishTank API key | Choose an API of your preference |
| `CLIPBOARD_SCAN_ENABLED` | Turn clipboard monitoring on/off | -- |

> **Your API keys are safe.** They are encrypted at rest using AES with a machine-specific key. The `settings.properties` file is gitignored and never leaves your machine.

---

## Privacy & Security

- **Everything runs locally.** URLs are analyzed on your machine - nothing is sent to any server except the reputation API lookups you've configured.
- **API keys are encrypted** at rest and never committed to version control.
- **Malicious URLs are defanged** (`hxxp://`, `[.]`) in all displays to prevent accidental clicks.
- **CSV exports are sanitized** against formula injection attacks.

## Under the Hood

Want to know how the 9 independent checks are built and how the risk scoring works?
[Check out the full Implementation Details here](Implementation_Details.md).
