# 🛡️ Naija Scam Shield

**A production-ready Python desktop & mobile application for detecting fraudulent websites targeting Nigerians.**

> Author: **Joshua Akadri** · GitHub: [sudopenmark](https://github.com/sudopenmark)  
> Version: 1.0.0 · Python 3.12 · PyQt6 (desktop) · Kivy (Android)

---

## Overview

Naija Scam Shield helps Nigerian internet users instantly verify whether a website is safe or a scam — before entering any personal, financial, or identity information.

It combines:
- **Offline intelligence** — 60+ verified official Nigerian domains, 20+ seed scam domains, URL/domain pattern rules
- **Live threat feeds** — VirusTotal, PhishTank, OpenPhish, URLhaus (optional API keys)
- **AI risk scoring** — 0–100 score with `Safe / Suspicious / High Risk / Likely Scam` verdict
- **Nigerian scam module** — detects impersonation of banks, fintechs, government agencies, betting platforms, crypto/Ponzi schemes

---

## Features

| Feature | Status |
|---|---|
| Manual URL scan | ✅ |
| Clipboard URL monitor | ✅ |
| QR code / barcode scanner (camera + image file) | ✅ |
| WHOIS domain age check | ✅ |
| HTTPS certificate verification | ✅ |
| Typosquatting / look-alike detection | ✅ |
| Suspicious URL & domain pattern analysis | ✅ |
| URL shortener & redirect detection | ✅ |
| Page title & metadata analysis | ✅ |
| Local SQLite reputation database (offline) | ✅ |
| VirusTotal API integration | ✅ |
| PhishTank API integration | ✅ |
| OpenPhish + URLhaus auto-update feeds | ✅ |
| Official domain verification (banks, fintechs, govt) | ✅ |
| Risk score 0–100 with explanations | ✅ |
| PDF report export | ✅ |
| CSV report export | ✅ |
| JSON report export | ✅ |
| Scan history (SQLite) | ✅ |
| Report suspicious site | ✅ |
| Dark & light themes | ✅ |
| Dashboard with statistics | ✅ |
| QR scanner screen | ✅ |
| Settings screen with API key entry | ✅ |
| Offline mode | ✅ |
| Auto signature updates (background thread) | ✅ |
| Windows EXE (PyInstaller) | ✅ |
| Linux binary/AppImage (PyInstaller) | ✅ |
| Android APK (Kivy + BeeWare Briefcase) | ✅ |
| 98 unit + integration tests | ✅ |

---

## Project Structure

```
naija_scam_shield/
├── main.py                        # Desktop app entry point
├── requirements.txt               # Python dependencies
├── pyproject.toml                 # BeeWare/Briefcase config (Android APK)
├── naija_scam_shield.spec         # PyInstaller build spec
├── Makefile                       # One-command build shortcuts
│
├── core/
│   ├── config.py                  # App configuration & paths
│   ├── logger.py                  # Logging setup (rotating file + console)
│   ├── models.py                  # ScanResult, ScanIndicator, RiskLevel …
│   ├── scanner.py                 # Security analysis engine (main orchestrator)
│   ├── nigerian_brands.py         # Official Nigerian domain registry (60+ brands)
│   ├── clipboard_monitor.py       # Background clipboard URL watcher (QThread)
│   └── reputation_updater.py      # Auto-update from OpenPhish/URLhaus (QThread)
│
├── database/
│   └── db_manager.py              # SQLite: scam domains, official domains, history
│
├── ui/
│   ├── main_window.py             # Main PyQt6 window with sidebar navigation
│   ├── styles.py                  # Dark/light theme stylesheets + color tokens
│   ├── mobile_app.py              # Kivy-based mobile UI (Android)
│   ├── screens/
│   │   ├── scanner_screen.py      # URL input + scan results + export buttons
│   │   ├── dashboard_screen.py    # Metrics cards + recent scan list
│   │   ├── history_screen.py      # Full scan history table + CSV export
│   │   ├── qr_screen.py           # Camera QR scanner + image file scanner
│   │   └── settings_screen.py     # Theme, API keys, scanner toggles
│   └── widgets/
│       └── common.py              # RiskBadge, ScoreDonut, StatCard, Toast …
│
├── reports/
│   └── report_generator.py        # PDF (ReportLab) + CSV + JSON export
│
├── scripts/
│   ├── update_signatures.py       # Manual signature update CLI
│   └── gen_assets.py              # Generate placeholder icon/splash PNGs
│
├── tests/
│   ├── conftest.py                # Pytest fixtures
│   ├── test_scanner.py            # Unit tests: models, brands, scanner, DB, reports
│   └── test_integration.py        # Integration tests: edge cases, concurrency
│
└── assets/
    ├── icon.png                   # App icon (256×256)
    ├── icon.ico                   # Windows icon (multi-size)
    ├── splash.png                 # Splash screen
    └── threat_rules.json          # Example threat detection rules & datasets
```

---

## Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/sudopenmark/naija-scam-shield.git
cd naija-scam-shield

# Install all dependencies
pip install -r requirements.txt

# Generate placeholder assets (if assets/ is empty)
python scripts/gen_assets.py
```

### 2. Run the Desktop App

```bash
python main.py
# or
make run
```

### 3. Scan your first URL

1. Type or paste a URL in the input box (e.g. `opay-promo-bonus.com`)
2. Press **Scan** or hit Enter
3. View the risk score, indicators, and recommendation

---

## Optional API Keys

The app works fully offline without any API keys. To enable live threat intelligence:

| Service | Free tier | How to get |
|---|---|---|
| VirusTotal | 500 req/day | [virustotal.com](https://www.virustotal.com) → Sign up → API Key |
| PhishTank | Unlimited (throttled) | [phishtank.com](https://www.phishtank.com) → Register |

Add keys in **Settings → API Keys** or via environment variables:

```bash
export VIRUSTOTAL_API_KEY="your_key_here"
export PHISHTANK_API_KEY="your_key_here"  # optional
python main.py
```

---

## Running Tests

```bash
# All tests (no network required)
python -m unittest tests/test_scanner.py tests/test_integration.py -v

# Or with pytest (if installed)
pytest tests/ -v

# Coverage report
pytest tests/ --cov=. --cov-report=html
```

**98 tests total** — all pass without network access:
- `TestScanResult` — risk scoring, indicator accumulation, serialization
- `TestNigerianBrandsRegistry` — 60+ official domains, impersonation detection
- `TestURLPatternAnalysis` — offline scanner checks
- `TestDatabaseManager` + `TestDatabaseManagerExtended` — CRUD, concurrency, stats
- `TestReportGenerator` — CSV, JSON, PDF export
- `TestClipboardURLExtraction` — URL detection from clipboard text
- `TestScannerOfflineAnalysis` — full offline scan pipeline
- `TestConfigPersistence` — settings save/reload, corrupt file handling

---

## Build Instructions

### Windows EXE

Run on Windows (or Wine on Linux):

```bat
pip install pyinstaller
pyinstaller naija_scam_shield.spec --clean --noconfirm
:: Output: dist\NaijaScamShield.exe
```

Or with Make:
```bash
make build-windows
```

**Requirements on build machine:**
- Python 3.12
- All `requirements.txt` packages installed
- Visual C++ Redistributable (for PyInstaller)

The produced `.exe` is fully self-contained — no Python installation needed on the target machine.

---

### Linux Binary / AppImage

```bash
# Standalone binary
pip install pyinstaller
pyinstaller naija_scam_shield.spec --clean --noconfirm
# Output: dist/NaijaScamShield

# AppImage (requires appimage-builder)
pip install appimage-builder
make build-linux-appimage
```

**System dependencies on target machine (if running the binary directly):**
```bash
sudo apt install libzbar0 libgl1-mesa-glx libxcb-xinerama0
```

---

### Android APK (BeeWare + Kivy)

The Android build uses the **Kivy** mobile UI (`ui/mobile_app.py`) instead of PyQt6.

#### Prerequisites

```bash
pip install briefcase
# Java 11+ and Android SDK must be installed:
# https://developer.android.com/studio
```

#### Build

```bash
briefcase create android    # Set up Android build environment
briefcase build android     # Compile APK (~5-10 min first time)
briefcase run android       # Deploy to connected device/emulator
```

#### APK output location
```
android/gradle/app/build/outputs/apk/debug/app-debug.apk
```

#### Preview mobile UI on desktop
```bash
pip install kivy
python ui/mobile_app.py
```

---

## Official Nigerian Domain Registry

Naija Scam Shield maintains a built-in registry of **60+ verified official Nigerian domains** across 6 categories. When a domain is scanned, it is instantly compared against this registry:

| Category | Examples |
|---|---|
| **Banks** | gtbank.com, zenithbank.com, firstbanknigeria.com, accessbankplc.com, ubagroup.com (16 banks) |
| **Fintechs** | opayweb.com, kuda.com, palmpay.com, moniepoint.com, piggyvest.com (11 fintechs) |
| **Government** | cbn.gov.ng, efcc.gov.ng, nimc.gov.ng, jamb.gov.ng, firs.gov.ng (12 agencies) |
| **Telecoms** | mtn.com.ng, airtel.com.ng, gloworld.com, 9mobile.com.ng |
| **E-Commerce** | jumia.com.ng, konga.com, giglogistics.com |
| **Betting** | bet9ja.com, sportybet.com, betking.com, 1xbet.com |

**Result shown to user:**
- ✅ `Official Domain — GTBank` — verified, risk score reduced
- 🚨 `Brand Impersonation — Impersonates GTBank` — risk score +40, category set

---

## Signature Updates

### Manual (CLI)

```bash
python scripts/update_signatures.py
# or
make update-sigs
```

Pulls from:
- **OpenPhish** — verified phishing URLs (no key required)
- **URLhaus (Abuse.ch)** — malware distribution URLs (no key required)
- **PhishStats** — high-confidence phishing domains (optional, large file)

### Automatic (in-app)

The `AutoUpdater` runs every 24 hours in the background while the app is open. Progress is logged and shown in the status bar. Configure interval in `core/reputation_updater.py`.

---

## Privacy & Security

- ❌ Never collects passwords or banking credentials
- ❌ Never transmits personal data to third parties
- ✅ All scan data stored locally in SQLite (`~/.naija_scam_shield/shield.db`)
- ✅ API calls use HTTPS only
- ✅ User-Agent clearly identifies the app to threat intelligence APIs
- ✅ Offline mode disables all network requests

To enable encrypted SQLite storage, install `sqlcipher3` and update `db_manager.py` to use `sqlcipher3` instead of `sqlite3`.

---

## Reporting Scams

In addition to the in-app "Report This Site" button, report Nigerian online scams to:

| Agency | Contact |
|---|---|
| **EFCC** | [efcc.gov.ng](https://efcc.gov.ng) · 0800-CALL-EFCC |
| **CBN Consumer Protection** | [cbn.gov.ng](https://cbn.gov.ng) · cpd@cbn.gov.ng |
| **NITDA** | [nitda.gov.ng](https://nitda.gov.ng) |
| **Nigeria Police Force (Cybercrime)** | [npf.gov.ng](https://npf.gov.ng) |

---

## Configuration Files

| File | Location | Purpose |
|---|---|---|
| `config.json` | `~/.naija_scam_shield/config.json` | Theme, API keys, feature flags |
| `shield.db` | `~/.naija_scam_shield/shield.db` | SQLite: scans, scam domains, official domains |
| `app.log` | `~/.naija_scam_shield/app.log` | Rotating log (5 MB × 3 files) |
| `last_update.json` | `~/.naija_scam_shield/last_update.json` | Timestamp of last signature update |
| Reports | `~/.naija_scam_shield/reports/` | Exported PDF/CSV/JSON reports |

---

## Development

```bash
# Install dev tools
make install-dev

# Run app
make run

# Lint
make lint

# Auto-format
make format

# Type check
make typecheck

# Clean build artifacts
make clean
```

---

## License

**Commercial / Proprietary License.** All rights reserved by Joshua Akadri.

See [LICENSE](LICENSE) for the full commercial license agreement, and
[THIRD-PARTY-LICENSES.txt](THIRD-PARTY-LICENSES.txt) for important notices
about bundled open-source dependencies — **in particular, PyQt6 requires
a separate commercial license from Riverbank Computing if you distribute
the desktop build as closed-source software.** See that file for details
and alternatives (e.g. migrating to PySide6, which is LGPL-licensed).

For licensing inquiries, OEM/redistribution agreements, or source code
licenses, contact dev@naijascamshield.ng.

---

## Acknowledgements

- [VirusTotal](https://virustotal.com) — threat intelligence API
- [PhishTank](https://phishtank.com) — phishing URL database
- [OpenPhish](https://openphish.com) — free phishing feed
- [Abuse.ch URLhaus](https://urlhaus.abuse.ch) — malware URL feed
- [ReportLab](https://reportlab.com) — PDF generation
- All Nigerian banks, fintechs, and government agencies whose official domains are listed here for verification purposes

---

*Naija Scam Shield is a community safety tool. It is not affiliated with any bank, government agency, or financial institution.*
