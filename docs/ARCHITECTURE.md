# Naija Scam Shield — Architecture Guide

**Author:** Joshua Akadri · GitHub: sudopenmark

---

## System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        USER INTERFACE LAYER                          │
│                                                                       │
│  ┌──────────────┐  ┌───────────┐  ┌───────────┐  ┌──────────────┐  │
│  │ ScannerScreen│  │Dashboard  │  │ History   │  │  QRScanner   │  │
│  │  (main scan) │  │(stats/    │  │ (history  │  │  (camera +   │  │
│  │              │  │ recent)   │  │  table)   │  │  image file) │  │
│  └──────┬───────┘  └─────┬─────┘  └─────┬─────┘  └──────┬───────┘  │
│         │                │              │                │           │
│  ┌──────▼───────────────────────────────▼────────────────▼───────┐  │
│  │                   MainWindow (PyQt6 / Kivy on Android)        │  │
│  └──────────────────────────────┬────────────────────────────────┘  │
└─────────────────────────────────┼───────────────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────────────┐
│                         CORE ENGINE LAYER                            │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                     Scanner (orchestrator)                   │    │
│  │                                                               │    │
│  │  1. _check_local_db()      ← SQLite scam/official domains   │    │
│  │  2. _resolve_and_fetch()   ← HTTP, redirects, page meta     │    │
│  │  3. _check_certificate()   ← TLS/SSL validity               │    │
│  │  4. _check_whois()         ← domain age (python-whois)      │    │
│  │  5. _check_virustotal()    ← VirusTotal API                 │    │
│  │  6. _check_phishtank()     ← PhishTank API                  │    │
│  │  7. _analyze_url_patterns()← regex rules (offline)          │    │
│  │  8. _check_official_domain()← Nigerian brands registry       │    │
│  │  9. _detect_scam_category()← category classification        │    │
│  │  10. _finalize()           ← summary + recommendation       │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                       │
│  ┌──────────────────┐  ┌───────────────────┐  ┌─────────────────┐  │
│  │ NigerianBrands   │  │  ClipboardMonitor  │  │ReputationUpdater│  │
│  │ (offline lookup) │  │  (QThread poller)  │  │ (QThread feeds) │  │
│  └──────────────────┘  └───────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────────────┐
│                          DATA LAYER                                   │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  SQLite  (~/.naija_scam_shield/shield.db)                    │    │
│  │                                                               │    │
│  │  Tables:                                                      │    │
│  │  • scam_domains   — known phishing/scam domains              │    │
│  │  • official_domains — verified Nigerian brand domains        │    │
│  │  • scan_history   — every scan result (full JSON)            │    │
│  │  • user_reports   — user-submitted suspicious URLs           │    │
│  │  • app_settings   — key-value settings store                 │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                       │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │   PDF Reports     │  │   CSV Reports     │  │   JSON Reports   │  │
│  │ (ReportLab)       │  │  (csv stdlib)     │  │  (json stdlib)   │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow: URL Scan

```
User inputs URL
      │
      ▼
Scanner.scan(url)
      │
      ├─► normalize URL (add scheme if missing)
      ├─► extract domain
      │
      ├─► [FAST, offline] check local SQLite scam_domains
      │         └─ if hit: add "Known Scam Domain" indicator (+50)
      │
      ├─► [NETWORK] resolve redirects, fetch page
      │         ├─ capture final URL, title, description
      │         ├─ detect redirect chains (>2 hops → +8)
      │         ├─ detect domain change after redirect (+15)
      │         └─ detect plain HTTP (+20)
      │
      ├─► [NETWORK] TLS certificate check
      │         ├─ verify validity
      │         ├─ check expiry (< 7 days → +15, < 30 days → +5)
      │         └─ flag free CAs like Let's Encrypt (+5)
      │
      ├─► [NETWORK] WHOIS domain age
      │         ├─ < 30 days → +30 (Very New Domain)
      │         ├─ < 90 days → +20 (New Domain)
      │         └─ < 365 days → +10 (Young Domain)
      │
      ├─► [NETWORK] VirusTotal API (if key configured)
      │         ├─ > 3 malicious → +40
      │         └─ any suspicious → +20
      │
      ├─► [NETWORK] PhishTank API
      │         ├─ verified phishing → +45
      │         └─ in database → +25
      │
      ├─► [FAST, offline] URL pattern analysis
      │         ├─ IP address URL → +20
      │         ├─ URL shortener → +15
      │         ├─ suspicious TLD (.xyz, .gq, etc.) → +12
      │         ├─ excessive subdomains (>4) → +10
      │         ├─ scam URL patterns (BVN, NIN, verify-account…) → +18
      │         ├─ scam domain patterns (ng-verify, cbn-reward…) → +20
      │         ├─ excessive hyphens (>3) → +5
      │         └─ very long URL (>150 chars) → +5
      │
      ├─► [FAST, offline] Official domain / impersonation check
      │         ├─ exact match in official_domains → is_official = True, score -20
      │         └─ fuzzy match / typo → Brand Impersonation (+40)
      │
      ├─► [FAST, offline] Scam category classification
      │         └─ match keywords → assign ScamCategory enum
      │
      └─► finalize()
                ├─ clamp score 0–100
                ├─ assign RiskLevel (Safe/Suspicious/High Risk/Likely Scam)
                ├─ generate summary text
                ├─ generate recommendation text
                └─ persist to SQLite
```

---

## Risk Score Calculation

| Score Range | Risk Level  | Colour |
|-------------|-------------|--------|
| 0 – 15      | Safe        | 🟢 Green  |
| 16 – 40     | Suspicious  | 🟡 Yellow |
| 41 – 65     | High Risk   | 🟠 Orange |
| 66 – 100    | Likely Scam | 🔴 Red    |

Score is the **sum of all indicator impacts**, capped at 100.  
When an official domain is confirmed, 20 points are subtracted.

---

## Threading Model

```
Main Thread (Qt event loop)
    │
    ├── ScanWorker (QThread)          ← one per scan, lives until scan complete
    │       └── Scanner.scan()
    │
    ├── ClipboardMonitor (QThread)    ← persistent, polls every 1.5 s
    │       └── QTimer → _check_clipboard()
    │
    └── ReputationUpdater (QThread)   ← fires every 24 h or on demand
            └── HTTP feeds → db.add_scam_domain()
```

All signals cross thread boundaries safely using Qt's `pyqtSignal` / `emit()`.

---

## Database Schema

```sql
-- Known scam/phishing domains (seed + auto-updated from feeds)
CREATE TABLE scam_domains (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT NOT NULL UNIQUE,
    category    TEXT,                 -- FAKE_BANK, PHISHING, etc.
    verdict     TEXT,                 -- human-readable description
    confidence  INTEGER DEFAULT 100,  -- 0–100
    source      TEXT,                 -- "seed", "OpenPhish", "user", …
    reported_by TEXT,
    date_added  TEXT,
    date_updated TEXT
);

-- Verified official Nigerian brand domains
CREATE TABLE official_domains (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT NOT NULL UNIQUE,
    brand_name  TEXT NOT NULL,
    category    TEXT,                 -- bank, fintech, government, …
    date_added  TEXT
);

-- Full scan history
CREATE TABLE scan_history (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    original_url     TEXT NOT NULL,
    domain           TEXT NOT NULL,
    risk_score       INTEGER,
    risk_level       TEXT,
    scam_category    TEXT,
    is_official      INTEGER DEFAULT 0,
    official_brand   TEXT,
    page_title       TEXT,
    indicators_json  TEXT,    -- JSON array of {type, desc}
    full_result_json TEXT,    -- complete ScanResult.to_dict()
    scan_time        TEXT,
    duration_ms      INTEGER
);

-- User-submitted suspicious site reports
CREATE TABLE user_reports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    url           TEXT NOT NULL,
    domain        TEXT NOT NULL,
    reporter_note TEXT,
    report_time   TEXT,
    submitted_online INTEGER DEFAULT 0
);
```

---

## Nigerian Brands Registry

Located in `core/nigerian_brands.py`.

Each `NigerianBrand` entry contains:
- `name` — human-readable brand name
- `category` — `bank | fintech | government | telecom | ecommerce | betting`
- `official_domains` — list of verified domains
- `common_typos` — list of known typosquat patterns
- `description` — brief description

**Fast lookup** via `OFFICIAL_DOMAIN_MAP` dict (O(1)):
```python
brand = lookup_domain("gtbank.com")   # → NigerianBrand or None
```

**Impersonation detection** via `find_impersonated_brand()`:
- Checks `common_typos` list
- Checks if any brand keyword appears in domain but doesn't match any official domain

---

## Adding New Detection Rules

### Add a known scam domain at runtime
```python
db.add_scam_domain(
    "fake-kuda-bank.com",
    category="FAKE_FINTECH",
    verdict="Kuda Bank phishing site",
    source="user",
)
```

### Add to seed dataset
Edit `SEED_SCAM_DOMAINS` in `database/db_manager.py`:
```python
("fake-kuda-bank.com", "FAKE_FINTECH", "Kuda Bank phishing", "seed"),
```

### Add a new official brand
Edit `core/nigerian_brands.py`:
```python
NigerianBrand(
    name="My New Brand",
    category="fintech",
    official_domains=["mynewbrand.com", "app.mynewbrand.com"],
    common_typos=["mynewbrand-ng", "mynewbr4nd"],
    description="My New Brand description",
),
```

### Add a new URL pattern rule
Edit `SCAM_URL_PATTERNS` in `core/nigerian_brands.py`:
```python
SCAM_URL_PATTERNS = [
    ...
    r"my-new-pattern",
]
```

---

## Configuration Reference

All settings live in `core/config.py` (`AppConfig` dataclass):

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `theme` | str | `"dark"` | UI theme: `"dark"` or `"light"` |
| `scan_timeout` | int | `15` | HTTP request timeout (seconds) |
| `max_redirects` | int | `5` | Maximum redirects to follow |
| `offline_mode` | bool | `False` | Disable all network requests |
| `enable_whois` | bool | `True` | Enable WHOIS domain age lookup |
| `enable_virustotal` | bool | `True` | Enable VirusTotal API |
| `enable_phishtank` | bool | `True` | Enable PhishTank API |
| `enable_qr_scanner` | bool | `True` | Enable QR/barcode scanner UI |
| `enable_clipboard_monitor` | bool | `False` | Enable background clipboard monitor |
| `virustotal_api_key` | str\|None | `None` | VirusTotal API key |
| `phishtank_api_key` | str\|None | `None` | PhishTank API key |
