# Naija Scam Shield — User Guide

**Author:** Joshua Akadri · GitHub: sudopenmark

---

## Installation

### Desktop (Windows / Linux / macOS)

1. **Download** the latest release from GitHub:  
   `https://github.com/sudopenmark/naija-scam-shield/releases`

2. **Windows:** Run `NaijaScamShield.exe` directly — no Python needed.

3. **Linux:** Make the binary executable and run:
   ```bash
   chmod +x NaijaScamShield
   ./NaijaScamShield
   ```

4. **From source** (Python 3.12+ required):
   ```bash
   git clone https://github.com/sudopenmark/naija-scam-shield.git
   cd naija-scam-shield
   pip install -r requirements.txt
   python main.py
   ```

### Android

Install the APK from the releases page.  
On first install, allow installation from unknown sources if prompted.

---

## Scanning a URL

### Method 1 — Type or Paste

1. Open the **Scan URL** screen (default screen)
2. Type or paste a URL in the input box
3. Press **🔍 Scan** or hit Enter
4. View results in 5–15 seconds

### Method 2 — Clipboard (one click)

1. **Copy** any URL (from WhatsApp, SMS, email, browser)
2. Open Naija Scam Shield
3. Tap **📋 Paste from Clipboard** — the URL fills automatically
4. Press **🔍 Scan**

### Method 3 — QR Code Scanner

1. Go to the **📷 QR Scanner** screen
2. Press **▶ Start Camera Scan**
3. Point your camera at the QR code
4. The detected URL is shown — press **🔍 Scan Detected URL**

To scan a QR code from a screenshot or saved image:
1. Press **🖼 Scan from Image File**
2. Select the image
3. Press **🔍 Scan Detected URL**

---

## Understanding Results

### Risk Score (0 – 100)

| Score | Level | What it means |
|-------|-------|---------------|
| 0 – 15 | ✅ **Safe** | No threats detected |
| 16 – 40 | ⚠️ **Suspicious** | Some warning signs — exercise caution |
| 41 – 65 | 🟠 **High Risk** | Multiple threat indicators — do not enter personal data |
| 66 – 100 | 🔴 **Likely Scam** | Almost certainly a scam — close immediately |

### Official Domain Banner

When you scan an official Nigerian domain (e.g. `gtbank.com`, `cbn.gov.ng`), you will see:

> ✅ **Official Domain — GTBank**

This means the domain is in the verified registry. Still always double-check the full address bar in your browser.

### Threat Indicators

Each indicator shows:
- **Icon** — 🔴 Critical · 🟠 High · 🟡 Medium · 🔵 Low
- **Type** — e.g. "Brand Impersonation", "New Domain", "Known Scam Domain"
- **Description** — plain-English explanation
- **+Score** — how many points this adds to the risk score

---

## Common Nigerian Scam Patterns

### 🏦 Fake Bank Websites
Sites like `gtbank-verify.com` or `zenith-bank-secure.online` look identical to real bank login pages. They steal your internet banking credentials.

**What to check:** The real GTBank domain is `gtbank.com`. Any variation is fake.

### 📱 Fake Fintech Portals
Sites claiming to be OPay, Kuda, or PalmPay offering "cashback" or "promo bonuses". They steal your app login credentials.

### 🏛️ Government Agency Impersonation
Sites impersonating CBN, EFCC, NIMC (NIN), JAMB, or WAEC. Common tactics:
- "Collect your CBN palliative reward" — CBN gives no such rewards
- "Your NIN needs re-verification" — NIMC's real site is `nimc.gov.ng`
- "EFCC has issued a warrant for your arrest" — extortion tactic

### 💸 Investment Fraud / Ponzi Schemes
Sites promising "₦50,000 daily profit", "double your money in 7 days", or "guaranteed forex returns". There are no legitimate guaranteed investment returns.

### 🎰 Fake Betting Sites
Sites impersonating Bet9ja, SportyBet, or BetKing to steal account credentials or demand fake "withdrawal fees".

### ₿ Fake Crypto / Play-to-Earn
Sites promising crypto earnings, NFT play-to-earn games, or "DeFi" platforms. Usually collect an upfront "gas fee" then disappear.

---

## Reporting a Scam Site

### In the App

1. After scanning, press **🚨 Report This Site**
2. The site is added to your local database
3. Future scans of the same domain will instantly flag it

### To Official Authorities

| Authority | How to Report |
|-----------|--------------|
| **EFCC** | [efcc.gov.ng](https://efcc.gov.ng) · Call 0800-CALL-EFCC (0800-2255-3322) |
| **CBN** | Email cpd@cbn.gov.ng |
| **NITDA** | [nitda.gov.ng](https://nitda.gov.ng) |
| **Your Bank** | Call your bank's anti-fraud hotline immediately if you entered credentials |

---

## If You've Already Been Scammed

1. **Call your bank immediately** — most banks can reverse transactions within 24 hours
2. **Change all passwords** for the affected app or website
3. **Report to EFCC** — [efcc.gov.ng](https://efcc.gov.ng)
4. **File a report with the Nigeria Police Force** — [npf.gov.ng](https://npf.gov.ng)
5. **Revoke any app permissions** granted to the scam site

---

## Settings

### Theme
Switch between **Dark** (default) and **Light** mode.

### API Keys (Optional)
Add VirusTotal and/or PhishTank API keys to enable live threat intelligence lookups. The app works fully without them.

- VirusTotal: free at [virustotal.com](https://virustotal.com) (500 scans/day)
- PhishTank: free at [phishtank.com](https://phishtank.com)

### Offline Mode
Enable this to prevent all network requests. Only local database and pattern analysis will run. Useful when on metered data.

### Scan Timeout
Increase if you're on a slow connection and getting "Unreachable" errors for legitimate sites.

---

## Exporting Reports

After scanning, three export options are available:

| Format | Button | Contents |
|--------|--------|----------|
| **PDF** | 📄 Export PDF Report | Full formatted report with all indicators, domain info, and recommendations |
| **CSV** | 📊 Export CSV | Single-row summary, machine-readable |
| **History** | History → Export CSV | All scans in a spreadsheet |

Reports are saved to: `~/.naija_scam_shield/reports/`

---

## Privacy

- No account required
- No data sent to Naija Scam Shield servers
- Scan history stored only on your device
- API calls go directly to VirusTotal/PhishTank (if keys are configured)
- Uninstalling the app removes all data from `~/.naija_scam_shield/`

---

## Troubleshooting

### "Camera not opening" (QR Scanner)
- **Linux:** Install `libzbar0`: `sudo apt install libzbar0`
- **Windows:** Install `pyzbar` wheel: `pip install pyzbar`
- Check camera permissions in your OS settings

### "WHOIS checks disabled"
Install python-whois: `pip install python-whois`

### PDF export not working
Install reportlab: `pip install reportlab`

### App won't start on Linux
Install Qt dependencies:
```bash
sudo apt install libxcb-xinerama0 libgl1-mesa-glx libxcb1
```

### Slow scans
- Increase **Scan Timeout** in Settings
- Enable **Offline Mode** for instant pattern-only scans
- WHOIS lookups can be slow for some domains — disable in Settings if not needed
