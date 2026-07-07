"""
core/scanner.py - Security Analysis Engine
Author: Joshua Akadri

Orchestrates all scanning modules and produces a ScanResult.
"""

import re
import time
import socket
import logging
import hashlib
import ssl
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Optional, List, Tuple
from pathlib import Path

import requests
from requests.exceptions import RequestException

from .models import (
    ScanResult, ScanIndicator, WhoisInfo, CertificateInfo,
    ThreatIntelResult, RiskLevel, ScamCategory
)
from .nigerian_brands import (
    lookup_domain, find_impersonated_brand,
    SCAM_URL_PATTERNS, SCAM_DOMAIN_PATTERNS,
    SUSPICIOUS_TLDS, URL_SHORTENERS
)
from .config import AppConfig

logger = logging.getLogger(__name__)

try:
    import whois as python_whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    logger.warning("python-whois not available; WHOIS checks disabled.")


class Scanner:
    """
    Main URL security scanner for Naija Scam Shield.
    Runs multiple analysis passes and aggregates into a ScanResult.
    """

    def __init__(self, config: AppConfig, db=None):
        self.config = config
        self.db = db
        self.session = requests.Session()
        self.session.headers["User-Agent"] = config.user_agent
        self.session.max_redirects = config.max_redirects

    # ── PUBLIC API ────────────────────────────────────────────────────────────

    def scan(self, url: str) -> ScanResult:
        """
        Full scan of a URL. Returns a populated ScanResult.
        This is the primary method called by the UI.
        """
        start = time.monotonic()
        url = self._normalize_url(url)
        domain = self._extract_domain(url)

        result = ScanResult(
            original_url=url,
            scanned_url=url,
            domain=domain,
        )

        try:
            # 1. Local database check (fastest, no network)
            self._check_local_db(result)

            if not self.config.offline_mode:
                # 2. Resolve redirects and fetch basic page info
                self._resolve_and_fetch(result)

                # 3. Certificate check
                self._check_certificate(result)

                # 4. WHOIS / domain age
                if self.config.enable_whois and WHOIS_AVAILABLE:
                    self._check_whois(result)

                # 5. External threat intelligence
                if self.config.enable_virustotal and self.config.virustotal_api_key:
                    self._check_virustotal(result)
                if self.config.enable_phishtank:
                    self._check_phishtank(result)

            # 6. URL pattern analysis (offline-capable)
            self._analyze_url_patterns(result)

            # 7. Official domain / impersonation check (offline)
            self._check_official_domain(result)

            # 8. Nigerian scam category detection (offline)
            self._detect_scam_category(result)

            # 9. Finalize scoring and generate summary
            self._finalize(result)

        except Exception as e:
            logger.exception("Unexpected scanner error for %s", url)
            result.error = str(e)

        result.duration_ms = int((time.monotonic() - start) * 1000)

        # Persist to database
        if self.db:
            try:
                result.scan_id = self.db.save_scan(result)
            except Exception as e:
                logger.warning("Could not save scan to DB: %s", e)

        return result

    # ── INTERNAL CHECKS ───────────────────────────────────────────────────────

    def _normalize_url(self, url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url

    def _extract_domain(self, url: str) -> str:
        try:
            parsed = urllib.parse.urlparse(url)
            host = parsed.netloc or parsed.path
            # Strip www.
            host = re.sub(r"^www\.", "", host.lower())
            # Strip port
            host = host.split(":")[0]
            return host
        except Exception:
            return url

    def _resolve_and_fetch(self, result: ScanResult):
        """Follow redirects and capture page metadata."""
        try:
            resp = self.session.get(
                result.scanned_url,
                timeout=self.config.scan_timeout,
                allow_redirects=True,
                verify=True,
            )
            result.final_url = resp.url
            result.redirect_chain = [r.url for r in resp.history] + [resp.url]

            # Detect redirect chain risk
            if len(resp.history) > 2:
                result.add_indicator(ScanIndicator(
                    indicator_type="Multiple Redirects",
                    description=f"URL redirected {len(resp.history)} times before landing.",
                    severity="medium",
                    score_impact=8,
                    details=" → ".join(result.redirect_chain),
                ))

            # Update domain from final URL
            final_domain = self._extract_domain(resp.url)
            if final_domain != result.domain:
                result.add_indicator(ScanIndicator(
                    indicator_type="Domain Mismatch After Redirect",
                    description=f"URL redirected from {result.domain} to {final_domain}.",
                    severity="high",
                    score_impact=15,
                ))
                result.domain = final_domain

            # Parse page title and meta description
            content = resp.text[:50000]
            title_match = re.search(r"<title[^>]*>(.*?)</title>", content, re.IGNORECASE | re.DOTALL)
            if title_match:
                result.page_title = title_match.group(1).strip()[:200]
            desc_match = re.search(
                r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']',
                content, re.IGNORECASE
            )
            if desc_match:
                result.page_description = desc_match.group(1).strip()[:300]

            # Resolve IP
            try:
                result.ip_address = socket.gethostbyname(result.domain)
            except Exception:
                pass

            # Non-HTTPS check
            if resp.url.startswith("http://"):
                result.add_indicator(ScanIndicator(
                    indicator_type="No HTTPS",
                    description="Website does not use HTTPS encryption.",
                    severity="high",
                    score_impact=20,
                ))

        except requests.exceptions.SSLError as e:
            result.add_indicator(ScanIndicator(
                indicator_type="SSL Certificate Error",
                description="The website has an invalid or untrusted SSL certificate.",
                severity="high",
                score_impact=25,
                details=str(e),
            ))
        except RequestException as e:
            logger.debug("Fetch error for %s: %s", result.scanned_url, e)
            result.add_indicator(ScanIndicator(
                indicator_type="Unreachable",
                description="The website could not be reached.",
                severity="medium",
                score_impact=10,
                details=str(e),
            ))

    def _check_certificate(self, result: ScanResult):
        """Inspect TLS certificate details."""
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.socket(socket.AF_INET),
                server_hostname=result.domain,
            ) as s:
                s.settimeout(5)
                s.connect((result.domain, 443))
                cert = s.getpeercert()

            not_after_str = cert.get("notAfter", "")
            expires = None
            if not_after_str:
                expires = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                expires = expires.replace(tzinfo=timezone.utc)

            days_remaining = None
            if expires:
                days_remaining = (expires - datetime.now(timezone.utc)).days

            # Extract issuer
            issuer_dict = dict(x[0] for x in cert.get("issuer", []))
            issuer = issuer_dict.get("organizationName", "Unknown")

            result.certificate = CertificateInfo(
                valid=True,
                issuer=issuer,
                expires=expires,
                days_remaining=days_remaining,
            )

            if days_remaining is not None and days_remaining < 7:
                result.add_indicator(ScanIndicator(
                    indicator_type="Certificate Expiring Soon",
                    description=f"SSL certificate expires in {days_remaining} days.",
                    severity="high",
                    score_impact=15,
                ))
            elif days_remaining is not None and days_remaining < 30:
                result.add_indicator(ScanIndicator(
                    indicator_type="Certificate Expiring",
                    description=f"SSL certificate expires in {days_remaining} days.",
                    severity="medium",
                    score_impact=5,
                ))

            # Free/suspicious CAs
            suspicious_issuers = ["Let's Encrypt", "ZeroSSL", "cPanel"]
            if any(si in issuer for si in suspicious_issuers):
                # Not inherently bad, but note it
                result.add_indicator(ScanIndicator(
                    indicator_type="Free SSL Certificate",
                    description=f"Certificate issued by {issuer} (free CA, common in phishing).",
                    severity="low",
                    score_impact=5,
                ))

        except ssl.SSLCertVerificationError as e:
            result.add_indicator(ScanIndicator(
                indicator_type="Invalid SSL Certificate",
                description="SSL certificate validation failed.",
                severity="critical",
                score_impact=30,
                details=str(e),
            ))
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass  # Not all sites have HTTPS on port 443

    def _check_whois(self, result: ScanResult):
        """Check domain registration details via WHOIS."""
        try:
            w = python_whois.whois(result.domain)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]

            age_days = None
            if creation:
                if isinstance(creation, str):
                    try:
                        creation = datetime.strptime(creation, "%Y-%m-%d")
                    except Exception:
                        creation = None
                if creation:
                    # Make timezone-naive for comparison
                    now = datetime.now()
                    if hasattr(creation, "tzinfo") and creation.tzinfo:
                        now = datetime.now(creation.tzinfo)
                    age_days = (now - creation).days

            result.whois = WhoisInfo(
                domain=result.domain,
                registrar=str(w.registrar) if w.registrar else None,
                creation_date=creation,
                age_days=age_days,
            )

            if age_days is not None:
                if age_days < 30:
                    result.add_indicator(ScanIndicator(
                        indicator_type="Very New Domain",
                        description=f"Domain registered only {age_days} days ago.",
                        severity="critical",
                        score_impact=30,
                    ))
                elif age_days < 90:
                    result.add_indicator(ScanIndicator(
                        indicator_type="New Domain",
                        description=f"Domain registered {age_days} days ago.",
                        severity="high",
                        score_impact=20,
                    ))
                elif age_days < 365:
                    result.add_indicator(ScanIndicator(
                        indicator_type="Young Domain",
                        description=f"Domain is only {age_days} days old (less than 1 year).",
                        severity="medium",
                        score_impact=10,
                    ))

        except Exception as e:
            logger.debug("WHOIS error for %s: %s", result.domain, e)

    def _analyze_url_patterns(self, result: ScanResult):
        """Analyze URL structure for suspicious patterns."""
        url_l = result.scanned_url.lower()
        domain_l = result.domain.lower()

        # URL shortener check
        for shortener in URL_SHORTENERS:
            if shortener in domain_l:
                result.add_indicator(ScanIndicator(
                    indicator_type="URL Shortener",
                    description=f"URL uses a shortener ({shortener}) that hides the real destination.",
                    severity="medium",
                    score_impact=15,
                ))
                break

        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain_l.endswith(tld):
                result.add_indicator(ScanIndicator(
                    indicator_type="Suspicious TLD",
                    description=f"Domain uses the '{tld}' TLD which is frequently abused in phishing.",
                    severity="medium",
                    score_impact=12,
                ))
                break

        # Excessive subdomains
        parts = domain_l.split(".")
        if len(parts) > 4:
            result.add_indicator(ScanIndicator(
                indicator_type="Excessive Subdomains",
                description=f"Domain has {len(parts)-2} subdomains, a common phishing trick.",
                severity="medium",
                score_impact=10,
            ))

        # IP address as URL
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain_l):
            result.add_indicator(ScanIndicator(
                indicator_type="IP Address URL",
                description="URL uses a raw IP address instead of a domain name.",
                severity="high",
                score_impact=20,
            ))

        # Suspicious URL patterns
        for pattern in SCAM_URL_PATTERNS:
            if re.search(pattern, url_l):
                result.add_indicator(ScanIndicator(
                    indicator_type="Suspicious URL Pattern",
                    description=f"URL contains a suspicious pattern: '{pattern}'.",
                    severity="high",
                    score_impact=18,
                    details=f"Pattern matched: {pattern}",
                ))
                break  # One hit is enough to flag

        # Suspicious domain patterns
        for pattern in SCAM_DOMAIN_PATTERNS:
            if re.search(pattern, domain_l):
                result.add_indicator(ScanIndicator(
                    indicator_type="Suspicious Domain Pattern",
                    description=f"Domain contains a Nigerian phishing pattern: '{pattern}'.",
                    severity="high",
                    score_impact=20,
                    details=f"Pattern matched: {pattern}",
                ))
                break

        # Lots of hyphens
        if domain_l.count("-") > 3:
            result.add_indicator(ScanIndicator(
                indicator_type="Excessive Hyphens",
                description=f"Domain contains {domain_l.count('-')} hyphens, unusual for legitimate sites.",
                severity="low",
                score_impact=5,
            ))

        # Very long URL
        if len(result.scanned_url) > 150:
            result.add_indicator(ScanIndicator(
                indicator_type="Unusually Long URL",
                description="URL is abnormally long, possibly to confuse or hide the real destination.",
                severity="low",
                score_impact=5,
            ))

        # Numeric padding in domain
        if re.search(r"\d{4,}", domain_l.split(".")[0]):
            result.add_indicator(ScanIndicator(
                indicator_type="Numeric Padding in Domain",
                description="Domain contains a long number sequence, unusual for official sites.",
                severity="low",
                score_impact=5,
            ))

    def _check_official_domain(self, result: ScanResult):
        """Check if domain is an official Nigerian brand or an impersonation."""
        # Check exact official match
        brand = lookup_domain(result.domain)
        if brand:
            result.is_official_domain = True
            result.official_brand = brand.name
            # Official domain - reduce risk score
            result.risk_score = max(0, result.risk_score - 20)
            result._update_risk_level()
            return

        # Check for impersonation
        impersonated = find_impersonated_brand(result.domain)
        if impersonated:
            result.scam_category = ScamCategory.BRAND_IMPERSONATION
            result.add_indicator(ScanIndicator(
                indicator_type="Brand Impersonation",
                description=(
                    f"Domain appears to impersonate '{impersonated.name}'. "
                    f"Official domain(s): {', '.join(impersonated.official_domains)}"
                ),
                severity="critical",
                score_impact=40,
                details=f"Suspected brand: {impersonated.name} ({impersonated.category})",
            ))

    def _check_local_db(self, result: ScanResult):
        """Check against the local SQLite scam domain database."""
        if not self.db:
            return
        try:
            verdict = self.db.check_domain(result.domain)
            if verdict:
                result.local_db_match = True
                result.local_db_verdict = verdict
                result.add_indicator(ScanIndicator(
                    indicator_type="Known Scam Domain",
                    description=f"Domain found in local scam database: {verdict}",
                    severity="critical",
                    score_impact=50,
                ))
        except Exception as e:
            logger.debug("Local DB check error: %s", e)

    def _check_virustotal(self, result: ScanResult):
        """Query VirusTotal API for domain reputation."""
        try:
            url_id = hashlib.sha256(result.domain.encode()).hexdigest()
            api_url = f"https://www.virustotal.com/api/v3/domains/{result.domain}"
            resp = self.session.get(
                api_url,
                headers={"x-apikey": self.config.virustotal_api_key},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) if stats else 0

                vt_result = ThreatIntelResult(
                    source="VirusTotal",
                    is_malicious=malicious > 0,
                    detection_count=malicious + suspicious,
                    total_engines=total,
                    permalink=f"https://www.virustotal.com/gui/domain/{result.domain}",
                    scan_date=datetime.utcnow(),
                )
                result.threat_intel.append(vt_result)

                if malicious > 3:
                    result.add_indicator(ScanIndicator(
                        indicator_type="VirusTotal Malicious",
                        description=f"VirusTotal: {malicious}/{total} engines flagged this domain.",
                        severity="critical",
                        score_impact=40,
                        details=f"Detections: {malicious} malicious, {suspicious} suspicious",
                    ))
                elif malicious > 0 or suspicious > 2:
                    result.add_indicator(ScanIndicator(
                        indicator_type="VirusTotal Suspicious",
                        description=f"VirusTotal: {malicious + suspicious}/{total} engines flagged this domain.",
                        severity="high",
                        score_impact=20,
                    ))
        except Exception as e:
            logger.debug("VirusTotal API error: %s", e)

    def _check_phishtank(self, result: ScanResult):
        """Query PhishTank for phishing reports."""
        try:
            data = {"url": result.scanned_url, "format": "json"}
            if self.config.phishtank_api_key:
                data["app_key"] = self.config.phishtank_api_key
            resp = self.session.post(
                "https://checkurl.phishtank.com/checkurl/",
                data=data,
                timeout=10,
            )
            if resp.status_code == 200:
                jdata = resp.json()
                results = jdata.get("results", {})
                in_database = results.get("in_database", False)
                verified = results.get("verified", False)

                pt_result = ThreatIntelResult(
                    source="PhishTank",
                    is_malicious=verified,
                    scan_date=datetime.utcnow(),
                )
                result.threat_intel.append(pt_result)

                if verified:
                    result.add_indicator(ScanIndicator(
                        indicator_type="PhishTank Verified Phishing",
                        description="This URL is confirmed as a phishing site by PhishTank.",
                        severity="critical",
                        score_impact=45,
                        details=results.get("phish_detail_page", ""),
                    ))
                elif in_database:
                    result.add_indicator(ScanIndicator(
                        indicator_type="PhishTank Reported",
                        description="This URL has been reported to PhishTank as potential phishing.",
                        severity="high",
                        score_impact=25,
                    ))
        except Exception as e:
            logger.debug("PhishTank API error: %s", e)

    def _detect_scam_category(self, result: ScanResult):
        """Assign a Nigerian scam category based on indicators and domain analysis."""
        if result.scam_category:
            return  # Already set by impersonation check

        domain_l = result.domain.lower()
        url_l = result.scanned_url.lower()
        title_l = (result.page_title or "").lower()
        combined = domain_l + " " + url_l + " " + title_l

        category_rules = [
            (ScamCategory.FAKE_BANK, [
                "bank", "gtb", "zenith", "access", "firstbank", "uba", "fcmb",
                "fidelity", "sterling", "union", "wema", "heritage",
            ]),
            (ScamCategory.FAKE_FINTECH, [
                "opay", "kuda", "palmpay", "moniepoint", "carbon", "paylater",
                "piggy", "cowry", "flutterwave", "paystack",
            ]),
            (ScamCategory.FAKE_DELIVERY, [
                "delivery", "logistics", "courier", "dhl", "gig", "pickup",
                "parcel", "tracking", "shipment",
            ]),
            (ScamCategory.FAKE_BETTING, [
                "bet9ja", "sportybet", "betking", "1xbet", "nairabet",
                "prediction", "win-bet", "soccer-bet",
            ]),
            (ScamCategory.INVESTMENT_FRAUD, [
                "investment", "daily-profit", "returns", "roi", "passive-income",
                "double-money", "ponzi", "pyramid",
            ]),
            (ScamCategory.FAKE_CRYPTO, [
                "crypto", "bitcoin", "ethereum", "nft", "play-to-earn",
                "p2e", "web3-earn", "defi-profit",
            ]),
            (ScamCategory.GOVT_IMPERSONATION, [
                "cbn", "efcc", "firs", "nimc", "jamb", "waec", "neco",
                "dpr", "frsc", "cac", "police", "government", "gov-ng",
            ]),
        ]

        for category, keywords in category_rules:
            if any(kw in combined for kw in keywords):
                result.scam_category = category
                break

    def _finalize(self, result: ScanResult):
        """Generate summary text and recommendation based on findings."""
        result._update_risk_level()

        if result.is_official_domain:
            result.summary = (
                f"✅ This is a verified official domain for {result.official_brand}. "
                "Always double-check the full URL before entering any credentials."
            )
            result.recommendation = (
                "This domain appears to be legitimate. Still exercise caution "
                "when entering sensitive information online."
            )
            return

        n = len(result.indicators)
        cat = result.scam_category.value if result.scam_category else "suspicious activity"

        if result.risk_level == RiskLevel.SAFE:
            result.summary = "No significant threats detected. This site appears safe."
            result.recommendation = "The URL appears safe. Stay cautious online regardless."

        elif result.risk_level == RiskLevel.SUSPICIOUS:
            result.summary = (
                f"⚠️ {n} suspicious indicator(s) detected. Exercise caution before proceeding."
            )
            result.recommendation = (
                "Do not enter passwords, BVN, NIN, or banking details. "
                "Verify the site independently before trusting it."
            )

        elif result.risk_level == RiskLevel.HIGH_RISK:
            result.summary = (
                f"🚨 HIGH RISK: {n} threat indicator(s) detected. "
                f"Possible {cat}."
            )
            result.recommendation = (
                "Do NOT interact with this site. Do not enter any personal, "
                "financial, or identity information. Close this page immediately."
            )

        else:  # LIKELY_SCAM
            result.summary = (
                f"🔴 LIKELY SCAM: {n} critical indicator(s) detected. "
                f"High probability of {cat}."
            )
            result.recommendation = (
                "🚫 STOP. This site is almost certainly a scam. "
                "Do NOT enter any information. Report to EFCC: efcc.gov.ng. "
                "If you already entered details, contact your bank immediately."
            )
