"""
core/models.py - Data Models for Scan Results
Author: Joshua Akadri
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum


class RiskLevel(str, Enum):
    SAFE = "Safe"
    SUSPICIOUS = "Suspicious"
    HIGH_RISK = "High Risk"
    LIKELY_SCAM = "Likely Scam"
    UNKNOWN = "Unknown"


class ScamCategory(str, Enum):
    FAKE_BANK = "Fake Banking Website"
    FAKE_FINTECH = "Fake Fintech Portal"
    FAKE_DELIVERY = "Fake Delivery/Logistics"
    FAKE_BETTING = "Fake Betting Platform"
    INVESTMENT_FRAUD = "Investment / Ponzi Scheme"
    FAKE_CRYPTO = "Fake Crypto / Play-to-Earn"
    GOVT_IMPERSONATION = "Government Agency Impersonation"
    BRAND_IMPERSONATION = "Brand Impersonation"
    PHISHING = "Phishing"
    TYPOSQUATTING = "Typosquatting"
    URL_SHORTENER = "URL Shortener / Redirect"
    MALWARE = "Malware Distribution"
    UNKNOWN = "Unknown"


@dataclass
class ScanIndicator:
    """A single detected security indicator."""
    indicator_type: str
    description: str
    severity: str  # "low", "medium", "high", "critical"
    score_impact: int  # how much this adds to risk score (0-25)
    details: Optional[str] = None


@dataclass
class WhoisInfo:
    """WHOIS lookup result."""
    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    age_days: Optional[int] = None
    country: Optional[str] = None
    registrant_email: Optional[str] = None
    name_servers: List[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class CertificateInfo:
    """SSL/TLS certificate information."""
    valid: bool = False
    issuer: Optional[str] = None
    subject: Optional[str] = None
    expires: Optional[datetime] = None
    days_remaining: Optional[int] = None
    is_ev: bool = False
    error: Optional[str] = None


@dataclass
class ThreatIntelResult:
    """Result from an external threat intelligence source."""
    source: str  # e.g., "VirusTotal", "PhishTank"
    is_malicious: bool = False
    detection_count: int = 0
    total_engines: int = 0
    categories: List[str] = field(default_factory=list)
    permalink: Optional[str] = None
    scan_date: Optional[datetime] = None
    error: Optional[str] = None


@dataclass
class ScanResult:
    """Complete result of a URL scan."""
    # Input
    original_url: str
    scanned_url: str  # after resolving redirects
    domain: str
    scan_id: Optional[int] = None

    # Timing
    scan_time: datetime = field(default_factory=datetime.utcnow)
    duration_ms: int = 0

    # Risk assessment
    risk_score: int = 0  # 0-100
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    scam_category: Optional[ScamCategory] = None
    is_official_domain: bool = False
    official_brand: Optional[str] = None

    # Detailed findings
    indicators: List[ScanIndicator] = field(default_factory=list)
    whois: Optional[WhoisInfo] = None
    certificate: Optional[CertificateInfo] = None
    threat_intel: List[ThreatIntelResult] = field(default_factory=list)

    # Page metadata
    page_title: Optional[str] = None
    page_description: Optional[str] = None
    final_url: Optional[str] = None
    redirect_chain: List[str] = field(default_factory=list)
    ip_address: Optional[str] = None
    hosting_country: Optional[str] = None

    # Local DB match
    local_db_match: bool = False
    local_db_verdict: Optional[str] = None

    # Summary
    summary: str = ""
    recommendation: str = ""
    error: Optional[str] = None

    def add_indicator(self, indicator: ScanIndicator):
        self.indicators.append(indicator)
        self.risk_score = min(100, self.risk_score + indicator.score_impact)
        self._update_risk_level()

    def _update_risk_level(self):
        if self.risk_score <= 15:
            self.risk_level = RiskLevel.SAFE
        elif self.risk_score <= 40:
            self.risk_level = RiskLevel.SUSPICIOUS
        elif self.risk_score <= 65:
            self.risk_level = RiskLevel.HIGH_RISK
        else:
            self.risk_level = RiskLevel.LIKELY_SCAM

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for storage/export."""
        return {
            "scan_id": self.scan_id,
            "original_url": self.original_url,
            "scanned_url": self.scanned_url,
            "domain": self.domain,
            "scan_time": self.scan_time.isoformat(),
            "duration_ms": self.duration_ms,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "scam_category": self.scam_category.value if self.scam_category else None,
            "is_official_domain": self.is_official_domain,
            "official_brand": self.official_brand,
            "indicators": [
                {
                    "type": i.indicator_type,
                    "description": i.description,
                    "severity": i.severity,
                    "score_impact": i.score_impact,
                    "details": i.details,
                }
                for i in self.indicators
            ],
            "page_title": self.page_title,
            "final_url": self.final_url,
            "redirect_chain": self.redirect_chain,
            "ip_address": self.ip_address,
            "hosting_country": self.hosting_country,
            "local_db_match": self.local_db_match,
            "local_db_verdict": self.local_db_verdict,
            "summary": self.summary,
            "recommendation": self.recommendation,
            "error": self.error,
        }
