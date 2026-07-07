"""
tests/test_scanner.py - Unit Tests for Naija Scam Shield
Author: Joshua Akadri
"""

import unittest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.models import ScanResult, ScanIndicator, RiskLevel, ScamCategory
from core.nigerian_brands import (
    lookup_domain, find_impersonated_brand,
    OFFICIAL_DOMAIN_MAP, ALL_BRANDS, URL_SHORTENERS
)
from core.config import AppConfig


# ── Model Tests ───────────────────────────────────────────────────────────────

class TestScanResult(unittest.TestCase):

    def setUp(self):
        self.result = ScanResult(
            original_url="https://test.com",
            scanned_url="https://test.com",
            domain="test.com",
        )

    def test_initial_risk_level_unknown(self):
        self.assertEqual(self.result.risk_level, RiskLevel.UNKNOWN)

    def test_risk_score_increments_with_indicator(self):
        ind = ScanIndicator(
            indicator_type="Test",
            description="Test indicator",
            severity="high",
            score_impact=20,
        )
        self.result.add_indicator(ind)
        self.assertEqual(self.result.risk_score, 20)

    def test_risk_level_safe(self):
        self.result.risk_score = 10
        self.result._update_risk_level()
        self.assertEqual(self.result.risk_level, RiskLevel.SAFE)

    def test_risk_level_suspicious(self):
        self.result.risk_score = 30
        self.result._update_risk_level()
        self.assertEqual(self.result.risk_level, RiskLevel.SUSPICIOUS)

    def test_risk_level_high_risk(self):
        self.result.risk_score = 55
        self.result._update_risk_level()
        self.assertEqual(self.result.risk_level, RiskLevel.HIGH_RISK)

    def test_risk_level_likely_scam(self):
        self.result.risk_score = 80
        self.result._update_risk_level()
        self.assertEqual(self.result.risk_level, RiskLevel.LIKELY_SCAM)

    def test_risk_score_capped_at_100(self):
        for _ in range(10):
            self.result.add_indicator(ScanIndicator(
                indicator_type="X", description="x", severity="critical", score_impact=20
            ))
        self.assertEqual(self.result.risk_score, 100)

    def test_to_dict_serialization(self):
        d = self.result.to_dict()
        self.assertIn("original_url", d)
        self.assertIn("risk_score", d)
        self.assertIn("risk_level", d)
        self.assertEqual(d["original_url"], "https://test.com")


# ── Nigerian Brands Registry Tests ───────────────────────────────────────────

class TestNigerianBrandsRegistry(unittest.TestCase):

    def test_official_domain_map_populated(self):
        self.assertGreater(len(OFFICIAL_DOMAIN_MAP), 50)

    def test_lookup_gtbank_official(self):
        brand = lookup_domain("gtbank.com")
        self.assertIsNotNone(brand)
        self.assertIn("GTBank", brand.name)

    def test_lookup_zenithbank_official(self):
        brand = lookup_domain("zenithbank.com")
        self.assertIsNotNone(brand)
        self.assertIn("Zenith", brand.name)

    def test_lookup_cbn_official(self):
        brand = lookup_domain("cbn.gov.ng")
        self.assertIsNotNone(brand)
        self.assertIn("Central Bank", brand.name)

    def test_lookup_opay_official(self):
        brand = lookup_domain("opayweb.com")
        self.assertIsNotNone(brand)
        self.assertIn("Opay", brand.name)

    def test_lookup_unknown_domain_returns_none(self):
        result = lookup_domain("totally-random-domain-xyz123.com")
        self.assertIsNone(result)

    def test_lookup_case_insensitive(self):
        brand = lookup_domain("GTBANK.COM")
        self.assertIsNotNone(brand)

    def test_find_impersonated_gtbank(self):
        brand = find_impersonated_brand("gtbankng-verify.com")
        self.assertIsNotNone(brand)

    def test_find_impersonated_opay_typo(self):
        brand = find_impersonated_brand("opayng-promo.com")
        self.assertIsNotNone(brand)

    def test_official_domain_not_flagged_as_impersonation(self):
        # Official domains should not come back as impersonations
        brand = lookup_domain("gtbank.com")
        self.assertIsNotNone(brand)
        self.assertTrue(brand.is_official("gtbank.com"))

    def test_all_brands_have_at_least_one_domain(self):
        for brand in ALL_BRANDS:
            self.assertGreater(
                len(brand.official_domains), 0,
                f"Brand '{brand.name}' has no official domains"
            )

    def test_url_shorteners_set_not_empty(self):
        self.assertIn("bit.ly", URL_SHORTENERS)
        self.assertIn("tinyurl.com", URL_SHORTENERS)

    def test_all_brands_have_category(self):
        for brand in ALL_BRANDS:
            self.assertIn(
                brand.category,
                {"bank", "fintech", "government", "telecom", "ecommerce", "logistics", "betting"},
                f"Brand '{brand.name}' has unexpected category '{brand.category}'"
            )


# ── Scanner URL Analysis Tests (no network) ──────────────────────────────────

class TestURLPatternAnalysis(unittest.TestCase):

    def setUp(self):
        self.config = AppConfig()
        self.config.offline_mode = True
        self.config.enable_whois = False
        self.config.enable_virustotal = False
        self.config.enable_phishtank = False

    def _scan_offline(self, url: str) -> ScanResult:
        """Run only offline checks against a URL."""
        from core.scanner import Scanner
        scanner = Scanner(self.config, db=None)
        result = ScanResult(
            original_url=url,
            scanned_url=url,
            domain=scanner._extract_domain(url),
        )
        scanner._analyze_url_patterns(result)
        scanner._check_official_domain(result)
        scanner._detect_scam_category(result)
        scanner._finalize(result)
        return result

    def test_ip_address_url_flagged(self):
        result = self._scan_offline("http://192.168.1.1/banking")
        types = [i.indicator_type for i in result.indicators]
        self.assertIn("IP Address URL", types)

    def test_suspicious_tld_xyz_flagged(self):
        result = self._scan_offline("http://nigeriangov-rewards.xyz")
        types = [i.indicator_type for i in result.indicators]
        self.assertIn("Suspicious TLD", types)

    def test_url_shortener_flagged(self):
        result = self._scan_offline("https://bit.ly/abc123")
        types = [i.indicator_type for i in result.indicators]
        self.assertIn("URL Shortener", types)

    def test_official_gtbank_domain_detected(self):
        result = self._scan_offline("https://gtbank.com/login")
        self.assertTrue(result.is_official_domain)
        self.assertIn("GTBank", result.official_brand)

    def test_official_cbn_domain_detected(self):
        result = self._scan_offline("https://cbn.gov.ng/policy")
        self.assertTrue(result.is_official_domain)
        self.assertIn("Central Bank", result.official_brand)

    def test_suspicious_verify_account_pattern(self):
        result = self._scan_offline("http://verify-account.ng-bank-secure.com")
        self.assertGreater(result.risk_score, 0)

    def test_brand_impersonation_zenith_detected(self):
        result = self._scan_offline("https://zenithbankng-secure.com")
        types = [i.indicator_type for i in result.indicators]
        self.assertIn("Brand Impersonation", types)

    def test_safe_known_site_no_extra_flags(self):
        result = self._scan_offline("https://cbn.gov.ng")
        self.assertTrue(result.is_official_domain)

    def test_excessive_subdomains_flagged(self):
        result = self._scan_offline("http://secure.login.verify.gtb.banking.scam.com")
        types = [i.indicator_type for i in result.indicators]
        self.assertIn("Excessive Subdomains", types)

    def test_suspicious_gq_tld_flagged(self):
        result = self._scan_offline("http://mtn-free-airtime.gq")
        types = [i.indicator_type for i in result.indicators]
        self.assertIn("Suspicious TLD", types)


# ── Database Tests ────────────────────────────────────────────────────────────

class TestDatabaseManager(unittest.TestCase):

    def setUp(self):
        import tempfile
        self.tmpdir = tempfile.mkdtemp()
        from database.db_manager import DatabaseManager
        self.db = DatabaseManager(Path(self.tmpdir) / "test.db")
        self.db.initialize()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_seed_scam_domains_loaded(self):
        domains = self.db.get_scam_domains()
        self.assertGreater(len(domains), 0)

    def test_check_known_scam_domain(self):
        verdict = self.db.check_domain("cbn-reward-portal.com")
        self.assertIsNotNone(verdict)

    def test_check_clean_domain_returns_none(self):
        verdict = self.db.check_domain("gtbank.com")
        self.assertIsNone(verdict)

    def test_is_official_domain_detected(self):
        brand = self.db.is_official("gtbank.com")
        self.assertIsNotNone(brand)
        self.assertIn("GTBank", brand)

    def test_add_and_check_custom_scam_domain(self):
        self.db.add_scam_domain(
            "fake-opay-promo.com", "FAKE_FINTECH", "Test scam", "test"
        )
        verdict = self.db.check_domain("fake-opay-promo.com")
        self.assertIsNotNone(verdict)

    def test_save_and_retrieve_scan(self):
        result = ScanResult(
            original_url="https://test-scan.com",
            scanned_url="https://test-scan.com",
            domain="test-scan.com",
            risk_score=65,
            risk_level=RiskLevel.HIGH_RISK,
        )
        result.scan_id = self.db.save_scan(result)
        self.assertIsNotNone(result.scan_id)

        history = self.db.get_scan_history()
        domains = [h["domain"] for h in history]
        self.assertIn("test-scan.com", domains)

    def test_get_history_stats(self):
        stats = self.db.get_history_stats()
        self.assertIn("total", stats)
        self.assertIn("threats_detected", stats)
        self.assertIn("safe", stats)

    def test_clear_history(self):
        result = ScanResult(
            original_url="https://clear-test.com",
            scanned_url="https://clear-test.com",
            domain="clear-test.com",
        )
        self.db.save_scan(result)
        self.db.clear_history()
        history = self.db.get_scan_history()
        self.assertEqual(len(history), 0)

    def test_add_user_report(self):
        self.db.add_user_report("https://scam-site.com", "scam-site.com", "Looks suspicious")
        reports = self.db.get_user_reports()
        urls = [r["url"] for r in reports]
        self.assertIn("https://scam-site.com", urls)


# ── Config Tests ──────────────────────────────────────────────────────────────

class TestAppConfig(unittest.TestCase):

    def test_config_creates_directories(self):
        config = AppConfig()
        self.assertTrue(config.data_dir.exists())
        self.assertTrue(config.reports_dir.exists())

    def test_default_theme_is_dark(self):
        config = AppConfig()
        self.assertEqual(config.theme, "dark")

    def test_default_offline_mode_false(self):
        config = AppConfig()
        self.assertFalse(config.offline_mode)


# ── Report Generator Tests ────────────────────────────────────────────────────

class TestReportGenerator(unittest.TestCase):

    def setUp(self):
        import tempfile
        self.tmpdir = Path(tempfile.mkdtemp())
        self.config = AppConfig()
        self.config.reports_dir = self.tmpdir
        from reports.report_generator import ReportGenerator
        self.gen = ReportGenerator(self.config)

    def tearDown(self):
        import shutil
        shutil.rmtree(str(self.tmpdir), ignore_errors=True)

    def test_csv_export_creates_file(self):
        results = [
            ScanResult(
                original_url="https://test.com",
                scanned_url="https://test.com",
                domain="test.com",
                risk_score=30,
                risk_level=RiskLevel.SUSPICIOUS,
            )
        ]
        path = self.gen.export_csv(results)
        self.assertIsNotNone(path)
        self.assertTrue(path.exists())

    def test_csv_export_has_correct_headers(self):
        results = [ScanResult(
            original_url="https://x.com",
            scanned_url="https://x.com",
            domain="x.com",
        )]
        path = self.gen.export_csv(results)
        import csv
        with open(path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames
        self.assertIn("domain", headers)
        self.assertIn("risk_level", headers)
        self.assertIn("risk_score", headers)

    def test_json_export_creates_file(self):
        results = [ScanResult(
            original_url="https://x.com",
            scanned_url="https://x.com",
            domain="x.com",
        )]
        path = self.gen.export_json(results)
        self.assertIsNotNone(path)
        self.assertTrue(path.exists())

    def test_pdf_export_skips_gracefully_without_reportlab(self):
        """If reportlab is unavailable, export_pdf should return None gracefully."""
        import reports.report_generator as rg
        original = rg.REPORTLAB_AVAILABLE
        rg.REPORTLAB_AVAILABLE = False
        result = ScanResult(
            original_url="https://x.com",
            scanned_url="https://x.com",
            domain="x.com",
        )
        path = self.gen.export_pdf(result)
        rg.REPORTLAB_AVAILABLE = original
        self.assertIsNone(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
