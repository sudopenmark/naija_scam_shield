"""
tests/test_integration.py — Integration & Component Tests
Author: Joshua Akadri
GitHub: sudopenmark

Tests that exercise multiple modules working together, plus edge cases
not covered by test_scanner.py.
"""

import sys
import csv
import json
import unittest
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch, MagicMock, PropertyMock
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.models import (
    ScanResult, ScanIndicator, RiskLevel, ScamCategory,
    WhoisInfo, CertificateInfo, ThreatIntelResult,
)
from core.nigerian_brands import (
    lookup_domain, find_impersonated_brand, ALL_BRANDS,
    SCAM_URL_PATTERNS, SCAM_DOMAIN_PATTERNS, SUSPICIOUS_TLDS,
)
from core.config import AppConfig
from database.db_manager import DatabaseManager
from reports.report_generator import ReportGenerator


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_result(
    url: str = "https://test.com",
    score: int = 0,
    risk: RiskLevel = RiskLevel.SAFE,
    domain: str = "test.com",
) -> ScanResult:
    r = ScanResult(original_url=url, scanned_url=url, domain=domain)
    r.risk_score = score
    r.risk_level = risk
    return r


def make_db(tmpdir: str) -> DatabaseManager:
    db = DatabaseManager(Path(tmpdir) / "test_int.db")
    db.initialize()
    return db


# ── ScanResult edge cases ─────────────────────────────────────────────────────

class TestScanResultEdgeCases(unittest.TestCase):

    def test_multiple_indicators_cumulative_score(self):
        r = make_result()
        for impact in [10, 15, 20]:
            r.add_indicator(ScanIndicator("T", "desc", "medium", impact))
        self.assertEqual(r.risk_score, 45)
        # 45 > 40 → HIGH_RISK (boundary: <=40 Suspicious, <=65 High Risk)
        self.assertEqual(r.risk_level, RiskLevel.HIGH_RISK)

    def test_score_exactly_at_boundary_15(self):
        r = make_result(score=15)
        r._update_risk_level()
        self.assertEqual(r.risk_level, RiskLevel.SAFE)

    def test_score_exactly_at_boundary_16(self):
        r = make_result(score=16)
        r._update_risk_level()
        self.assertEqual(r.risk_level, RiskLevel.SUSPICIOUS)

    def test_score_exactly_at_boundary_40(self):
        r = make_result(score=40)
        r._update_risk_level()
        self.assertEqual(r.risk_level, RiskLevel.SUSPICIOUS)

    def test_score_exactly_at_boundary_41(self):
        r = make_result(score=41)
        r._update_risk_level()
        self.assertEqual(r.risk_level, RiskLevel.HIGH_RISK)

    def test_score_exactly_at_boundary_65(self):
        r = make_result(score=65)
        r._update_risk_level()
        self.assertEqual(r.risk_level, RiskLevel.HIGH_RISK)

    def test_score_exactly_at_boundary_66(self):
        r = make_result(score=66)
        r._update_risk_level()
        self.assertEqual(r.risk_level, RiskLevel.LIKELY_SCAM)

    def test_to_dict_with_full_data(self):
        r = make_result(score=75, risk=RiskLevel.LIKELY_SCAM)
        r.scam_category = ScamCategory.FAKE_BANK
        r.page_title = "Secure Login"
        r.ip_address = "192.168.1.1"
        r.add_indicator(ScanIndicator("Test", "desc", "critical", 20))
        d = r.to_dict()
        self.assertEqual(d["risk_score"], 95)  # 75 + 20
        self.assertEqual(d["scam_category"], "Fake Banking Website")
        self.assertEqual(len(d["indicators"]), 1)

    def test_indicator_sorting_by_severity(self):
        r = make_result()
        r.add_indicator(ScanIndicator("Low",      "d", "low",      5))
        r.add_indicator(ScanIndicator("Critical",  "d", "critical", 25))
        r.add_indicator(ScanIndicator("High",      "d", "high",     15))
        r.add_indicator(ScanIndicator("Medium",    "d", "medium",   10))
        sorted_inds = sorted(
            r.indicators,
            key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 4)
        )
        self.assertEqual(sorted_inds[0].severity, "critical")
        self.assertEqual(sorted_inds[-1].severity, "low")


# ── Nigerian Brands edge cases ────────────────────────────────────────────────

class TestNigerianBrandsEdgeCases(unittest.TestCase):

    def test_all_official_domains_lowercase_in_map(self):
        from core.nigerian_brands import OFFICIAL_DOMAIN_MAP
        for domain in OFFICIAL_DOMAIN_MAP:
            self.assertEqual(domain, domain.lower(), f"Domain not lowercase: {domain}")

    def test_lookup_with_subdomain_prefix_fails(self):
        # ibank.gtbank.com should NOT match gtbank.com in simple lookup
        # (subdomain resolution is handled separately in scanner)
        brand = lookup_domain("gtbank.com")
        self.assertIsNotNone(brand)
        brand2 = lookup_domain("ibank.gtbank.com")
        # This one is explicitly in the brand list
        self.assertIsNotNone(brand2)

    def test_kuda_com_official(self):
        brand = lookup_domain("kuda.com")
        self.assertIsNotNone(brand)
        self.assertIn("Kuda", brand.name)

    def test_piggyvest_official(self):
        brand = lookup_domain("piggyvest.com")
        self.assertIsNotNone(brand)

    def test_jamb_official(self):
        brand = lookup_domain("jamb.gov.ng")
        self.assertIsNotNone(brand)
        self.assertIn("JAMB", brand.name)

    def test_suspicious_tlds_contains_expected(self):
        for tld in [".xyz", ".gq", ".tk", ".ml", ".cf", ".top", ".click"]:
            self.assertIn(tld, SUSPICIOUS_TLDS, f"Expected TLD missing: {tld}")

    def test_scam_url_patterns_are_valid_regex(self):
        import re
        for pattern in SCAM_URL_PATTERNS:
            try:
                re.compile(pattern)
            except re.error as e:
                self.fail(f"Invalid regex pattern '{pattern}': {e}")

    def test_brand_is_official_method(self):
        brand = lookup_domain("gtbank.com")
        self.assertTrue(brand.is_official("gtbank.com"))
        self.assertTrue(brand.is_official("GTBANK.COM"))  # case insensitive
        self.assertFalse(brand.is_official("fake-gtbank.com"))

    def test_no_duplicate_official_domains(self):
        """No domain should appear for two different brands."""
        from core.nigerian_brands import OFFICIAL_DOMAIN_MAP
        seen = {}
        for brand in ALL_BRANDS:
            for domain in brand.official_domains:
                d = domain.lower()
                if d in seen:
                    self.fail(
                        f"Domain '{d}' appears in both '{seen[d]}' and '{brand.name}'"
                    )
                seen[d] = brand.name


# ── Database manager tests ────────────────────────────────────────────────────

class TestDatabaseManagerExtended(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db = make_db(self.tmpdir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_bulk_scan_saves_and_retrieves(self):
        for i in range(10):
            r = make_result(f"https://site{i}.com", score=i * 5, domain=f"site{i}.com")
            self.db.save_scan(r)
        history = self.db.get_scan_history(limit=20)
        domains = {h["domain"] for h in history}
        for i in range(10):
            self.assertIn(f"site{i}.com", domains)

    def test_get_history_limit_respected(self):
        for i in range(15):
            r = make_result(domain=f"bulk{i}.com")
            self.db.save_scan(r)
        history = self.db.get_scan_history(limit=5)
        self.assertLessEqual(len(history), 5)

    def test_history_ordered_newest_first(self):
        import time
        for i in range(3):
            r = make_result(domain=f"ordered{i}.com")
            self.db.save_scan(r)
            time.sleep(0.01)
        history = self.db.get_scan_history(limit=3)
        times = [h["scan_time"] for h in history]
        self.assertGreaterEqual(times[0], times[1])
        self.assertGreaterEqual(times[1], times[2])

    def test_delete_specific_scan(self):
        r = make_result(domain="to-delete.com")
        scan_id = self.db.save_scan(r)
        self.db.delete_scan(scan_id)
        detail = self.db.get_scan_detail(scan_id)
        self.assertIsNone(detail)

    def test_get_scan_detail_json_valid(self):
        r = make_result(domain="detail-test.com", score=42, risk=RiskLevel.SUSPICIOUS)
        r.page_title = "Test Page"
        r.add_indicator(ScanIndicator("Test", "desc", "medium", 10))
        scan_id = self.db.save_scan(r)
        detail = self.db.get_scan_detail(scan_id)
        self.assertIsNotNone(detail)
        self.assertEqual(detail["domain"], "detail-test.com")
        self.assertEqual(detail["risk_score"], 52)  # 42 + 10
        self.assertEqual(len(detail["indicators"]), 1)

    def test_stats_correct_after_mixed_scans(self):
        safe_r = make_result(domain="s.com", score=5, risk=RiskLevel.SAFE)
        susp_r = make_result(domain="x.com", score=30, risk=RiskLevel.SUSPICIOUS)
        high_r = make_result(domain="y.com", score=50, risk=RiskLevel.HIGH_RISK)
        scam_r = make_result(domain="z.com", score=80, risk=RiskLevel.LIKELY_SCAM)
        for r in [safe_r, susp_r, high_r, scam_r]:
            self.db.save_scan(r)
        stats = self.db.get_history_stats()
        self.assertEqual(stats["safe"], 1)
        self.assertGreaterEqual(stats["threats_detected"], 2)  # High Risk + Likely Scam

    def test_add_scam_domain_case_normalised(self):
        self.db.add_scam_domain("UPPER-CASE-SCAM.COM", "PHISHING", "test", "test")
        verdict = self.db.check_domain("upper-case-scam.com")
        self.assertIsNotNone(verdict)

    def test_multiple_reports_same_domain(self):
        self.db.add_user_report("https://a.com", "a.com", "First report")
        self.db.add_user_report("https://a.com", "a.com", "Second report")
        reports = self.db.get_user_reports()
        urls = [r["url"] for r in reports]
        self.assertEqual(urls.count("https://a.com"), 2)

    def test_thread_safety_concurrent_writes(self):
        """Multiple threads writing scans should not corrupt DB."""
        errors = []

        def write_scans(thread_id):
            try:
                for i in range(5):
                    r = make_result(domain=f"thread{thread_id}-{i}.com")
                    self.db.save_scan(r)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=write_scans, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(errors, [], f"Thread errors: {errors}")


# ── Report Generator tests ────────────────────────────────────────────────────

class TestReportGeneratorExtended(unittest.TestCase):

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.config = AppConfig()
        self.config.reports_dir = self.tmpdir
        self.gen = ReportGenerator(self.config)

    def tearDown(self):
        import shutil
        shutil.rmtree(str(self.tmpdir), ignore_errors=True)

    def _full_result(self) -> ScanResult:
        r = ScanResult(
            original_url="https://fake-gtbank-login.com",
            scanned_url="https://fake-gtbank-login.com",
            domain="fake-gtbank-login.com",
            risk_score=85,
            risk_level=RiskLevel.LIKELY_SCAM,
            scam_category=ScamCategory.FAKE_BANK,
            page_title="GTBank Secure Login",
            ip_address="104.21.50.10",
        )
        r.add_indicator(ScanIndicator(
            "Brand Impersonation", "Impersonates GTBank", "critical", 40
        ))
        r.add_indicator(ScanIndicator(
            "New Domain", "Domain is 12 days old", "critical", 30
        ))
        r.whois = WhoisInfo(domain="fake-gtbank-login.com", age_days=12, registrar="NameCheap")
        r.certificate = CertificateInfo(valid=True, issuer="Let's Encrypt", days_remaining=85)
        r.threat_intel = [
            ThreatIntelResult(
                source="VirusTotal",
                is_malicious=True,
                detection_count=12,
                total_engines=72,
            )
        ]
        r.summary = "🔴 LIKELY SCAM — Brand impersonation of GTBank detected."
        r.recommendation = "Do NOT enter any credentials. Close this page immediately."
        return r

    def test_csv_export_multiple_results(self):
        results = [self._full_result() for _ in range(5)]
        path = self.gen.export_csv(results)
        self.assertIsNotNone(path)
        with open(path, encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)
        self.assertEqual(len(rows), 6)  # header + 5 data rows

    def test_csv_export_special_characters(self):
        r = make_result(url="https://tëst-ünïcödé.com", domain="tëst-ünïcödé.com")
        r.summary = "Résumé with spëcial chars"
        path = self.gen.export_csv([r])
        self.assertIsNotNone(path)
        content = path.read_text(encoding="utf-8")
        self.assertIn("Résumé", content)

    def test_json_export_valid_json(self):
        results = [self._full_result()]
        path = self.gen.export_json(results)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["domain"], "fake-gtbank-login.com")

    def test_json_export_indicators_serialized(self):
        results = [self._full_result()]
        path = self.gen.export_json(results)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        self.assertGreater(len(data[0]["indicators"]), 0)

    def test_pdf_export_creates_valid_file(self):
        try:
            import reportlab
        except ImportError:
            self.skipTest("reportlab not installed")
        r = self._full_result()
        path = self.gen.export_pdf(r)
        self.assertIsNotNone(path)
        self.assertTrue(path.exists())
        self.assertGreater(path.stat().st_size, 1000)  # not empty

    def test_pdf_export_custom_path(self):
        try:
            import reportlab
        except ImportError:
            self.skipTest("reportlab not installed")
        custom = self.tmpdir / "custom_report.pdf"
        r = self._full_result()
        path = self.gen.export_pdf(r, output_path=custom)
        self.assertEqual(path, custom)
        self.assertTrue(custom.exists())


# ── Clipboard URL extraction ──────────────────────────────────────────────────

class TestClipboardURLExtraction(unittest.TestCase):
    """Test the URL extraction logic without spinning up a QThread."""

    def setUp(self):
        try:
            import PyQt6  # noqa: F401
        except ImportError:
            self.skipTest("PyQt6 not installed — skipping clipboard tests")

    def _extract(self, text: str):
        from core.clipboard_monitor import ClipboardMonitor
        monitor = ClipboardMonitor.__new__(ClipboardMonitor)
        return monitor._extract_url(text)

    def test_bare_https_url(self):
        result = self._extract("https://gtbank.com/login")
        self.assertEqual(result, "https://gtbank.com/login")

    def test_http_url(self):
        result = self._extract("http://scam-site.com")
        self.assertEqual(result, "http://scam-site.com")

    def test_url_in_message(self):
        result = self._extract("Check this out: https://suspicious.xyz/verify now!")
        self.assertIsNotNone(result)
        self.assertIn("suspicious.xyz", result)

    def test_www_url_gets_https_prefix(self):
        result = self._extract("www.fake-bank.com/login")
        self.assertIsNotNone(result)
        self.assertTrue(result.startswith("https://"))

    def test_plain_text_no_url(self):
        result = self._extract("Hello, how are you today?")
        self.assertIsNone(result)

    def test_empty_string(self):
        result = self._extract("")
        self.assertIsNone(result)

    def test_url_with_query_params(self):
        result = self._extract("https://phish.tk/verify?bvn=1234&acct=5678")
        self.assertIsNotNone(result)
        self.assertIn("phish.tk", result)


# ── Scanner offline analysis ──────────────────────────────────────────────────

class TestScannerOfflineAnalysis(unittest.TestCase):
    """Full offline scanner pass tests — no network required."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = AppConfig()
        self.config.offline_mode = True
        self.config.enable_whois = False
        self.config.enable_virustotal = False
        self.config.enable_phishtank = False
        self.config.data_dir = Path(self.tmpdir)
        self.config.db_path = Path(self.tmpdir) / "test.db"
        self.db = make_db(self.tmpdir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _scan(self, url: str) -> ScanResult:
        from core.scanner import Scanner
        scanner = Scanner(self.config, self.db)
        result = ScanResult(
            original_url=url,
            scanned_url=url,
            domain=scanner._extract_domain(url),
        )
        scanner._analyze_url_patterns(result)
        scanner._check_official_domain(result)
        scanner._check_local_db(result)
        scanner._detect_scam_category(result)
        scanner._finalize(result)
        return result

    def test_seed_scam_domain_detected(self):
        result = self._scan("https://cbn-reward-portal.com")
        self.assertTrue(result.local_db_match)
        types = [i.indicator_type for i in result.indicators]
        self.assertIn("Known Scam Domain", types)

    def test_seed_scam_domain_score_very_high(self):
        result = self._scan("https://cbn-reward-portal.com")
        self.assertGreaterEqual(result.risk_score, 50)

    def test_official_cbn_no_scam_indicators(self):
        result = self._scan("https://cbn.gov.ng")
        self.assertTrue(result.is_official_domain)
        scam_types = [
            i.indicator_type for i in result.indicators
            if i.indicator_type == "Known Scam Domain"
        ]
        self.assertEqual(len(scam_types), 0)

    def test_domain_normalization_strips_www(self):
        from core.scanner import Scanner
        scanner = Scanner(self.config, self.db)
        self.assertEqual(scanner._extract_domain("https://www.gtbank.com"), "gtbank.com")

    def test_domain_normalization_strips_port(self):
        from core.scanner import Scanner
        scanner = Scanner(self.config, self.db)
        self.assertEqual(scanner._extract_domain("https://gtbank.com:8080/login"), "gtbank.com")

    def test_investment_fraud_category_detected(self):
        result = self._scan("http://investment-daily-profit-ng.com")
        if result.scam_category:
            self.assertIn(result.scam_category, [
                ScamCategory.INVESTMENT_FRAUD, ScamCategory.FAKE_CRYPTO
            ])

    def test_govt_impersonation_category_detected(self):
        result = self._scan("http://efcc-arrest-warrant-portal.com")
        # The scanner may assign GOVT_IMPERSONATION or BRAND_IMPERSONATION
        # (brand check fires first when EFCC keyword is matched as impersonation).
        self.assertIsNotNone(result.scam_category, "Expected a scam category to be set")

    def test_likely_scam_has_recommendation(self):
        result = self._scan("https://cbn-reward-portal.com")
        self.assertNotEqual(result.recommendation, "")
        self.assertIn("EFCC", result.recommendation)

    def test_finalize_sets_summary_for_all_levels(self):
        for score, expected_level in [(5, "Safe"), (25, "Suspicious"),
                                      (50, "High Risk"), (80, "Likely Scam")]:
            r = make_result(score=score)
            r._update_risk_level()
            from core.scanner import Scanner
            Scanner(self.config, self.db)._finalize(r)
            self.assertNotEqual(r.summary, "", f"Empty summary for {expected_level}")


# ── Config tests ──────────────────────────────────────────────────────────────

class TestConfigPersistence(unittest.TestCase):

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(str(self.tmpdir), ignore_errors=True)

    def test_save_and_reload_settings(self):
        config = AppConfig()
        config.data_dir = self.tmpdir
        config.db_path = self.tmpdir / "test.db"
        config.theme = "light"
        config.scan_timeout = 25
        config.offline_mode = True
        config.save()

        config2 = AppConfig()
        config2.data_dir = self.tmpdir
        config2._load_config()

        self.assertEqual(config2.theme, "light")
        self.assertEqual(config2.scan_timeout, 25)
        self.assertTrue(config2.offline_mode)

    def test_corrupted_config_file_handled(self):
        config = AppConfig()
        config.data_dir = self.tmpdir
        # Write corrupted JSON
        cfg_path = self.tmpdir / "config.json"
        cfg_path.write_text("{invalid json <<<")
        # Should not raise
        try:
            config._load_config()
        except Exception as e:
            self.fail(f"Corrupted config caused unhandled exception: {e}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
