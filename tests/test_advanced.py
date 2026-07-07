"""
tests/test_advanced.py — Encryption, Security & Advanced Report Tests
Author: Joshua Akadri
GitHub: sudopenmark
"""

import sys
import json
import tempfile
import unittest
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.models import ScanResult, ScanIndicator, RiskLevel, ScamCategory
from core.config import AppConfig
from database.db_manager import DatabaseManager
from reports.report_generator import ReportGenerator


# ── Encryption tests ──────────────────────────────────────────────────────────

class TestEncryption(unittest.TestCase):
    """Tests for core/encryption.py — key derivation, encrypt/decrypt, stores."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(str(self.tmpdir), ignore_errors=True)

    # ── Key derivation ────────────────────────────────────────────────────────

    def test_derive_key_returns_32_bytes(self):
        from core.encryption import derive_key
        key = derive_key("password", b"saltsaltsaltsalt" * 2)
        self.assertEqual(len(key), 32)

    def test_derive_key_deterministic(self):
        from core.encryption import derive_key
        salt = b"x" * 32
        k1 = derive_key("password", salt)
        k2 = derive_key("password", salt)
        self.assertEqual(k1, k2)

    def test_derive_key_different_passwords(self):
        from core.encryption import derive_key
        salt = b"y" * 32
        k1 = derive_key("password1", salt)
        k2 = derive_key("password2", salt)
        self.assertNotEqual(k1, k2)

    def test_derive_key_different_salts(self):
        from core.encryption import derive_key
        k1 = derive_key("password", b"a" * 32)
        k2 = derive_key("password", b"b" * 32)
        self.assertNotEqual(k1, k2)

    # ── Encrypt / Decrypt (fallback path) ────────────────────────────────────

    def test_fallback_encrypt_decrypt_roundtrip(self):
        from core.encryption import _fallback_encrypt, _fallback_decrypt, derive_key
        key = derive_key("test", b"s" * 32)
        plaintext = b"Hello, Naija Scam Shield!"
        iv, ct = _fallback_encrypt(plaintext, key)
        recovered = _fallback_decrypt(iv, ct, key)
        self.assertEqual(recovered, plaintext)

    def test_fallback_wrong_key_raises(self):
        from core.encryption import _fallback_encrypt, _fallback_decrypt, derive_key
        key1 = derive_key("correct", b"s" * 32)
        key2 = derive_key("wrong",   b"s" * 32)
        iv, ct = _fallback_encrypt(b"secret data", key1)
        with self.assertRaises(ValueError):
            _fallback_decrypt(iv, ct, key2)

    def test_fallback_tampered_ciphertext_raises(self):
        from core.encryption import _fallback_encrypt, _fallback_decrypt, derive_key
        key = derive_key("pw", b"s" * 32)
        iv, ct = _fallback_encrypt(b"original", key)
        # Flip a byte in the ciphertext
        tampered = ct[:5] + bytes([ct[5] ^ 0xFF]) + ct[6:]
        with self.assertRaises(ValueError):
            _fallback_decrypt(iv, tampered, key)

    def test_encrypt_produces_different_iv_each_call(self):
        from core.encryption import encrypt, derive_key
        key = derive_key("pw", b"s" * 32)
        iv1, _ = encrypt(b"data", key)
        iv2, _ = encrypt(b"data", key)
        # IVs must be random — same input different nonce
        self.assertNotEqual(iv1, iv2)

    def test_encrypt_decrypt_roundtrip(self):
        from core.encryption import encrypt, decrypt, derive_key
        key = derive_key("pw", b"s" * 32)
        plaintext = b"Sensitive Nigerian banking credential"
        iv, ct = encrypt(plaintext, key)
        recovered = decrypt(iv, ct, key)
        self.assertEqual(recovered, plaintext)

    def test_encrypt_large_payload(self):
        from core.encryption import encrypt, decrypt, derive_key
        key = derive_key("pw", b"s" * 32)
        plaintext = b"X" * 100_000  # 100 KB
        iv, ct = encrypt(plaintext, key)
        recovered = decrypt(iv, ct, key)
        self.assertEqual(recovered, plaintext)

    # ── EncryptedStore ────────────────────────────────────────────────────────

    def test_encrypted_store_save_load(self):
        from core.encryption import EncryptedStore
        store = EncryptedStore(self.tmpdir / "test.bin")
        data = {"api_key": "vt_abc123", "theme": "dark"}
        store.save(data, password="correct_password")
        loaded = store.load(password="correct_password")
        self.assertEqual(loaded["api_key"], "vt_abc123")
        self.assertEqual(loaded["theme"], "dark")

    def test_encrypted_store_wrong_password_raises(self):
        from core.encryption import EncryptedStore
        store = EncryptedStore(self.tmpdir / "test2.bin")
        store.save({"secret": "value"}, password="good_pw")
        with self.assertRaises((ValueError, Exception)):
            store.load(password="bad_pw")

    def test_encrypted_store_nonexistent_returns_none(self):
        from core.encryption import EncryptedStore
        store = EncryptedStore(self.tmpdir / "nonexistent.bin")
        result = store.load(password="pw")
        self.assertIsNone(result)

    def test_encrypted_store_delete(self):
        from core.encryption import EncryptedStore
        store = EncryptedStore(self.tmpdir / "del.bin")
        store.save({"k": "v"}, password="pw")
        self.assertTrue(store.exists())
        store.delete()
        self.assertFalse(store.exists())

    def test_encrypted_store_file_is_binary_not_plaintext(self):
        from core.encryption import EncryptedStore
        store = EncryptedStore(self.tmpdir / "binary.bin")
        store.save({"api_key": "SECRET_VALUE"}, password="pw")
        raw = (self.tmpdir / "binary.bin").read_bytes()
        self.assertNotIn(b"SECRET_VALUE", raw)
        self.assertNotIn(b"api_key", raw)

    def test_encrypted_store_roundtrip_unicode(self):
        from core.encryption import EncryptedStore
        store = EncryptedStore(self.tmpdir / "unicode.bin")
        data = {"name": "Àdéwálé Àjàyí", "note": "Ìgbàgbó 🇳🇬"}
        store.save(data, password="pw")
        loaded = store.load("pw")
        self.assertEqual(loaded["name"], data["name"])

    # ── Obfuscation helpers ───────────────────────────────────────────────────

    def test_obfuscate_deobfuscate_roundtrip(self):
        from core.encryption import obfuscate, deobfuscate
        original = "vt_abc123XYZ!@#"
        obf = obfuscate(original)
        self.assertNotEqual(obf, original)
        self.assertEqual(deobfuscate(obf), original)

    def test_obfuscate_hides_value(self):
        from core.encryption import obfuscate
        result = obfuscate("MY_SECRET_API_KEY")
        self.assertNotIn("MY_SECRET", result)
        self.assertNotIn("API_KEY", result)

    def test_deobfuscate_bad_input_returns_original(self):
        from core.encryption import deobfuscate
        bad = "not-hex-data!!!"
        result = deobfuscate(bad)
        self.assertEqual(result, bad)

    # ── SecureKeyStore ────────────────────────────────────────────────────────

    def test_secure_key_store_set_get(self):
        from core.encryption import SecureKeyStore
        ks = SecureKeyStore(self.tmpdir / "keys.bin")
        ks.set_password("pw")
        ks.set("virustotal", "my_vt_key")
        self.assertEqual(ks.get("virustotal"), "my_vt_key")

    def test_secure_key_store_missing_key_returns_default(self):
        from core.encryption import SecureKeyStore
        ks = SecureKeyStore(self.tmpdir / "keys2.bin")
        ks.set_password("pw")
        result = ks.get("nonexistent", default="fallback")
        self.assertEqual(result, "fallback")

    def test_secure_key_store_persists_across_instances(self):
        from core.encryption import SecureKeyStore
        path = self.tmpdir / "persistent.bin"
        ks1 = SecureKeyStore(path)
        ks1.set_password("pw")
        ks1.set("api", "value_123")

        ks2 = SecureKeyStore(path)
        ks2.set_password("pw")
        self.assertEqual(ks2.get("api"), "value_123")

    def test_secure_key_store_delete_key(self):
        from core.encryption import SecureKeyStore
        ks = SecureKeyStore(self.tmpdir / "del_key.bin")
        ks.set_password("pw")
        ks.set("to_delete", "value")
        ks.delete("to_delete")
        self.assertIsNone(ks.get("to_delete"))


# ── Advanced Report Tests ─────────────────────────────────────────────────────

class TestReportGeneratorAdvanced(unittest.TestCase):

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.config = AppConfig()
        self.config.reports_dir = self.tmpdir
        self.gen = ReportGenerator(self.config)

    def tearDown(self):
        import shutil
        shutil.rmtree(str(self.tmpdir), ignore_errors=True)

    def _result(self, **kwargs) -> ScanResult:
        defaults = dict(
            original_url="https://test.com",
            scanned_url="https://test.com",
            domain="test.com",
            risk_score=50,
            risk_level=RiskLevel.HIGH_RISK,
        )
        defaults.update(kwargs)
        return ScanResult(**defaults)

    def test_csv_empty_list(self):
        path = self.gen.export_csv([])
        self.assertIsNotNone(path)
        lines = path.read_text().splitlines()
        # Only header row
        self.assertEqual(len(lines), 1)

    def test_csv_all_risk_levels(self):
        results = [
            self._result(domain=f"site{i}.com",
                         risk_score=s,
                         risk_level=rl)
            for i, (s, rl) in enumerate([
                (5,  RiskLevel.SAFE),
                (25, RiskLevel.SUSPICIOUS),
                (55, RiskLevel.HIGH_RISK),
                (80, RiskLevel.LIKELY_SCAM),
            ])
        ]
        path = self.gen.export_csv(results)
        content = path.read_text(encoding="utf-8")
        for level in ["Safe", "Suspicious", "High Risk", "Likely Scam"]:
            self.assertIn(level, content)

    def test_json_output_is_list(self):
        path = self.gen.export_json([self._result()])
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        self.assertIsInstance(data, list)

    def test_json_output_contains_all_required_fields(self):
        r = self._result()
        r.scam_category = ScamCategory.FAKE_BANK
        r.page_title = "Test Page"
        path = self.gen.export_json([r])
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        item = data[0]
        for field in ["domain", "risk_score", "risk_level", "scam_category",
                       "original_url", "indicators", "summary"]:
            self.assertIn(field, item, f"Missing field: {field}")

    def test_json_output_indicators_serialized(self):
        r = self._result()
        r.add_indicator(ScanIndicator("Test", "description", "high", 15))
        path = self.gen.export_json([r])
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(len(data[0]["indicators"]), 1)
        self.assertEqual(data[0]["indicators"][0]["type"], "Test")

    def test_csv_official_domain_flag(self):
        r = self._result(domain="gtbank.com",
                         risk_score=0,
                         risk_level=RiskLevel.SAFE)
        r.is_official_domain = True
        r.official_brand = "GTBank"
        path = self.gen.export_csv([r])
        content = path.read_text(encoding="utf-8")
        self.assertIn("True", content)
        self.assertIn("GTBank", content)

    def test_pdf_export_with_no_indicators(self):
        """PDF should still render cleanly for a clean scan result."""
        try:
            import reportlab  # noqa
        except ImportError:
            self.skipTest("reportlab not installed")
        r = self._result(risk_score=0, risk_level=RiskLevel.SAFE)
        r.summary = "No threats detected."
        r.recommendation = "This site appears safe."
        path = self.gen.export_pdf(r)
        self.assertIsNotNone(path)
        self.assertTrue(path.exists())
        self.assertGreater(path.stat().st_size, 500)

    def test_pdf_export_with_official_domain(self):
        try:
            import reportlab  # noqa
        except ImportError:
            self.skipTest("reportlab not installed")
        r = self._result(domain="cbn.gov.ng",
                         risk_score=0,
                         risk_level=RiskLevel.SAFE)
        r.is_official_domain = True
        r.official_brand = "Central Bank of Nigeria (CBN)"
        r.summary = "✅ Official Domain — CBN"
        path = self.gen.export_pdf(r)
        self.assertIsNotNone(path)
        self.assertTrue(path.exists())

    def test_pdf_export_with_all_threat_levels(self):
        """PDF should render for all four risk levels without error."""
        try:
            import reportlab  # noqa
        except ImportError:
            self.skipTest("reportlab not installed")
        for score, level in [(5, RiskLevel.SAFE), (25, RiskLevel.SUSPICIOUS),
                              (55, RiskLevel.HIGH_RISK), (80, RiskLevel.LIKELY_SCAM)]:
            r = self._result(domain=f"test-{level.value.lower().replace(' ', '-')}.com",
                             risk_score=score, risk_level=level)
            r.summary = f"Test summary for {level.value}"
            r.recommendation = "Test recommendation."
            path = self.gen.export_pdf(r)
            self.assertIsNotNone(path, f"PDF failed for {level.value}")

    def test_report_filename_sanitizes_domain(self):
        r = self._result(domain="fake/bank.com:8080")
        path = self.gen.export_csv([r])
        # File should exist and have a safe name
        self.assertTrue(path.exists())
        self.assertNotIn("/", path.name)
        self.assertNotIn(":", path.name)


# ── Nigerian Brands comprehensive coverage ────────────────────────────────────

class TestNigerianBrandsComprehensive(unittest.TestCase):

    def test_all_16_banks_present(self):
        from core.nigerian_brands import BANKS
        self.assertGreaterEqual(len(BANKS), 16)

    def test_all_11_fintechs_present(self):
        from core.nigerian_brands import FINTECHS
        self.assertGreaterEqual(len(FINTECHS), 11)

    def test_government_agencies_include_key_ones(self):
        from core.nigerian_brands import GOVERNMENT
        names = [b.name for b in GOVERNMENT]
        for agency in ["Central Bank of Nigeria", "EFCC", "NIMC", "JAMB"]:
            self.assertTrue(
                any(agency in n for n in names),
                f"Missing government agency: {agency}"
            )

    def test_telecoms_big_four_present(self):
        from core.nigerian_brands import TELECOMS
        names = [b.name for b in TELECOMS]
        for telecom in ["MTN", "Airtel", "Glo", "9mobile"]:
            self.assertTrue(
                any(telecom in n for n in names),
                f"Missing telecom: {telecom}"
            )

    def test_betting_platforms_present(self):
        from core.nigerian_brands import BETTING
        names = [b.name for b in BETTING]
        self.assertTrue(any("Bet9ja" in n for n in names))
        self.assertTrue(any("SportyBet" in n for n in names))

    def test_all_brands_total_count(self):
        from core.nigerian_brands import ALL_BRANDS
        # Should be 60+ entries total
        self.assertGreaterEqual(len(ALL_BRANDS), 50)

    def test_official_domain_map_covers_all_brands(self):
        from core.nigerian_brands import ALL_BRANDS, OFFICIAL_DOMAIN_MAP
        for brand in ALL_BRANDS:
            for domain in brand.official_domains:
                self.assertIn(
                    domain.lower(), OFFICIAL_DOMAIN_MAP,
                    f"Domain '{domain}' from brand '{brand.name}' not in OFFICIAL_DOMAIN_MAP"
                )

    def test_specific_lookups(self):
        from core.nigerian_brands import lookup_domain
        cases = [
            ("zenithbank.com",         "Zenith"),
            ("mtn.com.ng",             "MTN"),
            ("fidelitybank.ng",        "Fidelity"),
            ("wemabank.com",           "Wema"),
            ("piggyvest.com",          "Piggyvest"),
            ("chippercash.com",        "Chipper"),
            ("sportybet.com",          "SportyBet"),
            ("jumia.com.ng",           "Jumia"),
            ("gloworld.com",           "Glo"),
            ("waecnigeria.org",        "WAEC"),
        ]
        for domain, expected_substring in cases:
            brand = lookup_domain(domain)
            self.assertIsNotNone(brand, f"Expected brand for {domain}")
            self.assertIn(
                expected_substring, brand.name,
                f"Brand name '{brand.name}' doesn't contain '{expected_substring}'"
            )


# ── Scanner domain normalisation ──────────────────────────────────────────────

class TestScannerDomainNormalisation(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        config = AppConfig()
        config.offline_mode = True
        config.enable_whois = False
        config.enable_virustotal = False
        config.enable_phishtank = False
        config.data_dir = Path(self.tmpdir)
        config.db_path = Path(self.tmpdir) / "n.db"
        self.config = config
        self.db = DatabaseManager(config.db_path)
        self.db.initialize()
        from core.scanner import Scanner
        self.scanner = Scanner(config, self.db)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_url_with_path_and_params(self):
        d = self.scanner._extract_domain("https://gtbank.com/login?redirect=/dashboard")
        self.assertEqual(d, "gtbank.com")

    def test_url_uppercase(self):
        d = self.scanner._extract_domain("HTTPS://GTBANK.COM/LOGIN")
        self.assertEqual(d, "gtbank.com")

    def test_url_with_port(self):
        d = self.scanner._extract_domain("https://example.com:8443/path")
        self.assertEqual(d, "example.com")

    def test_bare_domain_no_scheme(self):
        url = self.scanner._normalize_url("gtbank.com")
        self.assertTrue(url.startswith("https://"))

    def test_http_url_kept_as_is(self):
        url = self.scanner._normalize_url("http://scam.com")
        self.assertEqual(url, "http://scam.com")

    def test_strips_leading_whitespace(self):
        url = self.scanner._normalize_url("   https://test.com   ")
        self.assertEqual(url, "https://test.com")

    def test_subdomain_www_stripped(self):
        d = self.scanner._extract_domain("https://www.gtbank.com")
        self.assertEqual(d, "gtbank.com")

    def test_deep_subdomain_extracted_correctly(self):
        d = self.scanner._extract_domain("https://secure.login.phish.gq/verify")
        # Domain should be the full host minus www.
        self.assertIn("phish.gq", d)


if __name__ == "__main__":
    unittest.main(verbosity=2)
