"""
tests/conftest.py — Pytest Configuration & Shared Fixtures
Author: Joshua Akadri
GitHub: sudopenmark
"""

import sys
import tempfile
import shutil
from pathlib import Path

import pytest

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.config import AppConfig
from core.models import ScanResult, ScanIndicator, RiskLevel, ScamCategory
from database.db_manager import DatabaseManager


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def tmp_root(tmp_path_factory):
    """Session-scoped temporary directory."""
    return tmp_path_factory.mktemp("naija_test")


@pytest.fixture()
def config(tmp_path):
    """Fresh AppConfig pointing to a temp directory."""
    cfg = AppConfig()
    cfg.data_dir    = tmp_path
    cfg.db_path     = tmp_path / "test.db"
    cfg.reports_dir = tmp_path / "reports"
    cfg.cache_dir   = tmp_path / "cache"
    cfg.reports_dir.mkdir(parents=True, exist_ok=True)
    cfg.cache_dir.mkdir(parents=True, exist_ok=True)
    cfg.offline_mode      = True
    cfg.enable_whois      = False
    cfg.enable_virustotal = False
    cfg.enable_phishtank  = False
    return cfg


@pytest.fixture()
def db(config):
    """Initialized DatabaseManager tied to the temp config."""
    database = DatabaseManager(config.db_path)
    database.initialize()
    return database


@pytest.fixture()
def clean_result():
    """A brand-new ScanResult with zero risk."""
    return ScanResult(
        original_url="https://example.com",
        scanned_url="https://example.com",
        domain="example.com",
    )


@pytest.fixture()
def scam_result():
    """A fully-populated high-risk ScanResult."""
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
        indicator_type="Brand Impersonation",
        description="Impersonates GTBank",
        severity="critical",
        score_impact=0,   # already set risk_score manually above
    ))
    r.summary = "🔴 LIKELY SCAM — Brand impersonation detected."
    r.recommendation = "Do NOT enter any credentials. Close this page immediately."
    return r


@pytest.fixture()
def report_gen(config):
    """ReportGenerator bound to temp config."""
    from reports.report_generator import ReportGenerator
    return ReportGenerator(config)


@pytest.fixture()
def scanner(config, db):
    """Scanner in offline mode, tied to temp DB."""
    from core.scanner import Scanner
    return Scanner(config, db)


# ── Pytest settings ───────────────────────────────────────────────────────────

def pytest_configure(config_obj):
    config_obj.addinivalue_line(
        "markers",
        "network: mark test as requiring network access",
    )
    config_obj.addinivalue_line(
        "markers",
        "slow: mark test as slow-running",
    )
    config_obj.addinivalue_line(
        "markers",
        "qt: mark test as requiring PyQt6",
    )
