"""
database/db_manager.py - SQLite Database Manager
Author: Joshua Akadri

Handles all local data: scan history, known scam domains, official domains.
"""

import sqlite3
import json
import logging
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

logger = logging.getLogger(__name__)

SCHEMA = """
-- Scam domain blacklist (community + auto-updated)
CREATE TABLE IF NOT EXISTS scam_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    category TEXT,
    verdict TEXT,
    confidence INTEGER DEFAULT 100,
    source TEXT,
    reported_by TEXT,
    date_added TEXT DEFAULT (datetime('now')),
    date_updated TEXT DEFAULT (datetime('now'))
);

-- Official verified domains whitelist
CREATE TABLE IF NOT EXISTS official_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    brand_name TEXT NOT NULL,
    category TEXT,
    date_added TEXT DEFAULT (datetime('now'))
);

-- Scan history
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_url TEXT NOT NULL,
    domain TEXT NOT NULL,
    risk_score INTEGER,
    risk_level TEXT,
    scam_category TEXT,
    is_official INTEGER DEFAULT 0,
    official_brand TEXT,
    page_title TEXT,
    indicators_json TEXT,
    full_result_json TEXT,
    scan_time TEXT DEFAULT (datetime('now')),
    duration_ms INTEGER
);

-- App settings
CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at TEXT DEFAULT (datetime('now'))
);

-- User reports
CREATE TABLE IF NOT EXISTS user_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    domain TEXT NOT NULL,
    reporter_note TEXT,
    report_time TEXT DEFAULT (datetime('now')),
    submitted_online INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_scam_domains_domain ON scam_domains(domain);
CREATE INDEX IF NOT EXISTS idx_official_domains_domain ON official_domains(domain);
CREATE INDEX IF NOT EXISTS idx_scan_history_domain ON scan_history(domain);
CREATE INDEX IF NOT EXISTS idx_scan_history_time ON scan_history(scan_time);
"""

SEED_SCAM_DOMAINS = [
    ("cbn-reward-portal.com", "GOVT_IMPERSONATION", "CBN impersonation", "seed"),
    ("verify-gtbank-account.com", "FAKE_BANK", "GTBank phishing", "seed"),
    ("opay-promo-bonus.com", "FAKE_FINTECH", "OPay fake promo", "seed"),
    ("nin-registration-portal.online", "GOVT_IMPERSONATION", "NIN phishing", "seed"),
    ("efcc-arrest-warrant.com", "GOVT_IMPERSONATION", "EFCC impersonation", "seed"),
    ("bitcoin-investment-nigeria.com", "FAKE_CRYPTO", "Crypto investment scam", "seed"),
    ("double-your-money-ng.com", "INVESTMENT_FRAUD", "Ponzi scheme", "seed"),
    ("jumia-delivery-promo.click", "FAKE_DELIVERY", "Jumia fake promo", "seed"),
    ("free-airtime-mtn-ng.xyz", "BRAND_IMPERSONATION", "MTN fake promo", "seed"),
    ("palmpay-cashback-reward.top", "FAKE_FINTECH", "PalmPay phishing", "seed"),
    ("moniepoint-bonus-verification.com", "FAKE_FINTECH", "Moniepoint phishing", "seed"),
    ("kuda-bank-verify.online", "FAKE_FINTECH", "Kuda Bank phishing", "seed"),
    ("bet9ja-winning-prediction.com", "FAKE_BETTING", "Bet9ja fake prediction", "seed"),
    ("sportybet-insider-tips.xyz", "FAKE_BETTING", "SportyBet scam", "seed"),
    ("forex-daily-profit-nigeria.com", "INVESTMENT_FRAUD", "Forex scam", "seed"),
    ("play-to-earn-naira.com", "FAKE_CRYPTO", "Play-to-earn scam", "seed"),
    ("jamb-portal-2025.online", "GOVT_IMPERSONATION", "JAMB fake portal", "seed"),
    ("waec-result-checker-ng.xyz", "GOVT_IMPERSONATION", "WAEC fake checker", "seed"),
    ("first-bank-alert-verify.com", "FAKE_BANK", "FirstBank phishing", "seed"),
    ("zenith-bank-secure-login.com", "FAKE_BANK", "ZenithBank phishing", "seed"),
]


class DatabaseManager:
    """Manages the SQLite database for Naija Scam Shield."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._ensure_dir()

    def _ensure_dir(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self):
        """Create schema and seed initial data."""
        with self._conn() as conn:
            conn.executescript(SCHEMA)
            self._seed_scam_domains(conn)
            self._seed_official_domains(conn)
        logger.info("Database initialized: %s", self.db_path)

    def _seed_scam_domains(self, conn):
        for domain, category, verdict, source in SEED_SCAM_DOMAINS:
            conn.execute(
                """INSERT OR IGNORE INTO scam_domains
                   (domain, category, verdict, source) VALUES (?, ?, ?, ?)""",
                (domain, category, verdict, source),
            )

    def _seed_official_domains(self, conn):
        from core.nigerian_brands import ALL_BRANDS
        for brand in ALL_BRANDS:
            for domain in brand.official_domains:
                conn.execute(
                    """INSERT OR IGNORE INTO official_domains
                       (domain, brand_name, category) VALUES (?, ?, ?)""",
                    (domain, brand.name, brand.category),
                )

    # ── DOMAIN CHECKS ─────────────────────────────────────────────────────────

    def check_domain(self, domain: str) -> Optional[str]:
        """Return verdict string if domain is in scam list, else None."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT verdict FROM scam_domains WHERE domain = ?",
                (domain.lower(),)
            ).fetchone()
            return row["verdict"] if row else None

    def is_official(self, domain: str) -> Optional[str]:
        """Return brand name if domain is in official list, else None."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT brand_name FROM official_domains WHERE domain = ?",
                (domain.lower(),)
            ).fetchone()
            return row["brand_name"] if row else None

    # ── SCAN HISTORY ──────────────────────────────────────────────────────────

    def save_scan(self, result) -> int:
        """Persist a ScanResult and return its row ID."""
        with self._conn() as conn:
            cursor = conn.execute(
                """INSERT INTO scan_history
                   (original_url, domain, risk_score, risk_level, scam_category,
                    is_official, official_brand, page_title, indicators_json,
                    full_result_json, duration_ms)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    result.original_url,
                    result.domain,
                    result.risk_score,
                    result.risk_level.value,
                    result.scam_category.value if result.scam_category else None,
                    1 if result.is_official_domain else 0,
                    result.official_brand,
                    result.page_title,
                    json.dumps([
                        {"type": i.indicator_type, "desc": i.description}
                        for i in result.indicators
                    ]),
                    json.dumps(result.to_dict()),
                    result.duration_ms,
                ),
            )
            return cursor.lastrowid

    def get_scan_history(self, limit: int = 100) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT id, original_url, domain, risk_score, risk_level,
                          scam_category, is_official, official_brand,
                          page_title, scan_time, duration_ms
                   FROM scan_history
                   ORDER BY scan_time DESC LIMIT ?""",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_scan_detail(self, scan_id: int) -> Optional[Dict]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT full_result_json FROM scan_history WHERE id = ?",
                (scan_id,)
            ).fetchone()
            if row:
                return json.loads(row["full_result_json"])
            return None

    def delete_scan(self, scan_id: int):
        with self._conn() as conn:
            conn.execute("DELETE FROM scan_history WHERE id = ?", (scan_id,))

    def clear_history(self):
        with self._conn() as conn:
            conn.execute("DELETE FROM scan_history")

    def get_history_stats(self) -> Dict:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) as c FROM scan_history").fetchone()["c"]
            scams = conn.execute(
                "SELECT COUNT(*) as c FROM scan_history WHERE risk_level IN ('High Risk','Likely Scam')"
            ).fetchone()["c"]
            safe = conn.execute(
                "SELECT COUNT(*) as c FROM scan_history WHERE risk_level = 'Safe'"
            ).fetchone()["c"]
            return {"total": total, "threats_detected": scams, "safe": safe}

    # ── USER REPORTS ──────────────────────────────────────────────────────────

    def add_user_report(self, url: str, domain: str, note: str = ""):
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO user_reports (url, domain, reporter_note) VALUES (?, ?, ?)",
                (url, domain, note),
            )

    def get_user_reports(self) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM user_reports ORDER BY report_time DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    # ── CUSTOM SCAM DOMAINS ───────────────────────────────────────────────────

    def add_scam_domain(self, domain: str, category: str, verdict: str, source: str = "user"):
        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO scam_domains
                   (domain, category, verdict, source, date_updated)
                   VALUES (?, ?, ?, ?, datetime('now'))""",
                (domain.lower(), category, verdict, source),
            )

    def get_scam_domains(self) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM scam_domains ORDER BY date_added DESC"
            ).fetchall()
            return [dict(r) for r in rows]
