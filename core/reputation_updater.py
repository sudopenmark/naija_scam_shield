"""
core/reputation_updater.py — Automatic Signature & Reputation Update Manager
Author: Joshua Akadri
GitHub: sudopenmark

Handles scheduled background updates of the local scam domain database.
Runs as a QThread so it never blocks the UI.

Update sources (all free, no mandatory API key):
  • OpenPhish   — verified phishing URLs
  • URLhaus     — malware/botnet URLs (Abuse.ch)
  • PhishStats  — phishing domain CSV (no key required)
"""

import re
import json
import logging
import urllib.parse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Optional

import requests
from PyQt6.QtCore import QThread, pyqtSignal, QTimer

logger = logging.getLogger(__name__)

UPDATE_INTERVAL_HOURS = 24          # how often to auto-update
MIN_UPDATE_INTERVAL_HOURS = 6       # minimum gap between manual updates
STATE_FILE = "last_update.json"


FEEDS = [
    {
        "name": "OpenPhish",
        "url": "https://openphish.com/feed.txt",
        "format": "plaintext_urls",
        "category": "PHISHING",
        "verdict": "OpenPhish: verified phishing URL",
        "enabled": True,
    },
    {
        "name": "URLhaus",
        "url": "https://urlhaus.abuse.ch/downloads/text/",
        "format": "urlhaus_text",
        "category": "MALWARE",
        "verdict": "URLhaus (Abuse.ch): malware distribution URL",
        "enabled": True,
    },
    {
        "name": "PhishStats",
        "url": "https://phishstats.info/phish_score.csv",
        "format": "phishstats_csv",
        "category": "PHISHING",
        "verdict": "PhishStats: reported phishing domain",
        "enabled": False,          # Large file — disable by default
        "score_threshold": 7,      # Only import score >= 7/10
    },
]


def extract_domain(url: str) -> str:
    """Extract bare domain (no www., no port) from a URL string."""
    try:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc or parsed.path
        host = re.sub(r"^www\.", "", host.lower())
        return host.split(":")[0].strip("/").split("/")[0]
    except Exception:
        return ""


class ReputationUpdater(QThread):
    """
    Background thread that downloads fresh scam/phishing domain lists
    and merges them into the local SQLite database.
    """

    update_started = pyqtSignal()
    update_progress = pyqtSignal(str)        # status message
    update_complete = pyqtSignal(int)        # total domains added
    update_failed = pyqtSignal(str)          # error message

    def __init__(self, config, db, parent=None):
        super().__init__(parent)
        self.config = config
        self.db = db
        self._state_file = config.data_dir / STATE_FILE
        self._force = False

    # ── Public API ─────────────────────────────────────────────────────────────

    def check_and_update(self, force: bool = False):
        """Start an update if due (or forced). Returns immediately; update runs async."""
        self._force = force
        if not self.isRunning():
            self.start()

    def is_update_due(self) -> bool:
        """Returns True if the local database should be refreshed."""
        state = self._load_state()
        if not state:
            return True
        last = state.get("last_update")
        if not last:
            return True
        try:
            last_dt = datetime.fromisoformat(last)
            return datetime.utcnow() - last_dt > timedelta(hours=UPDATE_INTERVAL_HOURS)
        except Exception:
            return True

    def last_update_time(self) -> Optional[datetime]:
        state = self._load_state()
        if state and state.get("last_update"):
            try:
                return datetime.fromisoformat(state["last_update"])
            except Exception:
                pass
        return None

    # ── Thread entry ──────────────────────────────────────────────────────────

    def run(self):
        if not self._force and not self.is_update_due():
            logger.debug("Reputation update not due yet; skipping.")
            return

        self.update_started.emit()
        logger.info("Starting reputation database update…")

        total_added = 0
        session = requests.Session()
        session.headers["User-Agent"] = (
            "NaijaScamShield/1.0 ReputationUpdater (github.com/sudopenmark)"
        )

        for feed in FEEDS:
            if not feed.get("enabled", True):
                continue
            try:
                added = self._process_feed(feed, session)
                total_added += added
                self.update_progress.emit(
                    f"✅ {feed['name']}: {added} domains added"
                )
            except Exception as e:
                msg = f"⚠️ {feed['name']} failed: {e}"
                logger.warning(msg)
                self.update_progress.emit(msg)

        self._save_state(total_added)
        self.update_complete.emit(total_added)
        logger.info("Reputation update complete — %d domains added/updated.", total_added)

    # ── Feed processors ───────────────────────────────────────────────────────

    def _process_feed(self, feed: dict, session: requests.Session) -> int:
        self.update_progress.emit(f"⬇️  Fetching {feed['name']}…")
        resp = session.get(feed["url"], timeout=25, stream=True)
        resp.raise_for_status()

        content = resp.text
        urls: list[str] = []

        fmt = feed["format"]
        if fmt == "plaintext_urls":
            urls = [
                line.strip() for line in content.splitlines()
                if line.strip().startswith("http")
            ]

        elif fmt == "urlhaus_text":
            # URLhaus text format has comment lines starting with #
            urls = [
                line.strip() for line in content.splitlines()
                if line.strip().startswith("http")
            ]

        elif fmt == "phishstats_csv":
            import csv, io
            threshold = feed.get("score_threshold", 7)
            reader = csv.reader(io.StringIO(content))
            for row in reader:
                # Format: Date,Score,URL,IP
                if len(row) >= 3:
                    try:
                        score = float(row[1])
                        if score >= threshold:
                            urls.append(row[2].strip())
                    except (ValueError, IndexError):
                        continue

        added = 0
        seen_domains: set[str] = set()
        for url in urls:
            domain = extract_domain(url)
            if not domain or domain in seen_domains or len(domain) < 5:
                continue
            if "." not in domain:
                continue
            seen_domains.add(domain)
            try:
                self.db.add_scam_domain(
                    domain,
                    feed["category"],
                    feed["verdict"],
                    feed["name"],
                )
                added += 1
            except Exception:
                pass

        return added

    # ── State persistence ─────────────────────────────────────────────────────

    def _load_state(self) -> dict:
        try:
            if self._state_file.exists():
                with open(self._state_file) as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save_state(self, domains_added: int):
        try:
            state = {
                "last_update": datetime.utcnow().isoformat(),
                "domains_added_last_run": domains_added,
            }
            with open(self._state_file, "w") as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            logger.warning("Could not save update state: %s", e)


class AutoUpdater:
    """
    Convenience wrapper that attaches a ReputationUpdater to a QTimer
    so it fires every UPDATE_INTERVAL_HOURS hours automatically.
    """

    def __init__(self, config, db, on_complete: Optional[Callable] = None):
        self.updater = ReputationUpdater(config, db)
        self._timer = QTimer()
        self._timer.setInterval(UPDATE_INTERVAL_HOURS * 3600 * 1000)  # ms
        self._timer.timeout.connect(self._trigger)

        if on_complete:
            self.updater.update_complete.connect(on_complete)

        self.updater.update_progress.connect(
            lambda msg: logger.info("[ReputationUpdater] %s", msg)
        )
        self.updater.update_failed.connect(
            lambda err: logger.error("[ReputationUpdater] %s", err)
        )

    def start(self):
        """Begin the auto-update cycle. Checks immediately on first run."""
        self.updater.check_and_update(force=False)
        self._timer.start()
        logger.info("AutoUpdater started (interval: %dh)", UPDATE_INTERVAL_HOURS)

    def stop(self):
        self._timer.stop()
        if self.updater.isRunning():
            self.updater.quit()
            self.updater.wait(3000)

    def force_update(self):
        self.updater.check_and_update(force=True)

    def _trigger(self):
        logger.info("AutoUpdater: scheduled update triggered")
        self.updater.check_and_update(force=True)
