"""
scripts/update_signatures.py - Automatic Signature Update Script
Author: Joshua Akadri

Run periodically to pull fresh scam domain signatures from public threat feeds.
Usage:  python scripts/update_signatures.py
"""

import sys
import json
import logging
import requests
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.config import AppConfig
from database.db_manager import DatabaseManager

logger = logging.getLogger(__name__)

# Public threat intelligence feeds (free, no API key required)
FEEDS = [
    {
        "name": "OpenPhish",
        "url": "https://openphish.com/feed.txt",
        "format": "plaintext_urls",
        "category": "PHISHING",
        "verdict": "OpenPhish verified phishing",
    },
    # PhishTank verified feed (requires API key for full access)
    # {
    #     "name": "PhishTank",
    #     "url": "http://data.phishtank.com/data/online-valid.json",
    #     "format": "phishtank_json",
    #     "category": "PHISHING",
    #     "verdict": "PhishTank verified",
    # },
]


def extract_domain(url: str) -> str:
    import urllib.parse
    import re
    try:
        parsed = urllib.parse.urlparse(url if "://" in url else "https://" + url)
        host = parsed.netloc or parsed.path
        host = re.sub(r"^www\.", "", host.lower())
        return host.split(":")[0].strip("/")
    except Exception:
        return ""


def update_from_feed(db: DatabaseManager, feed: dict) -> int:
    """Download a feed and add new scam domains to the database. Returns count added."""
    added = 0
    try:
        logger.info("Fetching feed: %s (%s)", feed["name"], feed["url"])
        resp = requests.get(feed["url"], timeout=20, headers={
            "User-Agent": "NaijaScamShield/1.0 SignatureUpdater"
        })
        resp.raise_for_status()

        urls = []
        if feed["format"] == "plaintext_urls":
            urls = [line.strip() for line in resp.text.splitlines() if line.strip().startswith("http")]
        elif feed["format"] == "phishtank_json":
            data = resp.json()
            urls = [entry["url"] for entry in data if entry.get("verified") == "yes"]

        for url in urls:
            domain = extract_domain(url)
            if domain and "." in domain and len(domain) > 4:
                try:
                    db.add_scam_domain(domain, feed["category"], feed["verdict"], feed["name"])
                    added += 1
                except Exception:
                    pass

        logger.info("Feed '%s': added %d domains", feed["name"], added)
    except Exception as e:
        logger.error("Feed '%s' failed: %s", feed["name"], e)
    return added


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    config = AppConfig()
    db = DatabaseManager(config.db_path)
    db.initialize()

    total_added = 0
    for feed in FEEDS:
        total_added += update_from_feed(db, feed)

    logger.info("Signature update complete. Total domains added/updated: %d", total_added)

    # Save last update time
    config_file = config.data_dir / "last_update.json"
    with open(config_file, "w") as f:
        json.dump({"last_update": datetime.utcnow().isoformat(), "added": total_added}, f)

    print(f"\n✅ Signature update complete. {total_added} domains added/updated.")


if __name__ == "__main__":
    main()
