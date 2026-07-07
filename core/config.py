"""
core/config.py - Application Configuration
Author: Joshua Akadri
"""

import os
import json
import logging
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class AppConfig:
    """Central application configuration."""

    # Paths
    app_name: str = "Naija Scam Shield"
    version: str = "1.0.0"
    author: str = "Joshua Akadri"

    # Directories
    data_dir: Path = field(default_factory=lambda: Path.home() / ".naija_scam_shield")
    db_path: Path = field(default_factory=lambda: Path.home() / ".naija_scam_shield" / "shield.db")
    log_path: Path = field(default_factory=lambda: Path.home() / ".naija_scam_shield" / "app.log")
    reports_dir: Path = field(default_factory=lambda: Path.home() / ".naija_scam_shield" / "reports")
    cache_dir: Path = field(default_factory=lambda: Path.home() / ".naija_scam_shield" / "cache")

    # API Keys (loaded from environment or config file)
    virustotal_api_key: Optional[str] = None
    phishtank_api_key: Optional[str] = None
    urlscan_api_key: Optional[str] = None

    # Scanner settings
    scan_timeout: int = 15  # seconds
    max_redirects: int = 5
    user_agent: str = "NaijaScamShield/1.0 (Security Scanner; +https://naijascamshield.ng)"

    # UI settings
    theme: str = "dark"  # "dark" or "light"
    language: str = "en"

    # Feature flags
    enable_virustotal: bool = True
    enable_phishtank: bool = True
    enable_whois: bool = True
    enable_qr_scanner: bool = True
    enable_clipboard_monitor: bool = False

    # Offline mode
    offline_mode: bool = False

    def __post_init__(self):
        """Create directories and load persisted config."""
        for d in [self.data_dir, self.reports_dir, self.cache_dir]:
            d.mkdir(parents=True, exist_ok=True)

        # Load environment variables for API keys
        self.virustotal_api_key = os.environ.get("VIRUSTOTAL_API_KEY", self.virustotal_api_key)
        self.phishtank_api_key = os.environ.get("PHISHTANK_API_KEY", self.phishtank_api_key)
        self.urlscan_api_key = os.environ.get("URLSCAN_API_KEY", self.urlscan_api_key)

        # Load saved config
        self._load_config()

    def _config_file(self) -> Path:
        return self.data_dir / "config.json"

    def _load_config(self):
        """Load persisted settings from config file."""
        cfg_file = self._config_file()
        if cfg_file.exists():
            try:
                with open(cfg_file, "r") as f:
                    data = json.load(f)
                # Only override safe UI/settings fields
                for key in ("theme", "language", "enable_virustotal",
                            "enable_phishtank", "enable_whois",
                            "enable_qr_scanner", "enable_clipboard_monitor",
                            "offline_mode", "scan_timeout"):
                    if key in data:
                        setattr(self, key, data[key])
            except Exception as e:
                logger.warning("Could not load config: %s", e)

    def save(self):
        """Persist user-facing settings."""
        data = {
            "theme": self.theme,
            "language": self.language,
            "enable_virustotal": self.enable_virustotal,
            "enable_phishtank": self.enable_phishtank,
            "enable_whois": self.enable_whois,
            "enable_qr_scanner": self.enable_qr_scanner,
            "enable_clipboard_monitor": self.enable_clipboard_monitor,
            "offline_mode": self.offline_mode,
            "scan_timeout": self.scan_timeout,
        }
        try:
            with open(self._config_file(), "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error("Could not save config: %s", e)
