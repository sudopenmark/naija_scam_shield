"""
main.py — Naija Scam Shield Desktop Entry Point
Author: Joshua Akadri
GitHub: sudopenmark
Version: 1.0.0

Launches the PyQt6 desktop application with:
  • Splash screen
  • Database initialisation
  • Background ClipboardMonitor (optional)
  • Background AutoUpdater (24 h reputation feed refresh)
  • Main window with sidebar navigation
"""

import sys
import logging
from pathlib import Path

# ── Project root on sys.path ──────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))

from PyQt6.QtWidgets import QApplication, QSplashScreen, QMessageBox
from PyQt6.QtGui import QPixmap, QIcon, QFont, QColor, QPainter, QPen
from PyQt6.QtCore import Qt, QTimer

from core.config import AppConfig
from core.logger import setup_logging
from database.db_manager import DatabaseManager


def _make_text_splash(app: QApplication) -> QSplashScreen:
    """Create a programmatic splash screen (no image file needed)."""
    px = QPixmap(520, 240)
    px.fill(QColor("#0f1117"))
    painter = QPainter(px)
    painter.setPen(QPen(QColor("#3b82f6")))
    painter.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
    painter.drawText(px.rect(), Qt.AlignmentFlag.AlignCenter, "Shield  Naija Scam Shield")
    painter.setFont(QFont("Segoe UI", 10))
    painter.setPen(QPen(QColor("#64748b")))
    painter.drawText(
        px.rect().adjusted(0, 60, 0, 0),
        Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
        "v1.0.0  ·  Joshua Akadri  ·  github.com/sudopenmark",
    )
    painter.end()
    return QSplashScreen(px, Qt.WindowType.WindowStaysOnTopHint)


def _on_clipboard_url(url: str, window, config: AppConfig) -> None:
    """Called when ClipboardMonitor detects a new URL. Prompt user to scan."""
    reply = QMessageBox.question(
        window,
        "URL detected in clipboard",
        f"A URL was detected in your clipboard:\n\n"
        f"{url[:100]}{'…' if len(url) > 100 else ''}\n\nScan it now?",
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        QMessageBox.StandardButton.Yes,
    )
    if reply == QMessageBox.StandardButton.Yes:
        window._navigate("Scan URL")
        window._scanner_screen.set_url_and_scan(url)


def main() -> int:
    # ── Logging ───────────────────────────────────────────────────────────────
    setup_logging()
    logger = logging.getLogger(__name__)
    logger.info("=" * 60)
    logger.info("Naija Scam Shield v1.0.0  —  by Joshua Akadri (sudopenmark)")
    logger.info("=" * 60)

    # ── Qt Application ────────────────────────────────────────────────────────
    app = QApplication(sys.argv)
    app.setApplicationName("Naija Scam Shield")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("Joshua Akadri")
    app.setOrganizationDomain("naijascamshield.ng")

    icon_path = Path(__file__).parent / "assets" / "icon.png"
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    # ── Splash ────────────────────────────────────────────────────────────────
    splash_path = Path(__file__).parent / "assets" / "splash.png"
    if splash_path.exists():
        splash = QSplashScreen(QPixmap(str(splash_path)), Qt.WindowType.WindowStaysOnTopHint)
    else:
        splash = _make_text_splash(app)

    def _msg(text: str):
        splash.showMessage(
            f"  {text}",
            Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignLeft,
            QColor("#64748b"),
        )
        app.processEvents()

    splash.show()
    _msg("Initialising…")

    # ── Config & Database ─────────────────────────────────────────────────────
    config = AppConfig()
    logger.info("Data directory: %s", config.data_dir)
    _msg("Loading database…")

    db = DatabaseManager(config.db_path)
    db.initialize()
    logger.info("Database ready: %s", config.db_path)

    # ── Main Window ───────────────────────────────────────────────────────────
    _msg("Building UI…")
    from ui.main_window import MainWindow
    window = MainWindow(config, db)

    # ── Background Services ───────────────────────────────────────────────────

    # 1. Auto-updater: refresh scam domain signatures every 24 h
    auto_updater = None
    if not config.offline_mode:
        try:
            from core.reputation_updater import AutoUpdater

            def _on_update_complete(n: int):
                logger.info("Signature update: %d domains added.", n)
                window.statusBar().showMessage(
                    f"Signatures updated — {n} domains added", 6000
                )

            auto_updater = AutoUpdater(config, db, on_complete=_on_update_complete)
            auto_updater.updater.update_progress.connect(
                lambda msg: window.statusBar().showMessage(msg, 3000)
            )
            auto_updater.start()
            logger.info("AutoUpdater started.")
        except Exception as e:
            logger.warning("Could not start AutoUpdater: %s", e)

    # 2. Clipboard monitor (off by default — user enables in Settings)
    clipboard_monitor = None
    if config.enable_clipboard_monitor:
        try:
            from core.clipboard_monitor import ClipboardMonitor
            clipboard_monitor = ClipboardMonitor()
            clipboard_monitor.url_detected.connect(
                lambda url: _on_clipboard_url(url, window, config)
            )
            clipboard_monitor.start_monitoring()
            logger.info("Clipboard monitor started.")
        except Exception as e:
            logger.warning("Could not start clipboard monitor: %s", e)

    # ── Show window after splash ──────────────────────────────────────────────
    def _show():
        window.show()
        splash.finish(window)
        logger.info("Window shown.")

    QTimer.singleShot(1200, _show)

    # ── Event loop ────────────────────────────────────────────────────────────
    exit_code = app.exec()

    # ── Graceful shutdown ─────────────────────────────────────────────────────
    logger.info("Exiting (code %d)…", exit_code)
    if clipboard_monitor:
        clipboard_monitor.stop_monitoring()
    if auto_updater:
        auto_updater.stop()
    logger.info("Shutdown complete.")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
