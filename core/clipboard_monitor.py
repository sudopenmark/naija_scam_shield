"""
core/clipboard_monitor.py — Background Clipboard URL Monitor
Author: Joshua Akadri
GitHub: sudopenmark

Watches the system clipboard for URLs and emits a signal when one is detected.
Runs as a background QThread in the desktop app.

Usage:
    monitor = ClipboardMonitor()
    monitor.url_detected.connect(my_handler)
    monitor.start()
    # ... later:
    monitor.stop()
"""

import re
import logging
import urllib.parse
from PyQt6.QtCore import QThread, pyqtSignal, QTimer
from PyQt6.QtWidgets import QApplication

logger = logging.getLogger(__name__)

URL_PATTERN = re.compile(
    r"(https?://[^\s\"'<>]+|"          # full URLs
    r"www\.[a-zA-Z0-9\-\.]+\.[a-z]{2,}[^\s\"'<>]*|"  # www. URLs
    r"[a-zA-Z0-9\-]+\.[a-z]{2,6}/[^\s\"'<>]*)",       # bare domain/path
    re.IGNORECASE,
)


class ClipboardMonitor(QThread):
    """
    Polls the system clipboard every 1.5 seconds for new URLs.
    Emits url_detected(str) when a URL is found that wasn't seen before.
    """

    url_detected = pyqtSignal(str)    # raw URL string
    status_changed = pyqtSignal(str)  # status message

    POLL_INTERVAL_MS = 1500

    def __init__(self, parent=None):
        super().__init__(parent)
        self._running = False
        self._last_seen: str = ""
        self._timer: QTimer | None = None

    # ── Public API ────────────────────────────────────────────────────────────

    def start_monitoring(self):
        """Start the clipboard monitor (call from main thread)."""
        if not self._running:
            self._running = True
            self.start()
            logger.info("Clipboard monitor started")
            self.status_changed.emit("Clipboard monitor active")

    def stop_monitoring(self):
        """Stop the clipboard monitor."""
        self._running = False
        self.quit()
        self.wait(2000)
        logger.info("Clipboard monitor stopped")
        self.status_changed.emit("Clipboard monitor stopped")

    # ── Internal ──────────────────────────────────────────────────────────────

    def run(self):
        """Thread main loop — polls clipboard."""
        # QTimer must be created in the thread it runs in
        self._timer = QTimer()
        self._timer.setInterval(self.POLL_INTERVAL_MS)
        self._timer.timeout.connect(self._check_clipboard)
        self._timer.start()
        self.exec()  # Qt event loop for this thread

    def _check_clipboard(self):
        if not self._running:
            self._timer.stop()
            self.quit()
            return

        try:
            clipboard = QApplication.clipboard()
            text = clipboard.text().strip()

            if not text or text == self._last_seen:
                return

            self._last_seen = text

            url = self._extract_url(text)
            if url:
                logger.debug("Clipboard URL detected: %s", url)
                self.url_detected.emit(url)

        except Exception as e:
            logger.debug("Clipboard read error: %s", e)

    def _extract_url(self, text: str) -> str | None:
        """
        Extract the first URL from clipboard text.
        Returns normalised URL or None.
        """
        # Exact URL
        if text.startswith(("http://", "https://")):
            try:
                parsed = urllib.parse.urlparse(text.split()[0])
                if parsed.netloc:
                    return text.split()[0]
            except Exception:
                pass

        # Pattern match
        match = URL_PATTERN.search(text)
        if match:
            found = match.group(0)
            if not found.startswith(("http://", "https://")):
                found = "https://" + found
            return found

        return None
