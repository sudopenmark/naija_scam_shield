"""
ui/main_window.py - Main Application Window
Author: Joshua Akadri
GitHub: sudopenmark
"""

import logging
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QPushButton, QStackedWidget, QLabel, QFrame,
    QDialog, QDialogButtonBox, QScrollArea, QSizePolicy
)
from PyQt6.QtCore import Qt, pyqtSignal, QSize
from PyQt6.QtGui import QFont, QPixmap, QIcon, QColor, QPainter, QPen, QBrush

from .screens.scanner_screen import ScannerScreen
from .screens.history_screen import HistoryScreen
from .screens.dashboard_screen import DashboardScreen
from .screens.settings_screen import SettingsScreen
from .screens.qr_screen import QRScannerScreen
from .styles import get_stylesheet
from core.config import AppConfig
from database.db_manager import DatabaseManager

logger = logging.getLogger(__name__)


# ── About Dialog ──────────────────────────────────────────────────────────────

class AboutDialog(QDialog):
    """Polished About dialog with version, author, and license info."""

    def __init__(self, config: AppConfig, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About Naija Scam Shield")
        self.setFixedSize(480, 520)
        self.setWindowFlags(
            Qt.WindowType.Dialog |
            Qt.WindowType.WindowCloseButtonHint
        )
        self._build(config)

    def _build(self, config: AppConfig):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Hero banner ──────────────────────────────────────────────────────
        banner = QFrame()
        banner.setFixedHeight(160)
        banner.setStyleSheet(
            "background: qlineargradient(x1:0, y1:0, x2:1, y2:1,"
            " stop:0 #0f1117, stop:1 #1a2540);"
            "border-bottom: 1px solid #2a2d3e;"
        )
        banner_layout = QVBoxLayout(banner)
        banner_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        banner_layout.setSpacing(6)

        shield_lbl = QLabel("🛡️")
        shield_lbl.setFont(QFont("Segoe UI Emoji", 40))
        shield_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        shield_lbl.setStyleSheet("background: transparent;")

        title_lbl = QLabel("Naija Scam Shield")
        title_lbl.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_lbl.setStyleSheet("color: #f1f5f9; background: transparent;")

        banner_layout.addWidget(shield_lbl)
        banner_layout.addWidget(title_lbl)

        layout.addWidget(banner)

        # ── Info body ────────────────────────────────────────────────────────
        body = QWidget()
        body.setStyleSheet("background-color: #13151f;")
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(32, 24, 32, 16)
        body_layout.setSpacing(12)

        def _row(label: str, value: str, value_color: str = "#f1f5f9") -> QWidget:
            row = QWidget()
            row.setStyleSheet("background: transparent;")
            rl = QHBoxLayout(row)
            rl.setContentsMargins(0, 0, 0, 0)
            lbl = QLabel(label)
            lbl.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            lbl.setStyleSheet("color: #475569; text-transform: uppercase;"
                              "letter-spacing: 0.5px; background: transparent;")
            lbl.setFixedWidth(110)
            val = QLabel(value)
            val.setFont(QFont("Segoe UI", 10))
            val.setStyleSheet(f"color: {value_color}; background: transparent;")
            val.setWordWrap(True)
            rl.addWidget(lbl)
            rl.addWidget(val, 1)
            return row

        body_layout.addWidget(_row("Version",    f"v{config.version}",     "#60a5fa"))
        body_layout.addWidget(_row("Author",     config.author,             "#f1f5f9"))
        body_layout.addWidget(_row("GitHub",     "github.com/sudopenmark",  "#818cf8"))
        body_layout.addWidget(_row("Contact",    "dev@naijascamshield.ng",  "#94a3b8"))
        body_layout.addWidget(_row("License",    "Commercial — All rights reserved", "#f59e0b"))
        body_layout.addWidget(_row("Platform",   "Windows · Linux · Android",        "#94a3b8"))
        body_layout.addWidget(_row("Python",     "3.12+  ·  PyQt6  ·  Kivy (Android)", "#94a3b8"))

        # Divider
        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet("color: #2a2d3e; background: #2a2d3e; max-height: 1px;")
        body_layout.addWidget(div)

        # Description
        desc = QLabel(
            "Naija Scam Shield protects Nigerian internet users from phishing "
            "sites, fake banking portals, fraudulent fintech pages, government "
            "impersonation, and investment scams — using a hybrid offline/online "
            "security engine with a verified official-domain registry."
        )
        desc.setFont(QFont("Segoe UI", 9))
        desc.setStyleSheet("color: #64748b; background: transparent;")
        desc.setWordWrap(True)
        desc.setAlignment(Qt.AlignmentFlag.AlignTop)
        body_layout.addWidget(desc)

        # Report links
        report_lbl = QLabel(
            "Report scams: "
            "<a href='https://efcc.gov.ng' style='color:#60a5fa;'>efcc.gov.ng</a>"
            "  ·  "
            "<a href='https://cbn.gov.ng' style='color:#60a5fa;'>cbn.gov.ng</a>"
        )
        report_lbl.setFont(QFont("Segoe UI", 9))
        report_lbl.setStyleSheet("background: transparent;")
        report_lbl.setOpenExternalLinks(True)
        body_layout.addWidget(report_lbl)

        body_layout.addStretch()
        layout.addWidget(body, 1)

        # ── Footer button ────────────────────────────────────────────────────
        footer = QWidget()
        footer.setFixedHeight(60)
        footer.setStyleSheet("background-color: #0f1117; border-top: 1px solid #2a2d3e;")
        fl = QHBoxLayout(footer)
        fl.setContentsMargins(24, 0, 24, 0)

        close_btn = QPushButton("Close")
        close_btn.setFixedSize(100, 36)
        close_btn.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        close_btn.setStyleSheet(
            "QPushButton { background: #1e2130; color: #94a3b8; border: 1px solid #2a2d3e;"
            "border-radius: 8px; }"
            "QPushButton:hover { background: #252840; color: #f1f5f9; }"
        )
        close_btn.clicked.connect(self.accept)
        fl.addStretch()
        fl.addWidget(close_btn)
        layout.addWidget(footer)


# ── Nav Button ────────────────────────────────────────────────────────────────

class NavButton(QPushButton):
    """Sidebar navigation button — icon + text, checkable."""

    def __init__(self, icon_text: str, label: str, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setFixedHeight(50)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet("")   # styled via QSS in styles.py

        layout = QHBoxLayout(self)
        layout.setContentsMargins(18, 0, 12, 0)
        layout.setSpacing(12)

        icon_lbl = QLabel(icon_text)
        icon_lbl.setFixedWidth(22)
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_lbl.setFont(QFont("Segoe UI Emoji", 14))
        icon_lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

        text_lbl = QLabel(label)
        text_lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.DemiBold))
        text_lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

        layout.addWidget(icon_lbl)
        layout.addWidget(text_lbl, 1)


# ── Main Window ───────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    """Main application window with sidebar navigation and About dialog."""

    def __init__(self, config: AppConfig, db: DatabaseManager):
        super().__init__()
        self.config = config
        self.db = db
        self._setup_window()
        self._build_ui()
        self._apply_theme()
        # Start on scanner screen
        self._nav_buttons[0].setChecked(True)

    def _setup_window(self):
        self.setWindowTitle(
            f"{self.config.app_name}  v{self.config.version}  —  {self.config.author}"
        )
        self.setMinimumSize(1020, 680)
        self.resize(1240, 780)

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Sidebar ──────────────────────────────────────────────────────────
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(224)
        sb = QVBoxLayout(sidebar)
        sb.setContentsMargins(0, 0, 0, 0)
        sb.setSpacing(0)

        # Logo
        logo_frame = QFrame()
        logo_frame.setObjectName("logoFrame")
        logo_frame.setFixedHeight(76)
        lfl = QVBoxLayout(logo_frame)
        lfl.setContentsMargins(18, 10, 18, 8)
        lfl.setSpacing(2)

        logo_top = QLabel("🛡️  Naija Scam Shield")
        logo_top.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        logo_top.setObjectName("logoLabel")

        logo_sub = QLabel(f"v{self.config.version}  ·  {self.config.author}")
        logo_sub.setFont(QFont("Segoe UI", 8))
        logo_sub.setObjectName("versionLabel")

        lfl.addWidget(logo_top)
        lfl.addWidget(logo_sub)
        sb.addWidget(logo_frame)

        # Thin separator
        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet("background: #1e2130;")
        sb.addWidget(sep)

        sb.addSpacing(6)

        # Nav items
        nav_items = [
            ("🔍", "Scan URL"),
            ("📊", "Dashboard"),
            ("📋", "History"),
            ("📷", "QR Scanner"),
            ("⚙️", "Settings"),
        ]
        self._nav_buttons = []
        for icon, label in nav_items:
            btn = NavButton(icon, label)
            btn.clicked.connect(lambda checked, l=label: self._navigate(l))
            sb.addWidget(btn)
            self._nav_buttons.append(btn)

        sb.addStretch()

        # About button at bottom of sidebar
        about_btn = QPushButton("ℹ️  About")
        about_btn.setFixedHeight(40)
        about_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        about_btn.setStyleSheet(
            "QPushButton { background: transparent; color: #475569; border: none;"
            "font-size: 11px; font-family: 'Segoe UI'; text-align: left; padding: 0 18px; }"
            "QPushButton:hover { color: #94a3b8; }"
        )
        about_btn.clicked.connect(self._show_about)
        sb.addWidget(about_btn)

        # Status pill
        self._status_pill = QLabel("● Online")
        self._status_pill.setObjectName("statusPill")
        self._status_pill.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        self._status_pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_pill.setFixedHeight(32)
        sb.addWidget(self._status_pill)

        root.addWidget(sidebar)

        # ── Content stack ─────────────────────────────────────────────────────
        self._stack = QStackedWidget()
        self._stack.setObjectName("contentStack")

        self._scanner_screen   = ScannerScreen(self.config, self.db)
        self._dashboard_screen = DashboardScreen(self.config, self.db)
        self._history_screen   = HistoryScreen(self.config, self.db)
        self._qr_screen        = QRScannerScreen(self.config)
        self._settings_screen  = SettingsScreen(self.config)

        for w in [self._scanner_screen, self._dashboard_screen,
                  self._history_screen, self._qr_screen, self._settings_screen]:
            self._stack.addWidget(w)

        root.addWidget(self._stack)

        self._qr_screen.url_detected.connect(self._on_qr_url)
        self._settings_screen.theme_changed.connect(self._apply_theme)

        self.statusBar().showMessage(
            f"Ready  ·  Naija Scam Shield v{self.config.version}  ·  {self.config.author}"
        )

        self._screen_map = {
            "Scan URL": 0, "Dashboard": 1, "History": 2,
            "QR Scanner": 3, "Settings": 4,
        }

    # ── Navigation ────────────────────────────────────────────────────────────

    def _navigate(self, screen_name: str):
        idx = self._screen_map.get(screen_name, 0)
        self._stack.setCurrentIndex(idx)
        for i, btn in enumerate(self._nav_buttons):
            btn.setChecked(i == idx)
        if screen_name == "History":
            self._history_screen.refresh()
        if screen_name == "Dashboard":
            self._dashboard_screen.refresh()

    def _on_qr_url(self, url: str):
        self._navigate("Scan URL")
        self._scanner_screen.set_url_and_scan(url)

    # ── About dialog ──────────────────────────────────────────────────────────

    def _show_about(self):
        dlg = AboutDialog(self.config, parent=self)
        dlg.setStyleSheet(self.styleSheet())
        dlg.exec()

    # ── Theme ─────────────────────────────────────────────────────────────────

    def _apply_theme(self):
        self.setStyleSheet(get_stylesheet(self.config.theme))
        if self.config.offline_mode:
            self._status_pill.setText("● Offline")
            self._status_pill.setStyleSheet(
                "color: #f59e0b; background: #1c1a08; border-radius: 14px; margin: 8px 12px;"
            )
        else:
            self._status_pill.setText("● Online")
            self._status_pill.setStyleSheet(
                "color: #22c55e; background: #052e16; border-radius: 14px; margin: 8px 12px;"
            )
