"""
ui/screens/dashboard_screen.py - Dashboard & Statistics Screen
Author: Joshua Akadri
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QGridLayout, QScrollArea
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from core.config import AppConfig
from database.db_manager import DatabaseManager


class MetricCard(QFrame):
    def __init__(self, value: str, label: str, icon: str, color: str, parent=None):
        super().__init__(parent)
        self.setFixedHeight(110)
        self.setStyleSheet(
            f"QFrame {{ background-color: #1e2130; border: 1px solid #2a2d3e; "
            f"border-radius: 12px; border-left: 4px solid {color}; }}"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)

        icon_lbl = QLabel(icon)
        icon_lbl.setFont(QFont("Segoe UI Emoji", 20))

        val_lbl = QLabel(value)
        val_lbl.setFont(QFont("Segoe UI", 26, QFont.Weight.Black))
        val_lbl.setStyleSheet(f"color: {color};")

        lbl_lbl = QLabel(label)
        lbl_lbl.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        lbl_lbl.setStyleSheet("color: #64748b; letter-spacing: 0.5px;")

        layout.addWidget(icon_lbl)
        layout.addWidget(val_lbl)
        layout.addWidget(lbl_lbl)


class DashboardScreen(QWidget):
    def __init__(self, config: AppConfig, db: DatabaseManager):
        super().__init__()
        self.config = config
        self.db = db
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(20)

        title = QLabel("Dashboard")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        subtitle = QLabel("Your scan statistics and threat overview")
        subtitle.setFont(QFont("Segoe UI", 11))
        subtitle.setStyleSheet("color: #64748b;")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        # Metrics grid
        self._grid = QGridLayout()
        self._grid.setSpacing(12)
        layout.addLayout(self._grid)

        # Recent history
        history_title = QLabel("Recent Scans")
        history_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        layout.addWidget(history_title)

        scroll = QScrollArea()
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidgetResizable(True)

        self._history_widget = QWidget()
        self._history_layout = QVBoxLayout(self._history_widget)
        self._history_layout.setSpacing(6)
        self._history_layout.addStretch()

        scroll.setWidget(self._history_widget)
        layout.addWidget(scroll, 1)

        self.refresh()

    def refresh(self):
        self._update_metrics()
        self._update_history()

    def _update_metrics(self):
        # Clear grid
        while self._grid.count():
            item = self._grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        stats = self.db.get_history_stats() if self.db else {"total": 0, "threats_detected": 0, "safe": 0}
        suspicious = stats["total"] - stats["threats_detected"] - stats["safe"]

        cards = [
            (str(stats["total"]),             "Total Scans",        "🔍", "#3b82f6"),
            (str(stats["safe"]),              "Safe Sites",         "✅", "#22c55e"),
            (str(max(0, suspicious)),         "Suspicious",         "⚠️", "#f59e0b"),
            (str(stats["threats_detected"]),  "Threats Detected",   "🚨", "#ef4444"),
        ]
        for i, (val, label, icon, color) in enumerate(cards):
            card = MetricCard(val, label, icon, color)
            self._grid.addWidget(card, 0, i)

    def _update_history(self):
        while self._history_layout.count() > 1:
            item = self._history_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not self.db:
            return

        history = self.db.get_scan_history(limit=10)
        if not history:
            empty = QLabel("No scans yet. Scan a URL to get started!")
            empty.setFont(QFont("Segoe UI", 11))
            empty.setStyleSheet("color: #64748b;")
            empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self._history_layout.insertWidget(0, empty)
            return

        RISK_COLORS = {
            "Safe": "#22c55e", "Suspicious": "#f59e0b",
            "High Risk": "#f97316", "Likely Scam": "#ef4444",
        }

        for scan in history:
            row = QFrame()
            row.setFixedHeight(52)
            row.setStyleSheet(
                "QFrame { background-color: #1e2130; border: 1px solid #2a2d3e; "
                "border-radius: 8px; }"
            )
            rl = QHBoxLayout(row)
            rl.setContentsMargins(14, 0, 14, 0)

            risk = scan.get("risk_level", "Unknown")
            color = RISK_COLORS.get(risk, "#94a3b8")

            domain_lbl = QLabel(scan.get("domain", "—"))
            domain_lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))

            time_lbl = QLabel(str(scan.get("scan_time", ""))[:16])
            time_lbl.setFont(QFont("Segoe UI", 9))
            time_lbl.setStyleSheet("color: #64748b;")

            risk_lbl = QLabel(risk)
            risk_lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
            risk_lbl.setStyleSheet(f"color: {color};")
            risk_lbl.setFixedWidth(100)
            risk_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

            score_lbl = QLabel(f"{scan.get('risk_score', 0)}/100")
            score_lbl.setFont(QFont("Segoe UI", 9))
            score_lbl.setStyleSheet("color: #64748b;")
            score_lbl.setFixedWidth(60)
            score_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

            rl.addWidget(domain_lbl, 2)
            rl.addWidget(time_lbl, 2)
            rl.addWidget(score_lbl)
            rl.addWidget(risk_lbl)

            self._history_layout.insertWidget(self._history_layout.count() - 1, row)
