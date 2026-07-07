"""
ui/screens/history_screen.py - Scan History Screen
Author: Joshua Akadri
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QMessageBox, QFileDialog
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor
from core.config import AppConfig
from database.db_manager import DatabaseManager
from reports.report_generator import ReportGenerator


RISK_COLORS = {
    "Safe":        "#22c55e",
    "Suspicious":  "#f59e0b",
    "High Risk":   "#f97316",
    "Likely Scam": "#ef4444",
    "Unknown":     "#94a3b8",
}


class HistoryScreen(QWidget):
    def __init__(self, config: AppConfig, db: DatabaseManager):
        super().__init__()
        self.config = config
        self.db = db
        self._report_gen = ReportGenerator(config)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(16)

        # Header
        header = QHBoxLayout()
        title = QLabel("Scan History")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        header.addWidget(title)
        header.addStretch()

        export_btn = QPushButton("📊 Export CSV")
        export_btn.setFixedHeight(36)
        export_btn.setProperty("class", "secondary")
        export_btn.clicked.connect(self._export_csv)

        clear_btn = QPushButton("🗑 Clear History")
        clear_btn.setFixedHeight(36)
        clear_btn.setProperty("class", "danger")
        clear_btn.clicked.connect(self._clear_history)

        header.addWidget(export_btn)
        header.addWidget(clear_btn)
        layout.addLayout(header)

        # Table
        self._table = QTableWidget()
        self._table.setColumnCount(6)
        self._table.setHorizontalHeaderLabels([
            "Domain", "Risk Score", "Risk Level", "Category", "Scan Time", "Duration"
        ])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in range(1, 6):
            self._table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)

        layout.addWidget(self._table, 1)
        self.refresh()

    def refresh(self):
        if not self.db:
            return
        history = self.db.get_scan_history(limit=200)
        self._table.setRowCount(len(history))
        for row_idx, scan in enumerate(history):
            risk = scan.get("risk_level", "Unknown")
            color = QColor(RISK_COLORS.get(risk, "#94a3b8"))

            items = [
                scan.get("domain", ""),
                f"{scan.get('risk_score', 0)}/100",
                risk,
                scan.get("scam_category") or "—",
                str(scan.get("scan_time", ""))[:16],
                f"{scan.get('duration_ms', 0)}ms",
            ]
            for col_idx, text in enumerate(items):
                item = QTableWidgetItem(text)
                if col_idx == 2:
                    item.setForeground(color)
                    item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
                self._table.setItem(row_idx, col_idx, item)

        self._table.resizeRowsToContents()

    def _export_csv(self):
        if not self.db:
            return
        history = self.db.get_scan_history(limit=1000)
        if not history:
            QMessageBox.information(self, "Empty", "No scan history to export.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Save CSV", str(self.config.reports_dir / "scan_history.csv"),
            "CSV Files (*.csv)"
        )
        if path:
            import csv
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=history[0].keys())
                writer.writeheader()
                writer.writerows(history)
            QMessageBox.information(self, "Exported", f"History exported to:\n{path}")

    def _clear_history(self):
        reply = QMessageBox.question(
            self, "Clear History",
            "Delete all scan history? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes and self.db:
            self.db.clear_history()
            self.refresh()
