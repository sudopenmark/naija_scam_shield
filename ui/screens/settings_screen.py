"""
ui/screens/settings_screen.py - Settings Screen
Author: Joshua Akadri
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QGroupBox, QCheckBox, QComboBox, QLineEdit,
    QSpinBox, QFormLayout, QScrollArea, QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from core.config import AppConfig


class SettingsScreen(QWidget):
    theme_changed = pyqtSignal()

    def __init__(self, config: AppConfig):
        super().__init__()
        self.config = config
        self._build_ui()

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(32, 28, 32, 28)
        outer.setSpacing(16)

        title = QLabel("Settings")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        outer.addWidget(title)

        scroll = QScrollArea()
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidgetResizable(True)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setSpacing(20)
        layout.setContentsMargins(0, 0, 0, 0)

        # ── Appearance ───────────────────────────────────────────────────────
        appear_group = QGroupBox("Appearance")
        appear_layout = QFormLayout(appear_group)
        self._theme_combo = QComboBox()
        self._theme_combo.addItems(["Dark", "Light"])
        self._theme_combo.setCurrentText(self.config.theme.capitalize())
        self._theme_combo.currentTextChanged.connect(self._on_theme_change)
        appear_layout.addRow("Theme:", self._theme_combo)
        layout.addWidget(appear_group)

        # ── Scanner Settings ─────────────────────────────────────────────────
        scan_group = QGroupBox("Scanner Settings")
        scan_layout = QFormLayout(scan_group)

        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(5, 60)
        self._timeout_spin.setValue(self.config.scan_timeout)
        self._timeout_spin.setSuffix(" seconds")
        scan_layout.addRow("Scan Timeout:", self._timeout_spin)

        self._offline_cb = QCheckBox("Offline Mode (no network requests)")
        self._offline_cb.setChecked(self.config.offline_mode)
        scan_layout.addRow("", self._offline_cb)

        self._whois_cb = QCheckBox("Enable WHOIS domain age lookup")
        self._whois_cb.setChecked(self.config.enable_whois)
        scan_layout.addRow("", self._whois_cb)

        layout.addWidget(scan_group)

        # ── API Keys ─────────────────────────────────────────────────────────
        api_group = QGroupBox("API Keys (Optional - Enhances Detection)")
        api_layout = QFormLayout(api_group)

        api_note = QLabel(
            "These are optional. The app works without them using local intelligence.\n"
            "API keys are stored only on your device."
        )
        api_note.setFont(QFont("Segoe UI", 9))
        api_note.setStyleSheet("color: #64748b;")
        api_note.setWordWrap(True)
        api_layout.addRow(api_note)

        self._vt_key = QLineEdit()
        self._vt_key.setPlaceholderText("VirusTotal API key (free at virustotal.com)")
        self._vt_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._vt_key.setText(self.config.virustotal_api_key or "")
        self._vt_cb = QCheckBox("Enable VirusTotal")
        self._vt_cb.setChecked(self.config.enable_virustotal)
        api_layout.addRow("VirusTotal:", self._vt_key)
        api_layout.addRow("", self._vt_cb)

        self._pt_key = QLineEdit()
        self._pt_key.setPlaceholderText("PhishTank API key (optional, free at phishtank.com)")
        self._pt_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._pt_key.setText(self.config.phishtank_api_key or "")
        self._pt_cb = QCheckBox("Enable PhishTank")
        self._pt_cb.setChecked(self.config.enable_phishtank)
        api_layout.addRow("PhishTank:", self._pt_key)
        api_layout.addRow("", self._pt_cb)

        layout.addWidget(api_group)

        # ── QR Scanner ───────────────────────────────────────────────────────
        qr_group = QGroupBox("QR Scanner")
        qr_layout = QFormLayout(qr_group)
        self._qr_cb = QCheckBox("Enable QR code scanning")
        self._qr_cb.setChecked(self.config.enable_qr_scanner)
        qr_layout.addRow("", self._qr_cb)
        layout.addWidget(qr_group)

        # ── About ─────────────────────────────────────────────────────────────
        about_group = QGroupBox("About")
        about_layout = QVBoxLayout(about_group)
        about_text = QLabel(
            f"<b>Naija Scam Shield</b> v{self.config.version}<br>"
            f"Author: <b>{self.config.author}</b><br><br>"
            "Protecting Nigerians from online scams, phishing, and fraud.<br><br>"
            "Report suspected scams to:<br>"
            "• <a href='https://efcc.gov.ng'>EFCC: efcc.gov.ng</a><br>"
            "• <a href='https://cbn.gov.ng'>CBN: cbn.gov.ng</a><br>"
            "• <a href='https://nitda.gov.ng'>NITDA: nitda.gov.ng</a>"
        )
        about_text.setFont(QFont("Segoe UI", 10))
        about_text.setOpenExternalLinks(True)
        about_text.setWordWrap(True)
        about_layout.addWidget(about_text)
        layout.addWidget(about_group)

        # Save button
        save_btn = QPushButton("💾 Save Settings")
        save_btn.setFixedHeight(44)
        save_btn.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        save_btn.clicked.connect(self._save)
        layout.addWidget(save_btn)
        layout.addStretch()

        scroll.setWidget(content)
        outer.addWidget(scroll)

    def _on_theme_change(self, theme: str):
        self.config.theme = theme.lower()
        self.theme_changed.emit()

    def _save(self):
        self.config.scan_timeout = self._timeout_spin.value()
        self.config.offline_mode = self._offline_cb.isChecked()
        self.config.enable_whois = self._whois_cb.isChecked()
        self.config.enable_virustotal = self._vt_cb.isChecked()
        self.config.enable_phishtank = self._pt_cb.isChecked()
        self.config.enable_qr_scanner = self._qr_cb.isChecked()

        vt_key = self._vt_key.text().strip()
        if vt_key:
            self.config.virustotal_api_key = vt_key
        pt_key = self._pt_key.text().strip()
        if pt_key:
            self.config.phishtank_api_key = pt_key

        self.config.save()
        QMessageBox.information(self, "Saved", "Settings saved successfully.")
