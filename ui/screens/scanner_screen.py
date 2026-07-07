"""
ui/screens/scanner_screen.py - Main URL Scanner Screen
Author: Joshua Akadri
"""

import logging
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
    QLabel, QFrame, QScrollArea, QProgressBar, QGroupBox,
    QSizePolicy, QGraphicsDropShadowEffect
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QGuiApplication

from core.scanner import Scanner
from core.models import ScanResult, RiskLevel
from core.config import AppConfig
from database.db_manager import DatabaseManager
from ui.styles import risk_color, risk_badge_id
from reports.report_generator import ReportGenerator

logger = logging.getLogger(__name__)


RISK_BG = {
    "Safe":        ("#052e16", "#22c55e"),
    "Suspicious":  ("#1c1908", "#f59e0b"),
    "High Risk":   ("#1c0a04", "#f97316"),
    "Likely Scam": ("#1a0404", "#ef4444"),
    "Unknown":     ("#1a1d29", "#475569"),
}


class ScanWorker(QThread):
    scan_complete = pyqtSignal(object)
    scan_error    = pyqtSignal(str)

    def __init__(self, scanner: Scanner, url: str):
        super().__init__()
        self.scanner = scanner
        self.url = url

    def run(self):
        try:
            self.scan_complete.emit(self.scanner.scan(self.url))
        except Exception as e:
            logger.exception("Scan worker error")
            self.scan_error.emit(str(e))


# ── Reusable card builder ─────────────────────────────────────────────────────

def _card(bg: str = "#1a1d29", border: str = "#252840",
          radius: int = 12) -> QFrame:
    f = QFrame()
    f.setStyleSheet(
        f"QFrame {{ background-color: {bg}; border: 1px solid {border};"
        f"border-radius: {radius}px; }}"
    )
    return f


# ── Risk Meter ────────────────────────────────────────────────────────────────

class RiskMeter(QFrame):
    """Score number + badge + progress bar."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(106)
        self.setStyleSheet(
            "QFrame { background: #1a1d29; border: 1px solid #252840; border-radius: 12px; }"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 14, 22, 14)
        layout.setSpacing(8)

        top = QHBoxLayout()
        self._score_lbl = QLabel("—")
        self._score_lbl.setFont(QFont("Segoe UI", 38, QFont.Weight.Black))
        self._score_lbl.setStyleSheet("color: #475569; background: transparent; border: none;")

        self._badge = QLabel("—")
        self._badge.setObjectName("safe_badge")
        self._badge.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self._badge.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        self._badge.setStyleSheet("background: transparent; border: none; color: #475569;")

        self._out_of = QLabel("/100")
        self._out_of.setFont(QFont("Segoe UI", 13))
        self._out_of.setStyleSheet("color: #334155; background: transparent; border: none;")
        self._out_of.setAlignment(Qt.AlignmentFlag.AlignBottom)

        top.addWidget(self._score_lbl)
        top.addWidget(self._out_of)
        top.addSpacing(14)
        top.addWidget(self._badge)
        top.addStretch()
        layout.addLayout(top)

        self._bar = QProgressBar()
        self._bar.setRange(0, 100)
        self._bar.setValue(0)
        self._bar.setTextVisible(False)
        self._bar.setFixedHeight(6)
        self._bar.setStyleSheet(
            "QProgressBar { background: #252840; border: none; border-radius: 3px; }"
            "QProgressBar::chunk { border-radius: 3px; background: #475569; }"
        )
        layout.addWidget(self._bar)

    def update_score(self, score: int, risk_level: str, theme: str = "dark"):
        color = risk_color(risk_level, theme)
        self._score_lbl.setText(str(score))
        self._score_lbl.setStyleSheet(
            f"color: {color}; background: transparent; border: none;"
        )
        self._badge.setText(risk_level)
        self._badge.setObjectName(risk_badge_id(risk_level))
        self._badge.style().unpolish(self._badge)
        self._badge.style().polish(self._badge)
        self._bar.setValue(score)
        self._bar.setStyleSheet(
            f"QProgressBar {{ background: #252840; border: none; border-radius: 3px; }}"
            f"QProgressBar::chunk {{ border-radius: 3px; background: {color}; }}"
        )


# ── Indicator row ─────────────────────────────────────────────────────────────

SEVERITY_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class IndicatorRow(QFrame):
    def __init__(self, indicator, parent=None):
        super().__init__(parent)
        self.setStyleSheet(
            "QFrame { background: #13151f; border-radius: 8px; }"
        )
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 9, 14, 9)
        layout.setSpacing(10)

        icon = QLabel(SEVERITY_ICON.get(indicator.severity, "⚪"))
        icon.setFixedWidth(18)
        icon.setFont(QFont("Segoe UI Emoji", 11))
        icon.setStyleSheet("background: transparent;")

        text_col = QVBoxLayout()
        text_col.setSpacing(1)

        type_lbl = QLabel(indicator.indicator_type)
        type_lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        type_lbl.setStyleSheet("color: #e2e8f0; background: transparent;")

        desc_lbl = QLabel(indicator.description)
        desc_lbl.setFont(QFont("Segoe UI", 9))
        desc_lbl.setWordWrap(True)
        desc_lbl.setStyleSheet("color: #64748b; background: transparent;")

        text_col.addWidget(type_lbl)
        text_col.addWidget(desc_lbl)

        impact_lbl = QLabel(f"+{indicator.score_impact}")
        impact_lbl.setFixedWidth(36)
        impact_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        impact_lbl.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        sev_colors = {"critical": "#ef4444", "high": "#f97316",
                      "medium": "#f59e0b", "low": "#64748b"}
        impact_lbl.setStyleSheet(
            f"color: {sev_colors.get(indicator.severity, '#64748b')}; background: transparent;"
        )

        layout.addWidget(icon)
        layout.addLayout(text_col, 1)
        layout.addWidget(impact_lbl)


# ── Scanner screen ────────────────────────────────────────────────────────────

class ScannerScreen(QWidget):

    def __init__(self, config: AppConfig, db: DatabaseManager):
        super().__init__()
        self.config = config
        self.db = db
        self.scanner = Scanner(config, db)
        self._worker = None
        self._current_result = None
        self._report_gen = ReportGenerator(config)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Top bar ──────────────────────────────────────────────────────────
        topbar = QFrame()
        topbar.setFixedHeight(64)
        topbar.setStyleSheet(
            "QFrame { background: #0c0e17; border-bottom: 1px solid #1a1d2e; }"
        )
        tl = QHBoxLayout(topbar)
        tl.setContentsMargins(28, 0, 28, 0)
        tl.setSpacing(12)

        title = QLabel("Scan URL")
        title.setFont(QFont("Segoe UI", 15, QFont.Weight.Bold))
        title.setStyleSheet("color: #f1f5f9; background: transparent;")

        tl.addWidget(title)
        tl.addStretch()

        paste_btn = QPushButton("📋  Paste")
        paste_btn.setFixedHeight(34)
        paste_btn.setStyleSheet(
            "QPushButton { background: #1a1d29; color: #94a3b8; border: 1px solid #252840;"
            "border-radius: 8px; font-size: 11px; padding: 0 14px; }"
            "QPushButton:hover { background: #1e2235; color: #f1f5f9; }"
        )
        paste_btn.clicked.connect(self._paste_clipboard)
        tl.addWidget(paste_btn)

        layout.addWidget(topbar)

        # ── URL input strip ───────────────────────────────────────────────────
        input_strip = QFrame()
        input_strip.setFixedHeight(72)
        input_strip.setStyleSheet(
            "QFrame { background: #0f1117; border-bottom: 1px solid #1a1d2e; }"
        )
        il = QHBoxLayout(input_strip)
        il.setContentsMargins(28, 12, 28, 12)
        il.setSpacing(10)

        self._url_input = QLineEdit()
        self._url_input.setPlaceholderText(
            "Enter or paste a URL  —  e.g.  opay-promo-bonus.xyz  or  https://gtbank.com"
        )
        self._url_input.setFixedHeight(46)
        self._url_input.setFont(QFont("Segoe UI", 12))
        self._url_input.returnPressed.connect(self._start_scan)

        self._scan_btn = QPushButton("🔍  Scan")
        self._scan_btn.setFixedSize(116, 46)
        self._scan_btn.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        self._scan_btn.clicked.connect(self._start_scan)

        il.addWidget(self._url_input, 1)
        il.addWidget(self._scan_btn)
        layout.addWidget(input_strip)

        # Progress bar (4 px, hidden when idle)
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setFixedHeight(3)
        self._progress.setVisible(False)
        self._progress.setStyleSheet(
            "QProgressBar { background: #0f1117; border: none; }"
            "QProgressBar::chunk { background: #3b82f6; }"
        )
        layout.addWidget(self._progress)

        # ── Results scroll area ───────────────────────────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("background: #0f1117;")

        self._results_widget = QWidget()
        self._results_widget.setStyleSheet("background: #0f1117;")
        self._results_layout = QVBoxLayout(self._results_widget)
        self._results_layout.setContentsMargins(28, 24, 28, 28)
        self._results_layout.setSpacing(12)

        self._empty_state = self._build_empty_state()
        self._results_layout.addWidget(self._empty_state)
        self._results_layout.addStretch()

        scroll.setWidget(self._results_widget)
        layout.addWidget(scroll, 1)

    def _build_empty_state(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        l = QVBoxLayout(w)
        l.setAlignment(Qt.AlignmentFlag.AlignCenter)
        l.setSpacing(10)
        l.setContentsMargins(0, 80, 0, 0)

        shield = QLabel("🛡️")
        shield.setFont(QFont("Segoe UI Emoji", 52))
        shield.setAlignment(Qt.AlignmentFlag.AlignCenter)
        shield.setStyleSheet("background: transparent;")

        msg = QLabel("Enter any URL above to check if it's safe")
        msg.setFont(QFont("Segoe UI", 13))
        msg.setStyleSheet("color: #334155; background: transparent;")
        msg.setAlignment(Qt.AlignmentFlag.AlignCenter)

        hint = QLabel("Tip — use  📋 Paste  to check URLs from WhatsApp, SMS, or email")
        hint.setFont(QFont("Segoe UI", 10))
        hint.setStyleSheet("color: #252840; background: transparent;")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)

        l.addWidget(shield)
        l.addWidget(msg)
        l.addWidget(hint)
        return w

    # ── Public API ────────────────────────────────────────────────────────────

    def set_url_and_scan(self, url: str):
        self._url_input.setText(url)
        self._start_scan()

    # ── Internals ─────────────────────────────────────────────────────────────

    def _paste_clipboard(self):
        text = QGuiApplication.clipboard().text().strip()
        if text:
            self._url_input.setText(text)

    def _start_scan(self):
        url = self._url_input.text().strip()
        if not url or (self._worker and self._worker.isRunning()):
            return
        self._scan_btn.setEnabled(False)
        self._scan_btn.setText("Scanning…")
        self._progress.setVisible(True)
        self._clear_results()
        self._worker = ScanWorker(self.scanner, url)
        self._worker.scan_complete.connect(self._on_scan_complete)
        self._worker.scan_error.connect(self._on_scan_error)
        self._worker.start()

    def _on_scan_complete(self, result: ScanResult):
        self._current_result = result
        self._scan_btn.setEnabled(True)
        self._scan_btn.setText("🔍  Scan")
        self._progress.setVisible(False)
        self._display_result(result)

    def _on_scan_error(self, error: str):
        self._scan_btn.setEnabled(True)
        self._scan_btn.setText("🔍  Scan")
        self._progress.setVisible(False)
        err = QLabel(f"⚠️  Scan error: {error}")
        err.setStyleSheet("color: #f97316; background: transparent; padding: 12px 0;")
        self._results_layout.insertWidget(0, err)

    def _clear_results(self):
        while self._results_layout.count():
            item = self._results_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _display_result(self, result: ScanResult):
        self._clear_results()
        rl = result.risk_level.value
        bg, fg = RISK_BG.get(rl, RISK_BG["Unknown"])

        # ── Official domain banner ────────────────────────────────────────────
        if result.is_official_domain:
            banner = QFrame()
            banner.setFixedHeight(46)
            banner.setStyleSheet(
                "QFrame { background: #052e16; border: 1.5px solid #22c55e; border-radius: 10px; }"
            )
            bl = QHBoxLayout(banner)
            bl.setContentsMargins(16, 0, 16, 0)
            lbl = QLabel(f"✅  Official Domain  —  {result.official_brand}")
            lbl.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
            lbl.setStyleSheet("color: #22c55e; background: transparent;")
            bl.addWidget(lbl)
            self._results_layout.addWidget(banner)

        # ── Risk meter ────────────────────────────────────────────────────────
        meter = RiskMeter()
        meter.update_score(result.risk_score, rl, self.config.theme)
        self._results_layout.addWidget(meter)

        # ── Meta row (domain / category / IP / time) ─────────────────────────
        meta = _card()
        ml = QHBoxLayout(meta)
        ml.setContentsMargins(18, 12, 18, 12)
        ml.setSpacing(0)

        def _col(label: str, value: str) -> QVBoxLayout:
            col = QVBoxLayout()
            col.setSpacing(2)
            l = QLabel(label.upper())
            l.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
            l.setStyleSheet("color: #334155; letter-spacing: 0.5px; background: transparent;")
            v = QLabel(value or "—")
            v.setFont(QFont("Segoe UI", 11))
            v.setStyleSheet("color: #e2e8f0; background: transparent;")
            v.setWordWrap(True)
            col.addWidget(l)
            col.addWidget(v)
            return col

        sep_style = "background: #252840; min-width: 1px; max-width: 1px; margin: 6px 18px;"

        ml.addLayout(_col("Domain", result.domain), 3)
        s1 = QFrame(); s1.setFrameShape(QFrame.Shape.VLine); s1.setStyleSheet(sep_style)
        ml.addWidget(s1)
        ml.addLayout(_col("Category", result.scam_category.value if result.scam_category else "—"), 3)
        s2 = QFrame(); s2.setFrameShape(QFrame.Shape.VLine); s2.setStyleSheet(sep_style)
        ml.addWidget(s2)
        ml.addLayout(_col("IP", result.ip_address or "—"), 2)
        s3 = QFrame(); s3.setFrameShape(QFrame.Shape.VLine); s3.setStyleSheet(sep_style)
        ml.addWidget(s3)
        ml.addLayout(_col("Duration", f"{result.duration_ms} ms"), 2)
        self._results_layout.addWidget(meta)

        # ── Summary card ──────────────────────────────────────────────────────
        if result.summary:
            summ = QFrame()
            summ.setStyleSheet(
                f"QFrame {{ background: {bg}; border: 1.5px solid {fg}; border-radius: 10px; }}"
            )
            sl = QVBoxLayout(summ)
            sl.setContentsMargins(16, 12, 16, 12)
            sl.setSpacing(6)

            s_lbl = QLabel(result.summary)
            s_lbl.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
            s_lbl.setWordWrap(True)
            s_lbl.setStyleSheet(f"color: {fg}; background: transparent;")

            r_lbl = QLabel(result.recommendation)
            r_lbl.setFont(QFont("Segoe UI", 10))
            r_lbl.setWordWrap(True)
            r_lbl.setStyleSheet("color: #94a3b8; background: transparent;")

            sl.addWidget(s_lbl)
            sl.addWidget(r_lbl)
            self._results_layout.addWidget(summ)

        # ── Indicators ────────────────────────────────────────────────────────
        if result.indicators:
            ind_group = QGroupBox(f"Threat Indicators  ({len(result.indicators)})")
            ind_layout = QVBoxLayout(ind_group)
            ind_layout.setSpacing(4)
            ind_layout.setContentsMargins(8, 8, 8, 8)

            for ind in sorted(result.indicators,
                              key=lambda x: SEVERITY_ORDER.get(x.severity, 4)):
                ind_layout.addWidget(IndicatorRow(ind))
            self._results_layout.addWidget(ind_group)

        # ── WHOIS + Certificate ───────────────────────────────────────────────
        if result.whois or result.certificate:
            detail_group = QGroupBox("Domain & Certificate")
            dl = QHBoxLayout(detail_group)
            dl.setSpacing(20)
            dl.setContentsMargins(14, 10, 14, 10)

            if result.whois and result.whois.age_days is not None:
                age_parts = [f"📅  Domain age: {result.whois.age_days} days"]
                if result.whois.registrar:
                    age_parts.append(f"Registrar: {result.whois.registrar}")
                w_lbl = QLabel("\n".join(age_parts))
                w_lbl.setFont(QFont("Segoe UI", 10))
                w_lbl.setStyleSheet("color: #94a3b8; background: transparent;")
                w_lbl.setWordWrap(True)
                dl.addWidget(w_lbl, 1)

            if result.certificate:
                if result.certificate.valid:
                    cert_txt = (
                        f"🔒  SSL Valid"
                        + (f"  ·  Issuer: {result.certificate.issuer}" if result.certificate.issuer else "")
                        + (f"\nExpires in {result.certificate.days_remaining} days"
                           if result.certificate.days_remaining is not None else "")
                    )
                else:
                    cert_txt = f"⚠️  SSL Invalid: {result.certificate.error or 'unknown'}"
                c_lbl = QLabel(cert_txt)
                c_lbl.setFont(QFont("Segoe UI", 10))
                c_lbl.setStyleSheet("color: #94a3b8; background: transparent;")
                c_lbl.setWordWrap(True)
                dl.addWidget(c_lbl, 1)

            self._results_layout.addWidget(detail_group)

        # ── Threat Intel ──────────────────────────────────────────────────────
        if result.threat_intel:
            ti_group = QGroupBox("Threat Intelligence")
            tl = QVBoxLayout(ti_group)
            tl.setContentsMargins(14, 10, 14, 10)
            for ti in result.threat_intel:
                status = "⚠️  Malicious" if ti.is_malicious else "✅  Clean"
                text = (
                    f"{ti.source}:  {status}"
                    + (f"  ({ti.detection_count}/{ti.total_engines} detections)"
                       if ti.total_engines else "")
                    + (f"  —  {ti.error}" if ti.error else "")
                )
                l = QLabel(text)
                l.setFont(QFont("Segoe UI", 10))
                l.setStyleSheet("color: #94a3b8; background: transparent;")
                tl.addWidget(l)
            self._results_layout.addWidget(ti_group)

        # ── Action row ────────────────────────────────────────────────────────
        actions = QHBoxLayout()
        actions.setSpacing(8)
        actions.setContentsMargins(0, 4, 0, 0)

        def _action_btn(text: str, style: str) -> QPushButton:
            b = QPushButton(text)
            b.setFixedHeight(38)
            b.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
            b.setStyleSheet(style)
            return b

        primary  = "QPushButton { background:#3b82f6; color:#fff; border:none; border-radius:9px; padding:0 18px; } QPushButton:hover { background:#2563eb; }"
        secondary= "QPushButton { background:#1a1d29; color:#94a3b8; border:1px solid #252840; border-radius:9px; padding:0 18px; } QPushButton:hover { background:#1e2235; color:#f1f5f9; }"
        danger   = "QPushButton { background:#1a0404; color:#ef4444; border:1px solid #ef4444; border-radius:9px; padding:0 18px; } QPushButton:hover { background:#ef4444; color:#fff; }"

        pdf_btn  = _action_btn("📄  PDF Report", primary)
        csv_btn  = _action_btn("📊  CSV", secondary)
        rep_btn  = _action_btn("🚨  Report Site", danger)

        pdf_btn.clicked.connect(self._export_pdf)
        csv_btn.clicked.connect(self._export_csv)
        rep_btn.clicked.connect(self._report_site)

        actions.addWidget(pdf_btn)
        actions.addWidget(csv_btn)
        actions.addWidget(rep_btn)
        actions.addStretch()

        self._results_layout.addLayout(actions)
        self._results_layout.addStretch()

    # ── Export / report ───────────────────────────────────────────────────────

    def _export_pdf(self):
        if not self._current_result:
            return
        path = self._report_gen.export_pdf(self._current_result)
        if path:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.information(self, "Saved", f"PDF report saved to:\n{path}")

    def _export_csv(self):
        if not self._current_result:
            return
        path = self._report_gen.export_csv([self._current_result])
        if path:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.information(self, "Saved", f"CSV saved to:\n{path}")

    def _report_site(self):
        if not self._current_result:
            return
        if self.db:
            self.db.add_user_report(
                self._current_result.original_url,
                self._current_result.domain,
                f"User report — Risk: {self._current_result.risk_level.value}",
            )
        from PyQt6.QtWidgets import QMessageBox
        QMessageBox.information(
            self, "Reported",
            "Site added to your local report database.\n\n"
            "Also report to EFCC: efcc.gov.ng  ·  0800-CALL-EFCC"
        )
