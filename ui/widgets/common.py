"""
ui/widgets/common.py — Reusable PyQt6 Widgets
Author: Joshua Akadri
GitHub: sudopenmark
"""

from PyQt6.QtWidgets import (
    QFrame, QLabel, QHBoxLayout, QVBoxLayout,
    QPushButton, QWidget, QProgressBar, QLineEdit,
    QGraphicsDropShadowEffect,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QPainter, QPen, QBrush


# ── Utility ───────────────────────────────────────────────────────────────────

def shadow(widget: QWidget, blur: int = 16, color: str = "#000000", opacity: float = 0.25):
    """Apply a drop shadow to any widget."""
    effect = QGraphicsDropShadowEffect()
    effect.setBlurRadius(blur)
    c = QColor(color)
    c.setAlphaF(opacity)
    effect.setColor(c)
    effect.setOffset(0, 2)
    widget.setGraphicsEffect(effect)
    return effect


# ── Risk Badge ────────────────────────────────────────────────────────────────

RISK_STYLES = {
    "Safe": {
        "bg": "#052e16", "border": "#22c55e", "text": "#22c55e",
    },
    "Suspicious": {
        "bg": "#1c1a08", "border": "#f59e0b", "text": "#f59e0b",
    },
    "High Risk": {
        "bg": "#1c0a05", "border": "#f97316", "text": "#f97316",
    },
    "Likely Scam": {
        "bg": "#1a0505", "border": "#ef4444", "text": "#ef4444",
    },
    "Unknown": {
        "bg": "#1e2130", "border": "#475569", "text": "#94a3b8",
    },
}


class RiskBadge(QLabel):
    """Pill-shaped risk level badge."""

    def __init__(self, risk_level: str = "Unknown", parent=None):
        super().__init__(parent)
        self.set_risk(risk_level)

    def set_risk(self, risk_level: str):
        s = RISK_STYLES.get(risk_level, RISK_STYLES["Unknown"])
        self.setText(risk_level)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self.setFixedHeight(30)
        self.setMinimumWidth(100)
        self.setStyleSheet(
            f"background-color: {s['bg']};"
            f"color: {s['text']};"
            f"border: 1.5px solid {s['border']};"
            f"border-radius: 15px;"
            f"padding: 0 14px;"
        )


# ── Score Donut ───────────────────────────────────────────────────────────────

class ScoreDonut(QWidget):
    """
    Circular score gauge widget.
    Draws an arc whose sweep angle represents the 0-100 risk score.
    """

    RISK_COLORS = {
        "Safe":        QColor("#22c55e"),
        "Suspicious":  QColor("#f59e0b"),
        "High Risk":   QColor("#f97316"),
        "Likely Scam": QColor("#ef4444"),
        "Unknown":     QColor("#475569"),
    }

    def __init__(self, score: int = 0, risk_level: str = "Unknown", parent=None):
        super().__init__(parent)
        self._score = score
        self._risk_level = risk_level
        self.setFixedSize(120, 120)

    def set_score(self, score: int, risk_level: str):
        self._score = max(0, min(100, score))
        self._risk_level = risk_level
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = self.rect().adjusted(10, 10, -10, -10)
        color = self.RISK_COLORS.get(self._risk_level, QColor("#475569"))

        # Background arc
        pen_bg = QPen(QColor("#1e2130"))
        pen_bg.setWidth(10)
        pen_bg.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen_bg)
        painter.drawArc(rect, 0, 360 * 16)

        # Score arc
        pen_score = QPen(color)
        pen_score.setWidth(10)
        pen_score.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen_score)
        sweep = int(-self._score / 100 * 360 * 16)
        painter.drawArc(rect, 90 * 16, sweep)

        # Score text
        painter.setPen(QPen(color))
        painter.setFont(QFont("Segoe UI", 18, QFont.Weight.Black))
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, str(self._score))


# ── Stat Card ─────────────────────────────────────────────────────────────────

class StatCard(QFrame):
    """
    A metric card for the dashboard, showing icon + value + label.
    """

    def __init__(
        self,
        icon: str,
        value: str,
        label: str,
        accent_color: str = "#3b82f6",
        parent=None,
    ):
        super().__init__(parent)
        self._accent = accent_color
        self._value_lbl: QLabel = None  # type: ignore
        self._build(icon, value, label, accent_color)

    def _build(self, icon: str, value: str, label: str, color: str):
        self.setFixedHeight(110)
        self.setStyleSheet(
            f"QFrame {{ background-color: #1e2130; border-radius: 12px; "
            f"border: 1px solid #2a2d3e; border-left: 4px solid {color}; }}"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(3)

        icon_lbl = QLabel(icon)
        icon_lbl.setFont(QFont("Segoe UI Emoji", 18))

        self._value_lbl = QLabel(value)
        self._value_lbl.setFont(QFont("Segoe UI", 26, QFont.Weight.Black))
        self._value_lbl.setStyleSheet(f"color: {color};")

        label_lbl = QLabel(label.upper())
        label_lbl.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        label_lbl.setStyleSheet("color: #475569; letter-spacing: 0.5px;")

        layout.addWidget(icon_lbl)
        layout.addWidget(self._value_lbl)
        layout.addWidget(label_lbl)

    def update_value(self, value: str):
        self._value_lbl.setText(value)


# ── Clickable URL Label ───────────────────────────────────────────────────────

class URLLabel(QLabel):
    """Clickable URL label that emits clicked(url) signal."""

    clicked = pyqtSignal(str)

    def __init__(self, url: str, display: str = "", parent=None):
        super().__init__(parent)
        self._url = url
        self.setText(display or url)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet(
            "color: #60a5fa; text-decoration: underline;"
        )

    def mousePressEvent(self, event):
        self.clicked.emit(self._url)


# ── Section Divider ───────────────────────────────────────────────────────────

class SectionDivider(QWidget):
    """Horizontal rule with an optional label — used to separate result sections."""

    def __init__(self, label: str = "", parent=None):
        super().__init__(parent)
        self.setFixedHeight(24)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        def _line():
            f = QFrame()
            f.setFrameShape(QFrame.Shape.HLine)
            f.setStyleSheet("color: #2a2d3e;")
            return f

        if label:
            layout.addWidget(_line(), 1)
            lbl = QLabel(label.upper())
            lbl.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            lbl.setStyleSheet("color: #475569; letter-spacing: 0.5px;")
            layout.addWidget(lbl)
            layout.addWidget(_line(), 1)
        else:
            layout.addWidget(_line())


# ── Notification Toast ────────────────────────────────────────────────────────

class Toast(QFrame):
    """
    Temporary notification banner that auto-dismisses.
    Shows at the bottom of its parent widget.

    Usage:
        toast = Toast(parent=main_window, message="Scan complete!", level="success")
        toast.show_for(3000)
    """

    LEVELS = {
        "success": ("#052e16", "#22c55e"),
        "warning": ("#1c1a08", "#f59e0b"),
        "error":   ("#1a0505", "#ef4444"),
        "info":    ("#0c1730", "#3b82f6"),
    }

    def __init__(self, parent: QWidget, message: str, level: str = "info"):
        super().__init__(parent)
        bg, fg = self.LEVELS.get(level, self.LEVELS["info"])
        self.setStyleSheet(
            f"background-color: {bg}; border: 1.5px solid {fg}; "
            f"border-radius: 10px; padding: 4px 0;"
        )
        self.setFixedHeight(44)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 0, 16, 0)

        lbl = QLabel(message)
        lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        lbl.setStyleSheet(f"color: {fg}; background: transparent; border: none;")
        layout.addWidget(lbl)

        close_btn = QPushButton("✕")
        close_btn.setFixedSize(24, 24)
        close_btn.setStyleSheet(
            f"background: transparent; border: none; color: {fg}; font-size: 11px;"
        )
        close_btn.clicked.connect(self.hide)
        layout.addWidget(close_btn)

        self._reposition()

    def show_for(self, ms: int = 3000):
        """Show the toast and auto-hide after `ms` milliseconds."""
        from PyQt6.QtCore import QTimer
        self.show()
        self.raise_()
        QTimer.singleShot(ms, self.hide)

    def _reposition(self):
        if self.parent():
            parent = self.parent()
            w = parent.width() - 40
            self.setFixedWidth(w)
            self.move(20, parent.height() - 60)

    def resizeEvent(self, event):
        self._reposition()
        super().resizeEvent(event)


# ── Scan Input Bar ────────────────────────────────────────────────────────────

class ScanInputBar(QWidget):
    """
    Self-contained URL input bar with scan button, used in both the
    scanner screen and the main toolbar.
    """

    scan_requested = pyqtSignal(str)  # emitted with the URL

    def __init__(self, placeholder: str = "Enter URL to scan…", parent=None):
        super().__init__(parent)
        self.setFixedHeight(50)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self._input = QLineEdit()
        self._input.setPlaceholderText(placeholder)
        self._input.setFixedHeight(46)
        self._input.setFont(QFont("Segoe UI", 12))
        self._input.returnPressed.connect(self._emit)

        self._btn = QPushButton("🔍 Scan")
        self._btn.setFixedSize(100, 46)
        self._btn.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self._btn.clicked.connect(self._emit)

        layout.addWidget(self._input, 1)
        layout.addWidget(self._btn)

    @property
    def url(self) -> str:
        return self._input.text().strip()

    @url.setter
    def url(self, value: str):
        self._input.setText(value)

    def set_scanning(self, scanning: bool):
        self._btn.setEnabled(not scanning)
        self._btn.setText("Scanning…" if scanning else "🔍 Scan")

    def _emit(self):
        url = self.url
        if url:
            self.scan_requested.emit(url)
