"""
ui/styles.py - Application Stylesheets
Author: Joshua Akadri
"""

DARK = {
    "bg":          "#0f1117",
    "bg2":         "#13151f",
    "card":        "#1a1d29",
    "input":       "#1e2235",
    "sidebar":     "#0c0e17",
    "accent":      "#3b82f6",
    "accent_h":    "#2563eb",
    "green":       "#22c55e",
    "yellow":      "#f59e0b",
    "orange":      "#f97316",
    "red":         "#ef4444",
    "text":        "#f1f5f9",
    "text2":       "#94a3b8",
    "muted":       "#475569",
    "border":      "#252840",
    "border2":     "#1a1d2e",
}

LIGHT = {
    "bg":          "#f8fafc",
    "bg2":         "#f1f5f9",
    "card":        "#ffffff",
    "input":       "#f8fafc",
    "sidebar":     "#1a1d29",
    "accent":      "#2563eb",
    "accent_h":    "#1d4ed8",
    "green":       "#16a34a",
    "yellow":      "#d97706",
    "orange":      "#ea580c",
    "red":         "#dc2626",
    "text":        "#0f172a",
    "text2":       "#475569",
    "muted":       "#94a3b8",
    "border":      "#e2e8f0",
    "border2":     "#f1f5f9",
}

RISK_COLORS = {
    "dark": {
        "Safe":        ("#052e16", "#22c55e"),
        "Suspicious":  ("#1c1908", "#f59e0b"),
        "High Risk":   ("#1c0a04", "#f97316"),
        "Likely Scam": ("#1a0404", "#ef4444"),
        "Unknown":     ("#1a1d29", "#475569"),
    },
    "light": {
        "Safe":        ("#f0fdf4", "#16a34a"),
        "Suspicious":  ("#fffbeb", "#d97706"),
        "High Risk":   ("#fff7ed", "#ea580c"),
        "Likely Scam": ("#fef2f2", "#dc2626"),
        "Unknown":     ("#f8fafc", "#94a3b8"),
    },
}


def risk_color(risk_level: str, theme: str = "dark") -> str:
    return RISK_COLORS.get(theme, RISK_COLORS["dark"]).get(
        risk_level, ("#1a1d29", "#475569")
    )[1]


def risk_badge_id(risk_level: str) -> str:
    return {
        "Safe": "safe_badge", "Suspicious": "suspicious_badge",
        "High Risk": "highrisk_badge", "Likely Scam": "scam_badge",
    }.get(risk_level, "safe_badge")


def get_stylesheet(theme: str = "dark") -> str:
    c = DARK if theme == "dark" else LIGHT
    sidebar_text = "#cbd5e1"

    return f"""
/* ── Reset ──────────────────────────────────────────────────────────────── */
* {{ box-sizing: border-box; }}

QMainWindow, QWidget {{
    background-color: {c["bg"]};
    color: {c["text"]};
    font-family: "Segoe UI", "Inter", "Helvetica Neue", Arial, sans-serif;
    font-size: 13px;
}}

/* ── Sidebar ─────────────────────────────────────────────────────────────── */
QFrame#sidebar {{
    background-color: {c["sidebar"]};
    border-right: 1px solid {c["border"]};
}}

QFrame#logoFrame {{
    background-color: {c["sidebar"]};
}}

QLabel#logoLabel {{
    color: #f1f5f9;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.2px;
    background: transparent;
}}

QLabel#versionLabel {{
    color: #334155;
    font-size: 9px;
    background: transparent;
}}

/* ── Nav buttons ─────────────────────────────────────────────────────────── */
NavButton {{
    background-color: transparent;
    border: none;
    border-radius: 8px;
    color: #475569;
    text-align: left;
    margin: 1px 8px;
    padding: 0;
}}

NavButton QLabel {{
    background: transparent;
    color: inherit;
}}

NavButton:hover {{
    background-color: #1a1d2e;
    color: #94a3b8;
}}

NavButton:checked {{
    background-color: rgba(59,130,246,0.12);
    color: #60a5fa;
    border-left: 3px solid #3b82f6;
}}

NavButton:checked QLabel {{
    color: #60a5fa;
}}

QLabel#statusPill {{
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.3px;
    border-radius: 14px;
    margin: 6px 12px;
    padding: 4px 0;
}}

/* ── Stack / Content ─────────────────────────────────────────────────────── */
QStackedWidget#contentStack {{
    background-color: {c["bg"]};
}}

/* ── Cards ───────────────────────────────────────────────────────────────── */
QFrame.card, QFrame#card {{
    background-color: {c["card"]};
    border: 1px solid {c["border"]};
    border-radius: 12px;
}}

/* ── Input fields ────────────────────────────────────────────────────────── */
QLineEdit, QTextEdit, QPlainTextEdit {{
    background-color: {c["input"]};
    color: {c["text"]};
    border: 1.5px solid {c["border"]};
    border-radius: 9px;
    padding: 8px 14px;
    font-size: 13px;
    selection-background-color: {c["accent"]};
}}

QLineEdit:focus, QTextEdit:focus {{
    border-color: {c["accent"]};
    background-color: {c["card"]};
}}

/* ── Buttons ─────────────────────────────────────────────────────────────── */
QPushButton {{
    background-color: {c["accent"]};
    color: #ffffff;
    border: none;
    border-radius: 9px;
    padding: 9px 22px;
    font-size: 13px;
    font-weight: 600;
}}

QPushButton:hover  {{ background-color: {c["accent_h"]}; }}
QPushButton:pressed {{ background-color: #1d4ed8; }}
QPushButton:disabled {{ background-color: {c["muted"]}; color: {c["bg2"]}; }}

/* Tables ──────────────────────────────────────────────────────────────────── */
QTableWidget {{
    background-color: {c["card"]};
    color: {c["text"]};
    border: 1px solid {c["border"]};
    border-radius: 10px;
    gridline-color: {c["border2"]};
    font-size: 12px;
    outline: none;
}}

QTableWidget::item {{
    padding: 9px 14px;
    border: none;
}}

QTableWidget::item:selected {{
    background-color: rgba(59,130,246,0.15);
    color: {c["text"]};
}}

QHeaderView::section {{
    background-color: {c["bg2"]};
    color: {c["text2"]};
    border: none;
    border-bottom: 1px solid {c["border"]};
    padding: 9px 14px;
    font-weight: 700;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.6px;
}}

QHeaderView::section:first {{ border-top-left-radius: 10px; }}
QHeaderView::section:last  {{ border-top-right-radius: 10px; }}

/* ── Scroll bars ─────────────────────────────────────────────────────────── */
QScrollBar:vertical {{
    background: transparent;
    width: 6px;
    margin: 0;
}}

QScrollBar::handle:vertical {{
    background: {c["border"]};
    border-radius: 3px;
    min-height: 30px;
}}

QScrollBar::handle:vertical:hover {{ background: {c["muted"]}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: transparent; }}

QScrollBar:horizontal {{ height: 6px; background: transparent; }}
QScrollBar::handle:horizontal {{ background: {c["border"]}; border-radius: 3px; }}

/* ── Combo Box ───────────────────────────────────────────────────────────── */
QComboBox {{
    background-color: {c["input"]};
    color: {c["text"]};
    border: 1.5px solid {c["border"]};
    border-radius: 9px;
    padding: 7px 12px;
    font-size: 13px;
}}

QComboBox:focus {{ border-color: {c["accent"]}; }}
QComboBox::drop-down {{ border: none; width: 28px; }}
QComboBox QAbstractItemView {{
    background-color: {c["card"]};
    color: {c["text"]};
    border: 1px solid {c["border"]};
    selection-background-color: {c["accent"]};
    outline: none;
    padding: 4px;
}}

/* ── Progress Bar ────────────────────────────────────────────────────────── */
QProgressBar {{
    background-color: {c["border"]};
    border: none;
    border-radius: 5px;
    height: 8px;
    text-align: center;
    font-size: 0px;
}}

QProgressBar::chunk {{
    border-radius: 5px;
    background-color: {c["accent"]};
}}

/* ── Risk badges ─────────────────────────────────────────────────────────── */
QLabel#safe_badge {{
    background-color: #052e16; color: #22c55e;
    border: 1.5px solid #22c55e; border-radius: 20px;
    padding: 4px 16px; font-weight: 700; font-size: 11px;
}}

QLabel#suspicious_badge {{
    background-color: #1c1908; color: #f59e0b;
    border: 1.5px solid #f59e0b; border-radius: 20px;
    padding: 4px 16px; font-weight: 700; font-size: 11px;
}}

QLabel#highrisk_badge {{
    background-color: #1c0a04; color: #f97316;
    border: 1.5px solid #f97316; border-radius: 20px;
    padding: 4px 16px; font-weight: 700; font-size: 11px;
}}

QLabel#scam_badge {{
    background-color: #1a0404; color: #ef4444;
    border: 1.5px solid #ef4444; border-radius: 20px;
    padding: 4px 16px; font-weight: 700; font-size: 11px;
}}

/* ── Group Box ───────────────────────────────────────────────────────────── */
QGroupBox {{
    color: {c["text2"]};
    border: 1px solid {c["border"]};
    border-radius: 10px;
    margin-top: 14px;
    padding-top: 14px;
    font-weight: 700;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    left: 14px;
    padding: 0 6px;
    color: {c["muted"]};
    background-color: {c["bg"]};
}}

/* ── Checkbox ────────────────────────────────────────────────────────────── */
QCheckBox {{
    color: {c["text"]};
    spacing: 8px;
    font-size: 13px;
}}

QCheckBox::indicator {{
    width: 17px; height: 17px;
    border: 2px solid {c["border"]};
    border-radius: 5px;
    background-color: {c["input"]};
}}

QCheckBox::indicator:checked {{
    background-color: {c["accent"]};
    border-color: {c["accent"]};
}}

/* ── Spin Box ────────────────────────────────────────────────────────────── */
QSpinBox {{
    background-color: {c["input"]};
    color: {c["text"]};
    border: 1.5px solid {c["border"]};
    border-radius: 9px;
    padding: 6px 12px;
}}

/* ── Status Bar ──────────────────────────────────────────────────────────── */
QStatusBar {{
    background-color: {c["sidebar"]};
    color: {c["muted"]};
    border-top: 1px solid {c["border"]};
    font-size: 11px;
    padding: 0 14px;
}}

/* ── Tab ─────────────────────────────────────────────────────────────────── */
QTabWidget::pane {{
    background-color: {c["card"]};
    border: 1px solid {c["border"]};
    border-radius: 0 10px 10px 10px;
}}

QTabBar::tab {{
    background-color: {c["bg2"]};
    color: {c["text2"]};
    border: 1px solid {c["border"]};
    border-bottom: none;
    padding: 8px 20px;
    font-size: 12px;
    font-weight: 600;
}}

QTabBar::tab:selected {{ background-color: {c["card"]}; color: {c["text"]}; }}
QTabBar::tab:hover    {{ color: {c["text"]}; }}

/* ── Dialog ──────────────────────────────────────────────────────────────── */
QDialog {{
    background-color: #13151f;
    color: {c["text"]};
}}

/* ── Misc dim text ───────────────────────────────────────────────────────── */
QLabel#dimText {{ color: {c["text2"]}; }}

/* ── Tooltip ─────────────────────────────────────────────────────────────── */
QToolTip {{
    background-color: {c["card"]};
    color: {c["text"]};
    border: 1px solid {c["border"]};
    padding: 4px 8px;
    border-radius: 6px;
    font-size: 11px;
}}
"""


# keep old aliases so existing imports don't break
NAV_BUTTON_STYLE = ""
NAV_BUTTON_ACTIVE_STYLE = ""
