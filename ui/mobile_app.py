"""
ui/mobile_app.py — Kivy Mobile UI for Android APK
Author: Joshua Akadri
GitHub: sudopenmark

This module provides a Kivy-based mobile UI that replaces the PyQt6 desktop UI
when building for Android via BeeWare/Briefcase.

Usage (development):
    python ui/mobile_app.py

Build (Android APK via Briefcase):
    briefcase create android
    briefcase build android
    briefcase run android
"""

import sys
import os
import threading
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from kivy.app import App
    from kivy.uix.screenmanager import ScreenManager, Screen, SlideTransition
    from kivy.uix.boxlayout import BoxLayout
    from kivy.uix.gridlayout import GridLayout
    from kivy.uix.scrollview import ScrollView
    from kivy.uix.label import Label
    from kivy.uix.button import Button
    from kivy.uix.textinput import TextInput
    from kivy.uix.progressbar import ProgressBar
    from kivy.uix.widget import Widget
    from kivy.uix.popup import Popup
    from kivy.core.window import Window
    from kivy.metrics import dp, sp
    from kivy.clock import Clock
    from kivy.utils import get_color_from_hex
    from kivy.lang import Builder
    KIVY_AVAILABLE = True
except ImportError:
    KIVY_AVAILABLE = False

# ── KV Layout String ──────────────────────────────────────────────────────────

KV = """
#:import get_color_from_hex kivy.utils.get_color_from_hex

<RoundedButton@Button>:
    background_normal: ''
    background_color: get_color_from_hex('#3b82f6')
    color: get_color_from_hex('#ffffff')
    font_size: sp(14)
    bold: True
    size_hint_y: None
    height: dp(48)
    canvas.before:
        Color:
            rgba: self.background_color
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(10)]

<DangerButton@Button>:
    background_normal: ''
    background_color: get_color_from_hex('#ef4444')
    color: get_color_from_hex('#ffffff')
    font_size: sp(13)
    bold: True
    size_hint_y: None
    height: dp(44)
    canvas.before:
        Color:
            rgba: self.background_color
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(8)]

<SecondaryButton@Button>:
    background_normal: ''
    background_color: get_color_from_hex('#1e2130')
    color: get_color_from_hex('#94a3b8')
    font_size: sp(13)
    size_hint_y: None
    height: dp(44)
    canvas.before:
        Color:
            rgba: self.background_color
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(8)]

<NavBar>:
    size_hint_y: None
    height: dp(56)
    orientation: 'horizontal'
    spacing: dp(2)
    padding: dp(4)
    canvas.before:
        Color:
            rgba: get_color_from_hex('#13151f')
        Rectangle:
            pos: self.pos
            size: self.size

<CardWidget>:
    size_hint_y: None
    canvas.before:
        Color:
            rgba: get_color_from_hex('#1e2130')
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(12)]

<ScanScreen>:
    name: 'scan'
    BoxLayout:
        orientation: 'vertical'
        canvas.before:
            Color:
                rgba: get_color_from_hex('#0f1117')
            Rectangle:
                pos: self.pos
                size: self.size

        # Header
        BoxLayout:
            size_hint_y: None
            height: dp(64)
            padding: dp(16), dp(12)
            canvas.before:
                Color:
                    rgba: get_color_from_hex('#13151f')
                Rectangle:
                    pos: self.pos
                    size: self.size
            Label:
                text: '🛡️  Naija Scam Shield'
                font_size: sp(16)
                bold: True
                color: get_color_from_hex('#f1f5f9')
                halign: 'left'
                text_size: self.size
                valign: 'middle'

        # URL input area
        BoxLayout:
            orientation: 'vertical'
            padding: dp(16)
            spacing: dp(10)
            size_hint_y: None
            height: dp(160)

            Label:
                text: 'Enter URL to scan'
                font_size: sp(11)
                bold: True
                color: get_color_from_hex('#64748b')
                halign: 'left'
                text_size: self.size
                size_hint_y: None
                height: dp(20)

            TextInput:
                id: url_input
                hint_text: 'https://example.com or paste a URL'
                multiline: False
                font_size: sp(13)
                background_color: get_color_from_hex('#252840')
                foreground_color: get_color_from_hex('#f1f5f9')
                cursor_color: get_color_from_hex('#3b82f6')
                hint_text_color: get_color_from_hex('#475569')
                padding: dp(12), dp(10)
                size_hint_y: None
                height: dp(44)

            BoxLayout:
                spacing: dp(8)
                size_hint_y: None
                height: dp(48)

                RoundedButton:
                    text: '🔍  Scan URL'
                    on_press: root.start_scan()

                SecondaryButton:
                    text: '📋 Paste'
                    size_hint_x: 0.4
                    on_press: root.paste_clipboard()

        # Progress
        ProgressBar:
            id: progress_bar
            max: 100
            value: 0
            size_hint_y: None
            height: dp(4)
            opacity: 0

        # Results scroll area
        ScrollView:
            BoxLayout:
                id: results_box
                orientation: 'vertical'
                padding: dp(16)
                spacing: dp(10)
                size_hint_y: None
                height: self.minimum_height

        # Nav bar
        NavBar:
            id: nav_bar

<HistoryScreen>:
    name: 'history'
    BoxLayout:
        orientation: 'vertical'
        canvas.before:
            Color:
                rgba: get_color_from_hex('#0f1117')
            Rectangle:
                pos: self.pos
                size: self.size

        BoxLayout:
            size_hint_y: None
            height: dp(64)
            padding: dp(16), dp(12)
            canvas.before:
                Color:
                    rgba: get_color_from_hex('#13151f')
                Rectangle:
                    pos: self.pos
                    size: self.size
            Label:
                text: '📋  Scan History'
                font_size: sp(16)
                bold: True
                color: get_color_from_hex('#f1f5f9')
                halign: 'left'
                text_size: self.size
                valign: 'middle'

        ScrollView:
            BoxLayout:
                id: history_list
                orientation: 'vertical'
                padding: dp(12)
                spacing: dp(8)
                size_hint_y: None
                height: self.minimum_height

        NavBar:
            id: nav_bar

<SettingsScreen>:
    name: 'settings'
    BoxLayout:
        orientation: 'vertical'
        canvas.before:
            Color:
                rgba: get_color_from_hex('#0f1117')
            Rectangle:
                pos: self.pos
                size: self.size

        BoxLayout:
            size_hint_y: None
            height: dp(64)
            padding: dp(16), dp(12)
            canvas.before:
                Color:
                    rgba: get_color_from_hex('#13151f')
                Rectangle:
                    pos: self.pos
                    size: self.size
            Label:
                text: '⚙️  Settings'
                font_size: sp(16)
                bold: True
                color: get_color_from_hex('#f1f5f9')
                halign: 'left'
                text_size: self.size
                valign: 'middle'

        ScrollView:
            BoxLayout:
                id: settings_content
                orientation: 'vertical'
                padding: dp(16)
                spacing: dp(12)
                size_hint_y: None
                height: self.minimum_height

        NavBar:
            id: nav_bar
"""

# ── Risk Colors ───────────────────────────────────────────────────────────────

RISK_COLORS = {
    "Safe":        "#22c55e",
    "Suspicious":  "#f59e0b",
    "High Risk":   "#f97316",
    "Likely Scam": "#ef4444",
    "Unknown":     "#94a3b8",
}

RISK_BG = {
    "Safe":        "#052e16",
    "Suspicious":  "#1c1a08",
    "High Risk":   "#1c0a05",
    "Likely Scam": "#1a0505",
    "Unknown":     "#1e2130",
}


if KIVY_AVAILABLE:
    class NavBar(BoxLayout):
        """Bottom navigation bar."""

        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self._screen_manager = None

        def setup(self, screen_manager):
            self._screen_manager = screen_manager
            self.clear_widgets()

            buttons = [
                ("🔍\nScan",    "scan"),
                ("📋\nHistory", "history"),
                ("⚙️\nSettings","settings"),
            ]
            for label, screen_name in buttons:
                btn = Button(
                    text=label,
                    background_normal='',
                    background_color=get_color_from_hex('#13151f'),
                    color=get_color_from_hex('#94a3b8'),
                    font_size=sp(11),
                    halign='center',
                )
                btn.bind(on_press=lambda x, s=screen_name: self._navigate(s))
                self.add_widget(btn)

        def _navigate(self, screen_name: str):
            if self._screen_manager:
                self._screen_manager.current = screen_name

    class CardWidget(BoxLayout):
        pass

    class ScanScreen(Screen):
        """Main URL scan screen."""

        def __init__(self, config, db, **kwargs):
            super().__init__(**kwargs)
            self.config = config
            self.db = db
            self._result = None

        def on_enter(self):
            """Set up nav bar when screen is shown."""
            self.ids.nav_bar.setup(self.manager)

        def paste_clipboard(self):
            try:
                from kivy.core.clipboard import Clipboard
                text = Clipboard.paste()
                if text:
                    self.ids.url_input.text = text.strip()
            except Exception:
                pass

        def start_scan(self):
            url = self.ids.url_input.text.strip()
            if not url:
                return
            self._show_scanning()
            thread = threading.Thread(target=self._do_scan, args=(url,), daemon=True)
            thread.start()

        def _show_scanning(self):
            pb = self.ids.progress_bar
            pb.opacity = 1
            self._animate_progress()
            self._clear_results()

        def _animate_progress(self, *args):
            pb = self.ids.progress_bar
            if pb.value < 90:
                pb.value += 5
                Clock.schedule_once(self._animate_progress, 0.15)

        def _do_scan(self, url: str):
            from core.scanner import Scanner
            scanner = Scanner(self.config, self.db)
            result = scanner.scan(url)
            Clock.schedule_once(lambda dt: self._show_result(result), 0)

        def _show_result(self, result):
            self._result = result
            pb = self.ids.progress_bar
            pb.value = 100
            Clock.schedule_once(lambda dt: setattr(pb, 'opacity', 0), 0.5)
            self._render_result(result)

        def _clear_results(self):
            self.ids.results_box.clear_widgets()

        def _render_result(self, result):
            box = self.ids.results_box
            box.clear_widgets()

            risk = result.risk_level.value
            score = result.risk_score
            color = RISK_COLORS.get(risk, "#94a3b8")
            bg = RISK_BG.get(risk, "#1e2130")

            # Official domain banner
            if result.is_official_domain:
                off_card = self._make_card(
                    f"✅  Official Domain\n{result.official_brand}",
                    bg_color="#052e16", text_color="#22c55e",
                    font_size=sp(13), bold=True, height=dp(64),
                )
                box.add_widget(off_card)

            # Risk score card
            score_card = BoxLayout(
                orientation='vertical',
                size_hint_y=None,
                height=dp(110),
                padding=dp(14),
                spacing=dp(4),
            )
            with score_card.canvas.before:
                from kivy.graphics import Color as KColor, RoundedRectangle as KRR
                KColor(*get_color_from_hex(bg))
                KRR(pos=score_card.pos, size=score_card.size, radius=[dp(12)])

            score_card.bind(
                pos=lambda w, v: self._redraw_bg(w, bg),
                size=lambda w, v: self._redraw_bg(w, bg),
            )

            score_row = BoxLayout(size_hint_y=None, height=dp(44))
            score_lbl = Label(
                text=f"[b]{score}[/b]",
                markup=True,
                font_size=sp(32),
                color=get_color_from_hex(color),
                size_hint_x=0.3,
            )
            level_lbl = Label(
                text=f"[b]{risk}[/b]",
                markup=True,
                font_size=sp(16),
                color=get_color_from_hex(color),
                halign='left',
                valign='middle',
            )
            level_lbl.bind(size=lambda w, v: setattr(w, 'text_size', v))
            score_row.add_widget(score_lbl)
            score_row.add_widget(level_lbl)
            score_card.add_widget(score_row)

            pb = ProgressBar(max=100, value=score, size_hint_y=None, height=dp(8))
            score_card.add_widget(pb)
            box.add_widget(score_card)

            # Domain info
            domain_card = self._make_info_card([
                ("Domain", result.domain),
                ("Category", result.scam_category.value if result.scam_category else "—"),
                ("IP", result.ip_address or "—"),
            ])
            box.add_widget(domain_card)

            # Summary
            if result.summary:
                summary_card = self._make_card(
                    result.summary,
                    bg_color=bg, text_color=color,
                    height=dp(70), font_size=sp(12),
                )
                box.add_widget(summary_card)

                if result.recommendation:
                    rec_card = self._make_card(
                        result.recommendation,
                        bg_color="#1e2130", text_color="#cbd5e1",
                        height=dp(80), font_size=sp(11),
                    )
                    box.add_widget(rec_card)

            # Indicators
            if result.indicators:
                ind_title = Label(
                    text=f"[b]Threat Indicators ({len(result.indicators)})[/b]",
                    markup=True,
                    font_size=sp(12),
                    color=get_color_from_hex('#f1f5f9'),
                    size_hint_y=None,
                    height=dp(28),
                    halign='left',
                )
                ind_title.bind(size=lambda w, v: setattr(w, 'text_size', v))
                box.add_widget(ind_title)

                sev_colors = {
                    "critical": "#ef4444", "high": "#f97316",
                    "medium": "#f59e0b", "low": "#3b82f6"
                }
                sorted_inds = sorted(
                    result.indicators,
                    key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 4)
                )
                for ind in sorted_inds[:8]:  # Show top 8 on mobile
                    sc = sev_colors.get(ind.severity, "#94a3b8")
                    text = f"[color={sc}][b]{ind.indicator_type}[/b][/color]\n[color=#94a3b8][size=10]{ind.description}[/size][/color]"
                    ind_card = self._make_card(
                        text, markup=True,
                        bg_color="#1e2130", text_color="#f1f5f9",
                        height=dp(64), font_size=sp(12),
                    )
                    box.add_widget(ind_card)

            # Action buttons
            actions = BoxLayout(
                orientation='vertical',
                size_hint_y=None,
                height=dp(110),
                spacing=dp(8),
                padding=[0, dp(8), 0, 0],
            )

            report_btn = Button(
                text='🚨  Report This Site',
                background_normal='',
                background_color=get_color_from_hex('#ef4444'),
                color=get_color_from_hex('#fff'),
                font_size=sp(13),
                bold=True,
                size_hint_y=None,
                height=dp(44),
            )
            report_btn.bind(on_press=lambda x: self._report_site(result))

            share_btn = Button(
                text='📤  Share Report',
                background_normal='',
                background_color=get_color_from_hex('#1e2130'),
                color=get_color_from_hex('#94a3b8'),
                font_size=sp(13),
                size_hint_y=None,
                height=dp(44),
            )
            share_btn.bind(on_press=lambda x: self._share_result(result))

            actions.add_widget(report_btn)
            actions.add_widget(share_btn)
            box.add_widget(actions)

        def _report_site(self, result):
            if self.db:
                self.db.add_user_report(
                    result.original_url, result.domain,
                    f"Mobile report. Risk: {result.risk_level.value}"
                )
            popup = Popup(
                title='Reported',
                content=Label(
                    text="Reported to local database.\nAlso report to:\nEFCC: efcc.gov.ng",
                    halign='center',
                ),
                size_hint=(0.8, 0.35),
            )
            popup.open()

        def _share_result(self, result):
            text = (
                f"Naija Scam Shield Report\n"
                f"Domain: {result.domain}\n"
                f"Risk: {result.risk_level.value} ({result.risk_score}/100)\n"
                f"{result.summary}"
            )
            try:
                from kivy.core.clipboard import Clipboard
                Clipboard.copy(text)
                popup = Popup(
                    title='Copied',
                    content=Label(text="Report copied to clipboard!"),
                    size_hint=(0.7, 0.25),
                )
                popup.open()
            except Exception:
                pass

        def _make_card(self, text, bg_color="#1e2130", text_color="#f1f5f9",
                       height=None, font_size=None, bold=False, markup=False):
            from kivy.graphics import Color as KColor, RoundedRectangle as KRR
            card = BoxLayout(
                size_hint_y=None,
                height=height or dp(60),
                padding=dp(12),
            )

            def draw_bg(widget, *args):
                widget.canvas.before.clear()
                with widget.canvas.before:
                    KColor(*get_color_from_hex(bg_color))
                    KRR(pos=widget.pos, size=widget.size, radius=[dp(10)])

            card.bind(pos=draw_bg, size=draw_bg)

            lbl = Label(
                text=text,
                markup=markup,
                font_size=font_size or sp(12),
                color=get_color_from_hex(text_color),
                halign='left',
                valign='middle',
                bold=bold,
            )
            lbl.bind(size=lambda w, v: setattr(w, 'text_size', v))
            card.add_widget(lbl)
            return card

        def _make_info_card(self, items):
            from kivy.graphics import Color as KColor, RoundedRectangle as KRR
            card = BoxLayout(
                orientation='vertical',
                size_hint_y=None,
                height=dp(len(items) * 32 + 16),
                padding=dp(12),
                spacing=dp(4),
            )

            def draw_bg(widget, *args):
                widget.canvas.before.clear()
                with widget.canvas.before:
                    KColor(*get_color_from_hex('#1e2130'))
                    KRR(pos=widget.pos, size=widget.size, radius=[dp(10)])

            card.bind(pos=draw_bg, size=draw_bg)

            for label, value in items:
                row = BoxLayout(size_hint_y=None, height=dp(28))
                lbl = Label(
                    text=label.upper(),
                    font_size=sp(9),
                    bold=True,
                    color=get_color_from_hex('#64748b'),
                    size_hint_x=0.35,
                    halign='left',
                    valign='middle',
                )
                lbl.bind(size=lambda w, v: setattr(w, 'text_size', v))
                val = Label(
                    text=str(value),
                    font_size=sp(11),
                    color=get_color_from_hex('#f1f5f9'),
                    halign='left',
                    valign='middle',
                )
                val.bind(size=lambda w, v: setattr(w, 'text_size', v))
                row.add_widget(lbl)
                row.add_widget(val)
                card.add_widget(row)
            return card

        def _redraw_bg(self, widget, color):
            from kivy.graphics import Color as KColor, RoundedRectangle as KRR
            widget.canvas.before.clear()
            with widget.canvas.before:
                KColor(*get_color_from_hex(color))
                KRR(pos=widget.pos, size=widget.size, radius=[dp(12)])

    class HistoryScreen(Screen):
        """Scan history screen."""

        def __init__(self, db, **kwargs):
            super().__init__(**kwargs)
            self.db = db

        def on_enter(self):
            self.ids.nav_bar.setup(self.manager)
            self._load_history()

        def _load_history(self):
            box = self.ids.history_list
            box.clear_widgets()

            if not self.db:
                return

            history = self.db.get_scan_history(limit=50)
            if not history:
                lbl = Label(
                    text="No scan history yet.\nScan a URL to get started!",
                    font_size=sp(13),
                    color=get_color_from_hex('#64748b'),
                    halign='center',
                    size_hint_y=None,
                    height=dp(80),
                )
                box.add_widget(lbl)
                return

            RISK_COLORS_M = {
                "Safe": "#22c55e", "Suspicious": "#f59e0b",
                "High Risk": "#f97316", "Likely Scam": "#ef4444",
            }

            for scan in history:
                risk = scan.get("risk_level", "Unknown")
                color = RISK_COLORS_M.get(risk, "#94a3b8")
                from kivy.graphics import Color as KColor, RoundedRectangle as KRR

                row = BoxLayout(
                    size_hint_y=None,
                    height=dp(58),
                    padding=dp(12),
                    spacing=dp(8),
                )

                def draw_row_bg(widget, *args):
                    widget.canvas.before.clear()
                    with widget.canvas.before:
                        KColor(*get_color_from_hex('#1e2130'))
                        KRR(pos=widget.pos, size=widget.size, radius=[dp(8)])

                row.bind(pos=draw_row_bg, size=draw_row_bg)

                info = BoxLayout(orientation='vertical')
                domain_lbl = Label(
                    text=f"[b]{scan.get('domain', '—')}[/b]",
                    markup=True,
                    font_size=sp(12),
                    color=get_color_from_hex('#f1f5f9'),
                    halign='left',
                    valign='middle',
                )
                domain_lbl.bind(size=lambda w, v: setattr(w, 'text_size', v))
                time_lbl = Label(
                    text=str(scan.get('scan_time', ''))[:16],
                    font_size=sp(9),
                    color=get_color_from_hex('#64748b'),
                    halign='left',
                    valign='middle',
                )
                time_lbl.bind(size=lambda w, v: setattr(w, 'text_size', v))
                info.add_widget(domain_lbl)
                info.add_widget(time_lbl)

                risk_lbl = Label(
                    text=f"[b]{risk}[/b]\n[size=10]{scan.get('risk_score', 0)}/100[/size]",
                    markup=True,
                    font_size=sp(11),
                    color=get_color_from_hex(color),
                    size_hint_x=0.38,
                    halign='right',
                    valign='middle',
                )
                risk_lbl.bind(size=lambda w, v: setattr(w, 'text_size', v))

                row.add_widget(info)
                row.add_widget(risk_lbl)
                box.add_widget(row)

    class SettingsScreen(Screen):
        """Settings screen."""

        def __init__(self, config, **kwargs):
            super().__init__(**kwargs)
            self.config = config

        def on_enter(self):
            self.ids.nav_bar.setup(self.manager)
            self._build_settings()

        def _build_settings(self):
            box = self.ids.settings_content
            box.clear_widgets()

            # API key input
            vt_label = Label(
                text="VirusTotal API Key (optional)",
                font_size=sp(12),
                color=get_color_from_hex('#94a3b8'),
                size_hint_y=None,
                height=dp(28),
                halign='left',
            )
            vt_label.bind(size=lambda w, v: setattr(w, 'text_size', v))
            box.add_widget(vt_label)

            self._vt_input = TextInput(
                hint_text="Enter VirusTotal API key",
                text=self.config.virustotal_api_key or "",
                password=True,
                multiline=False,
                font_size=sp(12),
                background_color=get_color_from_hex('#252840'),
                foreground_color=get_color_from_hex('#f1f5f9'),
                hint_text_color=get_color_from_hex('#475569'),
                padding=dp(10),
                size_hint_y=None,
                height=dp(42),
            )
            box.add_widget(self._vt_input)

            save_btn = Button(
                text='💾  Save Settings',
                background_normal='',
                background_color=get_color_from_hex('#3b82f6'),
                color=get_color_from_hex('#ffffff'),
                font_size=sp(13),
                bold=True,
                size_hint_y=None,
                height=dp(46),
            )
            save_btn.bind(on_press=self._save)
            box.add_widget(save_btn)

            # About
            about = Label(
                text=(
                    "[b]Naija Scam Shield[/b] v1.0.0\n"
                    "Author: [b]Joshua Akadri[/b]\n"
                    "GitHub: sudopenmark\n\n"
                    "Protecting Nigerians from online scams.\n"
                    "Report scams: efcc.gov.ng | cbn.gov.ng"
                ),
                markup=True,
                font_size=sp(11),
                color=get_color_from_hex('#94a3b8'),
                halign='center',
                size_hint_y=None,
                height=dp(120),
            )
            about.bind(size=lambda w, v: setattr(w, 'text_size', v))
            box.add_widget(about)

        def _save(self, *args):
            vt_key = self._vt_input.text.strip()
            if vt_key:
                self.config.virustotal_api_key = vt_key
                self.config.enable_virustotal = True
            self.config.save()
            popup = Popup(
                title='Saved',
                content=Label(text="Settings saved!"),
                size_hint=(0.6, 0.2),
            )
            popup.open()

    class NaijaScamShieldApp(App):
        """Main Kivy Application."""

        def build(self):
            from core.config import AppConfig
            from database.db_manager import DatabaseManager
            from kivy.core.window import Window

            Window.clearcolor = get_color_from_hex('#0f1117')

            config = AppConfig()
            db = DatabaseManager(config.db_path)
            db.initialize()

            Builder.load_string(KV)

            sm = ScreenManager(transition=SlideTransition())

            scan_screen = ScanScreen(config=config, db=db, name='scan')
            history_screen = HistoryScreen(db=db, name='history')
            settings_screen = SettingsScreen(config=config, name='settings')

            sm.add_widget(scan_screen)
            sm.add_widget(history_screen)
            sm.add_widget(settings_screen)

            return sm

        def get_application_name(self):
            return "Naija Scam Shield"


def run_mobile():
    """Entry point for mobile/Kivy app."""
    if not KIVY_AVAILABLE:
        print("ERROR: Kivy is not installed.")
        print("Install with: pip install kivy")
        sys.exit(1)
    NaijaScamShieldApp().run()


if __name__ == "__main__":
    run_mobile()
