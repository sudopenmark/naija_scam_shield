"""
reports/report_generator.py - PDF and CSV Report Generation
Author: Joshua Akadri
"""

import csv
import logging
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from core.config import AppConfig
from core.models import ScanResult

logger = logging.getLogger(__name__)

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm, cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("reportlab not installed; PDF export will be disabled.")


RISK_COLORS_HEX = {
    "Safe":        "#22c55e",
    "Suspicious":  "#f59e0b",
    "High Risk":   "#f97316",
    "Likely Scam": "#ef4444",
    "Unknown":     "#94a3b8",
}

SEVERITY_COLORS = {
    "critical": "#ef4444",
    "high":     "#f97316",
    "medium":   "#f59e0b",
    "low":      "#3b82f6",
}


def _hex_to_rl_color(hex_color: str):
    """Convert hex color string to ReportLab Color."""
    hex_color = hex_color.lstrip("#")
    r, g, b = tuple(int(hex_color[i:i+2], 16) / 255 for i in (0, 2, 4))
    return colors.Color(r, g, b)


class ReportGenerator:
    """Generates PDF and CSV scan reports."""

    def __init__(self, config: AppConfig):
        self.config = config

    def export_pdf(self, result: ScanResult, output_path: Optional[Path] = None) -> Optional[Path]:
        """Export a single scan result as a PDF report."""
        if not REPORTLAB_AVAILABLE:
            logger.error("reportlab is not installed. Cannot generate PDF.")
            return None

        if output_path is None:
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            safe_domain = result.domain.replace(".", "_").replace("/", "_")
            output_path = self.config.reports_dir / f"scan_{safe_domain}_{ts}.pdf"

        try:
            self._build_pdf(result, output_path)
            logger.info("PDF report saved: %s", output_path)
            return output_path
        except Exception as e:
            logger.exception("PDF generation failed: %s", e)
            return None

    def _build_pdf(self, result: ScanResult, output_path: Path):
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            rightMargin=20 * mm,
            leftMargin=20 * mm,
            topMargin=20 * mm,
            bottomMargin=20 * mm,
            title=f"Naija Scam Shield Report — {result.domain}",
            author=self.config.author,
        )

        styles = getSampleStyleSheet()
        story = []

        # ── Styles ────────────────────────────────────────────────────────────
        h1 = ParagraphStyle(
            "H1", parent=styles["Heading1"],
            fontSize=20, textColor=colors.HexColor("#0f172a"),
            spaceAfter=4,
        )
        h2 = ParagraphStyle(
            "H2", parent=styles["Heading2"],
            fontSize=13, textColor=colors.HexColor("#1e293b"),
            spaceBefore=12, spaceAfter=4,
        )
        body = ParagraphStyle(
            "Body", parent=styles["Normal"],
            fontSize=10, textColor=colors.HexColor("#334155"),
            spaceAfter=4, leading=16,
        )
        small = ParagraphStyle(
            "Small", parent=styles["Normal"],
            fontSize=8, textColor=colors.HexColor("#64748b"),
        )
        label_style = ParagraphStyle(
            "Label", parent=styles["Normal"],
            fontSize=8, textColor=colors.HexColor("#64748b"),
            fontName="Helvetica-Bold",
        )

        # ── Header ────────────────────────────────────────────────────────────
        story.append(Paragraph("🛡️ Naija Scam Shield", h1))
        story.append(Paragraph(
            f"Security Scan Report &mdash; Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            small
        ))
        story.append(Paragraph(f"Author: {self.config.author} | v{self.config.version}", small))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0"), spaceAfter=12))

        # ── Risk Summary Box ─────────────────────────────────────────────────
        risk_color = _hex_to_rl_color(RISK_COLORS_HEX.get(result.risk_level.value, "#94a3b8"))
        bg_color = colors.HexColor("#f8fafc")

        risk_data = [
            [
                Paragraph(f"<b>Risk Score</b>", label_style),
                Paragraph(f"<b>Risk Level</b>", label_style),
                Paragraph(f"<b>Domain</b>", label_style),
                Paragraph(f"<b>Scan Time</b>", label_style),
            ],
            [
                Paragraph(f"<font size='20'><b>{result.risk_score}/100</b></font>", body),
                Paragraph(
                    f"<font color='{RISK_COLORS_HEX.get(result.risk_level.value, '#94a3b8')}'>"
                    f"<b>{result.risk_level.value}</b></font>",
                    body
                ),
                Paragraph(result.domain, body),
                Paragraph(result.scan_time.strftime("%Y-%m-%d %H:%M UTC"), body),
            ]
        ]

        risk_table = Table(risk_data, colWidths=["25%", "25%", "30%", "20%"])
        risk_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#ffffff")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LINEBELOW", (0, 0), (-1, 0), 2, risk_color),
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 12))

        # ── Official Domain Banner ────────────────────────────────────────────
        if result.is_official_domain:
            official_data = [[
                Paragraph(
                    f"✅ <b>OFFICIAL DOMAIN</b> — Verified as {result.official_brand}",
                    ParagraphStyle("Official", parent=body,
                                   textColor=colors.HexColor("#16a34a"),
                                   fontName="Helvetica-Bold")
                )
            ]]
            off_table = Table(official_data, colWidths=["100%"])
            off_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0fdf4")),
                ("BOX", (0, 0), (-1, -1), 1.5, colors.HexColor("#22c55e")),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]))
            story.append(off_table)
            story.append(Spacer(1, 8))

        # ── URL Info ─────────────────────────────────────────────────────────
        story.append(Paragraph("Scan Details", h2))
        details = [
            ("Original URL", result.original_url),
            ("Final URL", result.final_url or result.scanned_url),
            ("IP Address", result.ip_address or "—"),
            ("Scam Category", result.scam_category.value if result.scam_category else "—"),
            ("Scan Duration", f"{result.duration_ms}ms"),
            ("Page Title", result.page_title or "—"),
        ]
        for label, value in details:
            story.append(Paragraph(f"<b>{label}:</b> {value}", body))

        if result.redirect_chain and len(result.redirect_chain) > 1:
            story.append(Paragraph("<b>Redirect Chain:</b>", body))
            for i, url in enumerate(result.redirect_chain):
                story.append(Paragraph(f"  {i+1}. {url}", small))

        story.append(Spacer(1, 8))

        # ── Summary & Recommendation ─────────────────────────────────────────
        if result.summary:
            story.append(Paragraph("Assessment", h2))
            story.append(Paragraph(result.summary, body))
            if result.recommendation:
                rec_color = _hex_to_rl_color(RISK_COLORS_HEX.get(result.risk_level.value, "#94a3b8"))
                rec_data = [[Paragraph(f"<b>Recommendation:</b> {result.recommendation}", body)]]
                rec_table = Table(rec_data, colWidths=["100%"])
                rec_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                    ("LINERIGHT", (0, 0), (0, -1), 4, rec_color),
                    ("LEFTPADDING", (0, 0), (-1, -1), 14),
                    ("TOPPADDING", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ]))
                story.append(rec_table)
            story.append(Spacer(1, 8))

        # ── Threat Indicators ─────────────────────────────────────────────────
        if result.indicators:
            story.append(Paragraph(f"Threat Indicators ({len(result.indicators)})", h2))
            ind_data = [["Severity", "Indicator", "Description", "Score Impact"]]
            sorted_indicators = sorted(
                result.indicators,
                key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 4)
            )
            for ind in sorted_indicators:
                ind_data.append([
                    Paragraph(ind.severity.upper(), small),
                    Paragraph(f"<b>{ind.indicator_type}</b>", small),
                    Paragraph(ind.description, small),
                    Paragraph(f"+{ind.score_impact}", small),
                ])

            ind_table = Table(ind_data, colWidths=["13%", "22%", "55%", "10%"])
            ind_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))

            # Color severity column
            severity_colors_map = {
                "CRITICAL": "#ef4444", "HIGH": "#f97316",
                "MEDIUM": "#f59e0b", "LOW": "#3b82f6"
            }
            for row_idx, ind in enumerate(sorted_indicators, start=1):
                sc = severity_colors_map.get(ind.severity.upper(), "#94a3b8")
                ind_table.setStyle(TableStyle([
                    ("TEXTCOLOR", (0, row_idx), (0, row_idx), _hex_to_rl_color(sc)),
                    ("FONTNAME", (0, row_idx), (0, row_idx), "Helvetica-Bold"),
                ]))

            story.append(ind_table)
            story.append(Spacer(1, 8))

        # ── WHOIS / Certificate ───────────────────────────────────────────────
        if result.whois or result.certificate:
            story.append(Paragraph("Domain Intelligence", h2))
            if result.whois and result.whois.age_days is not None:
                story.append(Paragraph(
                    f"<b>Domain Age:</b> {result.whois.age_days} days"
                    + (f" | <b>Registrar:</b> {result.whois.registrar}" if result.whois.registrar else ""),
                    body
                ))
            if result.certificate:
                cert_status = "Valid" if result.certificate.valid else "INVALID"
                cert_text = (
                    f"<b>SSL Certificate:</b> {cert_status}"
                    + (f" | Issuer: {result.certificate.issuer}" if result.certificate.issuer else "")
                    + (f" | Expires in: {result.certificate.days_remaining} days"
                       if result.certificate.days_remaining is not None else "")
                )
                story.append(Paragraph(cert_text, body))
            story.append(Spacer(1, 8))

        # ── Threat Intel ──────────────────────────────────────────────────────
        if result.threat_intel:
            story.append(Paragraph("External Threat Intelligence", h2))
            for ti in result.threat_intel:
                status = "MALICIOUS" if ti.is_malicious else "CLEAN"
                if ti.total_engines > 0:
                    ti_text = f"<b>{ti.source}:</b> {status} ({ti.detection_count}/{ti.total_engines} detections)"
                else:
                    ti_text = f"<b>{ti.source}:</b> {status}"
                if ti.error:
                    ti_text = f"<b>{ti.source}:</b> Error — {ti.error}"
                story.append(Paragraph(ti_text, body))
            story.append(Spacer(1, 8))

        # ── Footer ────────────────────────────────────────────────────────────
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0"), spaceBefore=16))
        story.append(Paragraph(
            f"Naija Scam Shield v{self.config.version} by {self.config.author} &mdash; "
            "This report is for informational purposes only. "
            "Report scams to EFCC: efcc.gov.ng | CBN: cbn.gov.ng",
            small
        ))

        doc.build(story)

    def export_csv(self, results: List[ScanResult], output_path: Optional[Path] = None) -> Optional[Path]:
        """Export scan results as CSV."""
        if output_path is None:
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            output_path = self.config.reports_dir / f"scan_history_{ts}.csv"

        try:
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                fieldnames = [
                    "scan_id", "domain", "original_url", "risk_score", "risk_level",
                    "scam_category", "is_official_domain", "official_brand",
                    "indicator_count", "page_title", "ip_address",
                    "scan_time", "duration_ms", "summary",
                ]
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                for result in results:
                    writer.writerow({
                        "scan_id": result.scan_id,
                        "domain": result.domain,
                        "original_url": result.original_url,
                        "risk_score": result.risk_score,
                        "risk_level": result.risk_level.value,
                        "scam_category": result.scam_category.value if result.scam_category else "",
                        "is_official_domain": result.is_official_domain,
                        "official_brand": result.official_brand or "",
                        "indicator_count": len(result.indicators),
                        "page_title": result.page_title or "",
                        "ip_address": result.ip_address or "",
                        "scan_time": result.scan_time.isoformat(),
                        "duration_ms": result.duration_ms,
                        "summary": result.summary,
                    })
            logger.info("CSV report saved: %s", output_path)
            return output_path
        except Exception as e:
            logger.exception("CSV export failed: %s", e)
            return None

    def export_json(self, results: List[ScanResult], output_path: Optional[Path] = None) -> Optional[Path]:
        """Export scan results as JSON."""
        if output_path is None:
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            output_path = self.config.reports_dir / f"scan_history_{ts}.json"
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump([r.to_dict() for r in results], f, indent=2, default=str)
            return output_path
        except Exception as e:
            logger.exception("JSON export failed: %s", e)
            return None
