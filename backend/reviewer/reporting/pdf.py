"""ReportLab PDF Audit Pack generator (Phase 6 / Spec P3/P12)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from backend.reviewer.findings.schema import Finding
from backend.reviewer.guardrails.redact import redact_secrets


def _cell(text: str, style) -> Paragraph:
    safe = (
        redact_secrets(str(text or ""))
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    return Paragraph(safe, style)


def _styled_table(data: list[list[Any]], col_widths: list[float], header_bg=colors.HexColor("#1E3A5F")) -> Table:
    tbl = Table(data, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), header_bg),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return tbl


def generate_audit_pdf(audit_report: dict[str, Any], output_path: str | Path = "audit.pdf") -> Path:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    styles = getSampleStyleSheet()
    body_style = styles["BodyText"]
    body_style.fontSize = 8
    body_style.leading = 10

    doc = SimpleDocTemplate(
        str(out),
        pagesize=letter,
        leftMargin=0.55 * inch,
        rightMargin=0.55 * inch,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
    )

    story: list[Any] = []
    findings: list[Finding] = audit_report.get("findings", [])
    unverified: list[dict[str, Any]] = audit_report.get("unverified", [])
    catalogue: list[dict[str, Any]] = audit_report.get("check_catalogue", [])
    traceability: list[dict[str, Any]] = audit_report.get("traceability", [])
    invariants: dict[str, Any] = audit_report.get("invariants", {})
    cost: dict[str, Any] = audit_report.get("cost_summary", {})

    story.append(Paragraph("LineTrack Review Agent — Full SDLC & OT Safety Audit Pack", styles["Title"]))
    story.append(Spacer(1, 0.15 * inch))
    generated_at = audit_report.get("generated_at") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    cover_rows = [
        ["Field", "Value"],
        ["Target Repository", str(audit_report.get("repo", "unknown"))],
        ["Audit Mode", str(audit_report.get("mode", "full"))],
        ["Generated At", str(generated_at)],
        ["Release Verdict", str(audit_report.get("verdict", "BLOCK"))],
        ["Total Findings", str(len(findings))],
        ["UNVERIFIED Controls", str(len(unverified))],
        ["LLM Cost (USD)", f"${float(cost.get('total_cost_usd', 0.0)):.6f}"],
    ]
    story.append(_styled_table(cover_rows, [2.2 * inch, 5.1 * inch]))
    story.append(Spacer(1, 0.25 * inch))

    story.append(Paragraph("1. Findings by Severity", styles["Heading2"]))
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    story.append(_styled_table([["Severity", "Count"]] + [[k, str(v)] for k, v in sev_counts.items()], [2.0 * inch, 1.5 * inch]))
    story.append(Spacer(1, 0.15 * inch))

    if findings:
        f_rows = [["Check / Rule", "Sev", "Location", "Fix / Summary (Redacted)"]]
        for f in findings:
            f_rows.append([
                _cell(f"{f.check_id}\n{f.rule}", body_style),
                _cell(f.severity, body_style),
                _cell(f"{f.file}:{f.line}", body_style),
                _cell(f"{f.message}\nFix: {f.fix}", body_style),
            ])
        story.append(_styled_table(f_rows, [1.5 * inch, 0.7 * inch, 1.4 * inch, 3.7 * inch]))
    story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph("2. Check Catalogue (10 Mandatory Checks)", styles["Heading2"]))
    cat_rows = [["ID", "Check", "Standards", "Status"]]
    for c in catalogue:
        cat_rows.append([
            _cell(c.get("id", ""), body_style),
            _cell(c.get("name", ""), body_style),
            _cell(", ".join(c.get("standards", [])), body_style),
            _cell(c.get("status", "UNKNOWN"), body_style),
        ])
    story.append(_styled_table(cat_rows, [0.8 * inch, 2.3 * inch, 2.5 * inch, 1.7 * inch]))
    story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph("3. Cross-Cutting Invariants", styles["Heading2"]))
    inv_rows = [
        ["Invariant", "Result"],
        ["RBAC Matrix Validation", _cell(str(invariants.get("rbac_summary", "")), body_style)],
        ["MQTT ACL Matrix Validation", _cell(str(invariants.get("mqtt_summary", "")), body_style)],
        ["Genealogy Graph Integrity", _cell(str(invariants.get("genealogy_summary", "")), body_style)],
    ]
    story.append(_styled_table(inv_rows, [2.2 * inch, 5.1 * inch]))
    story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph("4. Traceability Matrix (Requirement -> Endpoint/Flow -> Test -> Evidence)", styles["Heading2"]))
    tr_rows = [["Requirement", "Endpoint / Flow", "Test Coverage", "Evidence / Status"]]
    for t in traceability:
        tr_rows.append([
            _cell(t.get("requirement", ""), body_style),
            _cell(t.get("implementation", "NONE"), body_style),
            _cell(t.get("test", "NONE"), body_style),
            _cell(t.get("status", "GAP"), body_style),
        ])
    story.append(_styled_table(tr_rows, [1.8 * inch, 1.9 * inch, 1.7 * inch, 1.9 * inch]))
    story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph("5. UNVERIFIED Controls (Never Assumed Pass — Spec P12)", styles["Heading2"]))
    unv_rows = [["Control", "Status", "Owner", "Due Date", "Required Evidence"]]
    for u in unverified:
        unv_rows.append([
            _cell(u.get("control", ""), body_style),
            _cell(u.get("status", "UNVERIFIED"), body_style),
            _cell(u.get("owner", ""), body_style),
            _cell(u.get("due_date", ""), body_style),
            _cell(u.get("required_evidence", ""), body_style),
        ])
    story.append(_styled_table(unv_rows, [1.5 * inch, 0.9 * inch, 1.2 * inch, 1.1 * inch, 2.6 * inch], header_bg=colors.HexColor("#7C2D12")))
    story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph("6. Cost Summary", styles["Heading2"]))
    cost_rows = [
        ["Metric", "Value"],
        ["LLM Calls", str(cost.get("llm_calls", 0))],
        ["Total Cost (USD)", f"${float(cost.get('total_cost_usd', 0.0)):.6f}"],
        ["Execution Time (sec)", f"{float(audit_report.get('duration_sec', 0.0)):.3f}s"],
        ["Pricing Baseline", "GPT-4o-mini $0.15/$0.60, GPT-4o $2.50/$10.00, Judge $5/$15 per 1M tokens"],
    ]
    story.append(_styled_table(cost_rows, [2.2 * inch, 5.1 * inch]))

    doc.build(story)
    return out
