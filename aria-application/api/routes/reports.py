"""PDF report generation for archives."""
import json
from io import BytesIO
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    ListFlowable,
    ListItem,
    KeepTogether,
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER

from response.db import get_session
from response.models import Archive

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


def _safe_text(value, default="N/A") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value
    return str(value)


def _parse_ips(source_ips) -> list:
    if not source_ips:
        return []
    if isinstance(source_ips, list):
        return source_ips
    if isinstance(source_ips, str):
        return [ip.strip() for ip in source_ips.split(",") if ip.strip()]
    return []


def _build_pdf(archive: Archive) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=18,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Heading1"],
        fontSize=20,
        textColor=colors.HexColor("#1a1a1a"),
        spaceAfter=20,
        alignment=TA_LEFT,
    )
    heading2_style = ParagraphStyle(
        "CustomHeading2",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=colors.HexColor("#2563eb"),
        spaceAfter=10,
        spaceBefore=16,
        borderWidth=0,
        borderColor=colors.HexColor("#e5e7eb"),
        borderPadding=5,
        leftIndent=0,
        backColor=colors.HexColor("#f8fafc"),
    )
    heading3_style = ParagraphStyle(
        "CustomHeading3",
        parent=styles["Heading3"],
        fontSize=11,
        textColor=colors.HexColor("#374151"),
        spaceAfter=6,
        spaceBefore=10,
    )
    body_style = ParagraphStyle(
        "CustomBody",
        parent=styles["BodyText"],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#4b5563"),
    )
    mono_style = ParagraphStyle(
        "Mono",
        parent=styles["Code"],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#374151"),
        backColor=colors.HexColor("#f3f4f6"),
        leftIndent=6,
        rightIndent=6,
        spaceBefore=4,
        spaceAfter=4,
    )

    story: list = []

    # Header
    story.append(Paragraph("ARIA Incident Report", title_style))
    story.append(Spacer(1, 4))

    meta_data = [
        ["Archive ID:", _safe_text(archive.id)],
        ["Incident ID:", _safe_text(archive.incident_id)],
        ["Investigation ID:", _safe_text(archive.investigation_id)],
        ["Severity:", _safe_text(archive.severity).upper()],
        ["Fix Status:", _safe_text(archive.fix_status).replace("_", " ").title()],
        ["Archived At:", archive.archived_at.isoformat() if archive.archived_at else "N/A"],
    ]
    meta_table = Table(meta_data, colWidths=[1.4 * inch, 4.6 * inch])
    meta_table.setStyle(
        TableStyle([
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#374151")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f9fafb")),
            ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ])
    )
    story.append(meta_table)
    story.append(Spacer(1, 12))

    # Parse context
    try:
        full_context = json.loads(archive.full_context_json) if archive.full_context_json else {}
    except Exception:
        full_context = {}

    investigation = full_context.get("investigation") or {}
    incident = full_context.get("incident") or {}
    alerts = full_context.get("alerts") or []
    playbook_run = full_context.get("playbook_run") or {}
    fix_verification = full_context.get("fix_verification") or {}
    approval = full_context.get("approval") or {}

    # Executive Summary
    story.append(Paragraph("Executive Summary", heading2_style))
    summary_parts = []
    title = investigation.get("incident_title") or archive.incident_title or "Untitled incident"
    summary_parts.append(f"<b>Incident:</b> {title}")

    target = investigation.get("target_host")
    if target:
        summary_parts.append(f"<b>Target Host:</b> {target}")

    ips = _parse_ips(investigation.get("source_ips") or archive.source_ips)
    if ips:
        summary_parts.append(f"<b>Source IPs:</b> {', '.join(ips)}")

    summary_parts.append(f"<b>Severity:</b> {_safe_text(archive.severity).upper()}")
    summary_parts.append(f"<b>Status:</b> {_safe_text(archive.fix_status).replace('_', ' ').title()}")

    ai_summary = investigation.get("ai_summary") or "No AI summary available."
    summary_parts.append(f"<b>Summary:</b> {ai_summary}")

    risk = investigation.get("ai_risk")
    if risk:
        summary_parts.append(f"<b>Risk Assessment:</b> {risk}")

    for part in summary_parts:
        story.append(Paragraph(part, body_style))
        story.append(Spacer(1, 4))
    story.append(Spacer(1, 8))

    # Timeline
    story.append(Paragraph("Incident Timeline", heading2_style))
    timeline_data = [["Event", "Timestamp", "Details"]]
    timeline_events = []

    if incident.get("created_at"):
        timeline_events.append(("First Alert Detected", incident.get("created_at"), "Incident created"))
    if investigation.get("created_at"):
        timeline_events.append(("Investigation Created", investigation.get("created_at"), "AI analysis started"))
    if investigation.get("playbook_yaml"):
        timeline_events.append(("Playbook Generated", investigation.get("updated_at") or "—", "Remediation playbook created"))
    if approval.get("decided_at"):
        decision = approval.get("decision", "—")
        timeline_events.append((f"Approval: {decision.title()}", approval.get("decided_at"), f"By: {approval.get('decided_by', '—')}"))
    if fix_verification.get("checked_at"):
        timeline_events.append(("Verification Completed", fix_verification.get("checked_at"), f"Status: {fix_verification.get('status', '—')}"))
    if archive.archived_at:
        timeline_events.append(("Archived", archive.archived_at.isoformat(), "Case closed and archived"))

    if timeline_events:
        for ev in timeline_events:
            timeline_data.append([ev[0], ev[1], ev[2]])
        timeline_table = Table(timeline_data, colWidths=[1.8 * inch, 1.8 * inch, 2.4 * inch])
        timeline_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#ffffff")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                ("FONTSIZE", (0, 1), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 1), (-1, -1), 6),
                ("TOPPADDING", (0, 1), (-1, -1), 6),
            ])
        )
        story.append(timeline_table)
    else:
        story.append(Paragraph("No timeline events available.", body_style))
    story.append(Spacer(1, 12))

    # Evidence / Related Alerts
    story.append(Paragraph("Evidence — Related Alerts", heading2_style))
    if alerts:
        alert_headers = ["Source", "Severity", "Rule", "Source IP", "Dest IP"]
        alert_rows = [alert_headers]
        for alert in alerts[:50]:  # limit to 50 for PDF performance
            alert_rows.append([
                _safe_text(alert.get("source")),
                _safe_text(alert.get("severity")),
                _safe_text(alert.get("rule_name")),
                _safe_text(alert.get("source_ip")),
                _safe_text(alert.get("dest_ip")),
            ])
        alert_table = Table(alert_rows, colWidths=[1.0 * inch, 0.8 * inch, 1.6 * inch, 1.2 * inch, 1.2 * inch])
        alert_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                ("FONTSIZE", (0, 1), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 1), (-1, -1), 6),
                ("TOPPADDING", (0, 1), (-1, -1), 6),
            ])
        )
        story.append(alert_table)
        if len(alerts) > 50:
            story.append(Paragraph(f"<i>Showing 50 of {len(alerts)} alerts.</i>", body_style))
    else:
        story.append(Paragraph("No related alerts available.", body_style))
    story.append(Spacer(1, 12))

    # AI Analysis
    story.append(Paragraph("AI Analysis", heading2_style))
    ai_items = [
        ("Summary", investigation.get("ai_summary")),
        ("Risk Assessment", investigation.get("ai_risk")),
        ("Attack Narrative", investigation.get("ai_narrative")),
        ("MITRE Tactics", investigation.get("mitre_tactics") or archive.mitre_tactics),
    ]
    for label, value in ai_items:
        if value:
            story.append(Paragraph(f"<b>{label}:</b>", heading3_style))
            story.append(Paragraph(_safe_text(value), body_style))
            story.append(Spacer(1, 4))
    story.append(Spacer(1, 8))

    # Remediation
    story.append(Paragraph("Remediation", heading2_style))
    playbook_yaml = investigation.get("playbook_yaml")
    if playbook_yaml:
        story.append(Paragraph("<b>Executed Playbook (YAML):</b>", heading3_style))
        for line in playbook_yaml.split("\n")[:80]:
            story.append(Paragraph(line.replace(" ", "&nbsp;"), mono_style))
        if len(playbook_yaml.split("\n")) > 80:
            story.append(Paragraph("<i>... truncated for readability</i>", mono_style))
    else:
        story.append(Paragraph("No playbook available.", body_style))

    if playbook_run:
        story.append(Paragraph("<b>Execution Result:</b>", heading3_style))
        run_status = playbook_run.get("status", "N/A")
        run_exit = playbook_run.get("exit_code")
        story.append(Paragraph(f"Status: {run_status} | Exit Code: {run_exit}", body_style))
        run_output = playbook_run.get("output")
        if run_output:
            story.append(Paragraph("Output preview:", body_style))
            for line in str(run_output).split("\n")[:20]:
                story.append(Paragraph(line.replace(" ", "&nbsp;"), mono_style))
    story.append(Spacer(1, 12))

    # Verification
    story.append(Paragraph("Fix Verification", heading2_style))
    if fix_verification:
        verif_status = fix_verification.get("status", "N/A")
        new_alerts = fix_verification.get("new_alerts_found", 0)
        detail = fix_verification.get("detail", "No details available.")

        story.append(Paragraph(f"<b>Verification Status:</b> {verif_status}", body_style))
        story.append(Paragraph(f"<b>New Duplicate Alerts Found:</b> {new_alerts}", body_style))
        story.append(Paragraph(f"<b>Detail:</b>", heading3_style))
        story.append(Paragraph(_safe_text(detail), body_style))
    else:
        story.append(Paragraph("No verification data available.", body_style))
    story.append(Spacer(1, 12))

    # Linked Objects
    story.append(Paragraph("Linked Objects", heading2_style))
    linked_data = [
        ["Object", "ID", "Status/Link"],
        ["Original Incident", _safe_text(archive.incident_id), _safe_text(incident.get("status"))],
        ["Investigation", _safe_text(archive.investigation_id), _safe_text(investigation.get("status"))],
        ["Related Alerts", str(len(alerts)), "—"],
        ["Playbook Run", _safe_text(playbook_run.get("status") if playbook_run else None), _safe_text(playbook_run.get("current_phase") if playbook_run else None)],
    ]
    linked_table = Table(linked_data, colWidths=[1.6 * inch, 2.4 * inch, 2.0 * inch])
    linked_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
            ("FONTSIZE", (0, 1), (-1, -1), 9),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 6),
            ("TOPPADDING", (0, 1), (-1, -1), 6),
        ])
    )
    story.append(linked_table)
    story.append(Spacer(1, 12))

    # Footer / generation info
    story.append(Spacer(1, 20))
    story.append(Paragraph(
        f"<i>Generated by ARIA (Adaptive Response Intelligence Automation) on {archive.archived_at.isoformat() if archive.archived_at else '—'}</i>",
        ParagraphStyle("Footer", parent=body_style, fontSize=8, textColor=colors.HexColor("#9ca3af"), alignment=TA_CENTER),
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()


@router.get("/archives/{archive_id}/pdf")
async def download_archive_pdf(
    archive_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Generate and download a PDF report for an archived investigation."""
    result = await session.execute(
        select(Archive).where(Archive.id == archive_id)
    )
    archive = result.scalar_one_or_none()
    if not archive:
        raise HTTPException(status_code=404, detail="Archive not found")

    pdf_bytes = _build_pdf(archive)

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="archive-report-{archive_id}.pdf"'
        },
    )
