import io
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
)
from scanner.services.report_service import ScanReportResponse


def generate_pdf_report(report: ScanReportResponse) -> bytes:
    """Generate a publication-grade PDF security report."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#0f172a"),
        fontName="Helvetica-Bold",
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontSize=11,
        textColor=colors.HexColor("#64748b"),
        leading=15,
    )
    heading2_style = ParagraphStyle(
        "Heading2_Custom",
        parent=styles["Heading2"],
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#1e293b"),
        fontName="Helvetica-Bold",
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "Body_Custom",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155"),
    )
    code_style = ParagraphStyle(
        "Code_Custom",
        parent=styles["Code"],
        fontSize=8,
        leading=10,
        fontName="Courier",
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f1f5f9"),
    )

    story = []

    # Title & Header
    created_str = report.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if hasattr(report.created_at, 'strftime') else str(report.created_at)
    story.append(Paragraph("AI App Security & Quality Scan Report", title_style))
    story.append(Paragraph(f"Repository: {report.repository_url} | Generated: {created_str}", subtitle_style))
    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#10b981"), spaceBefore=5, spaceAfter=15))

    # Executive Summary Table
    risk_color = colors.HexColor("#dc2626") if report.summary.risk_category == "Critical" else (
        colors.HexColor("#f97316") if report.summary.risk_category == "High" else (
            colors.HexColor("#eab308") if report.summary.risk_category == "Medium" else colors.HexColor("#10b981")
        )
    )

    summary_data = [
        [
            Paragraph("<b>Scan ID:</b>", body_style),
            Paragraph(report.scan_id, body_style),
            Paragraph("<b>Overall Risk Score:</b>", body_style),
            Paragraph(f"<b>{report.summary.risk_score} / 100</b> ({report.summary.risk_category})", body_style),
        ],
        [
            Paragraph("<b>Target Branch:</b>", body_style),
            Paragraph("main", body_style),
            Paragraph("<b>Status:</b>", body_style),
            Paragraph(f"<font color='{risk_color}'><b>{report.status.upper()}</b></font>", body_style),
        ],
        [
            Paragraph("<b>Total Findings:</b>", body_style),
            Paragraph(str(len(report.findings)), body_style),
            Paragraph("<b>Critical / High:</b>", body_style),
            Paragraph(f"{report.summary.critical_count} Critical / {report.summary.high_count} High", body_style),
        ],
    ]

    summary_table = Table(summary_data, colWidths=[110, 150, 130, 140])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 15))

    # Findings Breakdown
    story.append(Paragraph("Security Findings Overview", heading2_style))

    if not report.findings:
        story.append(Paragraph("No security vulnerabilities or weaknesses detected. The codebase adheres to scanned baseline rules.", body_style))
    else:
        # Findings Table
        table_headers = ["Severity", "Rule ID", "Title", "Category"]
        table_rows = [[
            Paragraph(f"<b>{h}</b>", body_style) for h in table_headers
        ]]

        for f in report.findings[:25]:  # limit top 25 in summary table
            sev_color = "#dc2626" if f.severity.value == "critical" else (
                "#f97316" if f.severity.value == "high" else (
                    "#eab308" if f.severity.value == "medium" else "#3b82f6"
                )
            )
            table_rows.append([
                Paragraph(f"<font color='{sev_color}'><b>{f.severity.value.upper()}</b></font>", body_style),
                Paragraph(f.rule_id, body_style),
                Paragraph(f.title[:45] + ("..." if len(f.title) > 45 else ""), body_style),
                Paragraph(f.category, body_style),
            ])

        findings_table = Table(table_rows, colWidths=[80, 80, 250, 120])
        findings_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(findings_table)

    story.append(Spacer(1, 15))

    # Detailed Findings Section
    story.append(Paragraph("Detailed Vulnerability Analysis", heading2_style))

    for idx, f in enumerate(report.findings[:15], 1):  # top 15 detailed
        sev_color = "#dc2626" if f.severity.value == "critical" else (
            "#f97316" if f.severity.value == "high" else "#eab308"
        )
        finding_box = [
            [Paragraph(f"<b>#{idx}. [{f.rule_id}] {f.title}</b>", body_style),
             Paragraph(f"<font color='{sev_color}'><b>{f.severity.value.upper()}</b></font>", body_style)],
            [Paragraph(f"<b>Category:</b> {f.category} | <b>Status:</b> {f.status.value}", body_style), ""],
            [Paragraph(f"<b>Description:</b> {f.description}", body_style), ""],
            [Paragraph(f"<b>Impact:</b> {f.impact}", body_style), ""],
            [Paragraph(f"<b>Recommendation:</b> {f.recommendation}", body_style), ""],
        ]

        if f.evidence:
            ev = f.evidence[0]
            clean_snippet = ev.code_snippet.replace("<", "&lt;").replace(">", "&gt;")[:200]
            finding_box.append([
                Paragraph(f"<b>Evidence:</b> {ev.file_path}:{ev.line_start}<br/><font face='Courier' size=7>{clean_snippet}</font>", body_style),
                ""
            ])

        detail_tbl = Table(finding_box, colWidths=[430, 100])
        detail_tbl.setStyle(TableStyle([
            ("SPAN", (0, 1), (1, 1)),
            ("SPAN", (0, 2), (1, 2)),
            ("SPAN", (0, 3), (1, 3)),
            ("SPAN", (0, 4), (1, 4)),
            ("SPAN", (0, 5), (1, 5)) if len(finding_box) > 5 else ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(detail_tbl)
        story.append(Spacer(1, 8))

    doc.build(story)
    return buffer.getvalue()
