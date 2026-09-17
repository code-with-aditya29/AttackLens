"""
AttackLens
PDF Service

This module converts a normalized AttackLens report document
into a professional PDF security assessment.

The service uses ReportLab and expects report data produced by:

    services/report_service.py

Responsibilities:

- Create PDF document structure
- Render executive summary
- Render asset inventory
- Render vulnerability / risk information
- Render attack path analysis
- Render defense analysis
- Render mitigation recommendations
- Render risk comparison
- Render methodology / disclaimer
- Return the generated PDF as an in-memory byte stream

This module does not perform security analysis.
"""

from io import BytesIO
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
)


# ============================================================
# PDF CONSTANTS
# ============================================================

PDF_TITLE = "AttackLens Security Assessment"
PDF_AUTHOR = "AttackLens"
PDF_SUBJECT = "Cybersecurity Assessment and Attack Path Analysis Report"
PDF_VERSION = "1.0"


# ============================================================
# COLOR PALETTE
# ============================================================

COLOR_PRIMARY = colors.HexColor("#7C3AED")
COLOR_PRIMARY_DARK = colors.HexColor("#3B176E")
COLOR_PRIMARY_DEEP = colors.HexColor("#6D28D9")
COLOR_PRIMARY_LIGHT = colors.HexColor("#F1ECFF")

COLOR_TEXT_PRIMARY = colors.HexColor("#211B2E")
COLOR_TEXT_SECONDARY = colors.HexColor("#6F687D")
COLOR_TEXT_MUTED = colors.HexColor("#8E8799")

COLOR_BORDER = colors.HexColor("#E6E1ED")
COLOR_BACKGROUND = colors.HexColor("#F7F7FB")
COLOR_WHITE = colors.white


# ============================================================
# MAIN PDF GENERATOR
# ============================================================

def generate_report_pdf(report_data, authorized_by=None):
    """
    Generate an AttackLens PDF report.

    Parameters
    ----------
    report_data : dict
        Normalized report data created by report_service.py.

    Returns
    -------
    BytesIO
        In-memory PDF stream positioned at byte zero.
    """

    report_data = normalize_dictionary(
        report_data
    )

    # Work on a shallow copy so PDF-only presentation metadata does
    # not mutate the normalized report document owned by report_service.
    report_data = dict(report_data)

    if authorized_by is not None:
        report_data["authorized_by"] = safe_text(
            authorized_by,
            default="Not available"
        )

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=22 * mm,
        bottomMargin=20 * mm,
        title=PDF_TITLE,
        author=PDF_AUTHOR,
        subject=PDF_SUBJECT,
    )

    styles = create_pdf_styles()

    story = []

    build_cover_page(
        story,
        report_data,
        styles
    )

    story.append(
        PageBreak()
    )

    build_report_information(
        story,
        report_data,
        styles
    )

    story.append(PageBreak())

    build_executive_summary_section(
        story,
        report_data,
        styles
    )

    story.append(PageBreak())

    build_asset_inventory_section(
        story,
        report_data,
        styles
    )

    story.append(PageBreak())

    build_vulnerability_section(
        story,
        report_data,
        styles
    )

    story.append(PageBreak())

    build_attack_path_section(
        story,
        report_data,
        styles
    )

    story.append(PageBreak())

    build_defense_section(
        story,
        report_data,
        styles
    )

    story.append(PageBreak())

    build_mitigation_section(
        story,
        report_data,
        styles
    )

    story.append(PageBreak())

    build_risk_comparison_section(
        story,
        report_data,
        styles
    )

    story.append(PageBreak())

    build_methodology_section(
        story,
        report_data,
        styles
    )

    document.build(
        story,
        onFirstPage=draw_cover_footer,
        onLaterPages=draw_page_header_footer,
    )

    buffer.seek(
        0
    )

    return buffer


# ============================================================
# PDF STYLES
# ============================================================

def create_pdf_styles():
    """
    Create the professional ParagraphStyle collection used by the PDF.

    The report uses larger print-friendly typography and a consistent
    hierarchy across headings, body copy, tables, metadata, and
    authorization information.
    """

    base_styles = getSampleStyleSheet()

    return {
        "cover_title": ParagraphStyle(
            "AttackLensCoverTitle",
            parent=base_styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=30,
            leading=35,
            textColor=COLOR_PRIMARY,
            alignment=TA_CENTER,
            spaceAfter=8,
        ),

        "cover_subtitle": ParagraphStyle(
            "AttackLensCoverSubtitle",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=15,
            leading=20,
            textColor=COLOR_TEXT_SECONDARY,
            alignment=TA_CENTER,
            spaceAfter=6,
        ),

        "cover_target_label": ParagraphStyle(
            "AttackLensCoverTargetLabel",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10.5,
            leading=14,
            textColor=COLOR_TEXT_SECONDARY,
            alignment=TA_CENTER,
            spaceAfter=4,
        ),

        "cover_target": ParagraphStyle(
            "AttackLensCoverTarget",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=17,
            leading=21,
            textColor=COLOR_TEXT_PRIMARY,
            alignment=TA_CENTER,
            spaceAfter=4,
        ),

        "cover_meta": ParagraphStyle(
            "AttackLensCoverMeta",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=10.5,
            leading=15,
            textColor=COLOR_TEXT_SECONDARY,
            alignment=TA_CENTER,
        ),

        "section_title": ParagraphStyle(
            "AttackLensSectionTitle",
            parent=base_styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=17,
            leading=21,
            textColor=COLOR_PRIMARY_DARK,
            spaceBefore=8,
            spaceAfter=10,
            keepWithNext=True,
        ),

        "subsection_title": ParagraphStyle(
            "AttackLensSubsectionTitle",
            parent=base_styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12.5,
            leading=16,
            textColor=COLOR_TEXT_PRIMARY,
            spaceBefore=7,
            spaceAfter=5,
            keepWithNext=True,
        ),

        "body": ParagraphStyle(
            "AttackLensBody",
            parent=base_styles["BodyText"],
            fontName="Helvetica",
            fontSize=11,
            leading=16,
            textColor=COLOR_TEXT_PRIMARY,
            spaceAfter=7,
        ),

        "body_muted": ParagraphStyle(
            "AttackLensBodyMuted",
            parent=base_styles["BodyText"],
            fontName="Helvetica",
            fontSize=10,
            leading=14.5,
            textColor=COLOR_TEXT_SECONDARY,
            spaceAfter=5,
        ),

        "table_header": ParagraphStyle(
            "AttackLensTableHeader",
            parent=base_styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=9.5,
            leading=12,
            textColor=COLOR_WHITE,
            alignment=TA_LEFT,
        ),

        "table_body": ParagraphStyle(
            "AttackLensTableBody",
            parent=base_styles["BodyText"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=13,
            textColor=COLOR_TEXT_PRIMARY,
        ),

        "table_sidebar": ParagraphStyle(
            "AttackLensTableSidebar",
            parent=base_styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=9.5,
            leading=13,
            textColor=COLOR_WHITE,
        ),

        "metric_label": ParagraphStyle(
            "AttackLensMetricLabel",
            parent=base_styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            textColor=COLOR_WHITE,
            alignment=TA_CENTER,
        ),

        "metric_value": ParagraphStyle(
            "AttackLensMetricValue",
            parent=base_styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=COLOR_TEXT_PRIMARY,
            alignment=TA_CENTER,
        ),

        "authorization_label": ParagraphStyle(
            "AttackLensAuthorizationLabel",
            parent=base_styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            textColor=COLOR_WHITE,
        ),

        "authorization_value": ParagraphStyle(
            "AttackLensAuthorizationValue",
            parent=base_styles["BodyText"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=COLOR_TEXT_PRIMARY,
        ),

        "disclaimer": ParagraphStyle(
            "AttackLensDisclaimer",
            parent=base_styles["BodyText"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=14,
            textColor=COLOR_TEXT_SECONDARY,
        ),
    }


# ============================================================
# COVER PAGE
# ============================================================

def build_cover_page(
    story,
    report_data,
    styles
):
    """
    Render a professional security assessment cover.

    The cover deliberately avoids academic/assignment wording and
    presents the report as a formal AttackLens assessment document.
    """

    scope = get_dictionary(
        report_data,
        "scope"
    )

    statistics = get_dictionary(
        report_data,
        "statistics"
    )

    targets = scope.get(
        "targets"
    )

    if not isinstance(
        targets,
        list
    ):
        targets = []

    target_text = (
        ", ".join(
            safe_text(target)
            for target in targets
            if safe_text(target)
        )
        or "No target available"
    )

    authorized_by = get_authorized_scanner(
        report_data
    )

    story.append(
        Spacer(
            1,
            27 * mm
        )
    )

    story.append(
        Paragraph(
            "ATTACKLENS",
            styles["cover_title"]
        )
    )

    story.append(
        Paragraph(
            "Security Assessment Report",
            styles["cover_subtitle"]
        )
    )

    story.append(
        Spacer(
            1,
            12 * mm
        )
    )

    story.append(
        Paragraph(
            "ASSESSMENT TARGET",
            styles["cover_target_label"]
        )
    )

    story.append(
        Paragraph(
            escape_text(
                target_text
            ),
            styles["cover_target"]
        )
    )

    story.append(
        Spacer(
            1,
            11 * mm
        )
    )

    cover_data = [
        [
            Paragraph(
                "Assets in Scope",
                styles["table_sidebar"]
            ),
            Paragraph(
                str(
                    safe_integer(
                        scope.get(
                            "asset_count",
                            0
                        )
                    )
                ),
                styles["table_body"]
            ),
        ],
        [
            Paragraph(
                "Current Risk",
                styles["table_sidebar"]
            ),
            Paragraph(
                format_risk(
                    statistics.get(
                        "current_risk_score",
                        0
                    ),
                    statistics.get(
                        "current_risk_level",
                        "LOW"
                    ),
                ),
                styles["table_body"]
            ),
        ],
        [
            Paragraph(
                "Projected Risk",
                styles["table_sidebar"]
            ),
            Paragraph(
                format_risk(
                    statistics.get(
                        "projected_risk_score",
                        0
                    ),
                    statistics.get(
                        "projected_risk_level",
                        "LOW"
                    ),
                ),
                styles["table_body"]
            ),
        ],
        [
            Paragraph(
                "Projected Reduction",
                styles["table_sidebar"]
            ),
            Paragraph(
                "{:.2f}%".format(
                    safe_number(
                        statistics.get(
                            "risk_reduction_percentage",
                            0
                        )
                    )
                ),
                styles["table_body"]
            ),
        ],
    ]

    table = Table(
        cover_data,
        colWidths=[
            68 * mm,
            68 * mm
        ],
        rowHeights=[
            14 * mm
        ] * len(
            cover_data
        ),
        hAlign="CENTER"
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    COLOR_PRIMARY
                ),
                (
                    "BACKGROUND",
                    (1, 0),
                    (1, -1),
                    COLOR_BACKGROUND
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.8,
                    COLOR_BORDER
                ),
                (
                    "INNERGRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    COLOR_BORDER
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE"
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    12
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    12
                ),
            ]
        )
    )

    story.append(
        table
    )

    story.append(
        Spacer(
            1,
            13 * mm
        )
    )

    generated_at = format_datetime(
        report_data.get(
            "generated_at"
        )
    )

    report_id = safe_text(
        report_data.get(
            "report_id"
        ),
        default="N/A"
    )

    story.append(
        Paragraph(
            (
                f"<b>Authorized Scanner:</b> {escape_text(authorized_by)}<br/>"
                f"<b>Report ID:</b> {escape_text(report_id)}<br/>"
                f"<b>Generated:</b> {escape_text(generated_at)}<br/>"
                "<b>Classification:</b> Security Assessment"
            ),
            styles["cover_meta"]
        )
    )


# ============================================================
# REPORT INFORMATION
# ============================================================

def build_report_information(
    story,
    report_data,
    styles
):
    """
    Render basic report metadata.
    """

    append_section_heading(
        story,
        "Report Information",
        styles
    )

    scope = get_dictionary(
        report_data,
        "scope"
    )

    targets = scope.get(
        "targets"
    )

    if not isinstance(
        targets,
        list
    ):
        targets = []

    target_text = (
        ", ".join(
            safe_text(
                target
            )
            for target in targets
        )
        if targets
        else "No analyzed targets available"
    )

    rows = [
        [
            "Report ID",
            safe_text(
                report_data.get(
                    "report_id"
                ),
                default="N/A"
            ),
        ],

        [
            "Report Type",
            humanize_label(
                safe_text(
                    report_data.get(
                        "report_type"
                    ),
                    default="security_assessment"
                )
            ),
        ],

        [
            "Report Version",
            safe_text(
                report_data.get(
                    "report_version"
                ),
                default=PDF_VERSION
            ),
        ],

        [
            "Report Status",
            safe_text(
                report_data.get(
                    "status"
                ),
                default="not_ready"
            ).upper(),
        ],

        [
            "Assets in Scope",
            str(
                safe_integer(
                    scope.get(
                        "asset_count",
                        0
                    )
                )
            ),
        ],

        [
            "Targets",
            target_text,
        ],

        [
            "Authorized Scanner",
            get_authorized_scanner(
                report_data
            ),
        ],

        [
            "Generated",
            format_datetime(
                report_data.get(
                    "generated_at"
                )
            ),
        ],
    ]

    story.append(
        build_key_value_table(
            rows,
            styles
        )
    )

    story.append(
        Spacer(
            1,
            4 * mm
        )
    )


# ============================================================
# EXECUTIVE SUMMARY
# ============================================================

def build_executive_summary_section(
    story,
    report_data,
    styles
):
    """
    Render the report executive summary.
    """

    append_section_heading(
        story,
        "1. Executive Summary",
        styles
    )

    summary = get_dictionary(
        report_data,
        "executive_summary"
    )

    statistics = get_dictionary(
        report_data,
        "statistics"
    )

    current_score = safe_number(
        summary.get(
            "overall_risk_score",
            statistics.get(
                "current_risk_score",
                0
            ),
        )
    )

    current_level = safe_risk_level(
        summary.get(
            "overall_risk_level",
            statistics.get(
                "current_risk_level",
                "LOW"
            ),
        )
    )

    projected_score = safe_number(
        summary.get(
            "projected_risk_score",
            statistics.get(
                "projected_risk_score",
                0
            ),
        )
    )

    projected_level = safe_risk_level(
        summary.get(
            "projected_risk_level",
            statistics.get(
                "projected_risk_level",
                "LOW"
            ),
        )
    )

    reduction_percentage = safe_number(
        summary.get(
            "projected_reduction_percentage",
            statistics.get(
                "risk_reduction_percentage",
                0
            ),
        )
    )

    story.append(
        build_metric_table(
            [
                (
                    "Assets",
                    summary.get(
                        "asset_count",
                        0
                    )
                ),

                (
                    "Vulnerabilities",
                    summary.get(
                        "vulnerability_count",
                        0
                    )
                ),

                (
                    "Attack Paths",
                    summary.get(
                        "attack_path_count",
                        0
                    )
                ),

                (
                    "Recommendations",
                    summary.get(
                        "recommendation_count",
                        0
                    )
                ),
            ],
            styles,
        )
    )

    story.append(
        Spacer(
            1,
            5 * mm
        )
    )

    summary_text = (
        "AttackLens analyzed the authorized asset inventory and "
        "generated an evidence-based security assessment. "
        f"The current overall risk is "
        f"<b>{current_score:.2f}/100 ({current_level})</b>. "
        f"The projected post-mitigation risk is "
        f"<b>{projected_score:.2f}/100 ({projected_level})</b>, "
        f"representing an estimated reduction of "
        f"<b>{reduction_percentage:.2f}%</b>."
    )

    story.append(
        Paragraph(
            summary_text,
            styles["body"]
        )
    )

    story.append(
        Paragraph(
            (
                "Projected values are analytical estimates based on "
                "available evidence and generated mitigation "
                "recommendations. AttackLens does not automatically "
                "apply patches, firewall rules, segmentation changes, "
                "or other remediation actions."
            ),
            styles["body_muted"]
        )
    )

    story.append(
        Spacer(
            1,
            5 * mm
        )
    )


# ============================================================
# ASSET INVENTORY
# ============================================================

def build_asset_inventory_section(
    story,
    report_data,
    styles
):
    """
    Render discovered asset inventory.
    """

    append_section_heading(
        story,
        "2. Asset Inventory",
        styles
    )

    sections = get_dictionary(report_data, "sections")
    assets = sections.get("assets")

    if not isinstance(assets, list):
        assets = []

    if not assets:
        append_empty_message(
            story,
            "No analyzed assets are available for this report.",
            styles
        )
        return

    table_data = [[
        paragraph("Target", styles["table_header"]),
        paragraph("Hostname", styles["table_header"]),
        paragraph("Operating System", styles["table_header"]),
        paragraph("Open Ports", styles["table_header"]),
        paragraph("Criticality", styles["table_header"]),
        paragraph("Exposure", styles["table_header"]),
        paragraph("Risk", styles["table_header"]),
    ]]

    for asset in assets:
        if not isinstance(asset, dict):
            continue

        target = get_asset_target(asset)
        hostname = safe_text(asset.get("hostname"), default="-")
        operating_system = get_asset_os(asset)
        open_ports = get_open_ports(asset)
        criticality = humanize_label(
            safe_text(asset.get("criticality"), default="Unknown")
        )
        exposure = humanize_label(
            safe_text(asset.get("exposure"), default="Unknown")
        )
        risk_score = get_asset_risk_score(asset)
        risk_level = get_asset_risk_level(asset)

        table_data.append([
            paragraph(target, styles["table_body"]),
            paragraph(hostname, styles["table_body"]),
            paragraph(operating_system, styles["table_body"]),
            paragraph(format_port_list(open_ports), styles["table_body"]),
            paragraph(criticality, styles["table_body"]),
            paragraph(exposure, styles["table_body"]),
            paragraph(format_risk(risk_score, risk_level), styles["table_body"]),
        ])

    table = Table(
        table_data,
        # Keep the full Asset Inventory table within the 178 mm
        # printable width while giving Criticality, Exposure, and Risk
        # enough room to render cleanly without awkward word wrapping.
        colWidths=[
            25 * mm,  # Target
            23 * mm,  # Hostname
            32 * mm,  # Operating System
            23 * mm,  # Open Ports
            23 * mm,  # Criticality
            23 * mm,  # Exposure
            29 * mm,  # Risk
        ],
        repeatRows=1,
    )
    apply_standard_table_style(table)
    story.append(table)
    story.append(Spacer(1, 3 * mm))


# ============================================================
# VULNERABILITY & RISK
# ============================================================

def build_vulnerability_section(
    story,
    report_data,
    styles
):
    """
    Render vulnerability and risk findings.
    """

    append_section_heading(
        story,
        "3. Vulnerability & Risk Assessment",
        styles
    )

    sections = get_dictionary(report_data, "sections")
    vulnerability_summary = get_dictionary(sections, "vulnerability_summary")
    count = safe_integer(vulnerability_summary.get("vulnerability_count", 0))
    vulnerable_assets = safe_integer(vulnerability_summary.get("vulnerable_assets", 0))

    if count == 0:
        summary_text = (
            "No vulnerability findings were identified in the current "
            "authorized analysis."
        )
    else:
        finding_word = "finding" if count == 1 else "findings"
        asset_word = "asset" if vulnerable_assets == 1 else "assets"
        summary_text = (
            f"AttackLens identified <b>{count}</b> vulnerability {finding_word} "
            f"across <b>{vulnerable_assets}</b> {asset_word} in the current "
            "authorized analysis."
        )

    story.append(Paragraph(summary_text, styles["body"]))

    findings = vulnerability_summary.get("findings")
    if not isinstance(findings, list):
        findings = []

    if not findings:
        table = build_status_table(
            headers=[
                "Target",
                "Finding",
                "Severity",
                "Score"
            ],
            message="No vulnerability or CVE findings are currently present in the analyzed asset data.",
            styles=styles,
            col_widths=[
                34 * mm,
                82 * mm,
                31 * mm,
                31 * mm
            ]
        )
        story.append(table)
        return

    table_data = [[
        paragraph("Target", styles["table_header"]),
        paragraph("Finding", styles["table_header"]),
        paragraph("Severity", styles["table_header"]),
        paragraph("Score", styles["table_header"]),
    ]]

    for record in findings:
        if not isinstance(record, dict):
            continue
        finding = record.get("finding")
        if not isinstance(finding, dict):
            finding = {}
        finding_name = get_finding_name(finding)
        severity = safe_text(finding.get("severity"), default="Unknown")
        score = get_finding_score(finding)
        table_data.append([
            paragraph(safe_text(record.get("target"), default="-"), styles["table_body"]),
            paragraph(finding_name, styles["table_body"]),
            paragraph(severity, styles["table_body"]),
            paragraph(f"{score:.2f}", styles["table_body"]),
        ])

    table = Table(
        table_data,
        colWidths=[34 * mm, 82 * mm, 31 * mm, 31 * mm],
        repeatRows=1,
    )
    apply_standard_table_style(table)
    story.append(table)
    story.append(Spacer(1, 3 * mm))


# ============================================================
# ATTACK PATH ANALYSIS
# ============================================================

def build_attack_path_section(
    story,
    report_data,
    styles
):
    """
    Render attack-path analysis.
    """

    sections = get_dictionary(report_data, "sections")
    attack_graph = get_dictionary(sections, "attack_path_analysis")
    paths = get_list(attack_graph, "paths")
    relationships = get_list(attack_graph, "relationships")

    relationship_count = len(relationships)
    path_count = len(paths)

    if relationship_count == 0 and path_count == 0:
        summary_text = (
            "No potential relationships or attack paths were identified "
            "from the currently available evidence."
        )
    else:
        relationship_word = "relationship" if relationship_count == 1 else "relationships"
        path_word = "attack path" if path_count == 1 else "attack paths"
        summary_text = (
            f"The current analysis contains <b>{relationship_count}</b> potential "
            f"{relationship_word} and <b>{path_count}</b> potential {path_word}."
        )

    heading = Paragraph(
        escape_text("4. Attack Path Analysis"),
        styles["section_title"]
    )
    summary = Paragraph(summary_text, styles["body"])

    if not paths:
        empty_table = build_status_table(
            headers=[
                "Path",
                "Score",
                "Risk"
            ],
            message="No potential attack paths were identified from the currently available evidence.",
            styles=styles,
            col_widths=[
                112 * mm,
                30 * mm,
                36 * mm
            ]
        )
        story.append(heading)
        story.append(summary)
        story.append(empty_table)
        return

    story.append(heading)
    story.append(summary)

    table_data = [[
        paragraph("Path", styles["table_header"]),
        paragraph("Score", styles["table_header"]),
        paragraph("Risk", styles["table_header"]),
    ]]

    for index, path_data in enumerate(paths, start=1):
        if not isinstance(path_data, dict):
            continue
        path_text = format_attack_path(path_data)
        score = safe_number(path_data.get("score", path_data.get("risk_score", 0)))
        level = safe_risk_level(
            path_data.get("risk_level", determine_risk_level(score))
        )
        table_data.append([
            paragraph(f"{index}. {path_text}", styles["table_body"]),
            paragraph(f"{score:.2f}", styles["table_body"]),
            paragraph(level, styles["table_body"]),
        ])

    table = Table(
        table_data,
        colWidths=[112 * mm, 30 * mm, 36 * mm],
        repeatRows=1,
    )
    apply_standard_table_style(table)
    story.append(table)
    story.append(Spacer(1, 3 * mm))


# ============================================================
# DEFENSE ANALYSIS
# ============================================================

def build_defense_section(
    story,
    report_data,
    styles
):
    """
    Render defense-analysis findings as a consistent professional table.
    """

    append_section_heading(
        story,
        "5. Defense Analysis",
        styles
    )

    sections = get_dictionary(
        report_data,
        "sections"
    )

    defense_analysis = get_dictionary(
        sections,
        "defense_analysis"
    )

    findings = get_list(
        defense_analysis,
        "findings"
    )

    if not findings:
        table = build_status_table(
            headers=[
                "Finding",
                "Priority",
                "Evidence"
            ],
            message="No defense findings are currently available for the analyzed environment.",
            styles=styles,
            col_widths=[
                58 * mm,
                30 * mm,
                90 * mm
            ]
        )
        story.append(table)
        return

    rows = [[
        paragraph(
            "Finding",
            styles["table_header"]
        ),
        paragraph(
            "Priority",
            styles["table_header"]
        ),
        paragraph(
            "Evidence",
            styles["table_header"]
        ),
    ]]

    for finding in findings:

        if not isinstance(
            finding,
            dict
        ):
            continue

        title = get_defense_title(
            finding
        )

        description = get_defense_description(
            finding
        )

        priority = get_priority(
            finding
        )

        evidence = get_defense_evidence(
            finding
        )

        detail = evidence or description or "-"

        rows.append([
            paragraph(
                title,
                styles["table_body"]
            ),
            paragraph(
                priority,
                styles["table_body"]
            ),
            paragraph(
                detail,
                styles["table_body"]
            ),
        ])

    table = Table(
        rows,
        colWidths=[
            58 * mm,
            30 * mm,
            90 * mm
        ],
        repeatRows=1,
    )

    apply_standard_table_style(
        table
    )

    story.append(
        table
    )


# ============================================================
# MITIGATION RECOMMENDATIONS
# ============================================================

def build_mitigation_section(
    story,
    report_data,
    styles
):
    """
    Render mitigation recommendations as a consistent professional table.
    """

    append_section_heading(
        story,
        "6. Mitigation Recommendations",
        styles
    )

    sections = get_dictionary(
        report_data,
        "sections"
    )

    mitigation_analysis = get_dictionary(
        sections,
        "mitigation_analysis"
    )

    recommendations = get_list(
        mitigation_analysis,
        "recommendations"
    )

    if not recommendations:
        table = build_status_table(
            headers=[
                "Recommendation",
                "Priority",
                "Target",
                "Expected Effect"
            ],
            message="No mitigation recommendations are currently available.",
            styles=styles,
            col_widths=[
                58 * mm,
                27 * mm,
                38 * mm,
                55 * mm
            ]
        )
        story.append(table)
        return

    rows = [[
        paragraph(
            "Recommendation",
            styles["table_header"]
        ),
        paragraph(
            "Priority",
            styles["table_header"]
        ),
        paragraph(
            "Target",
            styles["table_header"]
        ),
        paragraph(
            "Expected Effect",
            styles["table_header"]
        ),
    ]]

    for recommendation in recommendations:

        if not isinstance(
            recommendation,
            dict
        ):
            continue

        title = get_recommendation_title(
            recommendation
        )

        priority = get_priority(
            recommendation
        )

        target = get_recommendation_target(
            recommendation
        )

        expected_effect = get_expected_effect(
            recommendation
        )

        rows.append([
            paragraph(
                title,
                styles["table_body"]
            ),
            paragraph(
                priority,
                styles["table_body"]
            ),
            paragraph(
                target,
                styles["table_body"]
            ),
            paragraph(
                expected_effect or "-",
                styles["table_body"]
            ),
        ])

    table = Table(
        rows,
        colWidths=[
            58 * mm,
            27 * mm,
            38 * mm,
            55 * mm
        ],
        repeatRows=1,
    )

    apply_standard_table_style(
        table
    )

    story.append(
        table
    )


# ============================================================
# RISK COMPARISON
# ============================================================

def build_risk_comparison_section(
    story,
    report_data,
    styles
):
    """
    Render current vs projected risk comparison.
    """

    append_section_heading(
        story,
        "7. Before vs After Risk Comparison",
        styles
    )

    sections = get_dictionary(
        report_data,
        "sections"
    )

    comparison = get_dictionary(
        sections,
        "risk_comparison"
    )

    current_state = get_dictionary(
        comparison,
        "current_state"
    )

    projected_state = get_dictionary(
        comparison,
        "projected_state"
    )

    reduction = get_dictionary(
        comparison,
        "reduction"
    )

    current_risk = safe_number(
        current_state.get(
            "risk_score",
            0
        )
    )

    projected_risk = safe_number(
        projected_state.get(
            "risk_score",
            current_risk
        )
    )

    risk_reduction = safe_number(
        reduction.get(
            "risk_points",
            max(
                0,
                current_risk - projected_risk
            )
        )
    )

    reduction_percentage = safe_number(
        reduction.get(
            "risk_percentage",
            0
        )
    )

    rows = [
        [
            paragraph(
                "Metric",
                styles["table_header"]
            ),

            paragraph(
                "Current",
                styles["table_header"]
            ),

            paragraph(
                "Projected",
                styles["table_header"]
            ),

            paragraph(
                "Reduction",
                styles["table_header"]
            ),
        ],

        [
            paragraph(
                "Risk Score",
                styles["table_body"]
            ),

            paragraph(
                f"{current_risk:.2f}",
                styles["table_body"]
            ),

            paragraph(
                f"{projected_risk:.2f}",
                styles["table_body"]
            ),

            paragraph(
                f"{risk_reduction:.2f}",
                styles["table_body"]
            ),
        ],

        [
            paragraph(
                "Vulnerabilities",
                styles["table_body"]
            ),

            paragraph(
                str(
                    safe_integer(
                        current_state.get(
                            "vulnerability_count",
                            0
                        )
                    )
                ),
                styles["table_body"]
            ),

            paragraph(
                str(
                    safe_integer(
                        projected_state.get(
                            "vulnerability_count",
                            0
                        )
                    )
                ),
                styles["table_body"]
            ),

            paragraph(
                str(
                    safe_integer(
                        reduction.get(
                            "vulnerability_count",
                            0
                        )
                    )
                ),
                styles["table_body"]
            ),
        ],

        [
            paragraph(
                "Sensitive Ports",
                styles["table_body"]
            ),

            paragraph(
                str(
                    safe_integer(
                        current_state.get(
                            "sensitive_ports",
                            0
                        )
                    )
                ),
                styles["table_body"]
            ),

            paragraph(
                str(
                    safe_integer(
                        projected_state.get(
                            "sensitive_ports",
                            0
                        )
                    )
                ),
                styles["table_body"]
            ),

            paragraph(
                str(
                    safe_integer(
                        reduction.get(
                            "sensitive_ports",
                            0
                        )
                    )
                ),
                styles["table_body"]
            ),
        ],

        [
            paragraph(
                "Attack Paths",
                styles["table_body"]
            ),

            paragraph(
                str(
                    safe_integer(
                        current_state.get(
                            "attack_paths",
                            0
                        )
                    )
                ),
                styles["table_body"]
            ),

            paragraph(
                str(
                    safe_integer(
                        projected_state.get(
                            "attack_paths",
                            0
                        )
                    )
                ),
                styles["table_body"]
            ),

            paragraph(
                str(
                    safe_integer(
                        reduction.get(
                            "attack_paths",
                            0
                        )
                    )
                ),
                styles["table_body"]
            ),
        ],
    ]

    table = Table(
        rows,
        colWidths=[
            58 * mm,
            40 * mm,
            40 * mm,
            40 * mm
        ],
        repeatRows=1,
    )

    apply_standard_table_style(
        table
    )

    story.append(
        table
    )

    story.append(
        Spacer(
            1,
            4 * mm
        )
    )

    story.append(
        Paragraph(
            (
                f"The estimated overall risk reduction is "
                f"<b>{reduction_percentage:.2f}%</b>. "
                "Projected values represent modeled improvement "
                "based on applicable mitigation recommendations."
            ),
            styles["body"]
        )
    )

    story.append(
        Spacer(
            1,
            5 * mm
        )
    )


# ============================================================
# METHODOLOGY & DISCLAIMER
# ============================================================

def build_methodology_section(
    story,
    report_data,
    styles
):
    """
    Render methodology and report disclaimer on a dedicated final page.
    """

    # Allow methodology to follow the preceding analysis when space
    # permits. ReportLab will move it naturally when the page is full.
    append_section_heading(
        story,
        "8. Methodology & Disclaimer",
        styles
    )

    paragraphs = [
        (
            "AttackLens uses data collected from authorized security scans "
            "and analysis generated by the platform's asset, vulnerability, "
            "risk, attack-path, defense, mitigation, and risk-comparison modules."
        ),
        (
            "Potential relationships and attack paths are evidence-supported "
            "analytical representations. They do not necessarily indicate "
            "successful exploitation, confirmed lateral movement, or verified compromise."
        ),
        (
            "Mitigation recommendations are defensive guidance derived from available "
            "evidence. AttackLens does not automatically patch vulnerabilities, close "
            "services, modify firewall rules, create network segments, or otherwise "
            "alter target systems."
        ),
        (
            "Projected risk values are estimates intended for security prioritization "
            "and comparison. They should not be interpreted as guaranteed post-remediation "
            "risk scores. Actual risk should be validated after authorized remediation "
            "and reassessment."
        ),
    ]

    for text in paragraphs:
        story.append(Paragraph(text, styles["body"]))

    story.append(Spacer(1, 3.5 * mm))

    authorized_by = get_authorized_scanner(
        report_data
    )

    scope = get_dictionary(
        report_data,
        "scope"
    )

    targets = scope.get(
        "targets"
    )

    if not isinstance(
        targets,
        list
    ):
        targets = []

    target_text = (
        ", ".join(
            safe_text(target)
            for target in targets
            if safe_text(target)
        )
        or "Not available"
    )

    authorization_rows = [
        [
            Paragraph(
                "AUTHORIZED ASSESSMENT RECORD",
                styles["authorization_label"]
            ),
            Paragraph(
                "DETAILS",
                styles["authorization_label"]
            ),
        ],
        [
            Paragraph(
                "Authorized Scanner",
                styles["authorization_label"]
            ),
            Paragraph(
                escape_text(
                    authorized_by
                ),
                styles["authorization_value"]
            ),
        ],
        [
            Paragraph(
                "Assessment Target",
                styles["authorization_label"]
            ),
            Paragraph(
                escape_text(
                    target_text
                ),
                styles["authorization_value"]
            ),
        ],
        [
            Paragraph(
                "Report Generated",
                styles["authorization_label"]
            ),
            Paragraph(
                escape_text(
                    format_datetime(
                        report_data.get(
                            "generated_at"
                        )
                    )
                ),
                styles["authorization_value"]
            ),
        ],
    ]

    authorization_table = Table(
        authorization_rows,
        colWidths=[
            58 * mm,
            120 * mm
        ],
    )

    authorization_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    COLOR_PRIMARY
                ),
                (
                    "BACKGROUND",
                    (0, 1),
                    (0, -1),
                    COLOR_PRIMARY
                ),
                (
                    "BACKGROUND",
                    (1, 1),
                    (1, -1),
                    COLOR_BACKGROUND
                ),
                (
                    "SPAN",
                    (0, 0),
                    (0, 0)
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.8,
                    COLOR_PRIMARY
                ),
                (
                    "INNERGRID",
                    (0, 0),
                    (-1, -1),
                    0.45,
                    COLOR_BORDER
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE"
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    10
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    10
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    9
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    9
                ),
            ]
        )
    )

    story.append(
        authorization_table
    )

    story.append(
        Spacer(
            1,
            4 * mm
        )
    )

    story.append(
        Paragraph(
            (
                "<b>Authorized Use Only:</b> This report must contain analysis "
                "only for systems that the named scanner is authorized to assess."
            ),
            styles["disclaimer"]
        )
    )


# ============================================================
# PAGE FOOTER
# ============================================================

def draw_cover_footer(
    canvas,
    document
):
    """
    Draw a minimal footer on the cover page.
    """

    canvas.saveState()

    page_width, _ = A4

    canvas.setStrokeColor(
        COLOR_BORDER
    )

    canvas.setLineWidth(
        0.45
    )

    canvas.line(
        16 * mm,
        14 * mm,
        page_width - 16 * mm,
        14 * mm
    )

    canvas.setFont(
        "Helvetica",
        7.8
    )

    canvas.setFillColor(
        COLOR_TEXT_MUTED
    )

    canvas.drawString(
        16 * mm,
        9.5 * mm,
        "AttackLens Security Assessment"
    )

    canvas.drawRightString(
        page_width - 16 * mm,
        9.5 * mm,
        "Confidential - Authorized Use Only"
    )

    canvas.restoreState()


def draw_page_header_footer(
    canvas,
    document
):
    """
    Draw a consistent professional header and footer on report pages.
    """

    canvas.saveState()

    page_width, page_height = A4

    # Header
    canvas.setFont(
        "Helvetica-Bold",
        8
    )

    canvas.setFillColor(
        COLOR_PRIMARY_DARK
    )

    canvas.drawString(
        16 * mm,
        page_height - 12 * mm,
        "ATTACKLENS"
    )

    canvas.setFont(
        "Helvetica",
        7.8
    )

    canvas.setFillColor(
        COLOR_TEXT_MUTED
    )

    canvas.drawRightString(
        page_width - 16 * mm,
        page_height - 12 * mm,
        "Security Assessment Report"
    )

    canvas.setStrokeColor(
        COLOR_BORDER
    )

    canvas.setLineWidth(
        0.45
    )

    canvas.line(
        16 * mm,
        page_height - 15 * mm,
        page_width - 16 * mm,
        page_height - 15 * mm
    )

    # Footer
    canvas.line(
        16 * mm,
        14 * mm,
        page_width - 16 * mm,
        14 * mm
    )

    canvas.setFont(
        "Helvetica",
        7.8
    )

    canvas.setFillColor(
        COLOR_TEXT_MUTED
    )

    canvas.drawString(
        16 * mm,
        9.5 * mm,
        "AttackLens Security Assessment"
    )

    canvas.drawCentredString(
        page_width / 2,
        9.5 * mm,
        "Confidential - Authorized Use Only"
    )

    canvas.drawRightString(
        page_width - 16 * mm,
        9.5 * mm,
        f"Page {canvas.getPageNumber()}"
    )

    canvas.restoreState()


# ============================================================
# SECTION HELPERS
# ============================================================

def append_section_heading(
    story,
    title,
    styles
):
    """
    Append standardized section heading.
    """

    story.append(
        Paragraph(
            escape_text(
                title
            ),
            styles["section_title"]
        )
    )


def build_status_table(
    headers,
    message,
    styles,
    col_widths
):
    """
    Build a normal report table even when a section has no findings.

    This keeps zero-result sections visually consistent with populated
    sections instead of falling back to an unrelated pale message box.
    """

    header_row = [
        paragraph(
            header,
            styles["table_header"]
        )
        for header in headers
    ]

    message_row = [
        Paragraph(
            escape_text(
                message
            ),
            styles["table_body"]
        )
    ]

    table = Table(
        [
            header_row,
            message_row
        ],
        colWidths=col_widths,
        repeatRows=1,
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "SPAN",
                    (0, 1),
                    (-1, 1)
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    COLOR_PRIMARY
                ),
                (
                    "BACKGROUND",
                    (0, 1),
                    (-1, 1),
                    COLOR_BACKGROUND
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.7,
                    COLOR_BORDER
                ),
                (
                    "INNERGRID",
                    (0, 0),
                    (-1, 0),
                    0.4,
                    COLOR_BORDER
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE"
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    9
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    9
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    10
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    10
                ),
            ]
        )
    )

    return table


def build_empty_message_table(
    message,
    styles
):
    """
    Build a standardized empty-data message table.
    """

    table = Table(
        [[Paragraph(escape_text(message), styles["body_muted"]) ]],
        colWidths=[178 * mm],
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLOR_BACKGROUND),
        ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return table


def append_empty_message(
    story,
    message,
    styles
):
    """
    Append an empty-data message.
    """

    story.append(build_empty_message_table(message, styles))
    story.append(Spacer(1, 3.5 * mm))


# ============================================================
# TABLE HELPERS
# ============================================================

def build_key_value_table(
    rows,
    styles
):
    """
    Build two-column report-information table.
    """

    table_rows = []

    for label, value in rows:

        table_rows.append(
            [
                Paragraph(
                    escape_text(
                        label
                    ),
                    styles["table_sidebar"]
                ),

                Paragraph(
                    escape_text(
                        value
                    ),
                    styles["table_body"]
                ),
            ]
        )

    table = Table(
        table_rows,
        colWidths=[
            52 * mm,
            126 * mm
        ],
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    COLOR_PRIMARY
                ),

                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.6,
                    COLOR_BORDER
                ),

                (
                    "INNERGRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    COLOR_BORDER
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),

                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    11
                ),

                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    11
                ),

                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    10
                ),

                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    10
                ),
            ]
        )
    )

    return table


def build_metric_table(
    metrics,
    styles
):
    """
    Build executive-summary metric cards.
    """

    value_row = []
    label_row = []

    for label, value in metrics:

        value_row.append(
            Paragraph(
                escape_text(
                    value
                ),
                styles["metric_value"]
            )
        )

        label_row.append(
            Paragraph(
                escape_text(
                    label
                ),
                styles["metric_label"]
            )
        )

    table = Table(
        [
            label_row,
            value_row
        ],
        colWidths=[
            (178 * mm) / len(metrics)
        ] * len(
            metrics
        ),
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    COLOR_BACKGROUND
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    COLOR_PRIMARY
                ),

                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.6,
                    COLOR_BORDER
                ),

                (
                    "INNERGRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    COLOR_BORDER
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE"
                ),

                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, 0),
                    12
                ),

                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, 0),
                    8
                ),

                (
                    "TOPPADDING",
                    (0, 1),
                    (-1, 1),
                    8
                ),

                (
                    "BOTTOMPADDING",
                    (0, 1),
                    (-1, 1),
                    13
                ),
            ]
        )
    )

    return table


def apply_standard_table_style(
    table
):
    """
    Apply standard AttackLens data-table formatting.
    """

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    COLOR_PRIMARY
                ),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [
                        COLOR_WHITE,
                        COLOR_BACKGROUND
                    ]
                ),

                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.6,
                    COLOR_BORDER
                ),

                (
                    "INNERGRID",
                    (0, 0),
                    (-1, -1),
                    0.35,
                    COLOR_BORDER
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE"
                ),

                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    8
                ),

                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    8
                ),

                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    9
                ),

                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    9
                ),
            ]
        )
    )


def paragraph(
    value,
    style
):
    """
    Convert any value into a safe ReportLab Paragraph.
    """

    return Paragraph(
        escape_text(
            value
        ),
        style
    )


# ============================================================
# DATA HELPERS
# ============================================================

def normalize_dictionary(
    value
):
    """
    Normalize the top-level report object.
    """

    if isinstance(
        value,
        dict
    ):
        return value

    return {}


def get_dictionary(
    document,
    key
):
    """
    Safely retrieve dictionary value.
    """

    if not isinstance(
        document,
        dict
    ):
        return {}

    value = document.get(
        key
    )

    if isinstance(
        value,
        dict
    ):
        return value

    return {}


def get_list(
    document,
    key
):
    """
    Safely retrieve list value.
    """

    if not isinstance(
        document,
        dict
    ):
        return []

    value = document.get(
        key
    )

    if isinstance(
        value,
        list
    ):
        return value

    return []


# ============================================================
# AUTHORIZATION HELPERS
# ============================================================

def get_authorized_scanner(
    report_data
):
    """
    Return the authenticated display name supplied by the report route.

    The PDF service never invents a person's name. If the route does
    not provide one, the report clearly states that it is unavailable.
    """

    if not isinstance(
        report_data,
        dict
    ):
        return "Not available"

    possible_keys = (
        "authorized_by",
        "scanner_name",
        "generated_by_name",
        "username"
    )

    for key in possible_keys:

        value = safe_text(
            report_data.get(
                key
            )
        )

        if value:
            return value

    return "Not available"


# ============================================================
# TEXT HELPERS
# ============================================================

def safe_text(
    value,
    default=""
):
    """
    Safely normalize arbitrary values to strings.
    """

    if value is None:
        return default

    value = str(
        value
    ).strip()

    if not value:
        return default

    return value


def escape_text(
    value
):
    """
    Escape text for use inside ReportLab Paragraph markup.
    """

    value = safe_text(
        value
    )

    value = value.replace(
        "&",
        "&amp;"
    )

    value = value.replace(
        "<",
        "&lt;"
    )

    value = value.replace(
        ">",
        "&gt;"
    )

    return value


# ============================================================
# NUMBER HELPERS
# ============================================================

def humanize_label(value):
    """
    Convert internal identifiers into human-readable PDF labels.
    """

    normalized = safe_text(value)
    if not normalized:
        return "-"

    return normalized.replace("_", " ").replace("-", " ").title()


def safe_integer(
    value
):
    """
    Convert to non-negative integer.
    """

    try:

        value = int(
            value
        )

    except (
        TypeError,
        ValueError
    ):

        return 0

    return max(
        0,
        value
    )


def safe_number(
    value
):
    """
    Convert to non-negative floating-point number.
    """

    try:

        value = float(
            value
        )

    except (
        TypeError,
        ValueError
    ):

        return 0.0

    return round(
        max(
            0.0,
            value
        ),
        2
    )


# ============================================================
# DATETIME HELPERS
# ============================================================

def format_datetime(
    value
):
    """
    Convert datetime into readable UTC timestamp.
    """

    if isinstance(
        value,
        datetime
    ):

        if value.tzinfo is None:

            value = value.replace(
                tzinfo=timezone.utc
            )

        try:

            value = value.astimezone(
                timezone.utc
            )

        except (
            ValueError,
            OverflowError
        ):

            pass

        return value.strftime(
            "%d %B %Y, %H:%M UTC"
        )

    return "Not available"


# ============================================================
# RISK HELPERS
# ============================================================

def safe_risk_level(
    value
):
    """
    Normalize AttackLens risk level.
    """

    level = safe_text(
        value,
        default="LOW"
    ).upper()

    valid_levels = {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    }

    if level not in valid_levels:

        return "LOW"

    return level


def determine_risk_level(
    score
):
    """
    Determine AttackLens risk level from 0-100 score.
    """

    score = safe_number(
        score
    )

    if score >= 75:

        return "CRITICAL"

    if score >= 50:

        return "HIGH"

    if score >= 25:

        return "MEDIUM"

    return "LOW"


def format_risk(
    score,
    level
):
    """
    Format risk for display.
    """

    return (
        f"{safe_number(score):.2f}/100 "
        f"({safe_risk_level(level)})"
    )


# ============================================================
# ASSET HELPERS
# ============================================================

def get_asset_target(
    asset
):
    """
    Retrieve primary target identifier.
    """

    if not isinstance(
        asset,
        dict
    ):

        return "-"

    for key in (
        "target",
        "ip_address",
        "ip",
        "host"
    ):

        value = safe_text(
            asset.get(
                key
            )
        )

        if value:

            return value

    return "-"


def get_asset_os(
    asset
):
    """
    Retrieve asset operating-system display value.
    """

    if not isinstance(
        asset,
        dict
    ):

        return "Unknown"

    for key in (
        "operating_system",
        "os",
        "os_name"
    ):

        value = asset.get(
            key
        )

        if isinstance(
            value,
            str
        ):

            normalized = value.strip()

            if normalized:

                return normalized

        if isinstance(
            value,
            dict
        ):

            for nested_key in (
                "name",
                "display_name",
                "product"
            ):

                nested_value = safe_text(
                    value.get(
                        nested_key
                    )
                )

                if nested_value:

                    return nested_value

    return "Unknown"


def get_open_ports(
    asset
):
    """
    Retrieve explicitly open ports from asset data.
    """

    if not isinstance(
        asset,
        dict
    ):

        return []

    ports = asset.get(
        "ports"
    )

    if not isinstance(
        ports,
        list
    ):

        return []

    result = set()

    for port_data in ports:

        if not isinstance(
            port_data,
            dict
        ):

            continue

        state = safe_text(
            port_data.get(
                "state"
            )
        ).lower()

        if state != "open":

            continue

        port = port_data.get(
            "port"
        )

        try:

            port = int(
                port
            )

        except (
            TypeError,
            ValueError
        ):

            continue

        if 1 <= port <= 65535:

            result.add(
                port
            )

    return sorted(
        result
    )


def format_port_list(
    ports
):
    """
    Format list of open ports.
    """

    if not ports:

        return "None"

    return ", ".join(
        str(
            port
        )
        for port in ports
    )


def get_asset_risk_score(
    asset
):
    """
    Retrieve asset risk score.
    """

    if not isinstance(
        asset,
        dict
    ):

        return 0.0

    for key in (
        "risk_score",
        "score"
    ):

        if key in asset:

            return safe_number(
                asset.get(
                    key
                )
            )

    risk = asset.get(
        "risk"
    )

    if isinstance(
        risk,
        dict
    ):

        return safe_number(
            risk.get(
                "score",
                risk.get(
                    "risk_score",
                    0
                )
            )
        )

    return 0.0


def get_asset_risk_level(
    asset
):
    """
    Retrieve asset risk classification.
    """

    if not isinstance(
        asset,
        dict
    ):

        return "LOW"

    for key in (
        "risk_level",
        "level"
    ):

        value = asset.get(
            key
        )

        if value is not None:

            return safe_risk_level(
                value
            )

    risk = asset.get(
        "risk"
    )

    if isinstance(
        risk,
        dict
    ):

        value = risk.get(
            "level",
            risk.get(
                "risk_level"
            )
        )

        if value is not None:

            return safe_risk_level(
                value
            )

    return determine_risk_level(
        get_asset_risk_score(
            asset
        )
    )


# ============================================================
# VULNERABILITY HELPERS
# ============================================================

def get_finding_name(
    finding
):
    """
    Retrieve vulnerability/CVE display name.
    """

    if not isinstance(
        finding,
        dict
    ):

        return "Unknown finding"

    for key in (
        "cve_id",
        "cve",
        "id",
        "name",
        "title"
    ):

        value = safe_text(
            finding.get(
                key
            )
        )

        if value:

            return value

    return "Vulnerability finding"


def get_finding_score(
    finding
):
    """
    Retrieve vulnerability severity score.
    """

    if not isinstance(
        finding,
        dict
    ):

        return 0.0

    for key in (
        "cvss_score",
        "score",
        "severity_score"
    ):

        if key in finding:

            return safe_number(
                finding.get(
                    key
                )
            )

    return 0.0


# ============================================================
# ATTACK PATH HELPERS
# ============================================================

def format_attack_path(
    path_data
):
    """
    Format attack-path node progression.
    """

    if not isinstance(
        path_data,
        dict
    ):

        return "Unknown path"

    for key in (
        "path",
        "nodes",
        "asset_ids",
        "targets"
    ):

        value = path_data.get(
            key
        )

        if isinstance(
            value,
            list
        ) and value:

            result = []

            for item in value:

                if isinstance(
                    item,
                    dict
                ):

                    result.append(
                        get_asset_target(
                            item
                        )
                    )

                else:

                    normalized = safe_text(
                        item
                    )

                    if normalized:

                        result.append(
                            normalized
                        )

            if result:

                return " -> ".join(
                    result
                )

    source = safe_text(
        path_data.get(
            "source"
        )
    )

    target = safe_text(
        path_data.get(
            "target"
        )
    )

    if source and target:

        return (
            f"{source} -> {target}"
        )

    return "Potential attack path"


# ============================================================
# DEFENSE HELPERS
# ============================================================

def get_defense_title(
    finding
):
    """
    Retrieve defense finding title.
    """

    if not isinstance(
        finding,
        dict
    ):

        return "Defense Finding"

    for key in (
        "title",
        "name",
        "finding",
        "type"
    ):

        value = safe_text(
            finding.get(
                key
            )
        )

        if value:

            return value

    return "Defense Finding"


def get_defense_description(
    finding
):
    """
    Retrieve defense finding description.
    """

    if not isinstance(
        finding,
        dict
    ):

        return "No additional description available."

    for key in (
        "description",
        "reason",
        "summary",
        "details",
        "evidence"
    ):

        value = finding.get(
            key
        )

        if isinstance(
            value,
            str
        ):

            value = value.strip()

            if value:

                return value

        if isinstance(
            value,
            list
        ):

            values = [
                safe_text(
                    item
                )
                for item in value
                if safe_text(
                    item
                )
            ]

            if values:

                return "; ".join(
                    values
                )

    return "Defense analysis finding generated by AttackLens."


def get_defense_evidence(finding):
    """
    Retrieve explicit defense-analysis evidence when available.
    """

    if not isinstance(finding, dict):
        return ""

    for key in ("evidence", "evidence_summary", "supporting_evidence"):
        value = clean_evidence_text(finding.get(key))
        if value:
            return value

    return ""


# ============================================================
# MITIGATION HELPERS
# ============================================================

def get_recommendation_title(
    recommendation
):
    """
    Retrieve recommendation title.
    """

    if not isinstance(
        recommendation,
        dict
    ):

        return "Security Recommendation"

    for key in (
        "title",
        "recommendation",
        "name",
        "action"
    ):

        value = safe_text(
            recommendation.get(
                key
            )
        )

        if value:

            return value

    return "Security Recommendation"


def get_recommendation_target(
    recommendation
):
    """
    Retrieve mitigation target.
    """

    if not isinstance(
        recommendation,
        dict
    ):

        return "-"

    for key in (
        "target",
        "asset_target",
        "asset",
        "host"
    ):

        value = recommendation.get(
            key
        )

        if isinstance(
            value,
            dict
        ):

            return get_asset_target(
                value
            )

        normalized = safe_text(
            value
        )

        if normalized:

            return normalized

    return "-"


def get_recommendation_evidence(
    recommendation
):
    """
    Retrieve recommendation evidence.
    """

    if not isinstance(
        recommendation,
        dict
    ):

        return ""

    return clean_evidence_text(
        recommendation.get(
            "evidence"
        )
    )


def get_expected_effect(
    recommendation
):
    """
    Retrieve expected mitigation effect.
    """

    if not isinstance(
        recommendation,
        dict
    ):

        return ""

    for key in (
        "expected_effect",
        "expected_impact",
        "effect",
        "benefit"
    ):

        value = format_generic_value(
            recommendation.get(
                key
            )
        )

        if value:

            return value

    return ""


def get_priority(
    data
):
    """
    Retrieve priority classification.
    """

    if not isinstance(
        data,
        dict
    ):

        return "LOW"

    for key in (
        "priority",
        "severity",
        "risk_level"
    ):

        value = safe_text(
            data.get(
                key
            )
        )

        if value:

            return value.upper()

    return "LOW"


# ============================================================
# GENERIC VALUE FORMATTER
# ============================================================

def clean_evidence_text(
    value
):
    """
    Clean evidence text for professional PDF display.

    This function only affects presentation. It does not modify
    the underlying defense or mitigation analysis data.
    """

    text = format_generic_value(
        value
    )

    if not text:
        return ""

    # Remove awkward punctuation before semicolon separators.
    text = text.replace(
        ".;",
        ";"
    )

    # Humanize common generated wording.
    text = text.replace(
        "open port(s)",
        "open ports"
    )

    text = text.replace(
        "Open port(s)",
        "Open ports"
    )

    return text.strip()


def format_generic_value(
    value
):
    """
    Convert common structured values to readable text.
    """

    if value is None:

        return ""

    if isinstance(
        value,
        str
    ):

        return value.strip()

    if isinstance(
        value,
        (
            int,
            float,
            bool
        )
    ):

        return str(
            value
        )

    if isinstance(
        value,
        list
    ):

        parts = []

        for item in value:

            text = format_generic_value(
                item
            )

            if text:

                parts.append(
                    text
                )

        return "; ".join(
            parts
        )

    if isinstance(
        value,
        dict
    ):

        parts = []

        for key, item in value.items():

            text = format_generic_value(
                item
            )

            if not text:

                continue

            key_text = safe_text(
                key
            ).replace(
                "_",
                " "
            ).title()

            parts.append(
                f"{key_text}: {text}"
            )

        return "; ".join(
            parts
        )

    return safe_text(
        value
    )