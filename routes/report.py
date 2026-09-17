"""
AttackLens
Report Routes

This module provides the web routes used for:

- Viewing the Reports page
- Collecting report data for the logged-in user
- Generating the AttackLens Security Assessment PDF
- Downloading the generated PDF

The route layer does not perform security analysis itself.
It delegates analysis and report construction to the
existing AttackLens service layer.
"""

from datetime import datetime, timezone

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from routes.auth import login_required

from services.report_service import (
    build_report_asset_from_scan,
    generate_report_data,
)
from services.scan_service import (
    get_scan_by_id,
    get_scan_history,
)
from services.pdf_service import generate_report_pdf


# ============================================================
# BLUEPRINT
# ============================================================

report_bp = Blueprint(
    "report",
    __name__
)


# ============================================================
# REPORTS PAGE
# ============================================================

@report_bp.route(
    "/reports",
    methods=["GET"]
)
@login_required
def reports():
    """
    Display the AttackLens Reports page.

    Reports are scoped to one completed scan belonging to the
    currently authenticated user.

    If no scan_id is supplied, the latest completed scan is
    selected automatically.
    """

    db = current_app.config.get(
        "MONGO_DB"
    )

    if db is None:

        flash(
            "Database connection is unavailable.",
            "danger"
        )

        return render_template(
            "reports.html",
            current_page="reports",
            report_data=create_empty_report_context(),
            report_generation_available=False,
            completed_scans=[],
            selected_scan=None,
        )

    current_user_id = session.get(
        "admin_id"
    )

    if not current_user_id:

        flash(
            "Unable to identify the current user.",
            "danger"
        )

        return render_template(
            "reports.html",
            current_page="reports",
            report_data=create_empty_report_context(),
            report_generation_available=False,
            completed_scans=[],
            selected_scan=None,
        )

    try:

        scan_history = get_scan_history(
            db=db,
            created_by=current_user_id,
            limit=100
        )

        completed_scans = [
            scan
            for scan in scan_history
            if str(
                scan.get(
                    "status",
                    ""
                )
            ).strip().lower() == "completed"
        ]

        selected_scan = None

        requested_scan_id = str(
            request.args.get(
                "scan_id",
                ""
            )
        ).strip()

        if requested_scan_id:

            selected_scan = get_scan_by_id(
                db=db,
                scan_id=requested_scan_id,
                created_by=current_user_id
            )

            if not selected_scan:

                flash(
                    "The selected scan could not be found or is not accessible.",
                    "warning"
                )

            elif str(
                selected_scan.get(
                    "status",
                    ""
                )
            ).strip().lower() != "completed":

                selected_scan = None

                flash(
                    "Only completed scans can be used for report generation.",
                    "warning"
                )

        elif completed_scans:

            selected_scan = completed_scans[0]

        if not selected_scan:

            return render_template(
                "reports.html",
                current_page="reports",
                report_data=create_empty_report_context(),
                report_generation_available=False,
                completed_scans=completed_scans,
                selected_scan=None,
            )

        report_asset = build_report_asset_for_scan(
            db=db,
            scan=selected_scan,
            current_user_id=current_user_id
        )

        if not report_asset:

            return render_template(
                "reports.html",
                current_page="reports",
                report_data=create_empty_report_context(),
                report_generation_available=False,
                completed_scans=completed_scans,
                selected_scan=selected_scan,
            )

        report_data = generate_report_data(
            assets=[
                report_asset
            ],
            created_by=current_user_id,
        )

        report_generation_available = (
            get_report_generation_status(
                report_data
            )
        )

        return render_template(
            "reports.html",
            current_page="reports",
            report_data=report_data,
            report_generation_available=report_generation_available,
            completed_scans=completed_scans,
            selected_scan=selected_scan,
        )

    except Exception as error:

        current_app.logger.exception(
            "Failed to build report data: %s",
            error
        )

        flash(
            "Unable to prepare report data at this time.",
            "danger"
        )

        return render_template(
            "reports.html",
            current_page="reports",
            report_data=create_empty_report_context(),
            report_generation_available=False,
            completed_scans=[],
            selected_scan=None,
        )


# ============================================================
# GENERATE PDF REPORT
# ============================================================

@report_bp.route(
    "/reports/generate",
    methods=["POST"]
)
@login_required
def generate_report():
    """
    Generate and download one AttackLens Security Assessment PDF
    for one completed scan.

    The selected scan_id is validated against the current user
    before report generation.
    """

    db = current_app.config.get(
        "MONGO_DB"
    )

    if db is None:

        flash(
            "Database connection is unavailable.",
            "danger"
        )

        return redirect(
            url_for(
                "report.reports"
            )
        )

    current_user_id = session.get(
        "admin_id"
    )

    if not current_user_id:

        flash(
            "Unable to identify the current user.",
            "danger"
        )

        return redirect(
            url_for(
                "report.reports"
            )
        )

    scan_id = str(
        request.form.get(
            "scan_id",
            ""
        )
    ).strip()

    if not scan_id:

        flash(
            "Please select a completed scan before generating a report.",
            "warning"
        )

        return redirect(
            url_for(
                "report.reports"
            )
        )

    try:

        scan = get_scan_by_id(
            db=db,
            scan_id=scan_id,
            created_by=current_user_id
        )

        if not scan:

            flash(
                "The selected scan could not be found or is not accessible.",
                "danger"
            )

            return redirect(
                url_for(
                    "report.reports"
                )
            )

        if str(
            scan.get(
                "status",
                ""
            )
        ).strip().lower() != "completed":

            flash(
                "A PDF report can only be generated from a completed scan.",
                "warning"
            )

            return redirect(
                url_for(
                    "report.reports",
                    scan_id=scan_id
                )
            )

        report_asset = build_report_asset_for_scan(
            db=db,
            scan=scan,
            current_user_id=current_user_id
        )

        if not report_asset:

            flash(
                "Unable to prepare the selected scan for reporting.",
                "danger"
            )

            return redirect(
                url_for(
                    "report.reports",
                    scan_id=scan_id
                )
            )

        report_data = generate_report_data(
            assets=[
                report_asset
            ],
            created_by=current_user_id,
        )

        if not get_report_generation_status(
            report_data
        ):

            flash(
                (
                    "The report is not ready for PDF generation. "
                    "Please complete an authorized security scan first."
                ),
                "warning"
            )

            return redirect(
                url_for(
                    "report.reports",
                    scan_id=scan_id
                )
            )

        pdf_buffer = generate_report_pdf(
            report_data,
            authorized_by=session.get(
                "username",
                "Not available"
            )
        )

        filename = create_report_filename(
            scan
        )

        return send_file(
            pdf_buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename,
        )

    except Exception as error:

        current_app.logger.exception(
            "Failed to generate PDF report: %s",
            error
        )

        flash(
            "Unable to generate the PDF report at this time.",
            "danger"
        )

        return redirect(
            url_for(
                "report.reports",
                scan_id=scan_id
            )
        )


# ============================================================
# SCAN-SPECIFIC REPORT ASSET HELPER
# ============================================================

def build_report_asset_for_scan(
    db,
    scan,
    current_user_id
):
    """
    Convert one completed scan into the asset-shaped snapshot
    expected by the existing report-analysis pipeline.

    Current Asset Inventory contributes only manual contextual
    fields such as criticality and exposure.
    """

    if not isinstance(
        scan,
        dict
    ):

        return None

    target = str(
        scan.get(
            "target",
            ""
        )
    ).strip()

    if not target:

        return None

    asset_context = db.assets.find_one(
        {
            "target": target,
            "created_by": current_user_id
        }
    )

    return build_report_asset_from_scan(
        scan=scan,
        asset_context=asset_context
    )


# ============================================================
# REPORT STATUS HELPER
# ============================================================

def get_report_generation_status(
    report_data
):
    """
    Determine whether PDF report generation is available.

    report_service.py intentionally allows report generation
    whenever at least one analyzed asset is available.

    Zero vulnerabilities, zero attack paths, or zero mitigation
    recommendations are valid assessment outcomes and therefore
    must not disable PDF generation.
    """

    if not isinstance(
        report_data,
        dict
    ):

        return False

    readiness = report_data.get(
        "readiness"
    )

    if not isinstance(
        readiness,
        dict
    ):

        return False

    return bool(
        readiness.get(
            "report_generation_available",
            False
        )
    )


# ============================================================
# EMPTY REPORT CONTEXT
# ============================================================

def create_empty_report_context():
    """
    Return a safe zero-state report context.

    This allows reports.html to render even if database
    access or report aggregation fails.
    """

    now = datetime.now(
        timezone.utc
    )

    return {
        "report_id": None,
        "report_type": "security_assessment",
        "report_version": "1.0",
        "title": "AttackLens Security Assessment",
        "created_by": None,
        "status": "not_ready",

        "scope": {
            "asset_count": 0,
            "targets": [],
        },

        "executive_summary": {
            "asset_count": 0,
            "vulnerability_count": 0,
            "attack_path_count": 0,
            "defense_finding_count": 0,
            "recommendation_count": 0,
            "overall_risk_score": 0.0,
            "overall_risk_level": "LOW",
            "projected_risk_score": 0.0,
            "projected_risk_level": "LOW",
            "projected_reduction_percentage": 0.0,
        },

        "sections": {
            "assets": [],

            "vulnerability_summary": {
                "vulnerability_count": 0,
                "vulnerable_assets": 0,
                "findings": [],
            },

            "attack_path_analysis": {
                "nodes": [],
                "relationships": [],
                "paths": [],
            },

            "defense_analysis": {
                "findings": [],
            },

            "mitigation_analysis": {
                "recommendations": [],
            },

            "risk_comparison": {
                "current_state": {
                    "risk_score": 0.0,
                    "risk_level": "LOW",
                    "total_assets": 0,
                    "vulnerable_assets": 0,
                    "vulnerability_count": 0,
                    "open_ports": 0,
                    "sensitive_ports": 0,
                    "attack_paths": 0,
                    "high_risk_attack_paths": 0,
                },

                "projected_state": {
                    "risk_score": 0.0,
                    "risk_level": "LOW",
                    "total_assets": 0,
                    "vulnerable_assets": 0,
                    "vulnerability_count": 0,
                    "open_ports": 0,
                    "sensitive_ports": 0,
                    "attack_paths": 0,
                    "high_risk_attack_paths": 0,
                },

                "reduction": {
                    "risk_points": 0.0,
                    "risk_percentage": 0.0,
                    "vulnerable_assets": 0,
                    "vulnerability_count": 0,
                    "open_ports": 0,
                    "sensitive_ports": 0,
                    "attack_paths": 0,
                    "high_risk_attack_paths": 0,
                },

                "applied_recommendations": [],

                "statistics": {
                    "recommendation_count": 0,
                    "applicable_recommendations": 0,
                    "affected_assets": 0,
                    "current_risk_score": 0.0,
                    "projected_risk_score": 0.0,
                    "risk_reduction": 0.0,
                    "risk_reduction_percentage": 0.0,
                },
            },
        },

        "readiness": {
            "asset_inventory": False,
            "risk_assessment": False,
            "attack_path_analysis": False,
            "defense_analysis": False,
            "mitigation_recommendations": False,
            "risk_comparison": False,
            "report_generation_available": False,
        },

        "statistics": {
            "asset_count": 0,
            "open_ports": 0,
            "vulnerability_count": 0,
            "vulnerable_assets": 0,
            "attack_path_count": 0,
            "defense_finding_count": 0,
            "recommendation_count": 0,
            "current_risk_score": 0.0,
            "current_risk_level": "LOW",
            "projected_risk_score": 0.0,
            "projected_risk_level": "LOW",
            "risk_reduction": 0.0,
            "risk_reduction_percentage": 0.0,
        },

        "generated_at": now,
    }


# ============================================================
# REPORT FILENAME
# ============================================================

def create_report_filename(
    scan=None
):
    """
    Create a safe timestamped scan-specific PDF filename.
    """

    timestamp = datetime.now(
        timezone.utc
    ).strftime(
        "%Y%m%d_%H%M%S"
    )

    target = "scan"

    if isinstance(
        scan,
        dict
    ):

        target = str(
            scan.get(
                "target",
                "scan"
            )
        ).strip()

    safe_target = "".join(
        character
        if character.isalnum()
        or character in (
            "-",
            "_",
            "."
        )
        else "_"
        for character in target
    )

    safe_target = (
        safe_target.strip("._")
        or "scan"
    )

    return (
        f"AttackLens_{safe_target}_"
        f"Security_Assessment_{timestamp}.pdf"
    )