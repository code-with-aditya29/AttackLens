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
    send_file,
    session,
    url_for,
)

from routes.auth import login_required

from services.report_service import generate_report_data
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

    Only assets belonging to the currently authenticated user
    are included in the report data.
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
        )

    try:

        assets = list(
            db.assets.find(
                {
                    "created_by": current_user_id
                }
            )
        )

        report_data = generate_report_data(
            assets=assets,
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
    Generate and download the AttackLens Security Assessment PDF.

    PDF generation is allowed only when at least one authorized
    analyzed asset is available for the logged-in user.
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

    try:

        assets = list(
            db.assets.find(
                {
                    "created_by": current_user_id
                }
            )
        )

        if not assets:

            flash(
                (
                    "A security report cannot be generated because "
                    "no analyzed assets are currently available."
                ),
                "warning"
            )

            return redirect(
                url_for(
                    "report.reports"
                )
            )

        report_data = generate_report_data(
            assets=assets,
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
                    "report.reports"
                )
            )

        pdf_buffer = generate_report_pdf(
            report_data
        )

        filename = create_report_filename()

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
                "report.reports"
            )
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

def create_report_filename():
    """
    Create a safe timestamped PDF filename.
    """

    timestamp = datetime.now(
        timezone.utc
    ).strftime(
        "%Y%m%d_%H%M%S"
    )

    return (
        f"AttackLens_Security_Assessment_{timestamp}.pdf"
    )