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
from hashlib import sha256

from models.report_model import generate_report_id
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

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
    normalize_timezone_name,
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
# TIMEZONE CONFIGURATION
# ============================================================

DEFAULT_REPORT_TIMEZONE = "UTC"
TIMEZONE_SESSION_KEY = "report_timezone"


def get_client_timezone():
    """
    Resolve the user's report timezone.

    Priority:
    1. Submitted form timezone
    2. Query-string timezone
    3. Browser timezone cookie
    4. Previously validated session timezone
    5. UTC fallback

    The timezone must be an IANA timezone such as:
        Asia/Kolkata
        America/New_York
        America/Toronto
        Asia/Tokyo

    The route never infers timezone from the scan target or
    from an IP address.
    """

    candidates = [
        request.form.get("timezone_name"),
        request.args.get("timezone_name"),
        request.cookies.get("attacklens_timezone"),
        session.get(TIMEZONE_SESSION_KEY),
    ]

    for candidate in candidates:
        if candidate is None:
            continue

        candidate = str(candidate).strip()

        if not candidate:
            continue

        if is_valid_timezone(candidate):
            normalized = normalize_timezone_name(candidate)
            session[TIMEZONE_SESSION_KEY] = normalized
            return normalized

    return DEFAULT_REPORT_TIMEZONE


def is_valid_timezone(timezone_name):
    """Return True only when the supplied IANA timezone is valid."""

    if timezone_name is None:
        return False

    timezone_name = str(timezone_name).strip()

    if not timezone_name:
        return False

    try:
        ZoneInfo(timezone_name)
        return True
    except (ZoneInfoNotFoundError, ValueError, TypeError):
        return False


def get_timezone_object(timezone_name):
    """Return a safe ZoneInfo object for filename generation."""

    if not is_valid_timezone(timezone_name):
        return timezone.utc

    try:
        return ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, ValueError, TypeError):
        return timezone.utc


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

    db = current_app.config.get("MONGO_DB")
    timezone_name = get_client_timezone()

    if db is None:
        flash(
            "Database connection is unavailable.",
            "danger"
        )

        return render_template(
            "reports.html",
            current_page="reports",
            report_data=create_empty_report_context(
                timezone_name=timezone_name
            ),
            report_generation_available=False,
            completed_scans=[],
            selected_scan=None,
            timezone_name=timezone_name,
        )

    current_user_id = session.get("admin_id")

    if not current_user_id:
        flash(
            "Unable to identify the current user.",
            "danger"
        )

        return render_template(
            "reports.html",
            current_page="reports",
            report_data=create_empty_report_context(
                timezone_name=timezone_name
            ),
            report_generation_available=False,
            completed_scans=[],
            selected_scan=None,
            timezone_name=timezone_name,
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
                scan.get("status", "")
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
                report_data=create_empty_report_context(
                    timezone_name=timezone_name
                ),
                report_generation_available=False,
                completed_scans=completed_scans,
                selected_scan=None,
                timezone_name=timezone_name,
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
                report_data=create_empty_report_context(
                    timezone_name=timezone_name
                ),
                report_generation_available=False,
                completed_scans=completed_scans,
                selected_scan=selected_scan,
                timezone_name=timezone_name,
            )

        report_data = generate_report_data(
            assets=[
                report_asset
            ],
            created_by=current_user_id,
            timezone_name=timezone_name,
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
            timezone_name=timezone_name,
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
            report_data=create_empty_report_context(
                timezone_name=timezone_name
            ),
            report_generation_available=False,
            completed_scans=[],
            selected_scan=None,
            timezone_name=timezone_name,
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

    The browser-supplied timezone is validated and passed to the
    report service so presentation timestamps use the user's
    local timezone.
    """

    db = current_app.config.get("MONGO_DB")
    timezone_name = get_client_timezone()

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

    current_user_id = session.get("admin_id")

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
            timezone_name=timezone_name,
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

        # Allocate and persist the public report identity only when a PDF
        # is actually requested and the scan has passed readiness checks.
        # Never consume report numbers during GET /reports page previews.
        report_data["report_id"] = get_or_create_scan_report_id(
            db=db,
            scan=scan,
            scan_id=scan_id,
            current_user_id=current_user_id,
        )

        pdf_buffer = generate_report_pdf(
            report_data,
            authorized_by=session.get(
                "username",
                "Not available"
            )
        )

        filename = create_report_filename(
            scan=scan,
            timezone_name=timezone_name
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
# PERSISTENT, HUMAN-READABLE REPORT ID
# ============================================================

def get_or_create_scan_report_id(db, scan, scan_id, current_user_id):
    """Return the permanent public ID for this user's completed scan.

    The unique MongoDB _id prevents separate users' scans from sharing an
    identity. An atomic upsert keeps the same ID on repeated PDF downloads.
    The sequence is allocated by the existing report service's MongoDB
    counter; numbers can have gaps if concurrent first-time requests race.
    """
    from services.report_service import allocate_report_number
    from pymongo import ReturnDocument

    target = str(scan.get("target") or "").strip()
    if not target:
        raise ValueError("A scanned target is required for the Report ID")

    # Avoid exposing a user's account identifier in the MongoDB document key.
    identity_key = sha256(
        f"{current_user_id}:{scan_id}".encode("utf-8")
    ).hexdigest()
    collection = db["report_identities"]

    existing = collection.find_one({"_id": identity_key})
    if existing and existing.get("report_id"):
        return existing["report_id"]

    number = allocate_report_number(db)
    created_at = datetime.now(timezone.utc)
    candidate = generate_report_id(
        report_number=number,
        target=target,
        generated_at=created_at,
        timezone_name="Asia/Kolkata",
    )
    record = collection.find_one_and_update(
        {"_id": identity_key},
        {"$setOnInsert": {
            "report_id": candidate,
            "report_number": number,
            "scan_id": str(scan_id),
            "created_by": str(current_user_id),
            "target": target,
            "created_at": created_at,
        }},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    if not record or not record.get("report_id"):
        raise RuntimeError("Could not persist the Report ID")
    return record["report_id"]


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

    if not isinstance(scan, dict):
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

def create_empty_report_context(
    timezone_name=None
):
    """
    Return a safe zero-state report context.

    This allows reports.html to render even if database
    access or report aggregation fails.

    Presentation timestamps use the validated user timezone.
    """

    timezone_name = (
        normalize_timezone_name(
            timezone_name
        )
    )

    report_timezone = get_timezone_object(
        timezone_name
    )

    now_utc = datetime.now(
        timezone.utc
    )

    now_local = now_utc.astimezone(
        report_timezone
    )

    timezone_label = (
        now_local.tzname()
        or timezone_name
    )

    generated_at_display = (
        f"{now_local.strftime('%d %B %Y, %H:%M')} "
        f"{timezone_label}"
    )

    return {
        "report_id": None,
        "report_type": "security_assessment",
        "report_version": "1.1",
        "title": "AttackLens Security Assessment",
        "created_by": None,
        "status": "not_ready",

        "timezone": timezone_name,
        "generated_at_utc": now_utc.isoformat(),
        "generated_at_local": now_local.isoformat(),
        "generated_at_display": generated_at_display,

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
            "overall_risk_score": None,
            "overall_risk_level": None,
            "projected_risk_score": None,
            "projected_risk_level": None,
            "projected_reduction_percentage": 0.0,
        },

        "sections": {
            "assets": [],

            "vulnerability_summary": {
                "vulnerability_count": 0,
                "vulnerable_assets": 0,
                "findings": [],
            },

            "security_finding_summary": {
                "security_finding_count": 0,
                "affected_assets": 0,
                "affected_targets": [],
                "type_counts": {},
                "severity_counts": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0,
                    "UNKNOWN": 0,
                },
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
                    "risk_score": None,
                    "risk_level": None,
                    "total_assets": 0,
                    "vulnerable_assets": 0,
                    "vulnerability_count": 0,
                    "open_ports": 0,
                    "sensitive_ports": 0,
                    "attack_paths": 0,
                    "high_risk_attack_paths": 0,
                },

                "projected_state": {
                    "risk_score": None,
                    "risk_level": None,
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
                    "current_risk_score": None,
                    "projected_risk_score": None,
                    "risk_reduction": 0.0,
                    "risk_reduction_percentage": 0.0,
                },
            },
        },

        "security_finding_summary": {
            "security_finding_count": 0,
            "affected_assets": 0,
            "affected_targets": [],
            "type_counts": {},
            "severity_counts": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "UNKNOWN": 0,
            },
            "findings": [],
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
            "current_risk_score": None,
            "current_risk_level": None,
            "projected_risk_score": None,
            "projected_risk_level": None,
            "risk_reduction": 0.0,
            "risk_reduction_percentage": 0.0,
        },

        # Retained for backward compatibility with existing templates/tests.
        "generated_at": now_local,
    }


# ============================================================
# REPORT FILENAME
# ============================================================

def create_report_filename(
    scan=None,
    timezone_name=None
):
    """
    Create a safe timestamped scan-specific PDF filename.

    The timestamp uses the user's validated local timezone.
    """

    timezone_name = normalize_timezone_name(
        timezone_name
    )

    report_timezone = get_timezone_object(
        timezone_name
    )

    timestamp = datetime.now(
        timezone.utc
    ).astimezone(
        report_timezone
    ).strftime(
        "%Y%m%d_%H%M%S"
    )

    target = "scan"

    if isinstance(scan, dict):
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