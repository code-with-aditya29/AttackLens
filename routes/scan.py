from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    current_app
)

from routes.auth import login_required
from services.scan_validator import validate_target
from services.scan_service import create_scan


scan_bp = Blueprint(
    "scan",
    __name__
)


# ==========================================
# SCAN TARGET PAGE
# ==========================================

@scan_bp.route(
    "/scan",
    methods=["GET", "POST"]
)
@login_required
def scan_target():

    if request.method == "POST":

        target = request.form.get(
            "target",
            ""
        ).strip()

        scan_profile = request.form.get(
            "scan_profile",
            "standard"
        ).strip().lower()

        # ==================================
        # VALIDATE TARGET
        # ==================================

        is_valid, message = validate_target(
            target
        )

        if not is_valid:

            flash(
                message,
                "error"
            )

            return redirect(
                url_for(
                    "scan.scan_target"
                )
            )

        # ==================================
        # VALIDATE SCAN PROFILE
        # ==================================

        allowed_profiles = [
            "quick",
            "standard",
            "detailed"
        ]

        if scan_profile not in allowed_profiles:

            flash(
                "Invalid scan profile selected.",
                "error"
            )

            return redirect(
                url_for(
                    "scan.scan_target"
                )
            )

        # ==================================
        # CREATE SCAN RECORD
        # ==================================

        db = current_app.config[
            "MONGO_DB"
        ]

        scan = create_scan(
            db=db,
            target=target,
            scan_profile=scan_profile,
            created_by=session_user_id()
        )

        flash(
            "Scan created successfully. Scan execution will be added in the next phase.",
            "success"
        )

        return redirect(
            url_for(
                "scan.scan_results",
                scan_id=scan["_id"]
            )
        )

    return render_template(
        "scan.html",
        current_page="scan"
    )


# ==========================================
# SCAN RESULTS PAGE
# ==========================================

@scan_bp.route(
    "/scan/results/<scan_id>"
)
@login_required
def scan_results(scan_id):

    db = current_app.config[
        "MONGO_DB"
    ]

    from bson import ObjectId

    try:

        scan = db.scans.find_one(
            {
                "_id": ObjectId(
                    scan_id
                )
            }
        )

    except Exception:

        flash(
            "Invalid scan ID.",
            "error"
        )

        return redirect(
            url_for(
                "scan.scan_target"
            )
        )

    if not scan:

        flash(
            "Scan not found.",
            "error"
        )

        return redirect(
            url_for(
                "scan.scan_target"
            )
        )

    return render_template(
        "scan_results.html",
        scan=scan,
        current_page="scan"
    )


# ==========================================
# GET CURRENT USER ID
# ==========================================

def session_user_id():

    from flask import session

    return session.get(
        "admin_id"
    )