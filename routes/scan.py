from flask import (

    Blueprint,

    render_template,

    request,

    redirect,

    url_for,

    flash,

    current_app,

    session

)


from bson import ObjectId


from routes.auth import (

    login_required

)


from services.scan_validator import (

    validate_target

)


from services.scan_service import (

    create_scan,

    start_scan,

    save_scan_results,

    fail_scan

)


from services.nmap_service import (

    check_nmap_installed,

    run_nmap_scan

)


# ==========================================
# SCAN BLUEPRINT
# ==========================================

scan_bp = Blueprint(

    "scan",

    __name__

)


# ==========================================
# SCAN TARGET PAGE
# ==========================================

@scan_bp.route(

    "/scan",

    methods=[

        "GET",

        "POST"

    ]

)

@login_required

def scan_target():

    # ======================================
    # CREATE NEW SCAN
    # ======================================

    if request.method == "POST":

        # ==================================
        # GET FORM DATA
        # ==================================

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
        # CHECK NMAP INSTALLATION
        # ==================================

        if not check_nmap_installed():

            flash(

                "Nmap is not installed or cannot "
                "be found in the system PATH.",

                "error"

            )


            return redirect(

                url_for(

                    "scan.scan_target"

                )

            )


        # ==================================
        # GET DATABASE
        # ==================================

        db = current_app.config[

            "MONGO_DB"

        ]


        # ==================================
        # CREATE SCAN RECORD
        # ==================================

        scan = create_scan(

            db=db,

            target=target,

            scan_profile=scan_profile,

            created_by=session_user_id()

        )


        scan_id = str(

            scan["_id"]

        )


        # ==================================
        # MARK SCAN AS RUNNING
        # ==================================

        start_scan(

            db,

            scan_id

        )


        # ==================================
        # RUN NMAP SCAN
        # ==================================

        results = run_nmap_scan(

            target=target,

            scan_profile=scan_profile

        )


        # ==================================
        # HANDLE SCAN FAILURE
        # ==================================

        if not results.get(

            "success"

        ):

            fail_scan(

                db,

                scan_id,

                results.get(

                    "message",

                    "Scan failed."

                )

            )


            flash(

                results.get(

                    "message",

                    "Scan failed."

                ),

                "error"

            )


            return redirect(

                url_for(

                    "scan.scan_results",

                    scan_id=scan_id

                )

            )


        # ==================================
        # SAVE SCAN RESULTS
        # ==================================

        save_scan_results(

            db,

            scan_id,

            results

        )


        flash(

            "Security scan completed successfully.",

            "success"

        )


        return redirect(

            url_for(

                "scan.scan_results",

                scan_id=scan_id

            )

        )


    # ======================================
    # LOAD SCAN PAGE
    # ======================================

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

def scan_results(

    scan_id

):

    db = current_app.config[

        "MONGO_DB"

    ]


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

    return session.get(

        "admin_id"

    )