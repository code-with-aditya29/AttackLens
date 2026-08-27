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


from routes.auth import login_required


from services.scan_validator import (

    validate_target

)


from services.scan_service import (

    create_scan,

    update_scan_status,

    save_scan_results,

    mark_scan_failed

)


from services.nmap_service import (

    run_nmap_scan,

    check_nmap_installed

)


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
    # HANDLE SCAN FORM
    # ======================================

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
        # CHECK NMAP INSTALLATION
        # ==================================

        if not check_nmap_installed():

            flash(

                "Nmap is not installed or not available in the system PATH.",

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

            created_by=session.get(

                "admin_id"

            )

        )


        scan_id = str(

            scan["_id"]

        )


        try:

            # ==============================
            # UPDATE STATUS
            # ==============================

            update_scan_status(

                db=db,

                scan_id=scan_id,

                status="running"

            )


            # ==============================
            # RUN NMAP
            # ==============================

            results = run_nmap_scan(

                target=target,

                scan_profile=scan_profile

            )


            # ==============================
            # SAVE RESULTS
            # ==============================

            save_scan_results(

                db=db,

                scan_id=scan_id,

                results=results

            )


            flash(

                "Security scan completed successfully.",

                "success"

            )


        except Exception as error:

            # ==============================
            # HANDLE SCAN FAILURE
            # ==============================

            mark_scan_failed(

                db=db,

                scan_id=scan_id,

                error_message=str(

                    error

                )

            )


            flash(

                f"Scan failed: {str(error)}",

                "error"

            )


        # ==================================
        # REDIRECT TO RESULTS
        # ==================================

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


    # ======================================
    # VALIDATE OBJECT ID
    # ======================================

    try:

        scan_object_id = ObjectId(

            scan_id

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


    # ======================================
    # GET SCAN
    # ======================================

    scan = db.scans.find_one(

        {

            "_id": scan_object_id

        }

    )


    # ======================================
    # SCAN NOT FOUND
    # ======================================

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


    # ======================================
    # LOAD RESULTS PAGE
    # ======================================

    return render_template(

        "scan_results.html",

        scan=scan,

        current_page="scan"

    )