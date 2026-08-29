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

    fail_scan,

    get_scan_by_id,

    get_scan_history,

    delete_scan,

    bulk_delete_scans

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

        try:

            results = run_nmap_scan(

                target=target,

                scan_profile=scan_profile

            )


        except Exception as error:

            error_message = (
                f"Unexpected scan error: {error}"
            )


            fail_scan(

                db,

                scan_id,

                error_message

            )


            flash(

                error_message,

                "error"

            )


            return redirect(

                url_for(

                    "scan.scan_results",

                    scan_id=scan_id

                )

            )


        # ==================================
        # HANDLE SCAN FAILURE
        # ==================================

        if not results.get(
            "success"
        ):

            error_message = results.get(

                "message",

                "Scan failed."

            )


            fail_scan(

                db,

                scan_id,

                error_message

            )


            flash(

                error_message,

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


    # ======================================
    # GET SCAN WITH OWNERSHIP PROTECTION
    # ======================================

    scan = get_scan_by_id(

        db=db,

        scan_id=scan_id,

        created_by=get_scan_owner_filter()

    )


    if not scan:

        flash(

            "Scan not found or you do not "
            "have permission to view it.",

            "error"

        )


        return redirect(

            url_for(
                "scan.scan_history"
            )

        )


    return render_template(

        "scan_results.html",

        scan=scan,

        current_page="scan"

    )


# ==========================================
# SCAN HISTORY PAGE
# ==========================================

@scan_bp.route(
    "/scan/history"
)

@login_required

def scan_history():

    db = current_app.config[
        "MONGO_DB"
    ]


    # ======================================
    # LOAD SCAN HISTORY
    # ======================================

    scans = get_scan_history(

        db=db,

        created_by=get_scan_owner_filter(),

        limit=100

    )


    return render_template(

        "scan_history.html",

        scans=scans,

        current_page="scan_history"

    )


# ==========================================
# DELETE SINGLE SCAN
# ==========================================

@scan_bp.route(

    "/scan/delete/<scan_id>",

    methods=[
        "POST"
    ]

)

@login_required

def delete_scan_record(
    scan_id
):

    db = current_app.config[
        "MONGO_DB"
    ]


    deleted = delete_scan(

        db=db,

        scan_id=scan_id,

        created_by=get_scan_owner_filter()

    )


    if deleted:

        flash(

            "Scan deleted successfully.",

            "success"

        )

    else:

        flash(

            "Scan could not be deleted or "
            "you do not have permission.",

            "error"

        )


    return redirect(

        url_for(
            "scan.scan_history"
        )

    )


# ==========================================
# BULK DELETE SCANS
# ==========================================

@scan_bp.route(

    "/scan/delete-selected",

    methods=[
        "POST"
    ]

)

@login_required

def delete_selected_scans():

    # ======================================
    # GET SELECTED SCAN IDS
    # ======================================

    scan_ids = request.form.getlist(
        "scan_ids"
    )


    if not scan_ids:

        flash(

            "Please select at least one scan "
            "to delete.",

            "error"

        )


        return redirect(

            url_for(
                "scan.scan_history"
            )

        )


    db = current_app.config[
        "MONGO_DB"
    ]


    # ======================================
    # DELETE SELECTED SCANS
    # ======================================

    deleted_count = bulk_delete_scans(

        db=db,

        scan_ids=scan_ids,

        created_by=get_scan_owner_filter()

    )


    if deleted_count > 0:

        flash(

            f"{deleted_count} scan(s) deleted "
            "successfully.",

            "success"

        )

    else:

        flash(

            "No scans were deleted.",

            "error"

        )


    return redirect(

        url_for(
            "scan.scan_history"
        )

    )


# ==========================================
# GET CURRENT USER ID
# ==========================================

def session_user_id():

    return session.get(
        "admin_id"
    )


# ==========================================
# GET SCAN OWNER FILTER
# ==========================================

def get_scan_owner_filter():

    # ======================================
    # SUPER ADMIN
    # ======================================
    #
    # Super Admin is allowed to view and
    # manage all scan records.
    # ======================================

    if session.get(
        "role"
    ) == "super_admin":

        return None


    # ======================================
    # NORMAL ADMIN
    # ======================================
    #
    # Normal administrators can only view
    # or delete scans created by themselves.
    # ======================================

    return session_user_id()