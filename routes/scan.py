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


from services.vulnerability_service import (
    analyze_services_for_vulnerabilities
)


from services.risk_service import (
    calculate_risk_score
)


from services.asset_service import (
    upsert_asset_from_scan
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
        # VULNERABILITY ANALYSIS
        # ==================================

        try:

            services = results.get(
                "services",
                []
            )


            os_detection = results.get(
                "os_detection"
            )


            vulnerabilities = (
                analyze_services_for_vulnerabilities(
                    services=services,
                    results_per_service=10,
                    os_detection=os_detection
                )
            )


            results[
                "vulnerabilities"
            ] = vulnerabilities


            current_app.logger.info(
                "Vulnerability analysis completed. "
                "%s applicable potential "
                "finding(s) identified.",
                len(vulnerabilities)
            )


        except Exception as error:

            # ==================================
            # CVE analysis failure must NOT
            # cause successful Nmap scan to fail.
            # ==================================

            current_app.logger.warning(
                "Vulnerability analysis failed: %s",
                error
            )


            results[
                "vulnerabilities"
            ] = []


        # ==================================
        # RISK ANALYSIS
        # ==================================

        try:

            risk_result = calculate_risk_score(
                vulnerabilities=results.get(
                    "vulnerabilities",
                    []
                ),
                ports=results.get(
                    "ports",
                    []
                )
            )


            results[
                "risk_score"
            ] = risk_result.get(
                "risk_score"
            )


            results[
                "risk_level"
            ] = risk_result.get(
                "risk_level"
            )


            results[
                "risk_breakdown"
            ] = risk_result.get(
                "risk_breakdown"
            )


            current_app.logger.info(
                "Risk analysis completed. "
                "Score: %s | Level: %s",
                results.get(
                    "risk_score"
                ),
                results.get(
                    "risk_level"
                )
            )


        except Exception as error:

            # ==================================
            # Risk analysis failure must NOT
            # cause successful Nmap scan to fail.
            # ==================================

            current_app.logger.warning(
                "Risk analysis failed: %s",
                error
            )


            results[
                "risk_score"
            ] = None


            results[
                "risk_level"
            ] = None


            results[
                "risk_breakdown"
            ] = None


        # ==================================
        # SAVE SCAN RESULTS
        # ==================================

        save_scan_results(
            db,
            scan_id,
            results
        )


        # ==================================
        # UPDATE ASSET INVENTORY
        # ==================================
        #
        # The completed scan is now used to
        # create or update the current Asset.
        #
        # Asset synchronization failure must
        # NOT cause a successful scan to fail.
        # ==================================

        try:

            completed_scan = get_scan_by_id(

                db=db,

                scan_id=scan_id,

                created_by=session_user_id()

            )


            if completed_scan:

                upsert_asset_from_scan(

                    db=db,

                    scan=completed_scan

                )


                current_app.logger.info(

                    "Asset inventory updated "
                    "for target: %s",

                    target

                )


        except Exception as error:

            current_app.logger.warning(

                "Asset inventory update failed: %s",

                error

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
# RESCAN TARGET
# ==========================================

@scan_bp.route(
    "/scan/rescan/<scan_id>",
    methods=[
        "POST"
    ]
)
@login_required
def rescan_target(
    scan_id
):

    db = current_app.config[
        "MONGO_DB"
    ]


    # ======================================
    # GET ORIGINAL SCAN
    # ======================================

    original_scan = get_scan_by_id(
        db=db,
        scan_id=scan_id,
        created_by=get_scan_owner_filter()
    )


    if not original_scan:

        flash(
            "Scan not found or you do not "
            "have permission to rescan it.",
            "error"
        )


        return redirect(
            url_for(
                "scan.scan_history"
            )
        )


    # ======================================
    # GET ORIGINAL TARGET INFORMATION
    # ======================================

    target = (
        original_scan.get(
            "target",
            ""
        )
        or ""
    ).strip()


    scan_profile = (
        original_scan.get(
            "scan_profile",
            "standard"
        )
        or "standard"
    ).strip().lower()


    # ======================================
    # VALIDATE TARGET
    # ======================================

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
                "scan.scan_results",
                scan_id=scan_id
            )
        )


    # ======================================
    # VALIDATE SCAN PROFILE
    # ======================================

    allowed_profiles = [
        "quick",
        "standard",
        "detailed"
    ]


    if scan_profile not in allowed_profiles:

        flash(
            "The original scan contains an "
            "invalid scan profile.",
            "error"
        )


        return redirect(
            url_for(
                "scan.scan_results",
                scan_id=scan_id
            )
        )


    # ======================================
    # CHECK NMAP INSTALLATION
    # ======================================

    if not check_nmap_installed():

        flash(
            "Nmap is not installed or cannot "
            "be found in the system PATH.",
            "error"
        )


        return redirect(
            url_for(
                "scan.scan_results",
                scan_id=scan_id
            )
        )


    # ======================================
    # CREATE NEW SCAN RECORD
    # ======================================
    #
    # IMPORTANT:
    # The original scan is NOT overwritten.
    # A new database record is created.
    # ======================================

    new_scan = create_scan(
        db=db,
        target=target,
        scan_profile=scan_profile,
        created_by=session_user_id()
    )


    new_scan_id = str(
        new_scan["_id"]
    )


    # ======================================
    # MARK NEW SCAN AS RUNNING
    # ======================================

    start_scan(
        db,
        new_scan_id
    )


    # ======================================
    # RUN NMAP SCAN
    # ======================================

    try:

        results = run_nmap_scan(
            target=target,
            scan_profile=scan_profile
        )


    except Exception as error:

        error_message = (
            f"Unexpected rescan error: {error}"
        )


        fail_scan(
            db,
            new_scan_id,
            error_message
        )


        flash(
            error_message,
            "error"
        )


        return redirect(
            url_for(
                "scan.scan_results",
                scan_id=new_scan_id
            )
        )


    # ======================================
    # HANDLE RESCAN FAILURE
    # ======================================

    if not results.get(
        "success"
    ):

        error_message = results.get(
            "message",
            "Rescan failed."
        )


        fail_scan(
            db,
            new_scan_id,
            error_message
        )


        flash(
            error_message,
            "error"
        )


        return redirect(
            url_for(
                "scan.scan_results",
                scan_id=new_scan_id
            )
        )


    # ======================================
    # VULNERABILITY ANALYSIS
    # ======================================

    try:

        services = results.get(
            "services",
            []
        )


        os_detection = results.get(
            "os_detection"
        )


        vulnerabilities = (
            analyze_services_for_vulnerabilities(
                services=services,
                results_per_service=10,
                os_detection=os_detection
            )
        )


        results[
            "vulnerabilities"
        ] = vulnerabilities


        current_app.logger.info(
            "Rescan vulnerability analysis "
            "completed. %s applicable potential "
            "finding(s) identified.",
            len(vulnerabilities)
        )


    except Exception as error:

        current_app.logger.warning(
            "Rescan vulnerability analysis "
            "failed: %s",
            error
        )


        results[
            "vulnerabilities"
        ] = []


    # ======================================
    # RISK ANALYSIS
    # ======================================

    try:

        risk_result = calculate_risk_score(
            vulnerabilities=results.get(
                "vulnerabilities",
                []
            ),
            ports=results.get(
                "ports",
                []
            )
        )


        results[
            "risk_score"
        ] = risk_result.get(
            "risk_score"
        )


        results[
            "risk_level"
        ] = risk_result.get(
            "risk_level"
        )


        results[
            "risk_breakdown"
        ] = risk_result.get(
            "risk_breakdown"
        )


        current_app.logger.info(
            "Rescan risk analysis completed. "
            "Score: %s | Level: %s",
            results.get(
                "risk_score"
            ),
            results.get(
                "risk_level"
            )
        )


    except Exception as error:

        current_app.logger.warning(
            "Rescan risk analysis failed: %s",
            error
        )


        results[
            "risk_score"
        ] = None


        results[
            "risk_level"
        ] = None


        results[
            "risk_breakdown"
        ] = None


    # ======================================
    # SAVE NEW SCAN RESULTS
    # ======================================

    save_scan_results(
        db,
        new_scan_id,
        results
    )


    # ======================================
    # UPDATE ASSET INVENTORY
    # ======================================
    #
    # The newly completed rescan becomes the
    # current Asset state when it is newer
    # than the existing Asset snapshot.
    #
    # Asset synchronization failure must
    # NOT cause a successful rescan to fail.
    # ======================================

    try:

        completed_scan = get_scan_by_id(

            db=db,

            scan_id=new_scan_id,

            created_by=session_user_id()

        )


        if completed_scan:

            upsert_asset_from_scan(

                db=db,

                scan=completed_scan

            )


            current_app.logger.info(

                "Asset inventory updated "
                "after rescan for target: %s",

                target

            )


    except Exception as error:

        current_app.logger.warning(

            "Asset inventory update after "
            "rescan failed: %s",

            error

        )


    flash(
        "Rescan completed successfully.",
        "success"
    )


    return redirect(
        url_for(
            "scan.scan_results",
            scan_id=new_scan_id
        )
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