from datetime import datetime

from bson import ObjectId


# ==========================================
# CREATE NEW SCAN
# ==========================================

def create_scan(
    db,
    target,
    scan_profile,
    created_by
):

    scan_data = {

        # ==================================
        # BASIC INFORMATION
        # ==================================

        "target": target,

        "scan_profile": scan_profile,

        "status": "pending",

        "created_by": created_by,


        # ==================================
        # TIMESTAMPS
        # ==================================

        "created_at": datetime.utcnow(),

        "started_at": None,

        "completed_at": None,


        # ==================================
        # HOST INFORMATION
        # ==================================

        "hostname": None,

        "host_status": "unknown",

        "mac_address": None,


        # ==================================
        # NETWORK INFORMATION
        # ==================================

        "ports": [],

        "services": [],


        # ==================================
        # OS INFORMATION
        # ==================================

        "os_detection": None,

        "os_accuracy": None,


        # ==================================
        # SECURITY INFORMATION
        # ==================================

        "vulnerabilities": [],

        "vulnerability_count": 0,

        "highest_severity": None,

        "risk_score": None,

        "risk_level": None,

        "risk_breakdown": None,


        # ==================================
        # ERROR INFORMATION
        # ==================================

        "error_message": None

    }


    # ======================================
    # INSERT INTO DATABASE
    # ======================================

    result = db.scans.insert_one(
        scan_data
    )


    scan_data["_id"] = result.inserted_id


    return scan_data


# ==========================================
# START SCAN
# ==========================================

def start_scan(
    db,
    scan_id
):

    if not ObjectId.is_valid(
        scan_id
    ):

        return False


    result = db.scans.update_one(

        {
            "_id": ObjectId(
                scan_id
            )
        },

        {
            "$set": {

                "status": "running",

                "started_at": datetime.utcnow(),

                "error_message": None

            }
        }

    )


    return result.modified_count > 0


# ==========================================
# UPDATE SCAN STATUS
# ==========================================

def update_scan_status(
    db,
    scan_id,
    status
):

    if not ObjectId.is_valid(
        scan_id
    ):

        return False


    result = db.scans.update_one(

        {
            "_id": ObjectId(
                scan_id
            )
        },

        {
            "$set": {

                "status": status

            }
        }

    )


    return result.modified_count > 0


# ==========================================
# SAVE SCAN RESULTS
# ==========================================

def save_scan_results(
    db,
    scan_id,
    results
):

    if not ObjectId.is_valid(
        scan_id
    ):

        return False


    # ======================================
    # GET VULNERABILITY RESULTS
    # ======================================

    vulnerabilities = results.get(
        "vulnerabilities",
        []
    )


    # Ensure vulnerabilities always remain
    # a list before they are stored.

    if not isinstance(
        vulnerabilities,
        list
    ):

        vulnerabilities = []


    # ======================================
    # VULNERABILITY COUNT
    # ======================================

    vulnerability_count = len(
        vulnerabilities
    )


    # ======================================
    # HIGHEST SEVERITY
    # ======================================

    highest_severity = (
        get_highest_severity(
            vulnerabilities
        )
    )


    # ======================================
    # UPDATE SCAN DOCUMENT
    # ======================================

    result = db.scans.update_one(

        {
            "_id": ObjectId(
                scan_id
            )
        },

        {
            "$set": {

                # ==========================
                # HOST INFORMATION
                # ==========================

                "hostname": results.get(
                    "hostname"
                ),

                "host_status": results.get(
                    "host_status",
                    "unknown"
                ),

                "mac_address": results.get(
                    "mac_address"
                ),


                # ==========================
                # NETWORK INFORMATION
                # ==========================

                "ports": results.get(
                    "ports",
                    []
                ),

                "services": results.get(
                    "services",
                    []
                ),


                # ==========================
                # OS INFORMATION
                # ==========================

                "os_detection": results.get(
                    "os_detection"
                ),

                "os_accuracy": results.get(
                    "os_accuracy"
                ),


                # ==========================
                # SECURITY INFORMATION
                # ==========================

                "vulnerabilities": (
                    vulnerabilities
                ),

                "vulnerability_count": (
                    vulnerability_count
                ),

                "highest_severity": (
                    highest_severity
                ),

                "risk_score": results.get(
                    "risk_score"
                ),

                "risk_level": results.get(
                    "risk_level"
                ),

                "risk_breakdown": results.get(
                    "risk_breakdown"
                ),


                # ==========================
                # SCAN STATUS
                # ==========================

                "status": "completed",

                "completed_at": datetime.utcnow(),

                "error_message": None

            }
        }

    )


    return result.modified_count > 0


# ==========================================
# GET HIGHEST VULNERABILITY SEVERITY
# ==========================================

def get_highest_severity(
    vulnerabilities
):

    """
    Determine the highest vulnerability
    severity found during CVE correlation.

    Severity priority:

        CRITICAL
        HIGH
        MEDIUM
        LOW
        NONE
        UNKNOWN

    Returns None when no vulnerabilities
    were identified.
    """

    if not vulnerabilities:

        return None


    severity_priority = {

        "UNKNOWN": 0,

        "NONE": 1,

        "LOW": 2,

        "MEDIUM": 3,

        "HIGH": 4,

        "CRITICAL": 5

    }


    highest_severity = None

    highest_priority = -1


    for vulnerability in vulnerabilities:

        if not isinstance(
            vulnerability,
            dict
        ):

            continue


        severity = vulnerability.get(
            "severity",
            "UNKNOWN"
        )


        if severity:

            severity = (
                str(severity)
                .strip()
                .upper()
            )

        else:

            severity = "UNKNOWN"


        priority = severity_priority.get(
            severity,
            0
        )


        if priority > highest_priority:

            highest_priority = priority

            highest_severity = severity


    return highest_severity


# ==========================================
# FAIL SCAN
# ==========================================

def fail_scan(
    db,
    scan_id,
    error_message="Scan failed."
):

    if not ObjectId.is_valid(
        scan_id
    ):

        return False


    result = db.scans.update_one(

        {
            "_id": ObjectId(
                scan_id
            )
        },

        {
            "$set": {

                "status": "failed",

                "completed_at": datetime.utcnow(),

                "error_message": error_message

            }
        }

    )


    return result.modified_count > 0


# ==========================================
# GET SINGLE SCAN
# ==========================================

def get_scan_by_id(
    db,
    scan_id,
    created_by=None
):

    if not ObjectId.is_valid(
        scan_id
    ):

        return None


    query = {

        "_id": ObjectId(
            scan_id
        )

    }


    # ======================================
    # USER OWNERSHIP FILTER
    # ======================================
    #
    # If created_by is provided, the scan
    # must belong to that user.
    #
    # Super Admin can call this function
    # without created_by to access all scans.
    # ======================================

    if created_by is not None:

        query["created_by"] = created_by


    return db.scans.find_one(
        query
    )


# ==========================================
# GET SCAN HISTORY
# ==========================================

def get_scan_history(
    db,
    created_by=None,
    limit=100
):

    query = {}


    # ======================================
    # USER OWNERSHIP FILTER
    # ======================================

    if created_by is not None:

        query["created_by"] = created_by


    scans = db.scans.find(

        query

    ).sort(

        "created_at",
        -1

    ).limit(

        limit

    )


    return list(
        scans
    )


# ==========================================
# RECONCILE ASSET AFTER SCAN DELETION
# ==========================================

def _reconcile_asset_after_scan_deletion(
    db,
    target,
    created_by
):

    """
    Reconcile the Asset Inventory after one
    or more scan records have been deleted.

    Asset identity:

        created_by + target

    Rules:

    1. If completed scans still exist for the
       same owner and target, rebuild the
       current Asset from the newest remaining
       completed scan.

    2. first_seen is recalculated from the
       earliest remaining completed scan.

    3. last_seen and latest_scan_id are taken
       from the newest remaining scan.

    4. Manual Asset Context fields such as
       criticality and exposure are preserved.

    5. If no completed scan remains for the
       owner and target, delete the Asset.

    Downstream modules that use the Asset
    Inventory will therefore stop displaying
    stale information from deleted scans.
    """

    # ======================================
    # LOCAL IMPORTS
    # ======================================
    #
    # These are kept local because this
    # function is deletion-specific and it
    # avoids unnecessary service-level
    # dependencies during module loading.
    # ======================================

    from services.asset_service import (
        build_asset_update_from_scan,
        get_scan_timestamp
    )

    from models.asset_model import (
        create_asset_document
    )


    # ======================================
    # NORMALIZE IDENTITY
    # ======================================

    target = str(
        target or ""
    ).strip()


    if not target or not created_by:

        return False


    # ======================================
    # FIND REMAINING COMPLETED SCANS
    # ======================================

    remaining_scans = list(

        db.scans.find(

            {
                "target": target,
                "created_by": created_by,
                "status": "completed"
            }

        )

    )


    # ======================================
    # NO COMPLETED SCANS REMAIN
    # ======================================
    #
    # No scan now supports this Asset.
    #
    # Remove the Asset completely so that
    # Dashboard and all downstream analysis
    # stop using stale information.
    # ======================================

    if not remaining_scans:

        db.assets.delete_one(

            {
                "target": target,
                "created_by": created_by
            }

        )


        return True


    # ======================================
    # SORT REMAINING SCANS
    # ======================================

    remaining_scans = sorted(

        remaining_scans,

        key=get_scan_timestamp

    )


    earliest_scan = (
        remaining_scans[
            0
        ]
    )


    latest_scan = (
        remaining_scans[
            -1
        ]
    )


    earliest_time = get_scan_timestamp(
        earliest_scan
    )


    latest_time = get_scan_timestamp(
        latest_scan
    )


    # ======================================
    # BUILD CURRENT ASSET SNAPSHOT
    # ======================================

    asset_update = (
        build_asset_update_from_scan(
            latest_scan
        )
    )


    if not asset_update:

        return False


    # ======================================
    # FORCE CORRECT DISCOVERY RANGE
    # ======================================

    asset_update[
        "first_seen"
    ] = earliest_time


    asset_update[
        "last_seen"
    ] = latest_time


    # ======================================
    # UPDATE EXISTING ASSET
    # ======================================
    #
    # build_asset_update_from_scan() contains
    # scan-controlled fields only.
    #
    # criticality and exposure are therefore
    # intentionally preserved.
    # ======================================

    result = db.assets.update_one(

        {
            "target": target,
            "created_by": created_by
        },

        {
            "$set": asset_update
        }

    )


    # ======================================
    # RECREATE MISSING ASSET
    # ======================================
    #
    # Normally an Asset already exists here.
    #
    # This fallback repairs an inconsistent
    # database where completed scans exist
    # but the corresponding Asset document
    # is missing.
    # ======================================

    if result.matched_count == 0:

        asset = create_asset_document(

            target=target,

            created_by=created_by

        )


        asset.update(
            asset_update
        )


        asset[
            "first_seen"
        ] = earliest_time


        asset[
            "last_seen"
        ] = latest_time


        db.assets.insert_one(
            asset
        )


    return True


# ==========================================
# DELETE SINGLE SCAN
# ==========================================

def delete_scan(
    db,
    scan_id,
    created_by=None
):

    """
    Delete one scan and synchronize the
    Asset Inventory for the affected target.

    Ownership protection is applied before
    any deletion occurs.
    """

    # ======================================
    # VALIDATE SCAN ID
    # ======================================

    if not ObjectId.is_valid(
        scan_id
    ):

        return False


    # ======================================
    # BUILD DELETE QUERY
    # ======================================

    query = {

        "_id": ObjectId(
            scan_id
        )

    }


    # ======================================
    # USER OWNERSHIP FILTER
    # ======================================

    if created_by is not None:

        query[
            "created_by"
        ] = created_by


    # ======================================
    # LOAD SCAN BEFORE DELETION
    # ======================================
    #
    # target and created_by are required
    # afterwards to determine which Asset
    # must be rebuilt or removed.
    # ======================================

    scan = db.scans.find_one(
        query
    )


    if not scan:

        return False


    target = str(

        scan.get(
            "target",
            ""
        )

    ).strip()


    scan_owner = scan.get(
        "created_by"
    )


    # ======================================
    # DELETE SCAN
    # ======================================

    result = db.scans.delete_one(
        query
    )


    if result.deleted_count != 1:

        return False


    # ======================================
    # RECONCILE RELATED ASSET
    # ======================================

    if target and scan_owner:

        _reconcile_asset_after_scan_deletion(

            db=db,

            target=target,

            created_by=scan_owner

        )


    return True


# ==========================================
# BULK DELETE SCANS
# ==========================================

def bulk_delete_scans(
    db,
    scan_ids,
    created_by=None
):

    """
    Delete multiple scan records and then
    reconcile every affected Asset.

    Multiple deleted scans belonging to the
    same owner + target are reconciled only
    once.
    """

    valid_ids = []


    # ======================================
    # VALIDATE IDS
    # ======================================

    for scan_id in scan_ids:

        if ObjectId.is_valid(
            scan_id
        ):

            valid_ids.append(

                ObjectId(
                    scan_id
                )

            )


    if not valid_ids:

        return 0


    # ======================================
    # BUILD OWNERSHIP-PROTECTED QUERY
    # ======================================

    query = {

        "_id": {

            "$in": valid_ids

        }

    }


    if created_by is not None:

        query[
            "created_by"
        ] = created_by


    # ======================================
    # LOAD SCANS BEFORE DELETION
    # ======================================
    #
    # Once the documents are deleted we can
    # no longer obtain their target/owner
    # relationships.
    # ======================================

    scans_to_delete = list(

        db.scans.find(
            query
        )

    )


    if not scans_to_delete:

        return 0


    # ======================================
    # COLLECT AFFECTED ASSETS
    # ======================================
    #
    # Dictionary key:
    #
    #     str(created_by), target
    #
    # Dictionary value:
    #
    #     original created_by value
    #
    # This avoids reconciling the same Asset
    # repeatedly when several of its scans
    # are selected together.
    # ======================================

    affected_assets = {}


    for scan in scans_to_delete:

        target = str(

            scan.get(
                "target",
                ""
            )

        ).strip()


        scan_owner = scan.get(
            "created_by"
        )


        if not target or not scan_owner:

            continue


        key = (

            str(
                scan_owner
            ),

            target

        )


        affected_assets[
            key
        ] = scan_owner


    # ======================================
    # DELETE SELECTED SCANS
    # ======================================

    result = db.scans.delete_many(
        query
    )


    # ======================================
    # RECONCILE AFFECTED ASSETS
    # ======================================

    if result.deleted_count > 0:

        for (
            owner_string,
            target
        ), scan_owner in affected_assets.items():

            _reconcile_asset_after_scan_deletion(

                db=db,

                target=target,

                created_by=scan_owner

            )


    return result.deleted_count