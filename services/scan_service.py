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

        "risk_score": None,


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

    if not ObjectId.is_valid(scan_id):

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

    if not ObjectId.is_valid(scan_id):

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

    if not ObjectId.is_valid(scan_id):

        return False


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

                "vulnerabilities": results.get(
                    "vulnerabilities",
                    []
                ),

                "risk_score": results.get(
                    "risk_score"
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
# FAIL SCAN
# ==========================================

def fail_scan(
    db,
    scan_id,
    error_message="Scan failed."
):

    if not ObjectId.is_valid(scan_id):

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

    if not ObjectId.is_valid(scan_id):

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
# DELETE SINGLE SCAN
# ==========================================

def delete_scan(
    db,
    scan_id,
    created_by=None
):

    if not ObjectId.is_valid(scan_id):

        return False


    query = {

        "_id": ObjectId(
            scan_id
        )

    }


    # ======================================
    # USER OWNERSHIP FILTER
    # ======================================

    if created_by is not None:

        query["created_by"] = created_by


    result = db.scans.delete_one(
        query
    )


    return result.deleted_count == 1


# ==========================================
# BULK DELETE SCANS
# ==========================================

def bulk_delete_scans(
    db,
    scan_ids,
    created_by=None
):

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


    query = {

        "_id": {

            "$in": valid_ids

        }

    }


    # ======================================
    # USER OWNERSHIP FILTER
    # ======================================

    if created_by is not None:

        query["created_by"] = created_by


    result = db.scans.delete_many(
        query
    )


    return result.deleted_count