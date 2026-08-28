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

        "target": target,

        "scan_profile": scan_profile,

        "status": "pending",

        "created_by": created_by,

        "created_at": datetime.utcnow(),

        "started_at": None,

        "completed_at": None,

        # ==================================
        # HOST INFORMATION
        # ==================================

        "hostname": None,

        "host_status": None,

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
        # FUTURE VULNERABILITY DATA
        # ==================================

        "vulnerabilities": [],

        "risk_score": None,

        "error_message": None

    }


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

    db.scans.update_one(

        {
            "_id": ObjectId(
                scan_id
            )
        },

        {
            "$set": {

                "status": "running",

                "started_at": datetime.utcnow()

            }

        }

    )


# ==========================================
# SAVE SCAN RESULTS
# ==========================================

def save_scan_results(
    db,
    scan_id,
    results
):

    db.scans.update_one(

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
                # SCAN STATUS
                # ==========================

                "status": "completed",

                "completed_at": datetime.utcnow(),

                "error_message": None

            }

        }

    )


# ==========================================
# FAIL SCAN
# ==========================================

def fail_scan(
    db,
    scan_id,
    error_message=None
):

    db.scans.update_one(

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