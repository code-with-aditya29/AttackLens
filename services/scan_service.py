from datetime import datetime


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

        "ports": [],

        "services": [],

        "os_detection": None,

        "vulnerabilities": [],

        "risk_score": None

    }

    result = db.scans.insert_one(
        scan_data
    )

    scan_data["_id"] = result.inserted_id

    return scan_data


# ==========================================
# UPDATE SCAN STATUS
# ==========================================

def update_scan_status(
    db,
    scan_id,
    status
):

    from bson import ObjectId

    db.scans.update_one(

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


# ==========================================
# SAVE SCAN RESULTS
# ==========================================

def save_scan_results(
    db,
    scan_id,
    results
):

    from bson import ObjectId

    db.scans.update_one(

        {
            "_id": ObjectId(
                scan_id
            )
        },

        {
            "$set": {

                "ports": results.get(
                    "ports",
                    []
                ),

                "services": results.get(
                    "services",
                    []
                ),

                "os_detection": results.get(
                    "os_detection"
                ),

                "status": "completed",

                "completed_at": datetime.utcnow()

            }
        }

    )
    