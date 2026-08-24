# ==========================================
# SCAN MODEL
# ==========================================

def create_scan_document(
    target,
    scan_profile,
    created_by
):

    return {

        "target": target,

        "scan_profile": scan_profile,

        "status": "pending",

        "created_by": created_by,

        "ports": [],

        "services": [],

        "os_detection": None,

        "vulnerabilities": [],

        "risk_score": None

    }
