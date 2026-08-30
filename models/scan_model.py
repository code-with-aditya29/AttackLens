# ==========================================
# SCAN MODEL
# ==========================================

def create_scan_document(
    target,
    scan_profile,
    created_by
):

    return {

        # ==================================
        # BASIC SCAN INFORMATION
        # ==================================

        "target": target,

        "scan_profile": scan_profile,

        "status": "pending",

        "created_by": created_by,


        # ==================================
        # TIMESTAMP INFORMATION
        # ==================================

        "created_at": None,

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
        # OPERATING SYSTEM INFORMATION
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