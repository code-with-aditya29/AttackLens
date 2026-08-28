# ==========================================
# SCAN MODEL
# ==========================================

from datetime import datetime


# ==========================================
# CREATE SCAN DOCUMENT
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
        # OPERATING SYSTEM INFORMATION
        # ==================================

        "os_detection": None,

        "os_accuracy": None,


        # ==================================
        # FUTURE PHASE DATA
        # ==================================

        "vulnerabilities": [],

        "risk_score": None

    }