# ==========================================
# ATTACKLENS
# ASSET MODEL
# ==========================================

from datetime import datetime, timezone


# ==========================================
# CREATE ASSET DOCUMENT
# ==========================================

def create_asset_document(
    target,
    created_by
):
    """
    Create the default MongoDB document
    structure for an AttackLens asset.

    An asset represents the current known
    security state of a discovered target.

    A scan is historical.
    An asset is the latest representation
    of the target.
    """

    current_time = datetime.now(
        timezone.utc
    )

    return {

        # ==================================
        # BASIC ASSET INFORMATION
        # ==================================

        "target": target,

        "hostname": None,

        "host_status": "unknown",

        "mac_address": None,

        "created_by": created_by,


        # ==================================
        # OPERATING SYSTEM
        # ==================================

        "operating_system": None,

        "os_accuracy": None,


        # ==================================
        # NETWORK INFORMATION
        # ==================================

        "ports": [],

        "open_port_count": 0,

        "services": [],

        "service_count": 0,


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
        # ASSET CONTEXT
        # ==================================
        #
        # These fields will become important
        # when we build the Attack Path Engine.
        #
        # criticality:
        # LOW / NORMAL / HIGH / CRITICAL
        #
        # exposure:
        # INTERNAL / EXTERNAL / UNKNOWN
        # ==================================

        "criticality": "NORMAL",

        "exposure": "UNKNOWN",


        # ==================================
        # SOURCE INFORMATION
        # ==================================

        "latest_scan_id": None,

        "latest_scan_profile": None,


        # ==================================
        # TIMESTAMPS
        # ==================================

        "first_seen": current_time,

        "last_seen": current_time,

        "created_at": current_time,

        "updated_at": current_time
    }