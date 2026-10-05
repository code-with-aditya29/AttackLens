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

    Security information is intentionally
    separated into:

        vulnerabilities
            Existing CVE-based findings.

        security_findings
            Additional observable application,
            network/service, host/OS and web
            security findings.

    This preserves compatibility with the
    existing AttackLens CVE pipeline while
    allowing the broader security-analysis
    architecture to evolve independently.
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
        # CVE VULNERABILITY INFORMATION
        # ==================================
        #
        # Existing field retained for full
        # backward compatibility.
        # ==================================

        "vulnerabilities": [],

        "vulnerability_count": 0,


        # ==================================
        # ADDITIONAL SECURITY FINDINGS
        # ==================================
        #
        # These findings complement CVEs.
        #
        # Examples:
        #
        # - Network/service exposure
        # - Application/software conditions
        # - Host/OS security observations
        # - Web application surfaces
        #
        # Active web vulnerability checks
        # such as bounded SQLi/XSS/CSRF/IDOR
        # can later use the same structure.
        # ==================================

        "security_findings": [],

        "security_finding_count": 0,


        # ==================================
        # RISK INFORMATION
        # ==================================

        "highest_severity": None,

        "risk_score": None,

        "risk_level": None,

        "risk_breakdown": None,


        # ==================================
        # ASSET CONTEXT
        # ==================================
        #
        # These fields are user-controlled
        # context and must not be overwritten
        # by scan synchronization.
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