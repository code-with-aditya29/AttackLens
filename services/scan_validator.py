import ipaddress
import re


# ==========================================
# VALIDATE SCAN TARGET
# ==========================================

def validate_target(target):

    # ======================================
    # EMPTY TARGET CHECK
    # ======================================

    if not target:

        return (
            False,
            "Target is required."
        )

    # ======================================
    # REMOVE EXTRA SPACES
    # ======================================

    target = target.strip()

    # ======================================
    # IP ADDRESS VALIDATION
    # ======================================

    try:

        ipaddress.ip_address(
            target
        )

        return (
            True,
            "Valid IP address."
        )

    except ValueError:

        pass

    # ======================================
    # HOSTNAME VALIDATION
    # ======================================

    hostname_pattern = (
        r"^(?=.{1,253}$)"
        r"(?:(?!-)[A-Za-z0-9-]{1,63}"
        r"(?<!-)\.)*"
        r"(?!-)[A-Za-z0-9-]{1,63}"
        r"(?<!-)$"
    )

    if re.match(
        hostname_pattern,
        target
    ):

        return (
            True,
            "Valid hostname."
        )

    # ======================================
    # INVALID TARGET
    # ======================================

    return (
        False,
        "Please enter a valid IP address or hostname."
    )