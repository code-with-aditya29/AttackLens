
import ipaddress
import re


# ==========================================
# HOSTNAME VALIDATION PATTERN
# ==========================================
#
# Validates standard DNS hostname syntax:
#
# - Maximum hostname length: 253 characters
# - Maximum label length: 63 characters
# - Labels may contain letters, numbers and hyphens
# - Labels cannot start or end with a hyphen
#
# This checks hostname syntax only.
# It does not resolve DNS or verify scan authorization.
# ==========================================

HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)*"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)$"
)


# ==========================================
# VALIDATE SCAN TARGET
# ==========================================

def validate_target(target):

    # ======================================
    # INPUT TYPE VALIDATION
    # ======================================

    if not isinstance(target, str):

        return (
            False,
            "Target must be a valid IP address or hostname."
        )

    # ======================================
    # REMOVE SURROUNDING SPACES
    # ======================================

    target = target.strip()

    # ======================================
    # EMPTY TARGET CHECK
    # ======================================

    if not target:

        return (
            False,
            "Target is required."
        )

    # ======================================
    # IP ADDRESS VALIDATION
    # ======================================
    #
    # Supports both IPv4 and IPv6.
    #
    # No public/private IP restrictions
    # are applied.
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
    #
    # Checks hostname syntax without
    # performing DNS resolution.
    # ======================================

    if HOSTNAME_PATTERN.fullmatch(target):

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
