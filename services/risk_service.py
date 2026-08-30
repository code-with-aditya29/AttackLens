# ==========================================
# ATTACKLENS RISK ENGINE
# ==========================================


# ==========================================
# RISK ENGINE CONFIGURATION
# ==========================================


MAX_RISK_SCORE = 100


MAX_VULNERABILITY_SCORE = 80


MAX_ATTACK_SURFACE_SCORE = 20


# ==========================================
# CONFIDENCE WEIGHTS
# ==========================================


CONFIDENCE_WEIGHTS = {

    "HIGH": 1.00,

    "MEDIUM": 0.70,

    "LOW": 0.30,

    "UNKNOWN": 0.10

}


# ==========================================
# FINDING STATUS WEIGHTS
# ==========================================


STATUS_WEIGHTS = {

    "verified": 1.00,

    "likely": 1.00,

    "potential": 0.90,

    "accepted_risk": 0.50,

    "resolved": 0.00,

    "rejected": 0.00

}


# ==========================================
# HIGH-RISK / SENSITIVE PORTS
# ==========================================


SENSITIVE_PORTS = {

    21,     # FTP

    22,     # SSH

    23,     # Telnet

    25,     # SMTP

    53,     # DNS

    110,    # POP3

    135,    # MSRPC

    139,    # NetBIOS

    445,    # SMB

    1433,   # MSSQL

    1521,   # Oracle

    3306,   # MySQL

    3389,   # RDP

    5432,   # PostgreSQL

    5900,   # VNC

    6379,   # Redis

    27017   # MongoDB

}


# ==========================================
# CALCULATE RISK
# ==========================================


def calculate_risk_score(
    vulnerabilities=None,
    ports=None
):
    """
    Calculate an explainable AttackLens
    security risk score.

    Final score:

        Vulnerability Risk:
            0 - 80

        Attack Surface Risk:
            0 - 20

        Final Risk:
            0 - 100

    Returns:

        {
            "risk_score": 0-100,

            "risk_level":
                LOW / MEDIUM / HIGH / CRITICAL,

            "risk_breakdown": {...}
        }
    """

    if not isinstance(
        vulnerabilities,
        list
    ):

        vulnerabilities = []


    if not isinstance(
        ports,
        list
    ):

        ports = []


    # ======================================
    # VULNERABILITY COMPONENT
    # ======================================

    vulnerability_result = (
        calculate_vulnerability_risk(
            vulnerabilities
        )
    )


    # ======================================
    # ATTACK SURFACE COMPONENT
    # ======================================

    attack_surface_result = (
        calculate_attack_surface_risk(
            ports
        )
    )


    vulnerability_score = (
        vulnerability_result[
            "score"
        ]
    )


    attack_surface_score = (
        attack_surface_result[
            "score"
        ]
    )


    # ======================================
    # FINAL SCORE
    # ======================================

    final_score = (

        vulnerability_score

        +

        attack_surface_score

    )


    final_score = min(

        MAX_RISK_SCORE,

        max(
            0,
            final_score
        )

    )


    final_score = round(
        final_score
    )


    risk_level = determine_risk_level(
        final_score
    )


    # ======================================
    # RESULT
    # ======================================

    return {

        "risk_score": final_score,

        "risk_level": risk_level,

        "risk_breakdown": {

            # ==============================
            # VULNERABILITY RISK
            # ==============================

            "vulnerability_score": (
                vulnerability_score
            ),

            "critical_findings": (
                vulnerability_result[
                    "critical_findings"
                ]
            ),

            "high_findings": (
                vulnerability_result[
                    "high_findings"
                ]
            ),

            "medium_findings": (
                vulnerability_result[
                    "medium_findings"
                ]
            ),

            "low_findings": (
                vulnerability_result[
                    "low_findings"
                ]
            ),

            "unknown_findings": (
                vulnerability_result[
                    "unknown_findings"
                ]
            ),

            "weighted_findings": (
                vulnerability_result[
                    "weighted_findings"
                ]
            ),


            # ==============================
            # ATTACK SURFACE RISK
            # ==============================

            "attack_surface_score": (
                attack_surface_score
            ),

            "open_ports": (
                attack_surface_result[
                    "open_ports"
                ]
            ),

            "sensitive_ports": (
                attack_surface_result[
                    "sensitive_ports"
                ]
            )

        }

    }


# ==========================================
# VULNERABILITY RISK
# ==========================================


def calculate_vulnerability_risk(
    vulnerabilities
):
    """
    Calculate the vulnerability component.

    Maximum contribution:

        80 points

    Every CVE is adjusted according to:

        CVSS
        confidence
        finding status

    Higher-confidence findings contribute more.
    """

    critical_findings = 0

    high_findings = 0

    medium_findings = 0

    low_findings = 0

    unknown_findings = 0


    weighted_findings = []


    for vulnerability in vulnerabilities:

        if not isinstance(
            vulnerability,
            dict
        ):

            continue


        # ==================================
        # FINDING STATUS
        # ==================================

        status = str(

            vulnerability.get(
                "status",
                "potential"
            )

        ).strip().lower()


        status_weight = STATUS_WEIGHTS.get(

            status,

            0.50

        )


        # Completely ignored findings.

        if status_weight <= 0:

            continue


        # ==================================
        # CVSS SCORE
        # ==================================

        cvss_score = normalize_cvss_score(

            vulnerability.get(
                "cvss_score"
            )

        )


        # ==================================
        # SEVERITY
        # ==================================

        severity = normalize_severity(

            vulnerability.get(
                "severity"
            )

        )


        # ==================================
        # COUNT SEVERITIES
        # ==================================

        if severity == "CRITICAL":

            critical_findings += 1


        elif severity == "HIGH":

            high_findings += 1


        elif severity == "MEDIUM":

            medium_findings += 1


        elif severity == "LOW":

            low_findings += 1


        else:

            unknown_findings += 1


        # ==================================
        # CONFIDENCE
        # ==================================

        confidence = normalize_confidence(

            vulnerability.get(
                "confidence"
            )

        )


        confidence_weight = (
            CONFIDENCE_WEIGHTS.get(

                confidence,

                0.10

            )
        )


        # ==================================
        # WEIGHTED CVSS
        # ==================================

        weighted_cvss = (

            cvss_score

            *

            confidence_weight

            *

            status_weight

        )


        weighted_findings.append({

            "cve_id": vulnerability.get(
                "cve_id"
            ),

            "cvss_score": cvss_score,

            "severity": severity,

            "confidence": confidence,

            "status": status,

            "weighted_cvss": round(
                weighted_cvss,
                2
            )

        })


    # ======================================
    # SORT STRONGEST FINDINGS FIRST
    # ======================================

    weighted_findings.sort(

        key=lambda finding: finding.get(
            "weighted_cvss",
            0
        ),

        reverse=True

    )


    # ======================================
    # DIMINISHING RETURNS
    # ======================================
    #
    # The strongest CVEs have the greatest
    # effect.
    #
    # This prevents 20 weak findings from
    # automatically producing a risk score
    # of 100.
    # ======================================

    contribution_weights = [

        3.0,

        2.5,

        2.0,

        1.5,

        1.0

    ]


    raw_score = 0.0


    for index, finding in enumerate(

        weighted_findings[:5]

    ):

        weighted_cvss = finding.get(

            "weighted_cvss",

            0

        )


        multiplier = (
            contribution_weights[
                index
            ]
        )


        raw_score += (

            weighted_cvss

            *

            multiplier

        )


    vulnerability_score = min(

        MAX_VULNERABILITY_SCORE,

        raw_score

    )


    vulnerability_score = round(
        vulnerability_score,
        2
    )


    return {

        "score": vulnerability_score,

        "critical_findings": (
            critical_findings
        ),

        "high_findings": (
            high_findings
        ),

        "medium_findings": (
            medium_findings
        ),

        "low_findings": (
            low_findings
        ),

        "unknown_findings": (
            unknown_findings
        ),

        "weighted_findings": (
            weighted_findings
        )

    }


# ==========================================
# ATTACK SURFACE RISK
# ==========================================


def calculate_attack_surface_risk(
    ports
):
    """
    Calculate exposure based on discovered
    open ports.

    Maximum contribution:

        20 points

    This does NOT assume that the host is
    Internet-facing.

    It only represents local attack-surface
    exposure discovered during scanning.
    """

    open_ports = []


    sensitive_ports = []


    seen_ports = set()


    for port_data in ports:

        if not isinstance(
            port_data,
            dict
        ):

            continue


        state = str(

            port_data.get(
                "state",
                ""
            )

        ).strip().lower()


        if state != "open":

            continue


        port_number = port_data.get(
            "port"
        )


        try:

            port_number = int(
                port_number
            )


        except (
            TypeError,
            ValueError
        ):

            continue


        if port_number in seen_ports:

            continue


        seen_ports.add(
            port_number
        )


        open_ports.append(
            port_number
        )


        if port_number in SENSITIVE_PORTS:

            sensitive_ports.append(
                port_number
            )


    # ======================================
    # BASIC OPEN PORT CONTRIBUTION
    # ======================================

    base_score = (

        len(
            open_ports
        )

        *

        1.5

    )


    # ======================================
    # SENSITIVE PORT CONTRIBUTION
    # ======================================

    sensitive_score = (

        len(
            sensitive_ports
        )

        *

        2.0

    )


    attack_surface_score = (

        base_score

        +

        sensitive_score

    )


    attack_surface_score = min(

        MAX_ATTACK_SURFACE_SCORE,

        attack_surface_score

    )


    attack_surface_score = round(

        attack_surface_score,

        2

    )


    return {

        "score": attack_surface_score,

        "open_ports": open_ports,

        "sensitive_ports": sensitive_ports

    }


# ==========================================
# CVSS NORMALIZATION
# ==========================================


def normalize_cvss_score(
    score
):
    """
    Normalize CVSS into the valid 0-10 range.
    """

    try:

        score = float(
            score
        )


    except (
        TypeError,
        ValueError
    ):

        return 0.0


    return min(

        10.0,

        max(
            0.0,
            score
        )

    )


# ==========================================
# SEVERITY NORMALIZATION
# ==========================================


def normalize_severity(
    severity
):
    """
    Normalize vulnerability severity.
    """

    allowed = {

        "CRITICAL",

        "HIGH",

        "MEDIUM",

        "LOW",

        "NONE",

        "UNKNOWN"

    }


    if not severity:

        return "UNKNOWN"


    severity = str(
        severity
    ).strip().upper()


    if severity not in allowed:

        return "UNKNOWN"


    return severity


# ==========================================
# CONFIDENCE NORMALIZATION
# ==========================================


def normalize_confidence(
    confidence
):
    """
    Normalize CVE correlation confidence.
    """

    allowed = {

        "HIGH",

        "MEDIUM",

        "LOW",

        "UNKNOWN"

    }


    if not confidence:

        return "UNKNOWN"


    confidence = str(
        confidence
    ).strip().upper()


    if confidence not in allowed:

        return "UNKNOWN"


    return confidence


# ==========================================
# RISK LEVEL
# ==========================================


def determine_risk_level(
    risk_score
):
    """
    Convert numerical score into a human
    readable risk level.

        0 - 24
            LOW

        25 - 49
            MEDIUM

        50 - 74
            HIGH

        75 - 100
            CRITICAL
    """

    try:

        risk_score = float(
            risk_score
        )


    except (
        TypeError,
        ValueError
    ):

        return "UNKNOWN"


    if risk_score >= 75:

        return "CRITICAL"


    if risk_score >= 50:

        return "HIGH"


    if risk_score >= 25:

        return "MEDIUM"


    return "LOW"