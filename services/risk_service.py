# ==========================================
# ATTACKLENS RISK ENGINE
# ==========================================


# ==========================================
# RISK ENGINE CONFIGURATION
# ==========================================


MAX_RISK_SCORE = 100


# The existing AttackLens scoring model is
# deliberately preserved:
#
#   Security / Vulnerability Risk = 0 - 80
#   Attack Surface Risk          = 0 - 20
#
# The 80-point security component can now
# consider both:
#
#   1. CVE vulnerabilities
#   2. eligible non-CVE security findings
#
# This avoids changing the historical
# 100-point scale.

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
#
# Lower-case keys are used internally.
#
# Existing CVE statuses remain supported.
#
# New unified Security Finding statuses are
# also supported:
#
#   OBSERVED
#   POTENTIAL
#   VALIDATED
#   ACCEPTED_RISK
#   RESOLVED
#   REJECTED
#   UNKNOWN
# ==========================================


STATUS_WEIGHTS = {

    "verified": 1.00,

    "validated": 1.00,

    "likely": 1.00,

    "observed": 0.90,

    "potential": 0.90,

    "accepted_risk": 0.50,

    "unknown": 0.25,

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
# CONTEXT-ONLY SECURITY FINDINGS
# ==========================================
#
# These are useful assessment observations,
# but they are NOT vulnerabilities by
# themselves.
#
# They must therefore NOT increase the
# vulnerability/security score.
# ==========================================


CONTEXT_ONLY_CATEGORIES = {

    "WEB_APPLICATION_SURFACE",

    "LIMITED_VERSION_EVIDENCE",

    "LOW_CONFIDENCE_OS_DETECTION",

    "LARGE_ATTACK_SURFACE"

}


# ==========================================
# PORT / EXPOSURE FINDINGS
# ==========================================
#
# The Risk Engine already calculates attack
# surface risk directly from open and
# sensitive ports.
#
# Security Scanner findings representing the
# same port/service exposure must therefore
# not contribute again to the 80-point
# security component.
#
# This prevents double-counting.
# ==========================================


EXPOSURE_FINDING_TYPES = {

    "NETWORK",

    "SERVICE"

}


# ==========================================
# ELIGIBLE SECURITY FINDING TYPES
# ==========================================
#
# These finding domains may contribute to
# security risk when they represent an
# actual weakness and are not merely
# contextual observations.
#
# NETWORK and SERVICE are intentionally not
# listed here because their current scanner
# implementation primarily represents
# exposure already handled by the
# attack-surface component.
# ==========================================


RISK_BEARING_FINDING_TYPES = {

    "WEB",

    "APPLICATION",

    "HOST",

    "OS",

    "CONFIGURATION"

}


# ==========================================
# GENERIC SEVERITY SCORES
# ==========================================
#
# Non-CVE findings do not necessarily have
# CVSS scores.
#
# These values provide a conservative
# CVSS-like 0-10 internal risk value.
#
# They are NOT presented as official CVSS
# scores.
# ==========================================


GENERIC_SEVERITY_SCORES = {

    "CRITICAL": 9.0,

    "HIGH": 7.0,

    "MEDIUM": 5.0,

    "LOW": 2.5,

    "NONE": 0.0,

    "UNKNOWN": 0.0

}


# ==========================================
# CALCULATE RISK
# ==========================================


def calculate_risk_score(
    vulnerabilities=None,
    ports=None,
    security_findings=None
):
    """
    Calculate an explainable AttackLens
    security risk score.

    Backward compatibility:

        Existing callers may continue using:

            calculate_risk_score(
                vulnerabilities,
                ports
            )

        New callers may additionally provide:

            security_findings

    Final score:

        Security / Vulnerability Risk:
            0 - 80

        Attack Surface Risk:
            0 - 20

        Final Risk:
            0 - 100

    Security / Vulnerability Risk includes:

        - validated/potential CVEs
        - eligible non-CVE security findings

    Attack Surface Risk includes:

        - open ports
        - sensitive ports

    Important:

        Context-only observations and
        duplicate port/service exposure
        findings are not allowed to inflate
        the score.

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


    if not isinstance(
        security_findings,
        list
    ):

        security_findings = []


    # ======================================
    # CVE VULNERABILITY COMPONENT
    # ======================================

    vulnerability_result = (
        calculate_vulnerability_risk(
            vulnerabilities
        )
    )


    # ======================================
    # NON-CVE SECURITY FINDING COMPONENT
    # ======================================

    security_finding_result = (
        calculate_security_finding_risk(
            security_findings
        )
    )


    # ======================================
    # COMBINE SECURITY EVIDENCE
    # ======================================
    #
    # CVEs and eligible non-CVE findings are
    # combined before applying the existing
    # diminishing-return model.
    #
    # This is preferable to simply adding
    # two independent 80-point scores.
    # ======================================

    combined_weighted_findings = (

        vulnerability_result[
            "weighted_findings"
        ]

        +

        security_finding_result[
            "weighted_findings"
        ]

    )


    security_score = (
        calculate_weighted_finding_score(
            combined_weighted_findings
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


    attack_surface_score = (
        attack_surface_result[
            "score"
        ]
    )


    # ======================================
    # FINAL SCORE
    # ======================================

    final_score = (

        security_score

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
            # COMBINED SECURITY RISK
            # ==============================

            "vulnerability_score": (
                security_score
            ),

            "security_score": (
                security_score
            ),


            # ==============================
            # CVE FINDINGS
            # ==============================

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
            # NON-CVE SECURITY FINDINGS
            # ==============================

            "security_finding_score": (
                security_finding_result[
                    "score"
                ]
            ),

            "security_findings_considered": (
                security_finding_result[
                    "considered_findings"
                ]
            ),

            "security_findings_excluded": (
                security_finding_result[
                    "excluded_findings"
                ]
            ),

            "security_critical_findings": (
                security_finding_result[
                    "critical_findings"
                ]
            ),

            "security_high_findings": (
                security_finding_result[
                    "high_findings"
                ]
            ),

            "security_medium_findings": (
                security_finding_result[
                    "medium_findings"
                ]
            ),

            "security_low_findings": (
                security_finding_result[
                    "low_findings"
                ]
            ),

            "security_unknown_findings": (
                security_finding_result[
                    "unknown_findings"
                ]
            ),

            "weighted_security_findings": (
                security_finding_result[
                    "weighted_findings"
                ]
            ),

            "combined_weighted_findings": (
                combined_weighted_findings
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
    Calculate the CVE vulnerability component.

    Maximum contribution:

        80 points

    Every CVE is adjusted according to:

        CVSS
        confidence
        finding status

    Higher-confidence findings contribute more.

    This function retains the historical
    AttackLens behavior so existing tests and
    callers remain compatible.
    """

    if not isinstance(
        vulnerabilities,
        list
    ):

        vulnerabilities = []


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

        status = normalize_status(

            vulnerability.get(
                "status",
                "potential"
            )

        )


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

            "finding_type": "CVE",

            "cve_id": vulnerability.get(
                "cve_id"
            ),

            "finding_id": vulnerability.get(
                "finding_id"
            ),

            "cvss_score": cvss_score,

            "base_score": cvss_score,

            "severity": severity,

            "confidence": confidence,

            "status": status,

            "weighted_cvss": round(
                weighted_cvss,
                2
            ),

            "source": vulnerability.get(
                "source",
                "CVE"
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


    vulnerability_score = (
        calculate_weighted_finding_score(
            weighted_findings
        )
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
# SECURITY FINDING RISK
# ==========================================


def calculate_security_finding_risk(
    security_findings
):
    """
    Calculate risk contribution from eligible
    non-CVE AttackLens security findings.

    Important design rules:

    1. Context-only findings do not score.

    2. NETWORK/SERVICE exposure findings do
       not score here because open/sensitive
       ports are already handled by the
       attack-surface component.

    3. RESOLVED and REJECTED findings do not
       score.

    4. Eligible WEB/APPLICATION/HOST/OS/
       CONFIGURATION findings can contribute.

    5. Non-CVE severity is converted to an
       internal 0-10 risk value. This is not
       represented as an official CVSS score.
    """

    if not isinstance(
        security_findings,
        list
    ):

        security_findings = []


    critical_findings = 0

    high_findings = 0

    medium_findings = 0

    low_findings = 0

    unknown_findings = 0


    considered_findings = 0

    excluded_findings = 0


    weighted_findings = []


    seen_findings = set()


    for finding in security_findings:

        if not isinstance(
            finding,
            dict
        ):

            excluded_findings += 1

            continue


        # ==================================
        # TYPE / DOMAIN
        # ==================================

        finding_type = normalize_finding_type(

            finding.get(
                "finding_type",
                finding.get(
                    "type"
                )
            )

        )


        # ==================================
        # CATEGORY
        # ==================================

        category = normalize_category(

            finding.get(
                "category"
            )

        )


        # ==================================
        # CONTEXT-ONLY FINDINGS
        # ==================================

        if category in CONTEXT_ONLY_CATEGORIES:

            excluded_findings += 1

            continue


        # ==================================
        # PORT/SERVICE EXPOSURE
        # ==================================
        #
        # These are already represented by
        # calculate_attack_surface_risk().
        # ==================================

        if finding_type in EXPOSURE_FINDING_TYPES:

            excluded_findings += 1

            continue


        # ==================================
        # ALLOWED RISK-BEARING DOMAINS
        # ==================================

        if finding_type not in (
            RISK_BEARING_FINDING_TYPES
        ):

            excluded_findings += 1

            continue


        # ==================================
        # STATUS
        # ==================================

        status = normalize_status(

            finding.get(
                "status",
                "potential"
            )

        )


        status_weight = STATUS_WEIGHTS.get(

            status,

            0.25

        )


        if status_weight <= 0:

            excluded_findings += 1

            continue


        # ==================================
        # SEVERITY
        # ==================================

        severity = normalize_severity(

            finding.get(
                "severity"
            )

        )


        # ==================================
        # INTERNAL BASE SCORE
        # ==================================

        base_score = (
            get_security_finding_base_score(
                finding,
                severity
            )
        )


        # A finding without meaningful
        # severity/score evidence should not
        # inflate risk.

        if base_score <= 0:

            excluded_findings += 1

            continue


        # ==================================
        # CONFIDENCE
        # ==================================

        confidence = normalize_confidence(

            finding.get(
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
        # DEDUPLICATION
        # ==================================

        finding_key = (
            build_security_finding_key(
                finding,
                finding_type,
                category
            )
        )


        if finding_key in seen_findings:

            excluded_findings += 1

            continue


        seen_findings.add(
            finding_key
        )


        # ==================================
        # WEIGHTED RISK VALUE
        # ==================================

        weighted_score = (

            base_score

            *

            confidence_weight

            *

            status_weight

        )


        # ==================================
        # COUNT SEVERITY
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


        considered_findings += 1


        weighted_findings.append({

            "finding_type": finding_type,

            "finding_id": finding.get(
                "finding_id"
            ),

            "category": category,

            "title": finding.get(
                "title"
            ),

            "severity": severity,

            "confidence": confidence,

            "status": status,

            "base_score": round(
                base_score,
                2
            ),

            "weighted_cvss": round(
                weighted_score,
                2
            ),

            "source": finding.get(
                "source"
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


    security_finding_score = (
        calculate_weighted_finding_score(
            weighted_findings
        )
    )


    return {

        "score": security_finding_score,

        "considered_findings": (
            considered_findings
        ),

        "excluded_findings": (
            excluded_findings
        ),

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
# WEIGHTED FINDING SCORE
# ==========================================


def calculate_weighted_finding_score(
    weighted_findings
):
    """
    Apply AttackLens diminishing returns to
    an already-weighted list of findings.

    The strongest five findings have the
    greatest effect.

    Maximum contribution:

        80 points
    """

    if not isinstance(
        weighted_findings,
        list
    ):

        weighted_findings = []


    valid_findings = []


    for finding in weighted_findings:

        if not isinstance(
            finding,
            dict
        ):

            continue


        try:

            weighted_value = float(

                finding.get(
                    "weighted_cvss",
                    0
                )

            )


        except (
            TypeError,
            ValueError
        ):

            weighted_value = 0.0


        if weighted_value <= 0:

            continue


        normalized_finding = dict(
            finding
        )


        normalized_finding[
            "weighted_cvss"
        ] = weighted_value


        valid_findings.append(
            normalized_finding
        )


    valid_findings.sort(

        key=lambda finding: finding.get(
            "weighted_cvss",
            0
        ),

        reverse=True

    )


    # ======================================
    # DIMINISHING RETURNS
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

        valid_findings[:5]

    ):

        weighted_value = finding.get(

            "weighted_cvss",

            0

        )


        multiplier = (
            contribution_weights[
                index
            ]
        )


        raw_score += (

            weighted_value

            *

            multiplier

        )


    score = min(

        MAX_VULNERABILITY_SCORE,

        raw_score

    )


    return round(
        score,
        2
    )


# ==========================================
# SECURITY FINDING BASE SCORE
# ==========================================


def get_security_finding_base_score(
    finding,
    severity
):
    """
    Return a conservative internal 0-10
    risk value for a non-CVE finding.

    Priority:

        1. Explicit generic finding score
        2. Severity-derived internal score

    The generic Security Finding model may
    use a 0-100 score.

    Therefore:

        0-10   -> used directly
        10-100 -> converted to 0-10

    CVSS is deliberately not assumed for
    non-CVE findings.
    """

    explicit_score = finding.get(
        "score"
    )


    try:

        explicit_score = float(
            explicit_score
        )


        if explicit_score < 0:

            explicit_score = 0.0


        if explicit_score > 100:

            explicit_score = 100.0


        if explicit_score > 10:

            explicit_score = (
                explicit_score
                /
                10.0
            )


        if explicit_score > 0:

            return min(
                10.0,
                explicit_score
            )


    except (
        TypeError,
        ValueError
    ):

        pass


    return GENERIC_SEVERITY_SCORES.get(

        severity,

        0.0

    )


# ==========================================
# SECURITY FINDING DEDUPLICATION KEY
# ==========================================


def build_security_finding_key(
    finding,
    finding_type,
    category
):
    """
    Build a conservative identity key for
    non-CVE security findings.

    The key intentionally keeps findings on
    different ports/endpoints/parameters
    separate.
    """

    return (

        normalize_text_value(
            finding_type
        ),

        normalize_text_value(
            category
        ),

        normalize_text_value(
            finding.get(
                "target"
            )
        ),

        normalize_port_value(
            finding.get(
                "port"
            )
        ),

        normalize_text_value(
            finding.get(
                "protocol"
            )
        ),

        normalize_text_value(
            finding.get(
                "service"
            )
        ),

        normalize_text_value(
            finding.get(
                "product"
            )
        ),

        normalize_text_value(
            finding.get(
                "version"
            )
        ),

        normalize_text_value(
            finding.get(
                "endpoint"
            )
        ),

        normalize_text_value(
            finding.get(
                "method"
            )
        ),

        normalize_text_value(
            finding.get(
                "parameter"
            )
        ),

        normalize_text_value(
            finding.get(
                "title"
            )
        )

    )


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

    if not isinstance(
        ports,
        list
    ):

        ports = []


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


        if port_number < 1 or port_number > 65535:

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
    Normalize vulnerability/security finding
    severity.
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
    Normalize finding confidence.
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
# STATUS NORMALIZATION
# ==========================================


def normalize_status(
    status
):
    """
    Normalize CVE and unified Security
    Finding statuses to lower-case values.
    """

    if status is None:

        return "unknown"


    status = str(
        status
    ).strip().lower()


    if not status:

        return "unknown"


    return status


# ==========================================
# FINDING TYPE NORMALIZATION
# ==========================================


def normalize_finding_type(
    finding_type
):
    """
    Normalize unified Security Finding type.
    """

    if not finding_type:

        return "UNKNOWN"


    return str(
        finding_type
    ).strip().upper()


# ==========================================
# CATEGORY NORMALIZATION
# ==========================================


def normalize_category(
    category
):
    """
    Normalize a Security Finding category.
    """

    if not category:

        return ""


    return str(
        category
    ).strip().upper()


# ==========================================
# TEXT NORMALIZATION
# ==========================================


def normalize_text_value(
    value
):
    """
    Normalize a value for comparison and
    deduplication.
    """

    if value is None:

        return ""


    return str(
        value
    ).strip().lower()


# ==========================================
# PORT NORMALIZATION
# ==========================================


def normalize_port_value(
    port
):
    """
    Normalize a port value for finding
    deduplication.
    """

    try:

        port = int(
            port
        )


    except (
        TypeError,
        ValueError
    ):

        return None


    if port < 1 or port > 65535:

        return None


    return port


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