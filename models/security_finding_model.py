# ==========================================
# ATTACKLENS
# SECURITY FINDING MODEL
# ==========================================
#
# This model defines the normalized structure
# used for security findings discovered by
# AttackLens.
#
# It is designed to support:
#
# 1. CVE findings
# 2. Web application findings
# 3. Application / software findings
# 4. Network / service findings
# 5. Host / OS findings
# 6. Security configuration findings
#
# IMPORTANT:
#
# This model does NOT perform vulnerability
# scanning.
#
# Detection and analysis logic belongs inside
# the service layer.
#
# The structure is intentionally compatible
# with the fields already used by the existing
# AttackLens CVE pipeline.
# ==========================================


from datetime import datetime, timezone
from uuid import uuid4


# ==========================================
# VALID FINDING TYPES
# ==========================================

VALID_FINDING_TYPES = {
    "CVE",
    "WEB",
    "APPLICATION",
    "NETWORK",
    "SERVICE",
    "HOST",
    "OS",
    "CONFIGURATION"
}


# ==========================================
# VALID SEVERITIES
# ==========================================

VALID_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
    "UNKNOWN"
}


# ==========================================
# VALID CONFIDENCE LEVELS
# ==========================================

VALID_CONFIDENCE_LEVELS = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "UNKNOWN"
}


# ==========================================
# VALID FINDING STATUS VALUES
# ==========================================

VALID_FINDING_STATUSES = {
    "OBSERVED",
    "POTENTIAL",
    "VALIDATED",
    "ACCEPTED_RISK",
    "RESOLVED",
    "REJECTED",
    "UNKNOWN"
}


# ==========================================
# CREATE SECURITY FINDING
# ==========================================

def create_security_finding(
    finding_type,
    category,
    title,
    description="",
    target=None,
    port=None,
    protocol=None,
    service=None,
    product=None,
    version=None,
    operating_system=None,
    endpoint=None,
    method=None,
    parameter=None,
    severity="UNKNOWN",
    confidence="UNKNOWN",
    status="POTENTIAL",
    score=None,
    evidence=None,
    evidence_source=None,
    cve_id=None,
    cvss_score=None,
    cvss_version=None,
    references=None,
    metadata=None,
    created_by=None,
    finding_id=None
):
    """
    Create one normalized AttackLens security
    finding.

    The same structure can represent findings
    from CVE correlation, application analysis,
    web analysis, network/service analysis,
    host/OS analysis, and configuration checks.
    """

    if finding_id is None:

        finding_id = generate_finding_id()

    normalized_cvss = normalize_cvss_score(
        cvss_score
    )

    normalized_score = normalize_optional_score(
        score
    )

    # CVE findings may not provide a separate
    # generic score. Preserve compatibility by
    # allowing CVSS to act as the finding score.
    if (
        normalized_score is None
        and
        normalized_cvss is not None
    ):

        normalized_score = normalized_cvss

    return {

        # ==================================
        # FINDING IDENTITY
        # ==================================

        "finding_id":
            normalize_string(
                finding_id
            ),

        "finding_type":
            normalize_finding_type(
                finding_type
            ),

        "category":
            normalize_category(
                category
            ),

        "title":
            normalize_string(
                title,
                default="Security Finding"
            ),

        "description":
            normalize_string(
                description
            ),


        # ==================================
        # TARGET INFORMATION
        # ==================================

        "target":
            normalize_nullable_string(
                target
            ),

        "port":
            normalize_port(
                port
            ),

        "protocol":
            normalize_nullable_string(
                protocol
            ),

        "service":
            normalize_nullable_string(
                service
            ),

        "product":
            normalize_nullable_string(
                product
            ),

        "version":
            normalize_nullable_string(
                version
            ),

        "operating_system":
            normalize_nullable_string(
                operating_system
            ),


        # ==================================
        # APPLICATION / WEB CONTEXT
        # ==================================

        "endpoint":
            normalize_nullable_string(
                endpoint
            ),

        "method":
            normalize_http_method(
                method
            ),

        "parameter":
            normalize_nullable_string(
                parameter
            ),


        # ==================================
        # SECURITY CLASSIFICATION
        # ==================================

        "severity":
            normalize_severity(
                severity
            ),

        "confidence":
            normalize_confidence(
                confidence
            ),

        "status":
            normalize_status(
                status
            ),

        "score":
            normalized_score,


        # ==================================
        # EVIDENCE
        # ==================================

        "evidence":
            normalize_evidence(
                evidence
            ),

        "evidence_source":
            normalize_nullable_string(
                evidence_source
            ),


        # ==================================
        # CVE COMPATIBILITY
        # ==================================
        #
        # These fields intentionally use the
        # same names as the existing CVE
        # vulnerability pipeline.
        # ==================================

        "cve_id":
            normalize_cve_id(
                cve_id
            ),

        "cvss_score":
            normalized_cvss,

        "cvss_version":
            normalize_nullable_string(
                cvss_version
            ),

        "references":
            normalize_references(
                references
            ),


        # ==================================
        # EXTENSIBLE METADATA
        # ==================================
        #
        # Scanner-specific evidence can be
        # retained here without changing the
        # common finding schema.
        #
        # Examples:
        #
        # response_code
        # response_length
        # header_name
        # cookie_name
        # request_url
        # match_reason
        # product_match
        # version_match
        # platform_match
        # applicability_validated
        # ==================================

        "metadata":
            normalize_metadata(
                metadata
            ),


        # ==================================
        # OWNERSHIP
        # ==================================

        "created_by":
            normalize_nullable_string(
                created_by
            ),


        # ==================================
        # TIMESTAMP
        # ==================================

        "created_at":
            datetime.now(
                timezone.utc
            )
    }


# ==========================================
# CREATE FINDING COLLECTION
# ==========================================

def create_security_finding_collection(
    findings=None
):
    """
    Normalize a collection of security findings.
    """

    if not isinstance(
        findings,
        list
    ):

        return []

    normalized = []

    for finding in findings:

        if not isinstance(
            finding,
            dict
        ):

            continue

        normalized.append(
            finding
        )

    return normalized


# ==========================================
# GENERATE FINDING ID
# ==========================================

def generate_finding_id():
    """
    Generate a unique AttackLens finding ID.
    """

    return (
        "finding-"
        +
        str(
            uuid4()
        )
    )


# ==========================================
# NORMALIZE FINDING TYPE
# ==========================================

def normalize_finding_type(
    value
):
    """
    Normalize the high-level source/type of
    a security finding.
    """

    normalized = str(
        value
        or
        ""
    ).strip().upper()

    if normalized in VALID_FINDING_TYPES:

        return normalized

    return "CONFIGURATION"


# ==========================================
# NORMALIZE CATEGORY
# ==========================================

def normalize_category(
    value
):
    """
    Normalize finding category into a stable
    uppercase identifier.

    Examples:

    SQL_INJECTION
    REFLECTED_XSS
    CSRF
    IDOR
    INSECURE_PROTOCOL
    SENSITIVE_SERVICE_EXPOSURE
    MISSING_SECURITY_HEADER
    INSECURE_COOKIE
    KNOWN_CVE
    """

    if value is None:

        return "GENERAL"

    value = str(
        value
    ).strip().upper()

    if not value:

        return "GENERAL"

    value = value.replace(
        "-",
        "_"
    )

    value = value.replace(
        " ",
        "_"
    )

    while "__" in value:

        value = value.replace(
            "__",
            "_"
        )

    return value


# ==========================================
# NORMALIZE SEVERITY
# ==========================================

def normalize_severity(
    value
):
    """
    Normalize finding severity.
    """

    normalized = str(
        value
        or
        ""
    ).strip().upper()

    if normalized in VALID_SEVERITIES:

        return normalized

    return "UNKNOWN"


# ==========================================
# NORMALIZE CONFIDENCE
# ==========================================

def normalize_confidence(
    value
):
    """
    Normalize finding confidence.
    """

    normalized = str(
        value
        or
        ""
    ).strip().upper()

    if normalized in VALID_CONFIDENCE_LEVELS:

        return normalized

    return "UNKNOWN"


# ==========================================
# NORMALIZE STATUS
# ==========================================

def normalize_status(
    value
):
    """
    Normalize finding validation state.

    OBSERVED:
        Directly observed configuration or
        exposure condition.

    POTENTIAL:
        Evidence suggests a weakness but
        exploitation has not been proven.

    VALIDATED:
        Strong evidence confirms the finding.

    ACCEPTED_RISK:
        Finding intentionally accepted.

    RESOLVED:
        Finding considered remediated.

    REJECTED:
        Finding rejected during validation.
    """

    normalized = str(
        value
        or
        ""
    ).strip().upper()

    if normalized in VALID_FINDING_STATUSES:

        return normalized

    return "UNKNOWN"


# ==========================================
# NORMALIZE GENERIC SCORE
# ==========================================

def normalize_optional_score(
    value
):
    """
    Normalize a generic finding score.

    Security finding scores use a 0-100 range.

    None is preserved because a finding does
    not always have a numeric score.
    """

    if value is None:

        return None

    try:

        value = float(
            value
        )

    except (
        TypeError,
        ValueError
    ):

        return None

    value = max(
        0.0,
        min(
            100.0,
            value
        )
    )

    if value.is_integer():

        return int(
            value
        )

    return round(
        value,
        2
    )


# ==========================================
# NORMALIZE CVSS SCORE
# ==========================================

def normalize_cvss_score(
    value
):
    """
    Normalize CVSS base score.

    CVSS remains on its native 0-10 scale.
    """

    if value is None:

        return None

    try:

        value = float(
            value
        )

    except (
        TypeError,
        ValueError
    ):

        return None

    value = max(
        0.0,
        min(
            10.0,
            value
        )
    )

    return round(
        value,
        1
    )


# ==========================================
# NORMALIZE PORT
# ==========================================

def normalize_port(
    value
):
    """
    Normalize TCP/UDP port number.
    """

    if value is None:

        return None

    try:

        port = int(
            value
        )

    except (
        TypeError,
        ValueError
    ):

        return None

    if (
        port < 1
        or
        port > 65535
    ):

        return None

    return port


# ==========================================
# NORMALIZE HTTP METHOD
# ==========================================

def normalize_http_method(
    value
):
    """
    Normalize optional HTTP method.
    """

    if value is None:

        return None

    value = str(
        value
    ).strip().upper()

    if not value:

        return None

    return value


# ==========================================
# NORMALIZE CVE ID
# ==========================================

def normalize_cve_id(
    value
):
    """
    Normalize optional CVE identifier.

    Non-CVE findings return None.
    """

    if value is None:

        return None

    value = str(
        value
    ).strip().upper()

    if not value:

        return None

    return value


# ==========================================
# NORMALIZE EVIDENCE
# ==========================================

def normalize_evidence(
    evidence
):
    """
    Normalize finding evidence into a
    deduplicated list of strings.

    Evidence must describe what AttackLens
    actually observed. It must not invent
    vulnerability confirmation.
    """

    if evidence is None:

        return []

    if not isinstance(
        evidence,
        list
    ):

        evidence = [
            evidence
        ]

    normalized = []

    seen = set()

    for item in evidence:

        if item is None:

            continue

        if isinstance(
            item,
            dict
        ):

            item = format_evidence_dictionary(
                item
            )

        text = str(
            item
        ).strip()

        if not text:

            continue

        key = text.lower()

        if key in seen:

            continue

        seen.add(
            key
        )

        normalized.append(
            text
        )

    return normalized


# ==========================================
# FORMAT EVIDENCE DICTIONARY
# ==========================================

def format_evidence_dictionary(
    evidence
):
    """
    Convert a small evidence dictionary into
    a deterministic readable string.

    Detailed machine-readable scanner data
    should normally be placed in metadata.
    """

    if not isinstance(
        evidence,
        dict
    ):

        return str(
            evidence
        )

    parts = []

    for key in sorted(
        evidence.keys()
    ):

        value = evidence.get(
            key
        )

        if value is None:

            continue

        parts.append(
            f"{key}={value}"
        )

    return "; ".join(
        parts
    )


# ==========================================
# NORMALIZE REFERENCES
# ==========================================

def normalize_references(
    references
):
    """
    Normalize references while preserving
    compatibility with NVD CVE findings.
    """

    if not isinstance(
        references,
        list
    ):

        return []

    normalized = []

    seen = set()

    for reference in references:

        if reference is None:

            continue

        if isinstance(
            reference,
            dict
        ):

            # Preserve structured references
            # produced by the existing CVE
            # pipeline.
            key = repr(
                sorted(
                    reference.items()
                )
            )

            if key in seen:

                continue

            seen.add(
                key
            )

            normalized.append(
                reference
            )

            continue

        reference = str(
            reference
        ).strip()

        if not reference:

            continue

        key = reference.lower()

        if key in seen:

            continue

        seen.add(
            key
        )

        normalized.append(
            reference
        )

    return normalized


# ==========================================
# NORMALIZE METADATA
# ==========================================

def normalize_metadata(
    metadata
):
    """
    Preserve scanner-specific structured data.

    Metadata allows future scanners to add
    useful evidence without continuously
    changing the common finding model.
    """

    if not isinstance(
        metadata,
        dict
    ):

        return {}

    return dict(
        metadata
    )


# ==========================================
# NORMALIZE STRING
# ==========================================

def normalize_string(
    value,
    default=""
):
    """
    Normalize required/general text.
    """

    if value is None:

        return default

    value = str(
        value
    ).strip()

    if not value:

        return default

    return value


# ==========================================
# NORMALIZE NULLABLE STRING
# ==========================================

def normalize_nullable_string(
    value
):
    """
    Normalize optional text while preserving
    None when no value exists.
    """

    if value is None:

        return None

    value = str(
        value
    ).strip()

    if not value:

        return None

    return value