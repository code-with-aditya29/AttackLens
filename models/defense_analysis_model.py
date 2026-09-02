# ==========================================
# DEFENSE ANALYSIS MODEL
# ==========================================
#
# This model defines the normalized data
# structures used by the Defense Analysis
# Engine.
#
# Responsibilities:
#
# 1. Create a defense analysis document.
# 2. Create defensive findings.
# 3. Create defense priority records.
# 4. Create analysis statistics.
# 5. Normalize score, severity, confidence,
#    identifiers, evidence, and strings.
#
# IMPORTANT:
#
# Business logic must remain inside:
#
# services/defense_analysis_service.py
#
# This file should only provide clean and
# deterministic data structures.
# ==========================================


from datetime import (
    datetime,
    timezone
)


# ==========================================
# VALID VALUES
# ==========================================

VALID_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
    "UNKNOWN"
}


VALID_CONFIDENCE_LEVELS = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "UNKNOWN"
}


VALID_PRIORITY_LEVELS = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
    "UNKNOWN"
}


# ==========================================
# CREATE DEFENSE ANALYSIS DOCUMENT
# ==========================================

def create_defense_analysis_document(
    created_by=None
):
    """
    Create a normalized Defense Analysis
    result document.
    """

    return {

        "created_by":
            created_by,

        "generated_at":
            datetime.now(
                timezone.utc
            ),

        "findings":
            [],

        "priorities":
            [],

        "statistics":
            create_defense_statistics()

    }


# ==========================================
# CREATE DEFENSIVE FINDING
# ==========================================

def create_defense_finding(
    finding_id,
    finding_type,
    title,
    description,
    asset_id=None,
    target=None,
    severity="UNKNOWN",
    confidence="UNKNOWN",
    score=0,
    evidence=None,
    related_nodes=None,
    related_edges=None,
    related_paths=None
):
    """
    Create one normalized defense finding.
    """

    return {

        "id":
            normalize_string(
                finding_id
            ),

        "finding_type":
            normalize_string(
                finding_type,
                default="general"
            ),

        "title":
            normalize_string(
                title,
                default="Defense Finding"
            ),

        "description":
            normalize_string(
                description
            ),

        "asset_id":
            normalize_nullable_string(
                asset_id
            ),

        "target":
            normalize_nullable_string(
                target
            ),

        "severity":
            normalize_severity(
                severity
            ),

        "confidence":
            normalize_confidence(
                confidence
            ),

        "score":
            normalize_score(
                score
            ),

        "evidence":
            normalize_evidence(
                evidence
            ),

        "related_nodes":
            normalize_identifier_list(
                related_nodes
            ),

        "related_edges":
            normalize_identifier_list(
                related_edges
            ),

        "related_paths":
            normalize_identifier_list(
                related_paths
            )

    }


# ==========================================
# CREATE DEFENSE PRIORITY
# ==========================================

def create_defense_priority(
    priority_id,
    priority_type,
    title,
    description,
    priority_level="UNKNOWN",
    score=0,
    confidence="UNKNOWN",
    asset_id=None,
    target=None,
    reason=None,
    evidence=None,
    related_findings=None,
    related_paths=None
):
    """
    Create one normalized defense
    prioritization record.
    """

    return {

        "id":
            normalize_string(
                priority_id
            ),

        "priority_type":
            normalize_string(
                priority_type,
                default="general"
            ),

        "title":
            normalize_string(
                title,
                default="Defense Priority"
            ),

        "description":
            normalize_string(
                description
            ),

        "priority_level":
            normalize_priority_level(
                priority_level
            ),

        "score":
            normalize_score(
                score
            ),

        "confidence":
            normalize_confidence(
                confidence
            ),

        "asset_id":
            normalize_nullable_string(
                asset_id
            ),

        "target":
            normalize_nullable_string(
                target
            ),

        "reason":
            normalize_string(
                reason
            ),

        "evidence":
            normalize_evidence(
                evidence
            ),

        "related_findings":
            normalize_identifier_list(
                related_findings
            ),

        "related_paths":
            normalize_identifier_list(
                related_paths
            )

    }


# ==========================================
# CREATE DEFENSE STATISTICS
# ==========================================

def create_defense_statistics(
    findings=None,
    priorities=None
):
    """
    Create summary statistics for the
    Defense Analysis result.
    """

    findings = (
        findings
        if isinstance(
            findings,
            list
        )
        else []
    )

    priorities = (
        priorities
        if isinstance(
            priorities,
            list
        )
        else []
    )


    severity_counts = {

        "LOW": 0,

        "MEDIUM": 0,

        "HIGH": 0,

        "CRITICAL": 0,

        "UNKNOWN": 0

    }


    priority_counts = {

        "LOW": 0,

        "MEDIUM": 0,

        "HIGH": 0,

        "CRITICAL": 0,

        "UNKNOWN": 0

    }


    highest_finding_score = 0

    highest_priority_score = 0


    for finding in findings:

        if not isinstance(
            finding,
            dict
        ):

            continue


        severity = (
            normalize_severity(
                finding.get(
                    "severity"
                )
            )
        )


        severity_counts[
            severity
        ] += 1


        finding_score = (
            normalize_score(
                finding.get(
                    "score"
                )
            )
        )


        highest_finding_score = max(
            highest_finding_score,
            finding_score
        )


    for priority in priorities:

        if not isinstance(
            priority,
            dict
        ):

            continue


        priority_level = (
            normalize_priority_level(
                priority.get(
                    "priority_level"
                )
            )
        )


        priority_counts[
            priority_level
        ] += 1


        priority_score = (
            normalize_score(
                priority.get(
                    "score"
                )
            )
        )


        highest_priority_score = max(
            highest_priority_score,
            priority_score
        )


    return {

        "total_findings":
            len(
                findings
            ),

        "total_priorities":
            len(
                priorities
            ),

        "low_findings":
            severity_counts[
                "LOW"
            ],

        "medium_findings":
            severity_counts[
                "MEDIUM"
            ],

        "high_findings":
            severity_counts[
                "HIGH"
            ],

        "critical_findings":
            severity_counts[
                "CRITICAL"
            ],

        "unknown_findings":
            severity_counts[
                "UNKNOWN"
            ],

        "low_priorities":
            priority_counts[
                "LOW"
            ],

        "medium_priorities":
            priority_counts[
                "MEDIUM"
            ],

        "high_priorities":
            priority_counts[
                "HIGH"
            ],

        "critical_priorities":
            priority_counts[
                "CRITICAL"
            ],

        "unknown_priorities":
            priority_counts[
                "UNKNOWN"
            ],

        "highest_finding_score":
            highest_finding_score,

        "highest_priority_score":
            highest_priority_score

    }


# ==========================================
# NORMALIZE SCORE
# ==========================================

def normalize_score(
    value
):
    """
    Normalize numeric score into 0-100.
    """

    try:

        score = float(
            value
        )

    except (
        TypeError,
        ValueError
    ):

        return 0


    if score < 0:

        return 0


    if score > 100:

        return 100


    if score.is_integer():

        return int(
            score
        )


    return round(
        score,
        2
    )


# ==========================================
# NORMALIZE SEVERITY
# ==========================================

def normalize_severity(
    value
):
    """
    Normalize severity value.
    """

    normalized = (
        normalize_string(
            value,
            default="UNKNOWN"
        )
        .upper()
    )


    if normalized not in (
        VALID_SEVERITIES
    ):

        return "UNKNOWN"


    return normalized


# ==========================================
# NORMALIZE PRIORITY LEVEL
# ==========================================

def normalize_priority_level(
    value
):
    """
    Normalize priority level.
    """

    normalized = (
        normalize_string(
            value,
            default="UNKNOWN"
        )
        .upper()
    )


    if normalized not in (
        VALID_PRIORITY_LEVELS
    ):

        return "UNKNOWN"


    return normalized


# ==========================================
# NORMALIZE CONFIDENCE
# ==========================================

def normalize_confidence(
    value
):
    """
    Normalize confidence level.
    """

    normalized = (
        normalize_string(
            value,
            default="UNKNOWN"
        )
        .upper()
    )


    if normalized not in (
        VALID_CONFIDENCE_LEVELS
    ):

        return "UNKNOWN"


    return normalized


# ==========================================
# NORMALIZE EVIDENCE
# ==========================================

def normalize_evidence(
    evidence
):
    """
    Normalize and deduplicate evidence
    strings while preserving order.
    """

    if not isinstance(
        evidence,
        list
    ):

        return []


    normalized = []

    seen = set()


    for item in evidence:

        text = (
            normalize_string(
                item
            )
        )


        if not text:

            continue


        key = (
            text.lower()
        )


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
# NORMALIZE IDENTIFIER LIST
# ==========================================

def normalize_identifier_list(
    values
):
    """
    Normalize and deduplicate identifier
    values while preserving order.
    """

    if not isinstance(
        values,
        list
    ):

        return []


    normalized = []

    seen = set()


    for value in values:

        identifier = (
            normalize_string(
                value
            )
        )


        if not identifier:

            continue


        if identifier in seen:

            continue


        seen.add(
            identifier
        )


        normalized.append(
            identifier
        )


    return normalized


# ==========================================
# NORMALIZE STRING
# ==========================================

def normalize_string(
    value,
    default=""
):
    """
    Normalize any value into a stripped
    string.
    """

    if value is None:

        return default


    try:

        value = str(
            value
        ).strip()

    except Exception:

        return default


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
    Normalize a string while preserving
    missing values as None.
    """

    normalized = (
        normalize_string(
            value
        )
    )


    if not normalized:

        return None


    return normalized