# ==========================================
# MITIGATION RECOMMENDATION MODEL
# ==========================================
#
# This module defines the structured data
# representation used by the AttackLens
# Mitigation Recommendation Engine.
#
# It contains no Flask or database logic.
# ==========================================


from datetime import (
    datetime,
    timezone
)


# ==========================================
# CREATE MITIGATION DOCUMENT
# ==========================================

def create_mitigation_document(
    created_by=None,
    recommendations=None,
    statistics=None
):
    """
    Create the complete mitigation analysis
    document returned by the mitigation engine.
    """

    recommendations = normalize_list(
        recommendations
    )

    if statistics is None:

        statistics = (
            create_mitigation_statistics(
                recommendations
            )
        )

    return {

        "created_by":
            created_by,

        "generated_at":
            datetime.now(
                timezone.utc
            ),

        "recommendations":
            recommendations,

        "statistics":
            statistics
    }


# ==========================================
# CREATE MITIGATION RECOMMENDATION
# ==========================================

def create_mitigation_recommendation(
    recommendation_id,
    category,
    title,
    description,
    target=None,
    asset_id=None,
    priority_level="LOW",
    score=0,
    confidence="LOW",
    evidence=None,
    actions=None,
    expected_effect=None,
    related_finding_ids=None,
    related_cves=None,
    related_ports=None,
    related_path_ids=None
):
    """
    Create one normalized mitigation
    recommendation.
    """

    return {

        "id":
            normalize_string(
                recommendation_id
            ),

        "category":
            normalize_string(
                category
            ),

        "title":
            normalize_string(
                title
            ),

        "description":
            normalize_string(
                description
            ),

        "target":
            normalize_nullable_string(
                target
            ),

        "asset_id":
            normalize_nullable_string(
                asset_id
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

        "evidence":
            normalize_string_list(
                evidence
            ),

        "actions":
            normalize_string_list(
                actions
            ),

        "expected_effect":
            normalize_nullable_string(
                expected_effect
            ),

        "related_finding_ids":
            normalize_identifier_list(
                related_finding_ids
            ),

        "related_cves":
            normalize_identifier_list(
                related_cves
            ),

        "related_ports":
            normalize_port_list(
                related_ports
            ),

        "related_path_ids":
            normalize_identifier_list(
                related_path_ids
            )
    }


# ==========================================
# CREATE MITIGATION STATISTICS
# ==========================================

def create_mitigation_statistics(
    recommendations=None
):
    """
    Build summary statistics from a list of
    mitigation recommendations.
    """

    recommendations = normalize_list(
        recommendations
    )

    statistics = {

        "total_recommendations":
            len(
                recommendations
            ),

        "critical_recommendations":
            0,

        "high_recommendations":
            0,

        "medium_recommendations":
            0,

        "low_recommendations":
            0,

        "high_priority_recommendations":
            0,

        "affected_assets":
            0,

        "highest_score":
            0,

        "highest_priority":
            "NONE",

        "categories":
            {}
    }

    affected_assets = set()

    priority_rank = {
        "NONE": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    highest_priority_rank = 0

    for recommendation in recommendations:

        if not isinstance(
            recommendation,
            dict
        ):
            continue

        priority_level = (
            normalize_priority_level(
                recommendation.get(
                    "priority_level"
                )
            )
        )

        score = normalize_score(
            recommendation.get(
                "score"
            )
        )

        category = normalize_string(
            recommendation.get(
                "category"
            )
        )

        asset_id = (
            normalize_nullable_string(
                recommendation.get(
                    "asset_id"
                )
            )
        )

        target = (
            normalize_nullable_string(
                recommendation.get(
                    "target"
                )
            )
        )

        if priority_level == "CRITICAL":

            statistics[
                "critical_recommendations"
            ] += 1

        elif priority_level == "HIGH":

            statistics[
                "high_recommendations"
            ] += 1

        elif priority_level == "MEDIUM":

            statistics[
                "medium_recommendations"
            ] += 1

        else:

            statistics[
                "low_recommendations"
            ] += 1

        if priority_level in {
            "HIGH",
            "CRITICAL"
        }:

            statistics[
                "high_priority_recommendations"
            ] += 1

        statistics[
            "highest_score"
        ] = max(
            statistics[
                "highest_score"
            ],
            score
        )

        current_rank = (
            priority_rank.get(
                priority_level,
                0
            )
        )

        if current_rank > highest_priority_rank:

            highest_priority_rank = (
                current_rank
            )

            statistics[
                "highest_priority"
            ] = priority_level

        if category:

            statistics[
                "categories"
            ][category] = (
                statistics[
                    "categories"
                ].get(
                    category,
                    0
                )
                +
                1
            )

        asset_identity = (
            asset_id
            or
            target
        )

        if asset_identity:

            affected_assets.add(
                asset_identity
            )

    statistics[
        "affected_assets"
    ] = len(
        affected_assets
    )

    return statistics


# ==========================================
# NORMALIZE SCORE
# ==========================================

def normalize_score(
    value
):
    """
    Normalize a score to the inclusive
    range 0 - 100.
    """

    try:

        value = float(
            value
        )

    except (
        TypeError,
        ValueError
    ):

        return 0

    value = max(
        0,
        min(
            100,
            value
        )
    )

    return round(
        value,
        2
    )


# ==========================================
# NORMALIZE PRIORITY LEVEL
# ==========================================

def normalize_priority_level(
    value
):
    """
    Normalize mitigation priority level.
    """

    value = str(
        value
        or
        ""
    ).strip().upper()

    if value in {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    }:

        return value

    return "LOW"


# ==========================================
# NORMALIZE CONFIDENCE
# ==========================================

def normalize_confidence(
    value
):
    """
    Normalize recommendation confidence.
    """

    value = str(
        value
        or
        ""
    ).strip().upper()

    if value in {
        "LOW",
        "MEDIUM",
        "HIGH"
    }:

        return value

    return "LOW"


# ==========================================
# NORMALIZE STRING
# ==========================================

def normalize_string(
    value
):
    """
    Safely convert a value to a trimmed string.
    """

    if value is None:

        return ""

    return str(
        value
    ).strip()


# ==========================================
# NORMALIZE NULLABLE STRING
# ==========================================

def normalize_nullable_string(
    value
):
    """
    Return None for an empty string.
    """

    value = normalize_string(
        value
    )

    if not value:

        return None

    return value


# ==========================================
# NORMALIZE LIST
# ==========================================

def normalize_list(
    value
):
    """
    Return a safe list.
    """

    if isinstance(
        value,
        list
    ):

        return value

    if isinstance(
        value,
        tuple
    ):

        return list(
            value
        )

    return []


# ==========================================
# NORMALIZE STRING LIST
# ==========================================

def normalize_string_list(
    values
):
    """
    Normalize and deduplicate human-readable
    string values.
    """

    values = normalize_list(
        values
    )

    normalized = []

    seen = set()

    for value in values:

        text = normalize_string(
            value
        )

        if not text:

            continue

        if text in seen:

            continue

        seen.add(
            text
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
    Normalize IDs such as finding IDs,
    path IDs, and CVE identifiers.
    """

    return normalize_string_list(
        values
    )


# ==========================================
# NORMALIZE PORT LIST
# ==========================================

def normalize_port_list(
    values
):
    """
    Normalize network port numbers.
    """

    values = normalize_list(
        values
    )

    normalized = []

    seen = set()

    for value in values:

        try:

            port = int(
                value
            )

        except (
            TypeError,
            ValueError
        ):

            continue

        if port < 1 or port > 65535:

            continue

        if port in seen:

            continue

        seen.add(
            port
        )

        normalized.append(
            port
        )

    return sorted(
        normalized
    )