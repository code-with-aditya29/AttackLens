from datetime import datetime, timezone


# ==========================================
# RISK COMPARISON DOCUMENT
# ==========================================

def create_risk_comparison_document(
    current_state=None,
    projected_state=None,
    reduction=None,
    applied_recommendations=None,
    statistics=None,
    created_by=None
):
    """
    Create a normalized Before vs Projected
    After risk-comparison document.

    This model represents an analytical
    projection only. It does not indicate
    that mitigation actions were actually
    applied to the target environment.
    """

    return {
        "created_by": normalize_nullable_string(
            created_by
        ),

        "comparison_type":
            "current_vs_projected",

        "current_state":
            normalize_state(
                current_state
            ),

        "projected_state":
            normalize_state(
                projected_state
            ),

        "reduction":
            normalize_reduction(
                reduction
            ),

        "applied_recommendations":
            normalize_identifier_list(
                applied_recommendations
            ),

        "statistics":
            normalize_statistics(
                statistics
            ),

        "generated_at":
            datetime.now(
                timezone.utc
            )
    }


# ==========================================
# COMPARISON STATE
# ==========================================

def create_comparison_state(
    risk_score=0,
    risk_level="LOW",
    total_assets=0,
    vulnerable_assets=0,
    vulnerability_count=0,
    open_ports=0,
    sensitive_ports=0,
    attack_paths=0,
    high_risk_attack_paths=0
):
    """
    Create one side of the comparison:
    either current state or projected state.
    """

    return {
        "risk_score":
            normalize_score(
                risk_score
            ),

        "risk_level":
            normalize_risk_level(
                risk_level
            ),

        "total_assets":
            normalize_non_negative_integer(
                total_assets
            ),

        "vulnerable_assets":
            normalize_non_negative_integer(
                vulnerable_assets
            ),

        "vulnerability_count":
            normalize_non_negative_integer(
                vulnerability_count
            ),

        "open_ports":
            normalize_non_negative_integer(
                open_ports
            ),

        "sensitive_ports":
            normalize_non_negative_integer(
                sensitive_ports
            ),

        "attack_paths":
            normalize_non_negative_integer(
                attack_paths
            ),

        "high_risk_attack_paths":
            normalize_non_negative_integer(
                high_risk_attack_paths
            )
    }


# ==========================================
# REDUCTION RESULT
# ==========================================

def create_reduction_result(
    risk_points=0,
    risk_percentage=0,
    vulnerable_assets=0,
    vulnerability_count=0,
    open_ports=0,
    sensitive_ports=0,
    attack_paths=0,
    high_risk_attack_paths=0
):
    """
    Create normalized reduction metrics.
    """

    return {
        "risk_points":
            normalize_non_negative_number(
                risk_points
            ),

        "risk_percentage":
            normalize_percentage(
                risk_percentage
            ),

        "vulnerable_assets":
            normalize_non_negative_integer(
                vulnerable_assets
            ),

        "vulnerability_count":
            normalize_non_negative_integer(
                vulnerability_count
            ),

        "open_ports":
            normalize_non_negative_integer(
                open_ports
            ),

        "sensitive_ports":
            normalize_non_negative_integer(
                sensitive_ports
            ),

        "attack_paths":
            normalize_non_negative_integer(
                attack_paths
            ),

        "high_risk_attack_paths":
            normalize_non_negative_integer(
                high_risk_attack_paths
            )
    }


# ==========================================
# COMPARISON STATISTICS
# ==========================================

def create_comparison_statistics(
    recommendation_count=0,
    applicable_recommendations=0,
    affected_assets=0,
    current_risk_score=0,
    projected_risk_score=0,
    risk_reduction=0,
    risk_reduction_percentage=0
):
    """
    Create summary statistics for the
    comparison page.
    """

    return {
        "recommendation_count":
            normalize_non_negative_integer(
                recommendation_count
            ),

        "applicable_recommendations":
            normalize_non_negative_integer(
                applicable_recommendations
            ),

        "affected_assets":
            normalize_non_negative_integer(
                affected_assets
            ),

        "current_risk_score":
            normalize_score(
                current_risk_score
            ),

        "projected_risk_score":
            normalize_score(
                projected_risk_score
            ),

        "risk_reduction":
            normalize_non_negative_number(
                risk_reduction
            ),

        "risk_reduction_percentage":
            normalize_percentage(
                risk_reduction_percentage
            )
    }


# ==========================================
# NORMALIZE STATE
# ==========================================

def normalize_state(
    state
):

    if not isinstance(
        state,
        dict
    ):

        return create_comparison_state()

    return create_comparison_state(
        risk_score=state.get(
            "risk_score",
            0
        ),
        risk_level=state.get(
            "risk_level",
            "LOW"
        ),
        total_assets=state.get(
            "total_assets",
            0
        ),
        vulnerable_assets=state.get(
            "vulnerable_assets",
            0
        ),
        vulnerability_count=state.get(
            "vulnerability_count",
            0
        ),
        open_ports=state.get(
            "open_ports",
            0
        ),
        sensitive_ports=state.get(
            "sensitive_ports",
            0
        ),
        attack_paths=state.get(
            "attack_paths",
            0
        ),
        high_risk_attack_paths=state.get(
            "high_risk_attack_paths",
            0
        )
    )


# ==========================================
# NORMALIZE REDUCTION
# ==========================================

def normalize_reduction(
    reduction
):

    if not isinstance(
        reduction,
        dict
    ):

        return create_reduction_result()

    return create_reduction_result(
        risk_points=reduction.get(
            "risk_points",
            0
        ),
        risk_percentage=reduction.get(
            "risk_percentage",
            0
        ),
        vulnerable_assets=reduction.get(
            "vulnerable_assets",
            0
        ),
        vulnerability_count=reduction.get(
            "vulnerability_count",
            0
        ),
        open_ports=reduction.get(
            "open_ports",
            0
        ),
        sensitive_ports=reduction.get(
            "sensitive_ports",
            0
        ),
        attack_paths=reduction.get(
            "attack_paths",
            0
        ),
        high_risk_attack_paths=reduction.get(
            "high_risk_attack_paths",
            0
        )
    )


# ==========================================
# NORMALIZE STATISTICS
# ==========================================

def normalize_statistics(
    statistics
):

    if not isinstance(
        statistics,
        dict
    ):

        return create_comparison_statistics()

    return create_comparison_statistics(
        recommendation_count=statistics.get(
            "recommendation_count",
            0
        ),
        applicable_recommendations=statistics.get(
            "applicable_recommendations",
            0
        ),
        affected_assets=statistics.get(
            "affected_assets",
            0
        ),
        current_risk_score=statistics.get(
            "current_risk_score",
            0
        ),
        projected_risk_score=statistics.get(
            "projected_risk_score",
            0
        ),
        risk_reduction=statistics.get(
            "risk_reduction",
            0
        ),
        risk_reduction_percentage=statistics.get(
            "risk_reduction_percentage",
            0
        )
    )


# ==========================================
# NORMALIZE SCORE
# ==========================================

def normalize_score(
    value
):

    try:

        score = float(
            value
        )

    except (
        TypeError,
        ValueError
    ):

        score = 0.0

    score = max(
        0.0,
        min(
            100.0,
            score
        )
    )

    return round(
        score,
        2
    )


# ==========================================
# NORMALIZE RISK LEVEL
# ==========================================

def normalize_risk_level(
    value
):

    level = normalize_string(
        value
    ).upper()

    allowed_levels = {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    }

    if level not in allowed_levels:

        return "LOW"

    return level


# ==========================================
# NORMALIZE PERCENTAGE
# ==========================================

def normalize_percentage(
    value
):

    try:

        percentage = float(
            value
        )

    except (
        TypeError,
        ValueError
    ):

        percentage = 0.0

    percentage = max(
        0.0,
        min(
            100.0,
            percentage
        )
    )

    return round(
        percentage,
        2
    )


# ==========================================
# NORMALIZE NON-NEGATIVE NUMBER
# ==========================================

def normalize_non_negative_number(
    value
):

    try:

        number = float(
            value
        )

    except (
        TypeError,
        ValueError
    ):

        number = 0.0

    number = max(
        0.0,
        number
    )

    return round(
        number,
        2
    )


# ==========================================
# NORMALIZE NON-NEGATIVE INTEGER
# ==========================================

def normalize_non_negative_integer(
    value
):

    try:

        number = int(
            value
        )

    except (
        TypeError,
        ValueError
    ):

        number = 0

    return max(
        0,
        number
    )


# ==========================================
# NORMALIZE IDENTIFIER LIST
# ==========================================

def normalize_identifier_list(
    values
):

    if not isinstance(
        values,
        (
            list,
            tuple,
            set
        )
    ):

        return []

    normalized = []

    seen = set()

    for value in values:

        item = normalize_string(
            value
        )

        if (
            item
            and item not in seen
        ):

            seen.add(
                item
            )

            normalized.append(
                item
            )

    return normalized


# ==========================================
# NORMALIZE STRING
# ==========================================

def normalize_string(
    value
):

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

    normalized = normalize_string(
        value
    )

    if not normalized:

        return None

    return normalized