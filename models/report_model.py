"""
AttackLens
Report Model

This module defines the normalized structure used by the
Reports and PDF generation pipeline.

The report model does not perform security analysis.

Its responsibility is to organize and normalize data produced
by existing AttackLens modules such as:

- Asset Inventory
- Vulnerability / Risk Analysis
- Attack Path Analysis
- Defense Analysis
- Mitigation
- Risk Comparison

The resulting document can then be consumed by:

- Reports UI
- PDF generation service
- Report history storage
"""

from datetime import (
    datetime,
    timezone
)

from uuid import uuid4


# ============================================================
# REPORT CONSTANTS
# ============================================================

REPORT_TYPE_SECURITY_ASSESSMENT = "security_assessment"

REPORT_STATUS_READY = "ready"

REPORT_STATUS_NOT_READY = "not_ready"

REPORT_VERSION = "1.0"


# ============================================================
# MAIN REPORT DOCUMENT
# ============================================================

def create_report_document(
    created_by=None,
    report_id=None,
    title=None,
    scope=None,
    executive_summary=None,
    assets=None,
    vulnerability_summary=None,
    attack_path_analysis=None,
    defense_analysis=None,
    mitigation_analysis=None,
    risk_comparison=None,
    readiness=None,
    statistics=None,
    generated_at=None
):
    """
    Create a normalized AttackLens report document.

    The report document acts as the central structure shared
    between the Reports UI and PDF generation service.
    """

    normalized_report_id = normalize_identifier(
        report_id
    )

    if not normalized_report_id:
        normalized_report_id = generate_report_id()

    normalized_generated_at = normalize_datetime(
        generated_at
    )

    if normalized_generated_at is None:
        normalized_generated_at = datetime.now(
            timezone.utc
        )

    normalized_title = normalize_string(
        title,
        default="AttackLens Security Assessment"
    )

    normalized_readiness = normalize_readiness(
        readiness
    )

    normalized_statistics = normalize_report_statistics(
        statistics
    )

    return {
        "report_id": normalized_report_id,

        "report_type":
            REPORT_TYPE_SECURITY_ASSESSMENT,

        "report_version":
            REPORT_VERSION,

        "title":
            normalized_title,

        "created_by":
            normalize_identifier(
                created_by
            ),

        "status":
            determine_report_status(
                normalized_readiness
            ),

        "scope":
            normalize_scope(
                scope
            ),

        "executive_summary":
            normalize_executive_summary(
                executive_summary
            ),

        "sections": {
            "assets":
                normalize_assets(
                    assets
                ),

            "vulnerability_summary":
                normalize_dictionary(
                    vulnerability_summary
                ),

            "attack_path_analysis":
                normalize_dictionary(
                    attack_path_analysis
                ),

            "defense_analysis":
                normalize_dictionary(
                    defense_analysis
                ),

            "mitigation_analysis":
                normalize_dictionary(
                    mitigation_analysis
                ),

            "risk_comparison":
                normalize_dictionary(
                    risk_comparison
                )
        },

        "readiness":
            normalized_readiness,

        "statistics":
            normalized_statistics,

        "generated_at":
            normalized_generated_at
    }


# ============================================================
# REPORT SCOPE
# ============================================================

def create_report_scope(
    asset_count=0,
    target_count=0,
    targets=None,
    analysis_source=None
):
    """
    Create report scope information.

    Scope describes which authorized environment data is
    represented by the report.
    """

    return {
        "asset_count":
            normalize_non_negative_integer(
                asset_count
            ),

        "target_count":
            normalize_non_negative_integer(
                target_count
            ),

        "targets":
            normalize_string_list(
                targets
            ),

        "analysis_source":
            normalize_string(
                analysis_source,
                default="AttackLens Analysis"
            )
    }


def normalize_scope(
    scope
):
    """
    Normalize a report scope dictionary.
    """

    if not isinstance(
        scope,
        dict
    ):
        return create_report_scope()

    return create_report_scope(
        asset_count=scope.get(
            "asset_count",
            0
        ),

        target_count=scope.get(
            "target_count",
            0
        ),

        targets=scope.get(
            "targets",
            []
        ),

        analysis_source=scope.get(
            "analysis_source",
            "AttackLens Analysis"
        )
    )


# ============================================================
# EXECUTIVE SUMMARY
# ============================================================

def create_executive_summary(
    overall_risk_score=0,
    overall_risk_level="LOW",
    asset_count=0,
    vulnerability_count=0,
    attack_path_count=0,
    defense_finding_count=0,
    recommendation_count=0,
    projected_risk_score=0,
    projected_risk_level="LOW",
    projected_reduction=0,
    projected_reduction_percentage=0
):
    """
    Create the executive summary used by the Reports UI
    and generated PDF.
    """

    return {
        "overall_risk_score":
            normalize_score(
                overall_risk_score
            ),

        "overall_risk_level":
            normalize_risk_level(
                overall_risk_level
            ),

        "asset_count":
            normalize_non_negative_integer(
                asset_count
            ),

        "vulnerability_count":
            normalize_non_negative_integer(
                vulnerability_count
            ),

        "attack_path_count":
            normalize_non_negative_integer(
                attack_path_count
            ),

        "defense_finding_count":
            normalize_non_negative_integer(
                defense_finding_count
            ),

        "recommendation_count":
            normalize_non_negative_integer(
                recommendation_count
            ),

        "projected_risk_score":
            normalize_score(
                projected_risk_score
            ),

        "projected_risk_level":
            normalize_risk_level(
                projected_risk_level
            ),

        "projected_reduction":
            normalize_non_negative_number(
                projected_reduction
            ),

        "projected_reduction_percentage":
            normalize_percentage(
                projected_reduction_percentage
            )
    }


def normalize_executive_summary(
    summary
):
    """
    Normalize executive summary data.
    """

    if not isinstance(
        summary,
        dict
    ):
        return create_executive_summary()

    return create_executive_summary(
        overall_risk_score=summary.get(
            "overall_risk_score",
            0
        ),

        overall_risk_level=summary.get(
            "overall_risk_level",
            "LOW"
        ),

        asset_count=summary.get(
            "asset_count",
            0
        ),

        vulnerability_count=summary.get(
            "vulnerability_count",
            0
        ),

        attack_path_count=summary.get(
            "attack_path_count",
            0
        ),

        defense_finding_count=summary.get(
            "defense_finding_count",
            0
        ),

        recommendation_count=summary.get(
            "recommendation_count",
            0
        ),

        projected_risk_score=summary.get(
            "projected_risk_score",
            0
        ),

        projected_risk_level=summary.get(
            "projected_risk_level",
            "LOW"
        ),

        projected_reduction=summary.get(
            "projected_reduction",
            0
        ),

        projected_reduction_percentage=summary.get(
            "projected_reduction_percentage",
            0
        )
    )


# ============================================================
# REPORT READINESS
# ============================================================

def create_report_readiness(
    asset_inventory=False,
    risk_assessment=False,
    attack_path_analysis=False,
    defense_analysis=False,
    mitigation_recommendations=False,
    risk_comparison=False,
    report_generation_available=False
):
    """
    Create readiness state for each report section.

    Readiness allows the Reports page to show which parts
    of the security assessment currently contain data.
    """

    return {
        "asset_inventory":
            normalize_boolean(
                asset_inventory
            ),

        "risk_assessment":
            normalize_boolean(
                risk_assessment
            ),

        "attack_path_analysis":
            normalize_boolean(
                attack_path_analysis
            ),

        "defense_analysis":
            normalize_boolean(
                defense_analysis
            ),

        "mitigation_recommendations":
            normalize_boolean(
                mitigation_recommendations
            ),

        "risk_comparison":
            normalize_boolean(
                risk_comparison
            ),

        "report_generation_available":
            normalize_boolean(
                report_generation_available
            )
    }


def normalize_readiness(
    readiness
):
    """
    Normalize readiness state.
    """

    if not isinstance(
        readiness,
        dict
    ):
        return create_report_readiness()

    return create_report_readiness(
        asset_inventory=readiness.get(
            "asset_inventory",
            False
        ),

        risk_assessment=readiness.get(
            "risk_assessment",
            False
        ),

        attack_path_analysis=readiness.get(
            "attack_path_analysis",
            False
        ),

        defense_analysis=readiness.get(
            "defense_analysis",
            False
        ),

        mitigation_recommendations=readiness.get(
            "mitigation_recommendations",
            False
        ),

        risk_comparison=readiness.get(
            "risk_comparison",
            False
        ),

        report_generation_available=readiness.get(
            "report_generation_available",
            False
        )
    )


# ============================================================
# REPORT STATISTICS
# ============================================================

def create_report_statistics(
    total_assets=0,
    total_vulnerabilities=0,
    vulnerable_assets=0,
    open_ports=0,
    attack_paths=0,
    high_risk_attack_paths=0,
    defense_findings=0,
    recommendations=0,
    current_risk_score=0,
    current_risk_level="LOW",
    projected_risk_score=0,
    projected_risk_level="LOW",
    risk_reduction=0,
    risk_reduction_percentage=0
):
    """
    Create normalized summary statistics for a report.
    """

    return {
        "total_assets":
            normalize_non_negative_integer(
                total_assets
            ),

        "total_vulnerabilities":
            normalize_non_negative_integer(
                total_vulnerabilities
            ),

        "vulnerable_assets":
            normalize_non_negative_integer(
                vulnerable_assets
            ),

        "open_ports":
            normalize_non_negative_integer(
                open_ports
            ),

        "attack_paths":
            normalize_non_negative_integer(
                attack_paths
            ),

        "high_risk_attack_paths":
            normalize_non_negative_integer(
                high_risk_attack_paths
            ),

        "defense_findings":
            normalize_non_negative_integer(
                defense_findings
            ),

        "recommendations":
            normalize_non_negative_integer(
                recommendations
            ),

        "current_risk_score":
            normalize_score(
                current_risk_score
            ),

        "current_risk_level":
            normalize_risk_level(
                current_risk_level
            ),

        "projected_risk_score":
            normalize_score(
                projected_risk_score
            ),

        "projected_risk_level":
            normalize_risk_level(
                projected_risk_level
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


def normalize_report_statistics(
    statistics
):
    """
    Normalize report statistics.
    """

    if not isinstance(
        statistics,
        dict
    ):
        return create_report_statistics()

    return create_report_statistics(
        total_assets=statistics.get(
            "total_assets",
            0
        ),

        total_vulnerabilities=statistics.get(
            "total_vulnerabilities",
            0
        ),

        vulnerable_assets=statistics.get(
            "vulnerable_assets",
            0
        ),

        open_ports=statistics.get(
            "open_ports",
            0
        ),

        attack_paths=statistics.get(
            "attack_paths",
            0
        ),

        high_risk_attack_paths=statistics.get(
            "high_risk_attack_paths",
            0
        ),

        defense_findings=statistics.get(
            "defense_findings",
            0
        ),

        recommendations=statistics.get(
            "recommendations",
            0
        ),

        current_risk_score=statistics.get(
            "current_risk_score",
            0
        ),

        current_risk_level=statistics.get(
            "current_risk_level",
            "LOW"
        ),

        projected_risk_score=statistics.get(
            "projected_risk_score",
            0
        ),

        projected_risk_level=statistics.get(
            "projected_risk_level",
            "LOW"
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


# ============================================================
# REPORT STATUS
# ============================================================

def determine_report_status(
    readiness
):
    """
    Determine whether enough analysis data exists to
    generate a report.
    """

    if not isinstance(
        readiness,
        dict
    ):
        return REPORT_STATUS_NOT_READY

    if readiness.get(
        "report_generation_available"
    ):
        return REPORT_STATUS_READY

    return REPORT_STATUS_NOT_READY


# ============================================================
# ASSET NORMALIZATION
# ============================================================

def normalize_assets(
    assets
):
    """
    Normalize the report asset collection.

    Existing asset dictionaries are intentionally preserved
    because they already contain normalized AttackLens data
    produced by the asset pipeline.
    """

    if not isinstance(
        assets,
        list
    ):
        return []

    normalized_assets = []

    for asset in assets:

        if not isinstance(
            asset,
            dict
        ):
            continue

        normalized_assets.append(
            normalize_dictionary(
                asset
            )
        )

    return normalized_assets


# ============================================================
# GENERIC DICTIONARY NORMALIZATION
# ============================================================

def normalize_dictionary(
    value
):
    """
    Safely normalize dictionaries and nested values.

    This also converts MongoDB-specific values and other
    unsupported objects into safe representations where
    necessary.
    """

    if not isinstance(
        value,
        dict
    ):
        return {}

    normalized = {}

    for key, item in value.items():

        normalized_key = str(
            key
        )

        normalized[
            normalized_key
        ] = normalize_value(
            item
        )

    return normalized


def normalize_value(
    value
):
    """
    Recursively normalize values contained in report data.
    """

    if value is None:
        return None

    if isinstance(
        value,
        bool
    ):
        return value

    if isinstance(
        value,
        (
            int,
            float,
            str
        )
    ):
        return value

    if isinstance(
        value,
        datetime
    ):
        return value

    if isinstance(
        value,
        dict
    ):
        return normalize_dictionary(
            value
        )

    if isinstance(
        value,
        (
            list,
            tuple,
            set
        )
    ):

        return [
            normalize_value(
                item
            )
            for item in value
        ]

    return str(
        value
    )


# ============================================================
# IDENTIFIER HELPERS
# ============================================================

def generate_report_id():
    """
    Generate a unique report identifier.
    """

    return str(
        uuid4()
    )


def normalize_identifier(
    value
):
    """
    Normalize user, report, or database identifiers.
    """

    if value is None:
        return None

    normalized = str(
        value
    ).strip()

    if not normalized:
        return None

    return normalized


# ============================================================
# STRING HELPERS
# ============================================================

def normalize_string(
    value,
    default=""
):
    """
    Normalize general string values.
    """

    if value is None:
        return default

    normalized = str(
        value
    ).strip()

    if not normalized:
        return default

    return normalized


def normalize_string_list(
    values
):
    """
    Normalize a list of strings while removing duplicates.
    """

    if not isinstance(
        values,
        (
            list,
            tuple,
            set
        )
    ):
        return []

    normalized_values = []

    seen = set()

    for value in values:

        normalized = normalize_string(
            value
        )

        if not normalized:
            continue

        if normalized in seen:
            continue

        seen.add(
            normalized
        )

        normalized_values.append(
            normalized
        )

    return normalized_values


# ============================================================
# BOOLEAN NORMALIZATION
# ============================================================

def normalize_boolean(
    value
):
    """
    Normalize boolean values.
    """

    if isinstance(
        value,
        bool
    ):
        return value

    if isinstance(
        value,
        str
    ):

        normalized = value.strip().lower()

        if normalized in {
            "true",
            "1",
            "yes",
            "y"
        }:
            return True

        if normalized in {
            "false",
            "0",
            "no",
            "n"
        }:
            return False

    if isinstance(
        value,
        (
            int,
            float
        )
    ):
        return value != 0

    return False


# ============================================================
# NUMBER NORMALIZATION
# ============================================================

def normalize_non_negative_number(
    value
):
    """
    Normalize numeric values and prevent negative values.
    """

    try:
        normalized = float(
            value
        )

    except (
        TypeError,
        ValueError
    ):
        return 0.0

    if normalized < 0:
        return 0.0

    return round(
        normalized,
        2
    )


def normalize_non_negative_integer(
    value
):
    """
    Normalize integer values and prevent negative values.
    """

    try:
        normalized = int(
            value
        )

    except (
        TypeError,
        ValueError
    ):
        return 0

    if normalized < 0:
        return 0

    return normalized


def normalize_score(
    value
):
    """
    Normalize a security risk score to the AttackLens
    0-100 range.
    """

    try:
        score = float(
            value
        )

    except (
        TypeError,
        ValueError
    ):
        return 0.0

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


def normalize_percentage(
    value
):
    """
    Normalize percentage values to the 0-100 range.
    """

    try:
        percentage = float(
            value
        )

    except (
        TypeError,
        ValueError
    ):
        return 0.0

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


# ============================================================
# RISK LEVEL NORMALIZATION
# ============================================================

def normalize_risk_level(
    value
):
    """
    Normalize AttackLens risk classifications.

    Supported levels:

    LOW
    MEDIUM
    HIGH
    CRITICAL
    """

    normalized = normalize_string(
        value,
        default="LOW"
    ).upper()

    valid_levels = {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    }

    if normalized not in valid_levels:
        return "LOW"

    return normalized


# ============================================================
# DATETIME NORMALIZATION
# ============================================================

def normalize_datetime(
    value
):
    """
    Normalize report generation timestamps.
    """

    if isinstance(
        value,
        datetime
    ):

        if value.tzinfo is None:

            return value.replace(
                tzinfo=timezone.utc
            )

        return value

    return None