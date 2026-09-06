"""
AttackLens
Report Service

This service gathers the output of existing AttackLens analysis
modules and converts them into one normalized report document.

Pipeline:

Assets
    ↓
Attack Path Analysis
    ↓
Defense Analysis
    ↓
Mitigation Recommendations
    ↓
Risk Comparison
    ↓
Report Service
    ↓
Normalized Report Document

This module does not perform PDF rendering. PDF generation is
handled separately by services/pdf_service.py.
"""

from models.report_model import (
    create_report_document,
    create_report_scope,
    create_executive_summary,
    create_report_readiness,
    create_report_statistics
)

from services.attack_path_service import (
    generate_attack_graph
)

from services.defense_analysis_service import (
    generate_defense_analysis
)

from services.mitigation_service import (
    generate_mitigation_recommendations
)

from services.risk_comparison_service import (
    generate_risk_comparison
)


# ============================================================
# MAIN REPORT GENERATOR
# ============================================================

def generate_report_data(
    assets=None,
    attack_graph=None,
    defense_analysis=None,
    mitigation_analysis=None,
    risk_comparison=None,
    created_by=None
):
    """
    Generate the complete normalized AttackLens report data.

    Existing analysis results may be supplied by the caller.

    If they are not supplied, this service invokes the existing
    AttackLens analysis pipeline in the correct order.

    The returned document is suitable for:

    - Reports page
    - PDF generation
    - Future report-history storage
    """

    assets = normalize_assets(
        assets
    )

    # --------------------------------------------------------
    # ATTACK PATH ANALYSIS
    # --------------------------------------------------------

    if not isinstance(
        attack_graph,
        dict
    ):
        attack_graph = generate_attack_graph(
            assets=assets,
            created_by=created_by
        )

    attack_graph = normalize_document(
        attack_graph
    )

    # --------------------------------------------------------
    # DEFENSE ANALYSIS
    # --------------------------------------------------------

    if not isinstance(
        defense_analysis,
        dict
    ):
        defense_analysis = generate_defense_analysis(
            assets=assets,
            attack_graph=attack_graph,
            created_by=created_by
        )

    defense_analysis = normalize_document(
        defense_analysis
    )

    # --------------------------------------------------------
    # MITIGATION ANALYSIS
    # --------------------------------------------------------

    if not isinstance(
        mitigation_analysis,
        dict
    ):
        mitigation_analysis = (
            generate_mitigation_recommendations(
                assets=assets,
                attack_graph=attack_graph,
                defense_analysis=defense_analysis,
                created_by=created_by
            )
        )

    mitigation_analysis = normalize_document(
        mitigation_analysis
    )

    # --------------------------------------------------------
    # RISK COMPARISON
    # --------------------------------------------------------

    if not isinstance(
        risk_comparison,
        dict
    ):
        risk_comparison = generate_risk_comparison(
            assets=assets,
            attack_graph=attack_graph,
            defense_analysis=defense_analysis,
            mitigation_analysis=mitigation_analysis,
            created_by=created_by
        )

    risk_comparison = normalize_document(
        risk_comparison
    )

    # --------------------------------------------------------
    # REPORT COMPONENTS
    # --------------------------------------------------------

    vulnerability_summary = build_vulnerability_summary(
        assets
    )

    readiness = build_report_readiness(
        assets=assets,
        attack_graph=attack_graph,
        defense_analysis=defense_analysis,
        mitigation_analysis=mitigation_analysis,
        risk_comparison=risk_comparison
    )

    statistics = build_report_statistics(
        assets=assets,
        attack_graph=attack_graph,
        defense_analysis=defense_analysis,
        mitigation_analysis=mitigation_analysis,
        risk_comparison=risk_comparison
    )

    executive_summary = build_executive_summary(
        statistics
    )

    scope = build_report_scope(
        assets
    )

    # --------------------------------------------------------
    # FINAL REPORT
    # --------------------------------------------------------

    return create_report_document(
        created_by=created_by,
        title="AttackLens Security Assessment",
        scope=scope,
        executive_summary=executive_summary,
        assets=assets,
        vulnerability_summary=vulnerability_summary,
        attack_path_analysis=attack_graph,
        defense_analysis=defense_analysis,
        mitigation_analysis=mitigation_analysis,
        risk_comparison=risk_comparison,
        readiness=readiness,
        statistics=statistics
    )


# ============================================================
# REPORT SCOPE
# ============================================================

def build_report_scope(
    assets
):
    """
    Build the authorized environment scope represented
    by the report.
    """

    targets = []

    for asset in assets:

        target = get_asset_target(
            asset
        )

        if target and target not in targets:
            targets.append(
                target
            )

    return create_report_scope(
        asset_count=len(
            assets
        ),
        target_count=len(
            targets
        ),
        targets=targets,
        analysis_source="AttackLens Analysis"
    )


# ============================================================
# EXECUTIVE SUMMARY
# ============================================================

def build_executive_summary(
    statistics
):
    """
    Build a compact executive summary from normalized
    report statistics.
    """

    statistics = normalize_document(
        statistics
    )

    return create_executive_summary(
        overall_risk_score=statistics.get(
            "current_risk_score",
            0
        ),

        overall_risk_level=statistics.get(
            "current_risk_level",
            "LOW"
        ),

        asset_count=statistics.get(
            "total_assets",
            0
        ),

        vulnerability_count=statistics.get(
            "total_vulnerabilities",
            0
        ),

        attack_path_count=statistics.get(
            "attack_paths",
            0
        ),

        defense_finding_count=statistics.get(
            "defense_findings",
            0
        ),

        recommendation_count=statistics.get(
            "recommendations",
            0
        ),

        projected_risk_score=statistics.get(
            "projected_risk_score",
            0
        ),

        projected_risk_level=statistics.get(
            "projected_risk_level",
            "LOW"
        ),

        projected_reduction=statistics.get(
            "risk_reduction",
            0
        ),

        projected_reduction_percentage=statistics.get(
            "risk_reduction_percentage",
            0
        )
    )


# ============================================================
# REPORT READINESS
# ============================================================

def build_report_readiness(
    assets,
    attack_graph,
    defense_analysis,
    mitigation_analysis,
    risk_comparison
):
    """
    Determine which report sections are available.

    Important:

    A valid analysis containing zero attack paths or zero
    vulnerabilities is still considered completed analysis.

    Report generation requires at least one authorized asset.
    """

    has_assets = bool(
        assets
    )

    attack_path_ready = (
        has_assets
        and isinstance(
            attack_graph,
            dict
        )
    )

    defense_ready = (
        has_assets
        and isinstance(
            defense_analysis,
            dict
        )
    )

    mitigation_ready = (
        has_assets
        and isinstance(
            mitigation_analysis,
            dict
        )
    )

    comparison_ready = (
        has_assets
        and isinstance(
            risk_comparison,
            dict
        )
    )

    return create_report_readiness(
        asset_inventory=has_assets,
        risk_assessment=has_assets,
        attack_path_analysis=attack_path_ready,
        defense_analysis=defense_ready,
        mitigation_recommendations=mitigation_ready,
        risk_comparison=comparison_ready,

        # A report may legitimately contain:
        # 0 vulnerabilities
        # 0 attack paths
        # 0 recommendations
        #
        # Therefore generation depends on the presence of
        # authorized asset analysis rather than positive
        # finding counts.
        report_generation_available=has_assets
    )


# ============================================================
# REPORT STATISTICS
# ============================================================

def build_report_statistics(
    assets,
    attack_graph,
    defense_analysis,
    mitigation_analysis,
    risk_comparison
):
    """
    Build the summary statistics displayed on the Reports page
    and used by the PDF executive summary.
    """

    current_state = get_dictionary(
        risk_comparison,
        "current_state"
    )

    projected_state = get_dictionary(
        risk_comparison,
        "projected_state"
    )

    reduction = get_dictionary(
        risk_comparison,
        "reduction"
    )

    comparison_statistics = get_dictionary(
        risk_comparison,
        "statistics"
    )

    total_assets = safe_integer(
        current_state.get(
            "total_assets",
            len(
                assets
            )
        )
    )

    total_vulnerabilities = safe_integer(
        current_state.get(
            "vulnerability_count",
            0
        )
    )

    vulnerable_assets = safe_integer(
        current_state.get(
            "vulnerable_assets",
            0
        )
    )

    open_ports = safe_integer(
        current_state.get(
            "open_ports",
            count_open_ports(
                assets
            )
        )
    )

    attack_paths = safe_integer(
        current_state.get(
            "attack_paths",
            count_attack_paths(
                attack_graph
            )
        )
    )

    high_risk_attack_paths = safe_integer(
        current_state.get(
            "high_risk_attack_paths",
            0
        )
    )

    defense_findings = count_defense_findings(
        defense_analysis
    )

    recommendations = count_recommendations(
        mitigation_analysis
    )

    current_risk_score = safe_number(
        current_state.get(
            "risk_score",
            0
        )
    )

    current_risk_level = safe_risk_level(
        current_state.get(
            "risk_level",
            "LOW"
        )
    )

    projected_risk_score = safe_number(
        projected_state.get(
            "risk_score",
            current_risk_score
        )
    )

    projected_risk_level = safe_risk_level(
        projected_state.get(
            "risk_level",
            current_risk_level
        )
    )

    risk_reduction = safe_number(
        comparison_statistics.get(
            "risk_reduction",
            reduction.get(
                "risk_points",
                0
            )
        )
    )

    risk_reduction_percentage = safe_number(
        comparison_statistics.get(
            "risk_reduction_percentage",
            reduction.get(
                "risk_percentage",
                0
            )
        )
    )

    return create_report_statistics(
        total_assets=total_assets,
        total_vulnerabilities=total_vulnerabilities,
        vulnerable_assets=vulnerable_assets,
        open_ports=open_ports,
        attack_paths=attack_paths,
        high_risk_attack_paths=high_risk_attack_paths,
        defense_findings=defense_findings,
        recommendations=recommendations,
        current_risk_score=current_risk_score,
        current_risk_level=current_risk_level,
        projected_risk_score=projected_risk_score,
        projected_risk_level=projected_risk_level,
        risk_reduction=risk_reduction,
        risk_reduction_percentage=risk_reduction_percentage
    )


# ============================================================
# VULNERABILITY SUMMARY
# ============================================================

def build_vulnerability_summary(
    assets
):
    """
    Build a vulnerability summary from the asset inventory.

    The function remains conservative and does not fabricate
    vulnerability information.

    It only reports findings actually present on assets.
    """

    vulnerability_count = 0

    vulnerable_assets = 0

    affected_targets = []

    findings = []

    for asset in assets:

        asset_findings = get_asset_vulnerabilities(
            asset
        )

        if asset_findings:
            vulnerable_assets += 1

            target = get_asset_target(
                asset
            )

            if (
                target
                and target not in affected_targets
            ):
                affected_targets.append(
                    target
                )

        vulnerability_count += len(
            asset_findings
        )

        for finding in asset_findings:

            findings.append(
                {
                    "target":
                        get_asset_target(
                            asset
                        ),

                    "finding":
                        finding
                }
            )

    return {
        "vulnerability_count":
            vulnerability_count,

        "vulnerable_assets":
            vulnerable_assets,

        "affected_targets":
            affected_targets,

        "findings":
            findings
    }


# ============================================================
# ASSET HELPERS
# ============================================================

def get_asset_target(
    asset
):
    """
    Extract the primary target identifier from an asset.
    """

    if not isinstance(
        asset,
        dict
    ):
        return None

    possible_keys = (
        "target",
        "ip_address",
        "ip",
        "host"
    )

    for key in possible_keys:

        value = asset.get(
            key
        )

        if value is None:
            continue

        normalized = str(
            value
        ).strip()

        if normalized:
            return normalized

    return None


def get_asset_vulnerabilities(
    asset
):
    """
    Return vulnerability records explicitly present
    on an asset.

    Multiple historically used field names are supported,
    but nothing is inferred when no vulnerability data exists.
    """

    if not isinstance(
        asset,
        dict
    ):
        return []

    possible_keys = (
        "vulnerabilities",
        "cves",
        "findings"
    )

    for key in possible_keys:

        value = asset.get(
            key
        )

        if isinstance(
            value,
            list
        ):
            return [
                item
                for item in value
                if isinstance(
                    item,
                    dict
                )
            ]

    return []


def count_open_ports(
    assets
):
    """
    Count open ports across assets.

    Ports are counted per asset. Duplicate representations of
    the same port on a single asset are counted once.
    """

    total = 0

    for asset in assets:

        if not isinstance(
            asset,
            dict
        ):
            continue

        ports = asset.get(
            "ports"
        )

        if not isinstance(
            ports,
            list
        ):
            continue

        open_ports = set()

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

            port = port_data.get(
                "port"
            )

            try:
                port = int(
                    port
                )

            except (
                TypeError,
                ValueError
            ):
                continue

            if 1 <= port <= 65535:
                open_ports.add(
                    port
                )

        total += len(
            open_ports
        )

    return total


# ============================================================
# ATTACK PATH HELPERS
# ============================================================

def count_attack_paths(
    attack_graph
):
    """
    Count attack paths contained in an attack graph.
    """

    paths = get_list(
        attack_graph,
        "paths"
    )

    return len(
        paths
    )


# ============================================================
# DEFENSE ANALYSIS HELPERS
# ============================================================

def count_defense_findings(
    defense_analysis
):
    """
    Count defense-analysis findings.
    """

    findings = get_list(
        defense_analysis,
        "findings"
    )

    if findings:
        return len(
            findings
        )

    statistics = get_dictionary(
        defense_analysis,
        "statistics"
    )

    return safe_integer(
        statistics.get(
            "finding_count",
            statistics.get(
                "findings",
                0
            )
        )
    )


# ============================================================
# MITIGATION HELPERS
# ============================================================

def count_recommendations(
    mitigation_analysis
):
    """
    Count mitigation recommendations.
    """

    recommendations = get_list(
        mitigation_analysis,
        "recommendations"
    )

    if recommendations:
        return len(
            recommendations
        )

    statistics = get_dictionary(
        mitigation_analysis,
        "statistics"
    )

    return safe_integer(
        statistics.get(
            "recommendation_count",
            statistics.get(
                "recommendations",
                0
            )
        )
    )


# ============================================================
# COLLECTION NORMALIZATION
# ============================================================

def normalize_assets(
    assets
):
    """
    Safely normalize the asset collection without modifying
    existing working asset documents.
    """

    if not isinstance(
        assets,
        list
    ):
        return []

    normalized = []

    for asset in assets:

        if not isinstance(
            asset,
            dict
        ):
            continue

        normalized.append(
            asset
        )

    return normalized


def normalize_document(
    document
):
    """
    Ensure an analysis result is represented as a dictionary.
    """

    if isinstance(
        document,
        dict
    ):
        return document

    return {}


# ============================================================
# DICTIONARY HELPERS
# ============================================================

def get_dictionary(
    document,
    key
):
    """
    Safely retrieve a nested dictionary.
    """

    if not isinstance(
        document,
        dict
    ):
        return {}

    value = document.get(
        key
    )

    if not isinstance(
        value,
        dict
    ):
        return {}

    return value


def get_list(
    document,
    key
):
    """
    Safely retrieve a nested list.
    """

    if not isinstance(
        document,
        dict
    ):
        return []

    value = document.get(
        key
    )

    if not isinstance(
        value,
        list
    ):
        return []

    return value


# ============================================================
# NUMBER HELPERS
# ============================================================

def safe_integer(
    value
):
    """
    Convert a value to a non-negative integer.
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

    return max(
        0,
        normalized
    )


def safe_number(
    value
):
    """
    Convert a value to a non-negative floating-point number.
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

    normalized = max(
        0.0,
        normalized
    )

    return round(
        normalized,
        2
    )


# ============================================================
# RISK LEVEL HELPER
# ============================================================

def safe_risk_level(
    value
):
    """
    Normalize an AttackLens risk level.
    """

    normalized = str(
        value or "LOW"
    ).strip().upper()

    valid_levels = {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    }

    if normalized not in valid_levels:
        return "LOW"

    return normalized