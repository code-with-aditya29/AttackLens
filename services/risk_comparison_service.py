# ==========================================
# RISK COMPARISON SERVICE
# ==========================================
#
# Purpose:
# Compare the current measured security posture with a projected
# post-mitigation posture.
#
# IMPORTANT:
# This module does NOT:
# - apply patches
# - change firewall rules
# - close ports
# - alter network segmentation
# - guarantee risk reduction
#
# The projected state is an evidence-based estimate derived from
# applicable mitigation recommendations.
# ==========================================

from models.risk_comparison_model import (
    create_risk_comparison_document,
    create_comparison_state,
    create_reduction_result,
    create_comparison_statistics,
    normalize_score
)


# ==========================================
# SENSITIVE NETWORK PORTS
# ==========================================

SENSITIVE_PORTS = {
    21, 22, 23, 25, 53, 110, 111, 135, 139, 445,
    512, 513, 514, 1099, 1433, 1521, 1524, 2049,
    2121, 3306, 3389, 5432, 5900, 6000, 6379,
    6667, 8009, 8180, 27017
}


# ==========================================
# SUPPORTED MITIGATION CATEGORIES
# ==========================================

VULNERABILITY_CATEGORIES = {
    "patch_vulnerability",
    "vulnerability_remediation",
    "patching"
}

SECURITY_FINDING_CATEGORIES = {
    "security_finding_remediation"
}

SERVICE_EXPOSURE_CATEGORIES = {
    "service_exposure",
    "restrict_service",
    "close_unnecessary_port",
    "restrict_remote_administration"
}

EXTERNAL_EXPOSURE_CATEGORIES = {
    "reduce_external_exposure",
    "external_exposure",
    "exposure_reduction"
}

SEGMENTATION_CATEGORIES = {
    "segmentation",
    "network_segmentation",
    "review_graph_relationship"
}

ATTACK_PATH_CATEGORIES = {
    "attack_path_disruption"
}

HARDENING_CATEGORIES = {
    "harden_asset",
    "asset_hardening"
}

SUPPORTED_CATEGORIES = (
    VULNERABILITY_CATEGORIES
    | SECURITY_FINDING_CATEGORIES
    | SERVICE_EXPOSURE_CATEGORIES
    | EXTERNAL_EXPOSURE_CATEGORIES
    | SEGMENTATION_CATEGORIES
    | ATTACK_PATH_CATEGORIES
    | HARDENING_CATEGORIES
)


# ==========================================
# UNIFIED SECURITY FINDING POLICY
# ==========================================

CONTEXT_ONLY_SECURITY_CATEGORIES = {
    "WEB_APPLICATION_SURFACE",
    "LIMITED_VERSION_EVIDENCE",
    "LOW_CONFIDENCE_OS_DETECTION",
    "LARGE_ATTACK_SURFACE"
}

RISK_RELEVANT_SECURITY_FINDING_TYPES = {
    "WEB",
    "APPLICATION",
    "HOST",
    "OS",
    "CONFIGURATION"
}

INACTIVE_SECURITY_STATUSES = {
    "resolved",
    "rejected"
}


# ==========================================
# GENERATE RISK COMPARISON
# ==========================================

def generate_risk_comparison(
    assets=None,
    attack_graph=None,
    defense_analysis=None,
    mitigation_analysis=None,
    created_by=None
):
    assets = normalize_assets(assets, created_by=created_by)
    attack_graph = normalize_attack_graph(attack_graph)
    defense_analysis = normalize_dictionary(defense_analysis)
    mitigation_analysis = normalize_dictionary(mitigation_analysis)

    current_state = build_current_state(
        assets=assets,
        attack_graph=attack_graph
    )

    recommendations = mitigation_analysis.get("recommendations", [])

    if not isinstance(recommendations, list):
        recommendations = []

    applicable_recommendations = get_applicable_recommendations(
        recommendations
    )

    projected_state = build_projected_state(
        current_state=current_state,
        recommendations=applicable_recommendations
    )

    reduction = calculate_reduction(
        current_state=current_state,
        projected_state=projected_state
    )

    affected_assets = get_affected_assets(
        applicable_recommendations
    )

    statistics = create_comparison_statistics(
        recommendation_count=len(recommendations),
        applicable_recommendations=len(applicable_recommendations),
        affected_assets=len(affected_assets),
        current_risk_score=current_state.get("risk_score", 0),
        projected_risk_score=projected_state.get("risk_score", 0),
        risk_reduction=reduction.get("risk_points", 0),
        risk_reduction_percentage=reduction.get("risk_percentage", 0)
    )

    return create_risk_comparison_document(
        created_by=created_by,
        current_state=current_state,
        projected_state=projected_state,
        reduction=reduction,
        applied_recommendations=[
            recommendation.get("id")
            or recommendation.get("recommendation_id")
            or recommendation.get("title")
            for recommendation in applicable_recommendations
        ],
        statistics=statistics
    )


# ==========================================
# BUILD CURRENT STATE
# ==========================================

def build_current_state(assets, attack_graph):
    assets = normalize_list(assets)
    attack_graph = normalize_attack_graph(attack_graph)

    highest_risk_score = 0
    vulnerable_assets = 0
    vulnerability_count = 0
    open_ports_count = 0
    sensitive_ports_count = 0

    for asset in assets:
        if not isinstance(asset, dict):
            continue

        asset_risk_score = get_asset_risk_score(asset)
        highest_risk_score = max(
            highest_risk_score,
            asset_risk_score
        )

        cve_count = get_asset_vulnerability_count(asset)
        security_finding_count = get_asset_security_finding_count(asset)

        # Keep the existing comparison-model field name for compatibility.
        # Semantically this now represents active risk-bearing security
        # findings: CVEs + eligible non-CVE weaknesses.
        asset_security_count = cve_count + security_finding_count

        vulnerability_count += asset_security_count

        if asset_security_count > 0:
            vulnerable_assets += 1

        open_ports = get_asset_open_ports(asset)
        open_ports_count += len(open_ports)

        sensitive_ports_count += len([
            port
            for port in open_ports
            if port in SENSITIVE_PORTS
        ])

    attack_paths = attack_graph.get("paths", [])

    if not isinstance(attack_paths, list):
        attack_paths = []

    high_risk_attack_paths = count_high_risk_attack_paths(
        attack_paths
    )

    return create_comparison_state(
        risk_score=highest_risk_score,
        risk_level=determine_risk_level(highest_risk_score),
        total_assets=len(assets),
        vulnerable_assets=vulnerable_assets,
        vulnerability_count=vulnerability_count,
        open_ports=open_ports_count,
        sensitive_ports=sensitive_ports_count,
        attack_paths=len(attack_paths),
        high_risk_attack_paths=high_risk_attack_paths
    )


# ==========================================
# BUILD PROJECTED STATE
# ==========================================

def build_projected_state(current_state, recommendations):
    current_state = normalize_dictionary(current_state)
    recommendations = normalize_list(recommendations)

    current_risk = normalize_score(
        current_state.get("risk_score", 0)
    )

    projected_risk = current_risk

    projected_vulnerable_assets = normalize_non_negative_integer(
        current_state.get("vulnerable_assets", 0)
    )

    projected_vulnerability_count = normalize_non_negative_integer(
        current_state.get("vulnerability_count", 0)
    )

    projected_open_ports = normalize_non_negative_integer(
        current_state.get("open_ports", 0)
    )

    projected_sensitive_ports = normalize_non_negative_integer(
        current_state.get("sensitive_ports", 0)
    )

    projected_attack_paths = normalize_non_negative_integer(
        current_state.get("attack_paths", 0)
    )

    projected_high_risk_paths = normalize_non_negative_integer(
        current_state.get("high_risk_attack_paths", 0)
    )

    if not recommendations:
        return create_comparison_state(
            risk_score=current_risk,
            risk_level=determine_risk_level(current_risk),
            total_assets=normalize_non_negative_integer(
                current_state.get("total_assets", 0)
            ),
            vulnerable_assets=projected_vulnerable_assets,
            vulnerability_count=projected_vulnerability_count,
            open_ports=projected_open_ports,
            sensitive_ports=projected_sensitive_ports,
            attack_paths=projected_attack_paths,
            high_risk_attack_paths=projected_high_risk_paths
        )

    # Projection remains intentionally conservative.
    # Even with many recommendations, projected reduction cannot exceed
    # 50 percent of the measured current risk.
    maximum_risk_reduction = current_risk * 0.50
    total_risk_reduction = 0.0

    processed = set()

    for recommendation in recommendations:
        if not isinstance(recommendation, dict):
            continue

        category = normalize_category(
            recommendation.get("category")
        )

        if category not in SUPPORTED_CATEGORIES:
            continue

        target = normalize_target(recommendation)

        # Security-finding remediation may contain multiple independently
        # grouped weakness categories for the same asset, so include the
        # recommendation identity for that category. Existing categories
        # retain their previous target-level deduplication behavior.
        if category in SECURITY_FINDING_CATEGORIES:
            recommendation_identity = (
                recommendation.get("id")
                or recommendation.get("recommendation_id")
                or recommendation.get("title")
                or ""
            )

            deduplication_key = (
                category,
                target,
                str(recommendation_identity).strip()
            )
        else:
            deduplication_key = (
                category,
                target
            )

        if deduplication_key in processed:
            continue

        processed.add(deduplication_key)

        recommendation_score = get_recommendation_score(
            recommendation
        )

        # ==================================
        # CVE VULNERABILITY REMEDIATION
        # ==================================

        if category in VULNERABILITY_CATEGORIES:
            if projected_vulnerability_count > 0:
                projected_vulnerability_count -= 1

                risk_reduction = min(
                    12,
                    recommendation_score * 0.30
                )

                total_risk_reduction += risk_reduction

        # ==================================
        # NON-CVE SECURITY FINDING REMEDIATION
        # ==================================

        elif category in SECURITY_FINDING_CATEGORIES:
            if projected_vulnerability_count > 0:
                related_finding_ids = get_related_finding_ids(
                    recommendation
                )

                # The mitigation engine can group multiple related findings
                # into one recommendation. Use that evidence when available,
                # but never project removal of more findings than currently
                # exist.
                finding_reduction = max(
                    1,
                    len(related_finding_ids)
                )

                finding_reduction = min(
                    finding_reduction,
                    projected_vulnerability_count
                )

                projected_vulnerability_count -= finding_reduction

                # Keep this slightly more conservative than CVE patching.
                # These findings may include potential application,
                # configuration, host, or OS weaknesses requiring validation.
                risk_reduction = min(
                    10,
                    recommendation_score * 0.25
                )

                total_risk_reduction += risk_reduction

        # ==================================
        # SERVICE EXPOSURE
        # ==================================

        elif category in SERVICE_EXPOSURE_CATEGORIES:
            related_ports = get_related_ports(
                recommendation
            )

            sensitive_related_ports = [
                port
                for port in related_ports
                if port in SENSITIVE_PORTS
            ]

            if (
                sensitive_related_ports
                and projected_sensitive_ports > 0
            ):
                projected_sensitive_ports = max(
                    0,
                    projected_sensitive_ports
                    - len(sensitive_related_ports)
                )

                risk_reduction = min(
                    8,
                    recommendation_score * 0.20
                )

                total_risk_reduction += risk_reduction

        # ==================================
        # EXTERNAL EXPOSURE
        # ==================================

        elif category in EXTERNAL_EXPOSURE_CATEGORIES:
            risk_reduction = min(
                10,
                recommendation_score * 0.25
            )

            total_risk_reduction += risk_reduction

        # ==================================
        # NETWORK SEGMENTATION
        # ==================================

        elif category in SEGMENTATION_CATEGORIES:
            if projected_attack_paths > 0:
                projected_attack_paths -= 1

            if projected_high_risk_paths > 0:
                projected_high_risk_paths -= 1

            risk_reduction = min(
                8,
                recommendation_score * 0.20
            )

            total_risk_reduction += risk_reduction

        # ==================================
        # ATTACK PATH DISRUPTION
        # ==================================

        elif category in ATTACK_PATH_CATEGORIES:
            if projected_attack_paths > 0:
                projected_attack_paths -= 1

            if projected_high_risk_paths > 0:
                projected_high_risk_paths -= 1

            risk_reduction = min(
                10,
                recommendation_score * 0.25
            )

            total_risk_reduction += risk_reduction

        # ==================================
        # ASSET HARDENING
        # ==================================

        elif category in HARDENING_CATEGORIES:
            risk_reduction = min(
                5,
                recommendation_score * 0.15
            )

            total_risk_reduction += risk_reduction

    total_risk_reduction = min(
        total_risk_reduction,
        maximum_risk_reduction
    )

    projected_risk = max(
        0,
        current_risk - total_risk_reduction
    )

    projected_risk = normalize_score(
        projected_risk
    )

    if projected_vulnerability_count == 0:
        projected_vulnerable_assets = 0

    elif (
        projected_vulnerability_count
        < normalize_non_negative_integer(
            current_state.get("vulnerability_count", 0)
        )
        and projected_vulnerable_assets > 0
    ):
        # Without per-asset post-remediation evidence we cannot safely
        # claim that a specific vulnerable asset has become clean.
        projected_vulnerable_assets = max(
            1,
            projected_vulnerable_assets
        )

    return create_comparison_state(
        risk_score=projected_risk,
        risk_level=determine_risk_level(projected_risk),
        total_assets=normalize_non_negative_integer(
            current_state.get("total_assets", 0)
        ),
        vulnerable_assets=projected_vulnerable_assets,
        vulnerability_count=projected_vulnerability_count,
        open_ports=projected_open_ports,
        sensitive_ports=projected_sensitive_ports,
        attack_paths=projected_attack_paths,
        high_risk_attack_paths=projected_high_risk_paths
    )


# ==========================================
# CALCULATE REDUCTION
# ==========================================

def calculate_reduction(current_state, projected_state):
    current_state = normalize_dictionary(current_state)
    projected_state = normalize_dictionary(projected_state)

    current_risk = normalize_score(
        current_state.get("risk_score", 0)
    )

    projected_risk = normalize_score(
        projected_state.get("risk_score", 0)
    )

    risk_points = max(
        0,
        current_risk - projected_risk
    )

    if current_risk > 0:
        risk_percentage = (
            risk_points / current_risk
        ) * 100
    else:
        risk_percentage = 0

    return create_reduction_result(
        risk_points=risk_points,
        risk_percentage=risk_percentage,
        vulnerable_assets=calculate_integer_reduction(
            current_state,
            projected_state,
            "vulnerable_assets"
        ),
        vulnerability_count=calculate_integer_reduction(
            current_state,
            projected_state,
            "vulnerability_count"
        ),
        open_ports=calculate_integer_reduction(
            current_state,
            projected_state,
            "open_ports"
        ),
        sensitive_ports=calculate_integer_reduction(
            current_state,
            projected_state,
            "sensitive_ports"
        ),
        attack_paths=calculate_integer_reduction(
            current_state,
            projected_state,
            "attack_paths"
        ),
        high_risk_attack_paths=calculate_integer_reduction(
            current_state,
            projected_state,
            "high_risk_attack_paths"
        )
    )


# ==========================================
# GET APPLICABLE RECOMMENDATIONS
# ==========================================

def get_applicable_recommendations(recommendations):
    recommendations = normalize_list(recommendations)
    applicable = []

    for recommendation in recommendations:
        if not isinstance(recommendation, dict):
            continue

        category = normalize_category(
            recommendation.get("category")
        )

        if category not in SUPPORTED_CATEGORIES:
            continue

        applicable.append(recommendation)

    return applicable


# ==========================================
# GET AFFECTED ASSETS
# ==========================================

def get_affected_assets(recommendations):
    recommendations = normalize_list(recommendations)

    assets = []
    seen = set()

    for recommendation in recommendations:
        if not isinstance(recommendation, dict):
            continue

        candidates = [
            recommendation.get("asset_id"),
            recommendation.get("target_asset_id"),
            recommendation.get("target")
        ]

        for candidate in candidates:
            if candidate is None:
                continue

            candidate = str(candidate).strip()

            if not candidate or candidate in seen:
                continue

            seen.add(candidate)
            assets.append(candidate)
            break

    return assets


# ==========================================
# ASSET RISK SCORE
# ==========================================

def get_asset_risk_score(asset):
    if not isinstance(asset, dict):
        return 0

    return normalize_score(
        asset.get("risk_score", 0)
    )


# ==========================================
# ASSET CVE VULNERABILITY COUNT
# ==========================================

def get_asset_vulnerability_count(asset):
    if not isinstance(asset, dict):
        return 0

    vulnerability_count = asset.get(
        "vulnerability_count"
    )

    if vulnerability_count is not None:
        return normalize_non_negative_integer(
            vulnerability_count
        )

    vulnerabilities = asset.get(
        "vulnerabilities",
        []
    )

    if not isinstance(vulnerabilities, list):
        return 0

    return len([
        vulnerability
        for vulnerability in vulnerabilities
        if (
            isinstance(vulnerability, dict)
            and normalize_status(
                vulnerability.get("status")
            ) not in INACTIVE_SECURITY_STATUSES
        )
    ])


# ==========================================
# ASSET NON-CVE SECURITY FINDING COUNT
# ==========================================

def get_asset_security_finding_count(asset):
    return len(
        get_risk_relevant_security_findings(asset)
    )


def get_risk_relevant_security_findings(asset):
    """
    Return active non-CVE findings that represent risk-bearing weaknesses.

    Context-only findings are excluded. NETWORK/SERVICE findings are excluded
    because the current scanner primarily uses them to represent exposures
    already captured by open/sensitive-port evidence.
    """

    if not isinstance(asset, dict):
        return []

    findings = asset.get(
        "security_findings",
        []
    )

    if not isinstance(findings, list):
        return []

    eligible = []
    seen = set()

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        finding_type = normalize_text(
            finding.get(
                "finding_type",
                finding.get("type")
            )
        ).upper()

        category = normalize_text(
            finding.get("category")
        ).upper()

        status = normalize_status(
            finding.get("status")
        )

        if finding_type not in RISK_RELEVANT_SECURITY_FINDING_TYPES:
            continue

        if category in CONTEXT_ONLY_SECURITY_CATEGORIES:
            continue

        if status in INACTIVE_SECURITY_STATUSES:
            continue

        key = (
            normalize_text(
                finding.get("finding_id")
            ).lower(),
            finding_type,
            category,
            normalize_text(
                finding.get("target")
            ).lower(),
            normalize_port_number(
                finding.get("port")
            ),
            normalize_text(
                finding.get("endpoint")
            ).lower(),
            normalize_text(
                finding.get("method")
            ).lower(),
            normalize_text(
                finding.get("parameter")
            ).lower(),
            normalize_text(
                finding.get("title")
            ).lower()
        )

        if key in seen:
            continue

        seen.add(key)
        eligible.append(finding)

    return eligible


# ==========================================
# ASSET OPEN PORTS
# ==========================================

def get_asset_open_ports(asset):
    if not isinstance(asset, dict):
        return []

    # Scan-derived assets may expose port evidence through ports,
    # open_ports, or services depending on normalization stage.
    sources = [
        (asset.get("ports", []), True),
        (asset.get("open_ports", []), False),
        (asset.get("services", []), False)
    ]

    open_ports = []
    seen = set()

    for records, require_explicit_open in sources:
        if not isinstance(records, list):
            continue

        for port_data in records:
            if isinstance(port_data, (int, str)):
                port = normalize_port_number(port_data)

                if port is None or port in seen:
                    continue

                seen.add(port)
                open_ports.append(port)
                continue

            if not isinstance(port_data, dict):
                continue

            state = normalize_text(
                port_data.get("state")
            ).lower()

            if require_explicit_open:
                if state != "open":
                    continue
            elif state and state != "open":
                continue

            port = normalize_port_number(
                port_data.get("port")
                if port_data.get("port") is not None
                else port_data.get("portid")
            )

            if port is None or port in seen:
                continue

            seen.add(port)
            open_ports.append(port)

    return open_ports


# ==========================================
# RELATED PORTS
# ==========================================

def get_related_ports(recommendation):
    if not isinstance(recommendation, dict):
        return []

    candidates = [
        recommendation.get("port")
    ]

    ports = recommendation.get("ports", [])

    if isinstance(ports, list):
        candidates.extend(ports)

    related_ports = recommendation.get(
        "related_ports",
        []
    )

    if isinstance(related_ports, list):
        candidates.extend(related_ports)

    evidence = recommendation.get(
        "evidence",
        {}
    )

    if isinstance(evidence, dict):
        evidence_ports = evidence.get(
            "ports",
            []
        )

        if isinstance(evidence_ports, list):
            candidates.extend(evidence_ports)

    normalized = []
    seen = set()

    for candidate in candidates:
        port = normalize_port_number(candidate)

        if port is None or port in seen:
            continue

        seen.add(port)
        normalized.append(port)

    return normalized


# ==========================================
# RELATED SECURITY FINDING IDS
# ==========================================

def get_related_finding_ids(recommendation):
    if not isinstance(recommendation, dict):
        return []

    candidates = []

    for key in (
        "related_finding_ids",
        "finding_ids"
    ):
        values = recommendation.get(
            key,
            []
        )

        if isinstance(values, list):
            candidates.extend(values)

    single_finding = recommendation.get(
        "finding_id"
    )

    if single_finding is not None:
        candidates.append(single_finding)

    normalized = []
    seen = set()

    for candidate in candidates:
        value = normalize_text(candidate)

        if not value or value in seen:
            continue

        seen.add(value)
        normalized.append(value)

    return normalized


# ==========================================
# RECOMMENDATION SCORE
# ==========================================

def get_recommendation_score(recommendation):
    if not isinstance(recommendation, dict):
        return 0

    candidates = [
        recommendation.get("score"),
        recommendation.get("priority_score"),
        recommendation.get("risk_score")
    ]

    for candidate in candidates:
        if candidate is None:
            continue

        try:
            return normalize_score(candidate)
        except (TypeError, ValueError):
            continue

    return 0


# ==========================================
# COUNT HIGH-RISK ATTACK PATHS
# ==========================================

def count_high_risk_attack_paths(attack_paths):
    attack_paths = normalize_list(attack_paths)
    count = 0

    for path in attack_paths:
        if not isinstance(path, dict):
            continue

        score = normalize_score(
            path.get("score", 0)
        )

        if score >= 50:
            count += 1

    return count


# ==========================================
# DETERMINE RISK LEVEL
# ==========================================

def determine_risk_level(score):
    score = normalize_score(score)

    if score >= 75:
        return "CRITICAL"

    if score >= 50:
        return "HIGH"

    if score >= 25:
        return "MEDIUM"

    return "LOW"


# ==========================================
# CALCULATE INTEGER REDUCTION
# ==========================================

def calculate_integer_reduction(
    current_state,
    projected_state,
    key
):
    current_state = normalize_dictionary(
        current_state
    )

    projected_state = normalize_dictionary(
        projected_state
    )

    current_value = normalize_non_negative_integer(
        current_state.get(key, 0)
    )

    projected_value = normalize_non_negative_integer(
        projected_state.get(key, 0)
    )

    return max(
        0,
        current_value - projected_value
    )


# ==========================================
# NORMALIZE ASSETS
# ==========================================

def normalize_assets(assets, created_by=None):
    assets = normalize_list(assets)
    normalized = []

    for asset in assets:
        if not isinstance(asset, dict):
            continue

        if created_by is not None:
            asset_owner = asset.get(
                "created_by"
            )

            if str(asset_owner) != str(created_by):
                continue

        normalized.append(asset)

    return normalized


# ==========================================
# NORMALIZE ATTACK GRAPH
# ==========================================

def normalize_attack_graph(attack_graph):
    if not isinstance(attack_graph, dict):
        return {
            "nodes": [],
            "edges": [],
            "paths": []
        }

    nodes = attack_graph.get("nodes", [])
    edges = attack_graph.get("edges", [])
    paths = attack_graph.get("paths", [])

    if not isinstance(nodes, list):
        nodes = []

    if not isinstance(edges, list):
        edges = []

    if not isinstance(paths, list):
        paths = []

    return {
        "nodes": nodes,
        "edges": edges,
        "paths": paths
    }


# ==========================================
# NORMALIZATION HELPERS
# ==========================================

def normalize_category(value):
    return normalize_text(value).lower()


def normalize_status(value):
    return normalize_text(
        value,
        default="potential"
    ).lower()


def normalize_text(value, default=""):
    text = str(
        value
        if value is not None
        else default
    ).strip()

    return text or str(default).strip()


def normalize_target(recommendation):
    if not isinstance(recommendation, dict):
        return ""

    candidates = [
        recommendation.get("asset_id"),
        recommendation.get("target_asset_id"),
        recommendation.get("target"),
        recommendation.get("relationship_id"),
        recommendation.get("path_id"),
        recommendation.get("title")
    ]

    for candidate in candidates:
        if candidate is None:
            continue

        candidate = str(candidate).strip()

        if candidate:
            return candidate

    return ""


def normalize_port_number(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None

    if port < 1 or port > 65535:
        return None

    return port


def normalize_non_negative_integer(value):
    try:
        value = int(value or 0)
    except (TypeError, ValueError):
        return 0

    return max(0, value)


def normalize_list(value):
    if not isinstance(value, list):
        return []

    return value


def normalize_dictionary(value):
    if not isinstance(value, dict):
        return {}

    return value