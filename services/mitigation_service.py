# ==========================================
# MITIGATION RECOMMENDATION ENGINE
# ==========================================
#
# Converts AttackLens security evidence into
# conservative, evidence-based defensive
# recommendations.
#
# IMPORTANT:
# - Does not invent vulnerabilities.
# - Does not invent CVEs.
# - Does not assume reachability.
# - Does not claim guaranteed risk reduction.
# ==========================================


from models.mitigation_model import (
    create_mitigation_document,
    create_mitigation_recommendation,
    create_mitigation_statistics,
    normalize_score,
    normalize_confidence
)


# ==========================================
# SECURITY-SENSITIVE PORTS
# ==========================================

SENSITIVE_PORTS = {

    21,
    22,
    23,
    25,
    53,
    110,
    135,
    139,
    445,
    1433,
    1521,
    3306,
    3389,
    5432,
    5900,
    6379,
    27017
}


# ==========================================
# MAIN ENGINE
# ==========================================

def generate_mitigation_recommendations(
    assets=None,
    defense_analysis=None,
    attack_graph=None,
    created_by=None
):
    """
    Generate evidence-based mitigation
    recommendations using current assets,
    defense-analysis findings, and attack
    graph context.
    """

    assets = normalize_assets(
        assets,
        created_by=created_by
    )

    defense_analysis = (
        normalize_defense_analysis(
            defense_analysis
        )
    )

    attack_graph = (
        normalize_attack_graph(
            attack_graph
        )
    )

    asset_index = build_asset_index(
        assets
    )

    defense_scores = (
        build_defense_score_index(
            defense_analysis
        )
    )

    recommendations = []

    recommendations.extend(
        generate_sensitive_service_recommendations(
            assets=assets,
            defense_scores=defense_scores
        )
    )

    recommendations.extend(
        generate_external_exposure_recommendations(
            assets=assets,
            defense_scores=defense_scores
        )
    )

    recommendations.extend(
        generate_vulnerability_recommendations(
            assets=assets,
            defense_scores=defense_scores
        )
    )

    recommendations.extend(
        generate_relationship_recommendations(
            defense_analysis=defense_analysis,
            attack_graph=attack_graph,
            asset_index=asset_index
        )
    )

    recommendations.extend(
        generate_attack_path_recommendations(
            defense_analysis=defense_analysis,
            attack_graph=attack_graph,
            asset_index=asset_index
        )
    )

    recommendations = (
        deduplicate_recommendations(
            recommendations
        )
    )

    recommendations = (
        sort_recommendations(
            recommendations
        )
    )

    statistics = (
        create_mitigation_statistics(
            recommendations
        )
    )

    return create_mitigation_document(
        created_by=created_by,
        recommendations=recommendations,
        statistics=statistics
    )


# ==========================================
# NORMALIZE ASSETS
# ==========================================

def normalize_assets(
    assets,
    created_by=None
):
    """
    Safely normalize asset input and enforce
    owner isolation when created_by is supplied.
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

        if created_by is not None:

            if str(
                asset.get(
                    "created_by",
                    ""
                )
            ) != str(
                created_by
            ):

                continue

        normalized.append(
            asset
        )

    return normalized


# ==========================================
# NORMALIZE DEFENSE ANALYSIS
# ==========================================

def normalize_defense_analysis(
    defense_analysis
):
    """
    Return a safe defense-analysis structure.
    """

    if not isinstance(
        defense_analysis,
        dict
    ):

        return {
            "findings": [],
            "priorities": [],
            "statistics": {}
        }

    findings = defense_analysis.get(
        "findings"
    )

    priorities = defense_analysis.get(
        "priorities"
    )

    statistics = defense_analysis.get(
        "statistics"
    )

    if not isinstance(
        findings,
        list
    ):

        findings = []

    if not isinstance(
        priorities,
        list
    ):

        priorities = []

    if not isinstance(
        statistics,
        dict
    ):

        statistics = {}

    return {
        "findings": findings,
        "priorities": priorities,
        "statistics": statistics
    }


# ==========================================
# NORMALIZE ATTACK GRAPH
# ==========================================

def normalize_attack_graph(
    attack_graph
):
    """
    Return a safe attack graph structure.
    """

    if not isinstance(
        attack_graph,
        dict
    ):

        return {
            "nodes": [],
            "edges": [],
            "paths": [],
            "statistics": {}
        }

    nodes = attack_graph.get(
        "nodes"
    )

    edges = attack_graph.get(
        "edges"
    )

    paths = attack_graph.get(
        "paths"
    )

    statistics = attack_graph.get(
        "statistics"
    )

    if not isinstance(
        nodes,
        list
    ):

        nodes = []

    if not isinstance(
        edges,
        list
    ):

        edges = []

    if not isinstance(
        paths,
        list
    ):

        paths = []

    if not isinstance(
        statistics,
        dict
    ):

        statistics = {}

    return {
        "nodes": nodes,
        "edges": edges,
        "paths": paths,
        "statistics": statistics
    }


# ==========================================
# BUILD ASSET INDEX
# ==========================================

def build_asset_index(
    assets
):
    """
    Index assets using both asset ID and target.
    """

    index = {}

    for asset in assets:

        if not isinstance(
            asset,
            dict
        ):

            continue

        asset_id = str(
            asset.get(
                "_id",
                ""
            )
        ).strip()

        target = str(
            asset.get(
                "target",
                ""
            )
        ).strip()

        if asset_id:

            index[
                asset_id
            ] = asset

        if target:

            index[
                target
            ] = asset

    return index


# ==========================================
# BUILD DEFENSE SCORE INDEX
# ==========================================

def build_defense_score_index(
    defense_analysis
):
    """
    Build highest known defensive significance
    score for each target.
    """

    scores = {}

    findings = defense_analysis.get(
        "findings",
        []
    )

    priorities = defense_analysis.get(
        "priorities",
        []
    )

    for item in (
        findings
        +
        priorities
    ):

        if not isinstance(
            item,
            dict
        ):

            continue

        target = str(
            item.get(
                "target",
                ""
            )
        ).strip()

        if not target:

            continue

        score = normalize_score(
            item.get(
                "score",
                0
            )
        )

        scores[
            target
        ] = max(
            scores.get(
                target,
                0
            ),
            score
        )

    return scores


# ==========================================
# SENSITIVE SERVICE RECOMMENDATIONS
# ==========================================

def generate_sensitive_service_recommendations(
    assets,
    defense_scores=None
):
    """
    Recommend review/restriction when security-
    sensitive open ports are directly observed.
    """

    if not isinstance(
        defense_scores,
        dict
    ):

        defense_scores = {}

    recommendations = []

    for asset in assets:

        sensitive_ports = (
            get_sensitive_open_ports(
                asset
            )
        )

        if not sensitive_ports:

            continue

        target = get_asset_target(
            asset
        )

        asset_id = get_asset_id(
            asset
        )

        risk_score = normalize_risk_score(
            asset.get(
                "risk_score"
            )
        )

        defense_score = normalize_score(
            defense_scores.get(
                target,
                0
            )
        )

        score = normalize_score(
            max(
                risk_score,
                defense_score
            )
        )

        if score <= 0:

            score = normalize_score(
                min(
                    25,
                    5
                    +
                    (
                        len(
                            sensitive_ports
                        )
                        *
                        5
                    )
                )
            )

        priority_level = (
            determine_priority_level(
                score
            )
        )

        port_text = ", ".join(
            str(
                port
            )
            for port
            in sensitive_ports
        )

        recommendation = (
            create_mitigation_recommendation(

                recommendation_id=(
                    "sensitive-services:"
                    f"{asset_id or target}:"
                    f"{port_text}"
                ),

                category=
                    "service_exposure",

                title=
                    "Review Sensitive Network Services",

                description=(
                    "One or more security-sensitive "
                    "network services are currently "
                    "open on this asset."
                ),

                target=
                    target,

                asset_id=
                    asset_id,

                priority_level=
                    priority_level,

                score=
                    score,

                confidence=
                    "HIGH",

                evidence=[
                    (
                        "Security-sensitive open "
                        f"port(s) detected: "
                        f"{port_text}."
                    ),
                    (
                        "Current asset risk score "
                        f"is {risk_score}/100."
                    )
                ],

                actions=[
                    (
                        "Verify whether each identified "
                        "service is required for the "
                        "asset's intended function."
                    ),
                    (
                        "Restrict access to trusted "
                        "hosts or network segments "
                        "where appropriate."
                    ),
                    (
                        "Apply host or network firewall "
                        "rules to reduce unnecessary "
                        "service exposure."
                    ),
                    (
                        "Disable unnecessary services "
                        "when operationally safe."
                    )
                ],

                expected_effect=(
                    "Reduced exposure of security-"
                    "sensitive network services and "
                    "a smaller reachable attack surface."
                ),

                related_ports=
                    sensitive_ports
            )
        )

        recommendations.append(
            recommendation
        )

    return recommendations


# ==========================================
# EXTERNAL EXPOSURE RECOMMENDATIONS
# ==========================================

def generate_external_exposure_recommendations(
    assets,
    defense_scores=None
):
    """
    Recommend review of externally exposed
    assets only when the asset explicitly carries
    EXTERNAL exposure context.
    """

    if not isinstance(
        defense_scores,
        dict
    ):

        defense_scores = {}

    recommendations = []

    for asset in assets:

        exposure = normalize_exposure(
            asset.get(
                "exposure"
            )
        )

        if exposure != "EXTERNAL":

            continue

        target = get_asset_target(
            asset
        )

        asset_id = get_asset_id(
            asset
        )

        risk_score = normalize_risk_score(
            asset.get(
                "risk_score"
            )
        )

        defense_score = normalize_score(
            defense_scores.get(
                target,
                0
            )
        )

        score = normalize_score(
            max(
                risk_score,
                defense_score,
                25
            )
        )

        priority_level = (
            determine_priority_level(
                score
            )
        )

        recommendation = (
            create_mitigation_recommendation(

                recommendation_id=(
                    "external-exposure:"
                    f"{asset_id or target}"
                ),

                category=
                    "exposure_reduction",

                title=
                    "Review External Exposure",

                description=(
                    "The asset is explicitly classified "
                    "as externally exposed and should be "
                    "reviewed for unnecessary public "
                    "reachability."
                ),

                target=
                    target,

                asset_id=
                    asset_id,

                priority_level=
                    priority_level,

                score=
                    score,

                confidence=
                    "HIGH",

                evidence=[
                    (
                        "Asset exposure is classified "
                        "as EXTERNAL."
                    ),
                    (
                        "Current asset risk score "
                        f"is {risk_score}/100."
                    )
                ],

                actions=[
                    (
                        "Confirm which externally "
                        "reachable services are required."
                    ),
                    (
                        "Remove or restrict unnecessary "
                        "public-facing services."
                    ),
                    (
                        "Apply access-control and "
                        "firewall restrictions where "
                        "operationally appropriate."
                    ),
                    (
                        "Re-scan the asset after changes "
                        "to verify the resulting exposure."
                    )
                ],

                expected_effect=(
                    "Reduced unnecessary external "
                    "reachability and a smaller exposed "
                    "attack surface."
                )
            )
        )

        recommendations.append(
            recommendation
        )

    return recommendations


# ==========================================
# VULNERABILITY RECOMMENDATIONS
# ==========================================

def generate_vulnerability_recommendations(
    assets,
    defense_scores=None
):
    """
    Generate vulnerability remediation advice
    only when actual vulnerability evidence exists.
    """

    if not isinstance(
        defense_scores,
        dict
    ):

        defense_scores = {}

    recommendations = []

    for asset in assets:

        vulnerabilities = (
            get_vulnerabilities(
                asset
            )
        )

        if not vulnerabilities:

            continue

        target = get_asset_target(
            asset
        )

        asset_id = get_asset_id(
            asset
        )

        cve_ids = extract_cve_ids(
            vulnerabilities
        )

        highest_severity = (
            get_highest_vulnerability_severity(
                vulnerabilities
            )
        )

        risk_score = normalize_risk_score(
            asset.get(
                "risk_score"
            )
        )

        defense_score = normalize_score(
            defense_scores.get(
                target,
                0
            )
        )

        severity_score = {
            "UNKNOWN": 20,
            "LOW": 25,
            "MEDIUM": 45,
            "HIGH": 70,
            "CRITICAL": 90
        }.get(
            highest_severity,
            20
        )

        score = normalize_score(
            max(
                risk_score,
                defense_score,
                severity_score
            )
        )

        priority_level = (
            determine_priority_level(
                score
            )
        )

        evidence = [
            (
                f"{len(vulnerabilities)} "
                "identified vulnerability "
                "finding(s) are associated "
                "with this asset."
            ),
            (
                "Highest identified vulnerability "
                f"severity: {highest_severity}."
            )
        ]

        if cve_ids:

            evidence.append(
                (
                    "Identified CVE evidence: "
                    +
                    ", ".join(
                        cve_ids
                    )
                    +
                    "."
                )
            )

        actions = [
            (
                "Review the identified vulnerability "
                "evidence and affected service version."
            ),
            (
                "Consult the relevant vendor security "
                "advisory before applying remediation."
            ),
            (
                "Apply an appropriate vendor-supported "
                "patch or upgrade where available."
            ),
            (
                "If immediate remediation is not "
                "possible, restrict exposure of the "
                "affected service as a compensating "
                "control."
            ),
            (
                "Perform a follow-up authorized scan "
                "after remediation."
            )
        ]

        recommendation = (
            create_mitigation_recommendation(

                recommendation_id=(
                    "vulnerability-remediation:"
                    f"{asset_id or target}"
                ),

                category=
                    "vulnerability_remediation",

                title=
                    "Remediate Identified Vulnerabilities",

                description=(
                    "AttackLens has identified "
                    "vulnerability evidence associated "
                    "with this asset."
                ),

                target=
                    target,

                asset_id=
                    asset_id,

                priority_level=
                    priority_level,

                score=
                    score,

                confidence=(
                    "HIGH"
                    if cve_ids
                    else
                    "MEDIUM"
                ),

                evidence=
                    evidence,

                actions=
                    actions,

                expected_effect=(
                    "Reduced exposure to the identified "
                    "software weakness after validated "
                    "remediation."
                ),

                related_cves=
                    cve_ids
            )
        )

        recommendations.append(
            recommendation
        )

    return recommendations


# ==========================================
# RELATIONSHIP RECOMMENDATIONS
# ==========================================

def generate_relationship_recommendations(
    defense_analysis,
    attack_graph,
    asset_index
):
    """
    Convert relationship/choke-point defense
    findings into conservative segmentation and
    reachability-review recommendations.
    """

    recommendations = []

    findings = defense_analysis.get(
        "findings",
        []
    )

    for finding in findings:

        if not isinstance(
            finding,
            dict
        ):

            continue

        finding_type = str(
            finding.get(
                "finding_type",
                ""
            )
        ).strip().lower()

        title = str(
            finding.get(
                "title",
                ""
            )
        ).strip().lower()

        is_relationship = (
            "relationship"
            in finding_type
            or
            "choke"
            in finding_type
            or
            "relationship"
            in title
            or
            "choke"
            in title
        )

        if not is_relationship:

            continue

        target = str(
            finding.get(
                "target",
                ""
            )
        ).strip()

        asset_id = str(
            finding.get(
                "asset_id",
                ""
            )
        ).strip()

        score = normalize_score(
            finding.get(
                "score",
                0
            )
        )

        priority_level = (
            determine_priority_level(
                score
            )
        )

        confidence = normalize_confidence(
            finding.get(
                "confidence",
                "LOW"
            )
        )

        evidence = (
            normalize_evidence(
                finding.get(
                    "evidence"
                )
            )
        )

        finding_id = str(
            finding.get(
                "id",
                ""
            )
        ).strip()

        recommendation = (
            create_mitigation_recommendation(

                recommendation_id=(
                    "relationship-review:"
                    f"{finding_id or asset_id or target}"
                ),

                category=
                    "segmentation",

                title=
                    "Review Network Relationship and Segmentation",

                description=(
                    "Defense Analysis identified a "
                    "security-relevant relationship or "
                    "potential defensive choke point."
                ),

                target=
                    target or None,

                asset_id=
                    asset_id or None,

                priority_level=
                    priority_level,

                score=
                    score,

                confidence=
                    confidence,

                evidence=
                    evidence,

                actions=[
                    (
                        "Review whether the observed "
                        "network relationship is required."
                    ),
                    (
                        "Restrict unnecessary reachability "
                        "between affected systems."
                    ),
                    (
                        "Consider network segmentation or "
                        "access-control rules where "
                        "appropriate."
                    ),
                    (
                        "Validate intended connectivity "
                        "before enforcing restrictive "
                        "controls."
                    )
                ],

                expected_effect=(
                    "Reduced unnecessary lateral "
                    "reachability and a smaller potential "
                    "attacker movement surface."
                ),

                related_finding_ids=(
                    [finding_id]
                    if finding_id
                    else
                    []
                )
            )
        )

        recommendations.append(
            recommendation
        )

    return recommendations


# ==========================================
# ATTACK PATH RECOMMENDATIONS
# ==========================================

def generate_attack_path_recommendations(
    defense_analysis,
    attack_graph,
    asset_index
):
    """
    Generate path-disruption recommendations only
    for attack paths that actually exist in the
    generated attack graph.
    """

    recommendations = []

    paths = attack_graph.get(
        "paths",
        []
    )

    for path in paths:

        if not isinstance(
            path,
            dict
        ):

            continue

        path_id = str(
            path.get(
                "id",
                ""
            )
        ).strip()

        path_score = normalize_score(
            path.get(
                "score",
                0
            )
        )

        confidence = normalize_confidence(
            path.get(
                "confidence",
                "LOW"
            )
        )

        nodes = path.get(
            "nodes",
            []
        )

        if not isinstance(
            nodes,
            list
        ):

            nodes = []

        target_asset = None

        for node_id in reversed(
            nodes
        ):

            node_id = str(
                node_id
            ).strip()

            if node_id in asset_index:

                target_asset = (
                    asset_index[
                        node_id
                    ]
                )

                break

        if target_asset is None:

            continue

        target = get_asset_target(
            target_asset
        )

        asset_id = get_asset_id(
            target_asset
        )

        priority_level = (
            determine_priority_level(
                path_score
            )
        )

        evidence = (
            normalize_evidence(
                path.get(
                    "evidence"
                )
            )
        )

        evidence.append(
            (
                "Generated attack path score "
                f"is {path_score}/100."
            )
        )

        recommendation = (
            create_mitigation_recommendation(

                recommendation_id=(
                    "attack-path-disruption:"
                    f"{path_id or asset_id or target}"
                ),

                category=
                    "attack_path_disruption",

                title=
                    "Prioritize Attack Path Disruption",

                description=(
                    "A generated potential attack path "
                    "includes this asset and should be "
                    "reviewed for controls that break or "
                    "reduce the supported progression."
                ),

                target=
                    target,

                asset_id=
                    asset_id,

                priority_level=
                    priority_level,

                score=
                    path_score,

                confidence=
                    confidence,

                evidence=
                    evidence,

                actions=[
                    (
                        "Review the services and "
                        "relationships supporting this "
                        "generated attack path."
                    ),
                    (
                        "Prioritize controls at the "
                        "highest-value entry or choke "
                        "points."
                    ),
                    (
                        "Restrict unnecessary service "
                        "exposure and network reachability."
                    ),
                    (
                        "Remediate identified "
                        "vulnerabilities contributing to "
                        "the path when supported by scan "
                        "evidence."
                    ),
                    (
                        "Regenerate the attack graph after "
                        "changes to evaluate whether the "
                        "potential path remains."
                    )
                ],

                expected_effect=(
                    "Reduced support for the generated "
                    "attacker progression path."
                ),

                related_path_ids=(
                    [path_id]
                    if path_id
                    else
                    []
                )
            )
        )

        recommendations.append(
            recommendation
        )

    return recommendations


# ==========================================
# DETERMINE PRIORITY LEVEL
# ==========================================

def determine_priority_level(
    score
):
    """
    Map recommendation score to priority.
    """

    score = normalize_score(
        score
    )

    if score >= 75:

        return "CRITICAL"

    if score >= 50:

        return "HIGH"

    if score >= 25:

        return "MEDIUM"

    return "LOW"


# ==========================================
# GET OPEN PORTS
# ==========================================

def get_open_ports(
    asset
):
    """
    Return directly observed open TCP/UDP ports.
    """

    if not isinstance(
        asset,
        dict
    ):

        return []

    ports = asset.get(
        "ports"
    )

    if not isinstance(
        ports,
        list
    ):

        return []

    open_ports = []

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

        port = normalize_port_number(
            port_data.get(
                "port"
            )
        )

        if port is None:

            continue

        open_ports.append(
            port
        )

    return sorted(
        set(
            open_ports
        )
    )


# ==========================================
# GET SENSITIVE OPEN PORTS
# ==========================================

def get_sensitive_open_ports(
    asset
):
    """
    Return security-sensitive ports that are
    directly observed as open.
    """

    return [
        port
        for port
        in get_open_ports(
            asset
        )
        if port
        in SENSITIVE_PORTS
    ]


# ==========================================
# GET VULNERABILITIES
# ==========================================

def get_vulnerabilities(
    asset
):
    """
    Return stored vulnerability findings.
    """

    if not isinstance(
        asset,
        dict
    ):

        return []

    vulnerabilities = asset.get(
        "vulnerabilities"
    )

    if not isinstance(
        vulnerabilities,
        list
    ):

        return []

    return [
        vulnerability
        for vulnerability
        in vulnerabilities
        if isinstance(
            vulnerability,
            dict
        )
    ]


# ==========================================
# EXTRACT CVE IDS
# ==========================================

def extract_cve_ids(
    vulnerabilities
):
    """
    Extract only CVE identifiers that already
    exist in vulnerability evidence.
    """

    cve_ids = []

    seen = set()

    for vulnerability in vulnerabilities:

        if not isinstance(
            vulnerability,
            dict
        ):

            continue

        candidates = [

            vulnerability.get(
                "cve_id"
            ),

            vulnerability.get(
                "cve"
            ),

            vulnerability.get(
                "id"
            )
        ]

        for candidate in candidates:

            candidate = str(
                candidate
                or
                ""
            ).strip().upper()

            if not candidate.startswith(
                "CVE-"
            ):

                continue

            if candidate in seen:

                continue

            seen.add(
                candidate
            )

            cve_ids.append(
                candidate
            )

    return cve_ids


# ==========================================
# HIGHEST VULNERABILITY SEVERITY
# ==========================================

def get_highest_vulnerability_severity(
    vulnerabilities
):
    """
    Return highest stored vulnerability severity.
    """

    severity_rank = {
        "UNKNOWN": 0,
        "NONE": 1,
        "LOW": 2,
        "MEDIUM": 3,
        "HIGH": 4,
        "CRITICAL": 5
    }

    highest = "UNKNOWN"

    highest_rank = 0

    for vulnerability in vulnerabilities:

        if not isinstance(
            vulnerability,
            dict
        ):

            continue

        severity = str(
            vulnerability.get(
                "severity",
                "UNKNOWN"
            )
        ).strip().upper()

        if severity not in severity_rank:

            severity = "UNKNOWN"

        rank = severity_rank[
            severity
        ]

        if rank > highest_rank:

            highest_rank = rank

            highest = severity

    return highest


# ==========================================
# NORMALIZE RISK SCORE
# ==========================================

def normalize_risk_score(
    value
):
    """
    Normalize existing asset risk score.
    """

    return normalize_score(
        value
    )


# ==========================================
# NORMALIZE EXPOSURE
# ==========================================

def normalize_exposure(
    value
):
    """
    Normalize asset exposure context.
    """

    value = str(
        value
        or
        ""
    ).strip().upper()

    if value in {
        "INTERNAL",
        "EXTERNAL",
        "UNKNOWN"
    }:

        return value

    return "UNKNOWN"


# ==========================================
# NORMALIZE PORT NUMBER
# ==========================================

def normalize_port_number(
    value
):
    """
    Return a valid TCP/UDP port or None.
    """

    try:

        port = int(
            value
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
# NORMALIZE EVIDENCE
# ==========================================

def normalize_evidence(
    value
):
    """
    Convert evidence to a safe list of strings.
    """

    if not isinstance(
        value,
        list
    ):

        return []

    evidence = []

    seen = set()

    for item in value:

        text = str(
            item
            or
            ""
        ).strip()

        if not text:

            continue

        if text in seen:

            continue

        seen.add(
            text
        )

        evidence.append(
            text
        )

    return evidence


# ==========================================
# GET ASSET TARGET
# ==========================================

def get_asset_target(
    asset
):
    """
    Return best display target.
    """

    if not isinstance(
        asset,
        dict
    ):

        return None

    target = str(
        asset.get(
            "target",
            ""
        )
    ).strip()

    if target:

        return target

    hostname = str(
        asset.get(
            "hostname",
            ""
        )
    ).strip()

    if hostname:

        return hostname

    return None


# ==========================================
# GET ASSET ID
# ==========================================

def get_asset_id(
    asset
):
    """
    Safely return asset ID as string.
    """

    if not isinstance(
        asset,
        dict
    ):

        return None

    asset_id = str(
        asset.get(
            "_id",
            ""
        )
    ).strip()

    if not asset_id:

        return None

    return asset_id


# ==========================================
# DEDUPLICATE RECOMMENDATIONS
# ==========================================

def deduplicate_recommendations(
    recommendations
):
    """
    Remove duplicate mitigation recommendations.
    """

    if not isinstance(
        recommendations,
        list
    ):

        return []

    unique = []

    seen = set()

    for recommendation in recommendations:

        if not isinstance(
            recommendation,
            dict
        ):

            continue

        key = (

            str(
                recommendation.get(
                    "category",
                    ""
                )
            ).strip(),

            str(
                recommendation.get(
                    "asset_id",
                    ""
                )
            ).strip(),

            str(
                recommendation.get(
                    "target",
                    ""
                )
            ).strip(),

            str(
                recommendation.get(
                    "title",
                    ""
                )
            ).strip()
        )

        if key in seen:

            continue

        seen.add(
            key
        )

        unique.append(
            recommendation
        )

    return unique


# ==========================================
# SORT RECOMMENDATIONS
# ==========================================

def sort_recommendations(
    recommendations
):
    """
    Highest recommendation score first.
    """

    if not isinstance(
        recommendations,
        list
    ):

        return []

    return sorted(
        recommendations,
        key=lambda recommendation: (
            normalize_score(
                recommendation.get(
                    "score",
                    0
                )
            ),
            str(
                recommendation.get(
                    "title",
                    ""
                )
            )
        ),
        reverse=True
    )