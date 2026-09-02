# ==========================================
# DEFENSE ANALYSIS SERVICE
# ==========================================
#
# This service contains the business logic
# for the AttackLens Defense Analysis Engine.
#
# Responsibilities:
#
# 1. Analyze current Asset Inventory data.
# 2. Analyze Attack Path graph data.
# 3. Identify security-relevant assets.
# 4. Identify attack-path concentration.
# 5. Identify relationship choke points.
# 6. Create defensive findings.
# 7. Rank defense priorities.
# 8. Produce summary statistics.
#
# IMPORTANT:
#
# This service determines:
#
# WHAT should be prioritized
# and
# WHY it matters.
#
# It does NOT generate detailed mitigation
# instructions. Those will be handled later
# by the Mitigation Recommendation Engine.
#
# No Flask logic or database access should
# exist in this file.
# ==========================================


from models.defense_analysis_model import (
    create_defense_analysis_document,
    create_defense_finding,
    create_defense_priority,
    create_defense_statistics,
    normalize_score,
    normalize_confidence,
    normalize_string
)


# ==========================================
# DEFENSE ANALYSIS CONSTANTS
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


RISK_LEVEL_ORDER = {
    "UNKNOWN": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}


CONFIDENCE_WEIGHT = {
    "UNKNOWN": 0,
    "LOW": 5,
    "MEDIUM": 10,
    "HIGH": 15
}


# ==========================================
# GENERATE DEFENSE ANALYSIS
# ==========================================

def generate_defense_analysis(
    assets,
    attack_graph,
    created_by=None
):
    """
    Generate a complete Defense Analysis
    result using current assets and the
    Attack Path graph.
    """

    analysis = (
        create_defense_analysis_document(
            created_by=created_by
        )
    )


    normalized_assets = (
        normalize_assets(
            assets,
            created_by=created_by
        )
    )


    graph = (
        normalize_attack_graph(
            attack_graph
        )
    )


    if (
        not normalized_assets
        and
        not graph["nodes"]
    ):

        return analysis


    asset_index = (
        build_asset_index(
            normalized_assets
        )
    )


    path_frequency = (
        calculate_asset_path_frequency(
            graph["paths"]
        )
    )


    edge_frequency = (
        calculate_asset_edge_frequency(
            graph["edges"]
        )
    )


    # ======================================
    # ASSET FINDINGS
    # ======================================

    asset_findings = (
        generate_asset_findings(
            assets=normalized_assets,
            path_frequency=path_frequency,
            edge_frequency=edge_frequency
        )
    )


    # ======================================
    # RELATIONSHIP FINDINGS
    # ======================================

    relationship_findings = (
        generate_relationship_findings(
            edges=graph["edges"],
            paths=graph["paths"],
            asset_index=asset_index
        )
    )


    # ======================================
    # PATH FINDINGS
    # ======================================

    path_findings = (
        generate_path_findings(
            paths=graph["paths"],
            asset_index=asset_index
        )
    )


    findings = (
        asset_findings
        +
        relationship_findings
        +
        path_findings
    )


    findings = (
        deduplicate_findings(
            findings
        )
    )


    findings = (
        sort_findings(
            findings
        )
    )


    # ======================================
    # DEFENSE PRIORITIES
    # ======================================

    priorities = (
        generate_defense_priorities(
            findings=findings,
            assets=normalized_assets,
            paths=graph["paths"],
            path_frequency=path_frequency
        )
    )


    priorities = (
        deduplicate_priorities(
            priorities
        )
    )


    priorities = (
        sort_priorities(
            priorities
        )
    )


    analysis["findings"] = (
        findings
    )


    analysis["priorities"] = (
        priorities
    )


    analysis["statistics"] = (
        create_defense_statistics(
            findings=findings,
            priorities=priorities
        )
    )


    return analysis


# ==========================================
# NORMALIZE ASSETS
# ==========================================

def normalize_assets(
    assets,
    created_by=None
):
    """
    Normalize Asset Inventory input and
    enforce owner isolation.
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


        asset_id = (
            normalize_string(
                asset.get(
                    "_id"
                )
            )
        )


        target = (
            normalize_string(
                asset.get(
                    "target"
                )
            )
        )


        if (
            not asset_id
            or
            not target
        ):

            continue


        if created_by is not None:

            owner = (
                normalize_string(
                    asset.get(
                        "created_by"
                    )
                )
            )


            if (
                owner
                !=
                normalize_string(
                    created_by
                )
            ):

                continue


        normalized.append(
            asset
        )


    normalized.sort(
        key=lambda asset: (
            normalize_string(
                asset.get(
                    "target"
                )
            ),
            normalize_string(
                asset.get(
                    "_id"
                )
            )
        )
    )


    return normalized


# ==========================================
# NORMALIZE ATTACK GRAPH
# ==========================================

def normalize_attack_graph(
    attack_graph
):
    """
    Safely normalize Attack Path graph input.
    """

    if not isinstance(
        attack_graph,
        dict
    ):

        return {
            "nodes": [],
            "edges": [],
            "paths": []
        }


    nodes = (
        attack_graph.get(
            "nodes"
        )
    )


    edges = (
        attack_graph.get(
            "edges"
        )
    )


    paths = (
        attack_graph.get(
            "paths"
        )
    )


    return {

        "nodes":
            nodes
            if isinstance(
                nodes,
                list
            )
            else [],

        "edges":
            edges
            if isinstance(
                edges,
                list
            )
            else [],

        "paths":
            paths
            if isinstance(
                paths,
                list
            )
            else []

    }


# ==========================================
# BUILD ASSET INDEX
# ==========================================

def build_asset_index(
    assets
):
    """
    Build a dictionary keyed by Asset ID.
    """

    index = {}


    if not isinstance(
        assets,
        list
    ):

        return index


    for asset in assets:

        if not isinstance(
            asset,
            dict
        ):

            continue


        asset_id = (
            normalize_string(
                asset.get(
                    "_id"
                )
            )
        )


        if not asset_id:

            continue


        index[
            asset_id
        ] = asset


    return index


# ==========================================
# ASSET PATH FREQUENCY
# ==========================================

def calculate_asset_path_frequency(
    paths
):
    """
    Count how many generated attack paths
    contain each asset node.
    """

    frequency = {}


    if not isinstance(
        paths,
        list
    ):

        return frequency


    for path in paths:

        if not isinstance(
            path,
            dict
        ):

            continue


        nodes = (
            path.get(
                "nodes"
            )
        )


        if not isinstance(
            nodes,
            list
        ):

            continue


        seen = set()


        for node_id in nodes:

            node_id = (
                normalize_string(
                    node_id
                )
            )


            if (
                not node_id
                or
                node_id
                ==
                "external-attacker"
            ):

                continue


            if node_id in seen:

                continue


            seen.add(
                node_id
            )


            frequency[
                node_id
            ] = (
                frequency.get(
                    node_id,
                    0
                )
                +
                1
            )


    return frequency


# ==========================================
# ASSET EDGE FREQUENCY
# ==========================================

def calculate_asset_edge_frequency(
    edges
):
    """
    Count how many graph relationships
    reference each asset.
    """

    frequency = {}


    if not isinstance(
        edges,
        list
    ):

        return frequency


    for edge in edges:

        if not isinstance(
            edge,
            dict
        ):

            continue


        source = (
            normalize_string(
                edge.get(
                    "source"
                )
            )
        )


        target = (
            normalize_string(
                edge.get(
                    "target"
                )
            )
        )


        for node_id in {
            source,
            target
        }:

            if (
                not node_id
                or
                node_id
                ==
                "external-attacker"
            ):

                continue


            frequency[
                node_id
            ] = (
                frequency.get(
                    node_id,
                    0
                )
                +
                1
            )


    return frequency


# ==========================================
# GENERATE ASSET FINDINGS
# ==========================================

def generate_asset_findings(
    assets,
    path_frequency=None,
    edge_frequency=None
):
    """
    Generate defensive findings from current
    Asset Inventory evidence.
    """

    if not isinstance(
        assets,
        list
    ):

        return []


    path_frequency = (
        path_frequency
        if isinstance(
            path_frequency,
            dict
        )
        else {}
    )


    edge_frequency = (
        edge_frequency
        if isinstance(
            edge_frequency,
            dict
        )
        else {}
    )


    findings = []


    for asset in assets:

        if not isinstance(
            asset,
            dict
        ):

            continue


        asset_id = (
            normalize_string(
                asset.get(
                    "_id"
                )
            )
        )


        if not asset_id:

            continue


        target = (
            normalize_string(
                asset.get(
                    "target"
                )
            )
        )


        risk_score = (
            normalize_risk_score(
                asset.get(
                    "risk_score"
                )
            )
        )


        risk_level = (
            normalize_risk_level(
                asset.get(
                    "risk_level"
                )
            )
        )


        exposure = (
            normalize_exposure(
                asset.get(
                    "exposure"
                )
            )
        )


        criticality = (
            normalize_criticality(
                asset.get(
                    "criticality"
                )
            )
        )


        vulnerability_count = (
            get_vulnerability_count(
                asset
            )
        )


        sensitive_ports = (
            get_sensitive_open_ports(
                asset
            )
        )


        path_count = (
            path_frequency.get(
                asset_id,
                0
            )
        )


        relationship_count = (
            edge_frequency.get(
                asset_id,
                0
            )
        )


        # ==================================
        # CALCULATE DEFENSIVE IMPORTANCE
        # ==================================

        score = (
            calculate_asset_defense_score(
                asset=asset,
                path_count=path_count,
                relationship_count=(
                    relationship_count
                )
            )
        )


        evidence = []


        if risk_score > 0:

            evidence.append(
                f"Current asset risk score is {risk_score}/100."
            )


        if exposure == "EXTERNAL":

            evidence.append(
                "Asset is marked as externally exposed."
            )


        if criticality == "HIGH":

            evidence.append(
                "Asset criticality is marked HIGH."
            )


        if vulnerability_count > 0:

            evidence.append(
                f"{vulnerability_count} security finding"
                f"{'' if vulnerability_count == 1 else 's'} "
                "currently associated with the asset."
            )


        if sensitive_ports:

            evidence.append(
                "Security-sensitive open ports detected: "
                +
                ", ".join(
                    str(
                        port
                    )
                    for port
                    in sensitive_ports
                )
                +
                "."
            )


        if path_count > 0:

            evidence.append(
                f"Asset appears in {path_count} generated "
                f"attack path{'' if path_count == 1 else 's'}."
            )


        if relationship_count > 0:

            evidence.append(
                f"Asset participates in {relationship_count} "
                "graph relationship"
                f"{'' if relationship_count == 1 else 's'}."
            )


        # ==================================
        # ONLY CREATE A FINDING WHEN
        # SECURITY EVIDENCE EXISTS
        # ==================================

        if not should_create_asset_finding(
            risk_score=risk_score,
            risk_level=risk_level,
            exposure=exposure,
            vulnerability_count=(
                vulnerability_count
            ),
            sensitive_ports=(
                sensitive_ports
            ),
            path_count=path_count,
            relationship_count=(
                relationship_count
            )
        ):

            continue


        severity = (
            determine_finding_severity(
                score
            )
        )


        finding = (
            create_defense_finding(

                finding_id=(
                    f"asset-defense-{asset_id}"
                ),

                finding_type=(
                    "asset_security_priority"
                ),

                title=(
                    f"Security-Relevant Asset: {target}"
                ),

                description=(
                    "This asset contains security evidence "
                    "that increases its defensive importance "
                    "within the current environment."
                ),

                asset_id=asset_id,

                target=target,

                severity=severity,

                confidence="HIGH",

                score=score,

                evidence=evidence,

                related_nodes=[
                    asset_id
                ]

            )
        )


        findings.append(
            finding
        )


    return findings


# ==========================================
# SHOULD CREATE ASSET FINDING
# ==========================================

def should_create_asset_finding(
    risk_score,
    risk_level,
    exposure,
    vulnerability_count,
    sensitive_ports,
    path_count,
    relationship_count
):
    """
    Decide whether an asset has sufficient
    defensive significance for a finding.
    """

    if (
        risk_level
        in {
            "HIGH",
            "CRITICAL"
        }
    ):

        return True


    if risk_score >= 25:

        return True


    if exposure == "EXTERNAL":

        return True


    if vulnerability_count > 0:

        return True


    if sensitive_ports:

        return True


    if path_count > 0:

        return True


    if relationship_count > 0:

        return True


    return False


# ==========================================
# ASSET DEFENSE SCORE
# ==========================================

def calculate_asset_defense_score(
    asset,
    path_count=0,
    relationship_count=0
):
    """
    Calculate defensive importance score.

    Maximum score = 100

    Components:

    Asset Risk           0-40
    Path Presence        0-20
    Relationships        0-10
    External Exposure    0-10
    Vulnerabilities      0-10
    Sensitive Services   0-10
    """

    if not isinstance(
        asset,
        dict
    ):

        return 0


    score = 0


    # ======================================
    # ASSET RISK
    # MAX 40
    # ======================================

    risk_score = (
        normalize_risk_score(
            asset.get(
                "risk_score"
            )
        )
    )


    score += (
        risk_score
        *
        0.40
    )


    # ======================================
    # PATH PRESENCE
    # MAX 20
    # ======================================

    path_count = (
        normalize_non_negative_integer(
            path_count
        )
    )


    score += min(
        path_count * 7,
        20
    )


    # ======================================
    # RELATIONSHIP PRESENCE
    # MAX 10
    # ======================================

    relationship_count = (
        normalize_non_negative_integer(
            relationship_count
        )
    )


    score += min(
        relationship_count * 4,
        10
    )


    # ======================================
    # EXTERNAL EXPOSURE
    # MAX 10
    # ======================================

    if (
        normalize_exposure(
            asset.get(
                "exposure"
            )
        )
        ==
        "EXTERNAL"
    ):

        score += 10


    # ======================================
    # VULNERABILITY EVIDENCE
    # MAX 10
    # ======================================

    vulnerability_count = (
        get_vulnerability_count(
            asset
        )
    )


    score += min(
        vulnerability_count * 4,
        10
    )


    # ======================================
    # SENSITIVE SERVICES
    # MAX 10
    # ======================================

    sensitive_ports = (
        get_sensitive_open_ports(
            asset
        )
    )


    score += min(
        len(
            sensitive_ports
        )
        *
        3,
        10
    )


    return normalize_score(
        score
    )


# ==========================================
# GENERATE RELATIONSHIP FINDINGS
# ==========================================

def generate_relationship_findings(
    edges,
    paths,
    asset_index=None
):
    """
    Identify relationships that may represent
    defensive choke points.
    """

    if not isinstance(
        edges,
        list
    ):

        return []


    asset_index = (
        asset_index
        if isinstance(
            asset_index,
            dict
        )
        else {}
    )


    edge_path_frequency = (
        calculate_edge_path_frequency(
            paths
        )
    )


    findings = []


    for edge in edges:

        if not isinstance(
            edge,
            dict
        ):

            continue


        edge_id = (
            normalize_string(
                edge.get(
                    "id"
                )
            )
        )


        if not edge_id:

            continue


        source = (
            normalize_string(
                edge.get(
                    "source"
                )
            )
        )


        target = (
            normalize_string(
                edge.get(
                    "target"
                )
            )
        )


        relationship = (
            normalize_string(
                edge.get(
                    "relationship"
                ),
                default="potential_relationship"
            )
        )


        confidence = (
            normalize_confidence(
                edge.get(
                    "confidence"
                )
            )
        )


        edge_score = (
            normalize_score(
                edge.get(
                    "score"
                )
            )
        )


        path_count = (
            edge_path_frequency.get(
                edge_id,
                0
            )
        )


        score = (
            calculate_relationship_defense_score(
                edge=edge,
                path_count=path_count
            )
        )


        evidence = []


        existing_evidence = (
            edge.get(
                "evidence"
            )
        )


        if isinstance(
            existing_evidence,
            list
        ):

            evidence.extend(
                existing_evidence
            )


        evidence.append(
            f"Relationship score is {edge_score}/100."
        )


        if path_count > 0:

            evidence.append(
                f"Relationship appears in {path_count} "
                f"attack path{'' if path_count == 1 else 's'}."
            )


        evidence.append(
            f"Relationship confidence is {confidence}."
        )


        if source == "external-attacker":

            evidence.append(
                "Relationship represents a potential "
                "external entry point."
            )


        severity = (
            determine_finding_severity(
                score
            )
        )


        related_nodes = []


        if (
            source
            and
            source !=
            "external-attacker"
        ):

            related_nodes.append(
                source
            )


        if (
            target
            and
            target !=
            "external-attacker"
        ):

            related_nodes.append(
                target
            )


        target_asset = (
            asset_index.get(
                target
            )
        )


        target_name = (
            normalize_string(
                target_asset.get(
                    "target"
                )
            )
            if isinstance(
                target_asset,
                dict
            )
            else target
        )


        finding = (
            create_defense_finding(

                finding_id=(
                    f"relationship-defense-{edge_id}"
                ),

                finding_type=(
                    "relationship_choke_point"
                ),

                title=(
                    "Potential Defensive Choke Point"
                ),

                description=(
                    "This graph relationship contributes "
                    "to potential attacker progression and "
                    "may be significant when prioritizing "
                    "defensive controls."
                ),

                asset_id=(
                    target
                    if target
                    in asset_index
                    else None
                ),

                target=(
                    target_name
                ),

                severity=severity,

                confidence=confidence,

                score=score,

                evidence=evidence,

                related_nodes=(
                    related_nodes
                ),

                related_edges=[
                    edge_id
                ]

            )
        )


        findings.append(
            finding
        )


    return findings


# ==========================================
# EDGE PATH FREQUENCY
# ==========================================

def calculate_edge_path_frequency(
    paths
):
    """
    Count how many attack paths use each
    graph edge.
    """

    frequency = {}


    if not isinstance(
        paths,
        list
    ):

        return frequency


    for path in paths:

        if not isinstance(
            path,
            dict
        ):

            continue


        edges = (
            path.get(
                "edges"
            )
        )


        if not isinstance(
            edges,
            list
        ):

            continue


        seen = set()


        for edge_id in edges:

            edge_id = (
                normalize_string(
                    edge_id
                )
            )


            if (
                not edge_id
                or
                edge_id
                in seen
            ):

                continue


            seen.add(
                edge_id
            )


            frequency[
                edge_id
            ] = (
                frequency.get(
                    edge_id,
                    0
                )
                +
                1
            )


    return frequency


# ==========================================
# RELATIONSHIP DEFENSE SCORE
# ==========================================

def calculate_relationship_defense_score(
    edge,
    path_count=0
):
    """
    Calculate defensive significance of
    a graph relationship.

    Maximum score = 100.

    Components:

    Relationship score    0-60
    Path frequency        0-25
    Confidence            0-15
    """

    if not isinstance(
        edge,
        dict
    ):

        return 0


    score = 0


    edge_score = (
        normalize_score(
            edge.get(
                "score"
            )
        )
    )


    score += (
        edge_score
        *
        0.60
    )


    path_count = (
        normalize_non_negative_integer(
            path_count
        )
    )


    score += min(
        path_count * 8,
        25
    )


    confidence = (
        normalize_confidence(
            edge.get(
                "confidence"
            )
        )
    )


    score += (
        CONFIDENCE_WEIGHT.get(
            confidence,
            0
        )
    )


    return normalize_score(
        score
    )


# ==========================================
# GENERATE PATH FINDINGS
# ==========================================

def generate_path_findings(
    paths,
    asset_index=None
):
    """
    Generate defensive findings from
    discovered attack paths.
    """

    if not isinstance(
        paths,
        list
    ):

        return []


    asset_index = (
        asset_index
        if isinstance(
            asset_index,
            dict
        )
        else {}
    )


    findings = []


    for index, path in enumerate(
        paths
    ):

        if not isinstance(
            path,
            dict
        ):

            continue


        path_id = (
            normalize_string(
                path.get(
                    "id"
                ),
                default=(
                    f"path-{index + 1}"
                )
            )
        )


        score = (
            normalize_score(
                path.get(
                    "score"
                )
            )
        )


        risk_level = (
            normalize_risk_level(
                path.get(
                    "risk_level"
                )
            )
        )


        confidence = (
            normalize_confidence(
                path.get(
                    "confidence"
                )
            )
        )


        nodes = (
            path.get(
                "nodes"
            )
        )


        if not isinstance(
            nodes,
            list
        ):

            nodes = []


        edges = (
            path.get(
                "edges"
            )
        )


        if not isinstance(
            edges,
            list
        ):

            edges = []


        asset_nodes = [

            normalize_string(
                node_id
            )

            for node_id
            in nodes

            if (
                normalize_string(
                    node_id
                )
                and
                normalize_string(
                    node_id
                )
                !=
                "external-attacker"
            )

        ]


        evidence = []


        evidence.append(
            f"Attack path score is {score}/100."
        )


        evidence.append(
            f"Attack path risk level is {risk_level}."
        )


        evidence.append(
            f"Attack path confidence is {confidence}."
        )


        evidence.append(
            f"Attack path contains {len(asset_nodes)} "
            f"asset node{'' if len(asset_nodes) == 1 else 's'}."
        )


        existing_evidence = (
            path.get(
                "evidence"
            )
        )


        if isinstance(
            existing_evidence,
            list
        ):

            evidence.extend(
                existing_evidence
            )


        severity = (
            determine_finding_severity(
                score
            )
        )


        final_asset_id = (
            asset_nodes[-1]
            if asset_nodes
            else None
        )


        final_asset = (
            asset_index.get(
                final_asset_id
            )
        )


        final_target = (

            normalize_string(
                final_asset.get(
                    "target"
                )
            )

            if isinstance(
                final_asset,
                dict
            )

            else None

        )


        finding = (
            create_defense_finding(

                finding_id=(
                    f"path-defense-{path_id}"
                ),

                finding_type=(
                    "attack_path_priority"
                ),

                title=(
                    "Potential Attack Path Requires Review"
                ),

                description=(
                    "This generated attack path represents "
                    "potential attacker progression across "
                    "the analyzed environment and contributes "
                    "to defensive prioritization."
                ),

                asset_id=(
                    final_asset_id
                ),

                target=(
                    final_target
                ),

                severity=severity,

                confidence=confidence,

                score=score,

                evidence=evidence,

                related_nodes=(
                    asset_nodes
                ),

                related_edges=(
                    edges
                ),

                related_paths=[
                    path_id
                ]

            )
        )


        findings.append(
            finding
        )


    return findings


# ==========================================
# GENERATE DEFENSE PRIORITIES
# ==========================================

def generate_defense_priorities(
    findings,
    assets=None,
    paths=None,
    path_frequency=None
):
    """
    Convert defensive findings into ranked
    priority records.

    This does not generate mitigation steps.
    """

    if not isinstance(
        findings,
        list
    ):

        return []


    priorities = []


    for finding in findings:

        if not isinstance(
            finding,
            dict
        ):

            continue


        finding_id = (
            normalize_string(
                finding.get(
                    "id"
                )
            )
        )


        if not finding_id:

            continue


        finding_type = (
            normalize_string(
                finding.get(
                    "finding_type"
                ),
                default="general"
            )
        )


        score = (
            normalize_score(
                finding.get(
                    "score"
                )
            )
        )


        priority_level = (
            determine_priority_level(
                score
            )
        )


        confidence = (
            normalize_confidence(
                finding.get(
                    "confidence"
                )
            )
        )


        target = (
            finding.get(
                "target"
            )
        )


        asset_id = (
            finding.get(
                "asset_id"
            )
        )


        # ==================================
        # PRIORITY TYPE / TITLE
        # ==================================

        if (
            finding_type
            ==
            "asset_security_priority"
        ):

            priority_type = (
                "asset_priority"
            )

            title = (
                "Prioritize Asset Review"
            )

            reason = (
                "The asset combines security evidence "
                "that increases its defensive importance."
            )


        elif (
            finding_type
            ==
            "relationship_choke_point"
        ):

            priority_type = (
                "relationship_priority"
            )

            title = (
                "Prioritize Graph Relationship Review"
            )

            reason = (
                "The relationship contributes to potential "
                "attacker progression and may represent a "
                "defensive choke point."
            )


        elif (
            finding_type
            ==
            "attack_path_priority"
        ):

            priority_type = (
                "attack_path_priority"
            )

            title = (
                "Prioritize Attack Path Review"
            )

            reason = (
                "The attack path contributes directly "
                "to potential attacker progression across "
                "the current environment."
            )


        else:

            priority_type = (
                "general_priority"
            )

            title = (
                "Review Security Finding"
            )

            reason = (
                "The finding contributes to the current "
                "defensive risk context."
            )


        priority = (
            create_defense_priority(

                priority_id=(
                    f"priority-{finding_id}"
                ),

                priority_type=(
                    priority_type
                ),

                title=(
                    title
                ),

                description=(
                    finding.get(
                        "description",
                        ""
                    )
                ),

                priority_level=(
                    priority_level
                ),

                score=(
                    score
                ),

                confidence=(
                    confidence
                ),

                asset_id=(
                    asset_id
                ),

                target=(
                    target
                ),

                reason=(
                    reason
                ),

                evidence=(
                    finding.get(
                        "evidence"
                    )
                ),

                related_findings=[
                    finding_id
                ],

                related_paths=(
                    finding.get(
                        "related_paths"
                    )
                )

            )
        )


        priorities.append(
            priority
        )


    return priorities


# ==========================================
# DETERMINE FINDING SEVERITY
# ==========================================

def determine_finding_severity(
    score
):
    """
    Convert Defense Analysis score into
    severity.
    """

    score = (
        normalize_score(
            score
        )
    )


    if score >= 75:

        return "CRITICAL"


    if score >= 50:

        return "HIGH"


    if score >= 25:

        return "MEDIUM"


    return "LOW"


# ==========================================
# DETERMINE PRIORITY LEVEL
# ==========================================

def determine_priority_level(
    score
):
    """
    Convert defensive score into
    prioritization level.
    """

    return determine_finding_severity(
        score
    )


# ==========================================
# RISK NORMALIZATION
# ==========================================

def normalize_risk_score(
    value
):
    """
    Normalize asset risk score into 0-100.
    """

    return normalize_score(
        value
    )


def normalize_risk_level(
    value
):
    """
    Normalize risk level.
    """

    normalized = (
        normalize_string(
            value,
            default="UNKNOWN"
        )
        .upper()
    )


    if normalized not in (
        RISK_LEVEL_ORDER
    ):

        return "UNKNOWN"


    return normalized


# ==========================================
# EXPOSURE NORMALIZATION
# ==========================================

def normalize_exposure(
    value
):
    """
    Normalize asset exposure.

    UNKNOWN is preserved because users may
    not yet have classified an asset.
    """

    normalized = (
        normalize_string(
            value,
            default="UNKNOWN"
        )
        .upper()
    )


    if normalized in {
        "INTERNAL",
        "EXTERNAL",
        "UNKNOWN"
    }:

        return normalized


    return "UNKNOWN"


# ==========================================
# CRITICALITY NORMALIZATION
# ==========================================

def normalize_criticality(
    value
):
    """
    Normalize asset criticality.
    """

    normalized = (
        normalize_string(
            value,
            default="NORMAL"
        )
        .upper()
    )


    if normalized in {
        "LOW",
        "NORMAL",
        "HIGH",
        "CRITICAL"
    }:

        return normalized


    return "NORMAL"


# ==========================================
# OPEN PORTS
# ==========================================

def get_open_ports(
    asset
):
    """
    Return unique currently open TCP/UDP
    ports from an asset.
    """

    if not isinstance(
        asset,
        dict
    ):

        return []


    ports = (
        asset.get(
            "ports"
        )
    )


    if not isinstance(
        ports,
        list
    ):

        return []


    normalized = []

    seen = set()


    for port_record in ports:

        if not isinstance(
            port_record,
            dict
        ):

            continue


        state = (
            normalize_string(
                port_record.get(
                    "state"
                )
            )
            .lower()
        )


        if state != "open":

            continue


        port_number = (
            normalize_port_number(
                port_record.get(
                    "port"
                )
            )
        )


        if port_number is None:

            continue


        protocol = (
            normalize_string(
                port_record.get(
                    "protocol"
                ),
                default="tcp"
            )
            .lower()
        )


        key = (
            protocol,
            port_number
        )


        if key in seen:

            continue


        seen.add(
            key
        )


        normalized.append({

            "port":
                port_number,

            "protocol":
                protocol,

            "state":
                "open",

            "service":
                normalize_string(
                    port_record.get(
                        "service"
                    )
                )

        })


    normalized.sort(
        key=lambda item: (
            item["port"],
            item["protocol"]
        )
    )


    return normalized


# ==========================================
# SENSITIVE OPEN PORTS
# ==========================================

def get_sensitive_open_ports(
    asset
):
    """
    Return security-sensitive ports that are
    currently open.
    """

    ports = (
        get_open_ports(
            asset
        )
    )


    sensitive = []


    for port_record in ports:

        port_number = (
            port_record.get(
                "port"
            )
        )


        if (
            port_number
            in SENSITIVE_PORTS
        ):

            sensitive.append(
                port_number
            )


    return sorted(
        set(
            sensitive
        )
    )


# ==========================================
# VULNERABILITY COUNT
# ==========================================

def get_vulnerability_count(
    asset
):
    """
    Safely determine current vulnerability
    count for an asset.
    """

    if not isinstance(
        asset,
        dict
    ):

        return 0


    vulnerabilities = (
        asset.get(
            "vulnerabilities"
        )
    )


    if isinstance(
        vulnerabilities,
        list
    ):

        valid_count = 0


        for vulnerability in vulnerabilities:

            if not isinstance(
                vulnerability,
                dict
            ):

                continue


            status = (
                normalize_string(
                    vulnerability.get(
                        "status"
                    ),
                    default="potential"
                )
                .lower()
            )


            if status in {
                "resolved",
                "rejected"
            }:

                continue


            valid_count += 1


        return valid_count


    return normalize_non_negative_integer(
        asset.get(
            "vulnerability_count"
        )
    )


# ==========================================
# NORMALIZE PORT NUMBER
# ==========================================

def normalize_port_number(
    value
):
    """
    Safely normalize valid TCP/UDP port.
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


    if (
        port < 1
        or
        port > 65535
    ):

        return None


    return port


# ==========================================
# NORMALIZE NON-NEGATIVE INTEGER
# ==========================================

def normalize_non_negative_integer(
    value
):
    """
    Normalize integer while preventing
    negative values.
    """

    try:

        value = int(
            value
        )

    except (
        TypeError,
        ValueError
    ):

        return 0


    if value < 0:

        return 0


    return value


# ==========================================
# DEDUPLICATE FINDINGS
# ==========================================

def deduplicate_findings(
    findings
):
    """
    Remove duplicate findings using
    finding ID.
    """

    if not isinstance(
        findings,
        list
    ):

        return []


    result = []

    seen = set()


    for finding in findings:

        if not isinstance(
            finding,
            dict
        ):

            continue


        finding_id = (
            normalize_string(
                finding.get(
                    "id"
                )
            )
        )


        if (
            not finding_id
            or
            finding_id
            in seen
        ):

            continue


        seen.add(
            finding_id
        )


        result.append(
            finding
        )


    return result


# ==========================================
# DEDUPLICATE PRIORITIES
# ==========================================

def deduplicate_priorities(
    priorities
):
    """
    Remove duplicate priority records.
    """

    if not isinstance(
        priorities,
        list
    ):

        return []


    result = []

    seen = set()


    for priority in priorities:

        if not isinstance(
            priority,
            dict
        ):

            continue


        priority_id = (
            normalize_string(
                priority.get(
                    "id"
                )
            )
        )


        if (
            not priority_id
            or
            priority_id
            in seen
        ):

            continue


        seen.add(
            priority_id
        )


        result.append(
            priority
        )


    return result


# ==========================================
# SORT FINDINGS
# ==========================================

def sort_findings(
    findings
):
    """
    Sort findings deterministically with
    highest defensive score first.
    """

    if not isinstance(
        findings,
        list
    ):

        return []


    return sorted(

        findings,

        key=lambda finding: (

            -normalize_score(
                finding.get(
                    "score"
                )
            ),

            normalize_string(
                finding.get(
                    "id"
                )
            )

        )

    )


# ==========================================
# SORT PRIORITIES
# ==========================================

def sort_priorities(
    priorities
):
    """
    Sort defense priorities with highest
    priority score first.
    """

    if not isinstance(
        priorities,
        list
    ):

        return []


    return sorted(

        priorities,

        key=lambda priority: (

            -normalize_score(
                priority.get(
                    "score"
                )
            ),

            normalize_string(
                priority.get(
                    "id"
                )
            )

        )

    )