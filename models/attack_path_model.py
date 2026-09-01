# ==========================================
# ATTACK PATH MODEL
# ==========================================
#
# This file defines the normalized data
# structures used by the Attack Path Engine.
#
# IMPORTANT:
#
# The model does NOT generate attack paths.
#
# It only creates predictable graph,
# node, edge, path, and statistics
# structures for the service layer.
# ==========================================


from datetime import datetime, timezone


# ==========================================
# CREATE ATTACK GRAPH DOCUMENT
# ==========================================

def create_attack_graph_document(
    created_by=None
):
    """
    Create the base Attack Path graph
    structure.

    Parameters
    ----------
    created_by:
        Owner/user identifier associated
        with this graph.

    Returns
    -------
    dict
        Normalized attack graph document.
    """

    return {

        # ==================================
        # OWNERSHIP INFORMATION
        # ==================================

        "created_by": created_by,


        # ==================================
        # GENERATION INFORMATION
        # ==================================

        "generated_at": (
            datetime.now(
                timezone.utc
            )
        ),


        # ==================================
        # GRAPH INFORMATION
        # ==================================

        "nodes": [],

        "edges": [],

        "paths": [],


        # ==================================
        # GRAPH STATISTICS
        # ==================================

        "statistics": {

            "total_nodes": 0,

            "total_assets": 0,

            "total_edges": 0,

            "total_paths": 0,

            "low_risk_paths": 0,

            "medium_risk_paths": 0,

            "high_risk_paths": 0,

            "critical_risk_paths": 0
        }
    }


# ==========================================
# CREATE ASSET NODE
# ==========================================

def create_asset_node(
    asset_id,
    target,
    hostname=None,
    risk_score=None,
    risk_level=None,
    criticality=None,
    exposure=None,
    operating_system=None,
    open_ports=None,
    services=None,
    vulnerability_count=0
):
    """
    Create a normalized graph node for an
    AttackLens Asset.
    """

    return {

        # ==================================
        # NODE IDENTITY
        # ==================================

        "id": str(
            asset_id
        ),

        "node_type": "asset",


        # ==================================
        # ASSET IDENTITY
        # ==================================

        "target": target,

        "hostname": hostname,


        # ==================================
        # SECURITY CONTEXT
        # ==================================

        "risk_score": risk_score,

        "risk_level": risk_level,

        "criticality": criticality,

        "exposure": exposure,


        # ==================================
        # SYSTEM INFORMATION
        # ==================================

        "operating_system": (
            operating_system
        ),


        # ==================================
        # ATTACK SURFACE
        # ==================================

        "open_ports": (
            open_ports
            if isinstance(
                open_ports,
                list
            )
            else []
        ),

        "services": (
            services
            if isinstance(
                services,
                list
            )
            else []
        ),


        # ==================================
        # SECURITY FINDINGS
        # ==================================

        "vulnerability_count": (
            normalize_non_negative_integer(
                vulnerability_count
            )
        )
    }


# ==========================================
# CREATE EXTERNAL ATTACKER NODE
# ==========================================

def create_external_attacker_node():
    """
    Create the logical external attacker node.

    This node is NOT a scanned asset.

    It represents the external starting point
    for assets explicitly marked as EXTERNAL.
    """

    return {

        "id": "external-attacker",

        "node_type": "attacker",

        "target": None,

        "hostname": "External Attacker",

        "risk_score": None,

        "risk_level": None,

        "criticality": None,

        "exposure": "EXTERNAL",

        "operating_system": None,

        "open_ports": [],

        "services": [],

        "vulnerability_count": 0
    }


# ==========================================
# CREATE ATTACK EDGE
# ==========================================

def create_attack_edge(
    edge_id,
    source,
    target,
    relationship,
    confidence,
    score,
    evidence=None
):
    """
    Create a normalized graph relationship.

    An edge represents a POTENTIAL attack
    relationship.

    It does not automatically mean that
    exploitation or lateral movement has
    been verified.
    """

    return {

        # ==================================
        # EDGE IDENTITY
        # ==================================

        "id": str(
            edge_id
        ),

        "source": str(
            source
        ),

        "target": str(
            target
        ),


        # ==================================
        # RELATIONSHIP INFORMATION
        # ==================================

        "relationship": (
            normalize_string(
                relationship,
                default="potential_relationship"
            )
        ),


        # ==================================
        # CONFIDENCE
        # ==================================

        "confidence": (
            normalize_confidence(
                confidence
            )
        ),


        # ==================================
        # EDGE SCORE
        # ==================================

        "score": (
            normalize_score(
                score
            )
        ),


        # ==================================
        # EVIDENCE
        # ==================================

        "evidence": (
            normalize_evidence(
                evidence
            )
        )
    }


# ==========================================
# CREATE ATTACK PATH
# ==========================================

def create_attack_path(
    path_id,
    node_ids,
    edge_ids,
    score,
    risk_level,
    confidence,
    evidence=None
):
    """
    Create a normalized attack path.

    A path contains ordered node and edge
    identifiers describing a potential
    attacker progression.
    """

    return {

        # ==================================
        # PATH IDENTITY
        # ==================================

        "id": str(
            path_id
        ),


        # ==================================
        # ORDERED GRAPH ELEMENTS
        # ==================================

        "nodes": (
            normalize_identifier_list(
                node_ids
            )
        ),

        "edges": (
            normalize_identifier_list(
                edge_ids
            )
        ),


        # ==================================
        # PATH SCORE
        # ==================================

        "score": (
            normalize_score(
                score
            )
        ),


        # ==================================
        # PATH RISK
        # ==================================

        "risk_level": (
            normalize_risk_level(
                risk_level
            )
        ),


        # ==================================
        # PATH CONFIDENCE
        # ==================================

        "confidence": (
            normalize_confidence(
                confidence
            )
        ),


        # ==================================
        # SUPPORTING EVIDENCE
        # ==================================

        "evidence": (
            normalize_evidence(
                evidence
            )
        )
    }


# ==========================================
# CREATE GRAPH STATISTICS
# ==========================================

def create_graph_statistics(
    nodes=None,
    edges=None,
    paths=None
):
    """
    Generate graph-level statistics from the
    normalized graph structures.
    """

    nodes = (
        nodes
        if isinstance(
            nodes,
            list
        )
        else []
    )

    edges = (
        edges
        if isinstance(
            edges,
            list
        )
        else []
    )

    paths = (
        paths
        if isinstance(
            paths,
            list
        )
        else []
    )


    # ======================================
    # ASSET NODE COUNT
    # ======================================

    total_assets = 0

    for node in nodes:

        if not isinstance(
            node,
            dict
        ):

            continue

        if (
            node.get(
                "node_type"
            )
            ==
            "asset"
        ):

            total_assets += 1


    # ======================================
    # PATH RISK COUNTS
    # ======================================

    low_risk_paths = 0

    medium_risk_paths = 0

    high_risk_paths = 0

    critical_risk_paths = 0


    for path in paths:

        if not isinstance(
            path,
            dict
        ):

            continue


        risk_level = (
            normalize_risk_level(
                path.get(
                    "risk_level"
                )
            )
        )


        if risk_level == "LOW":

            low_risk_paths += 1

        elif risk_level == "MEDIUM":

            medium_risk_paths += 1

        elif risk_level == "HIGH":

            high_risk_paths += 1

        elif risk_level == "CRITICAL":

            critical_risk_paths += 1


    # ======================================
    # RETURN STATISTICS
    # ======================================

    return {

        "total_nodes": len(
            nodes
        ),

        "total_assets": (
            total_assets
        ),

        "total_edges": len(
            edges
        ),

        "total_paths": len(
            paths
        ),

        "low_risk_paths": (
            low_risk_paths
        ),

        "medium_risk_paths": (
            medium_risk_paths
        ),

        "high_risk_paths": (
            high_risk_paths
        ),

        "critical_risk_paths": (
            critical_risk_paths
        )
    }


# ==========================================
# NORMALIZE SCORE
# ==========================================

def normalize_score(
    value
):
    """
    Normalize a score into the 0-100 range.
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


    score = max(
        0.0,
        min(
            100.0,
            score
        )
    )


    if score.is_integer():

        return int(
            score
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
    """
    Normalize AttackLens risk level.
    """

    if value is None:

        return "UNKNOWN"


    risk_level = str(
        value
    ).strip().upper()


    if risk_level not in (
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ):

        return "UNKNOWN"

    return risk_level


# ==========================================
# NORMALIZE CONFIDENCE
# ==========================================

def normalize_confidence(
    value
):
    """
    Normalize attack-path confidence.
    """

    if value is None:

        return "UNKNOWN"


    confidence = str(
        value
    ).strip().upper()


    if confidence not in (
        "LOW",
        "MEDIUM",
        "HIGH"
    ):

        return "UNKNOWN"

    return confidence


# ==========================================
# NORMALIZE EVIDENCE
# ==========================================

def normalize_evidence(
    evidence
):
    """
    Normalize evidence into a deduplicated
    list of strings.
    """

    if not isinstance(
        evidence,
        list
    ):

        return []


    normalized = []

    seen = set()


    for item in evidence:

        if item is None:

            continue


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
# NORMALIZE IDENTIFIER LIST
# ==========================================

def normalize_identifier_list(
    values
):
    """
    Normalize path node/edge identifiers.
    """

    if not isinstance(
        values,
        list
    ):

        return []


    normalized = []

    seen = set()


    for value in values:

        if value is None:

            continue


        identifier = str(
            value
        ).strip()


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
# NORMALIZE NON-NEGATIVE INTEGER
# ==========================================

def normalize_non_negative_integer(
    value
):
    """
    Convert a value into a safe non-negative
    integer.
    """

    try:

        number = int(
            value
        )

    except (
        TypeError,
        ValueError
    ):

        return 0


    return max(
        0,
        number
    )


# ==========================================
# NORMALIZE STRING
# ==========================================

def normalize_string(
    value,
    default=""
):
    """
    Normalize text fields safely.
    """

    if value is None:

        return default


    value = str(
        value
    ).strip()


    if not value:

        return default

    return value