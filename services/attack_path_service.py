# ==========================================

# ATTACK PATH SERVICE

# ==========================================

#

# This service generates the logical attack

# graph used by AttackLens.

#

# IMPORTANT:

#

# Attack paths produced by this service are

# POTENTIAL attack paths based on available

# security evidence.

#

# They do not prove successful exploitation,

# network reachability, or lateral movement.

#

# The service intentionally uses conservative

# rules so AttackLens does not fabricate

# unsupported relationships.

# ==========================================





from models.attack_path_model import (

    create_attack_graph_document,

    create_asset_node,

    create_external_attacker_node,

    create_attack_edge,

    create_attack_path,

    create_graph_statistics,

    normalize_score,

    normalize_risk_level

)





# ==========================================

# ENGINE CONSTANTS

# ==========================================





# Ports commonly associated with remote

# administration, lateral movement, database

# access, or other security-sensitive

# services.



SENSITIVE_PORTS = {

    21: "FTP",

    22: "SSH",

    23: "Telnet",

    25: "SMTP",

    53: "DNS",

    110: "POP3",

    135: "MSRPC",

    139: "NetBIOS",

    445: "SMB",

    512: "rexec",

    513: "rlogin",

    514: "rsh",

    1099: "Java RMI",

    1433: "Microsoft SQL Server",

    1524: "Bind Shell",

    1521: "Oracle Database",

    2049: "NFS",

    2121: "FTP / ProFTPD",

    3306: "MySQL",

    3389: "RDP",

    5432: "PostgreSQL",

    5900: "VNC",

    6000: "X11",

    6379: "Redis",

    6667: "IRC",

    8009: "AJP13",

    8180: "HTTP / Tomcat",

    27017: "MongoDB"

}





# ==========================================

# RISK LEVEL ORDER

# ==========================================



RISK_LEVEL_ORDER = {

    "UNKNOWN": 0,

    "LOW": 1,

    "MEDIUM": 2,

    "HIGH": 3,

    "CRITICAL": 4

}





# ==========================================

# CRITICALITY WEIGHTS

# ==========================================



CRITICALITY_WEIGHTS = {

    "LOW": 2,

    "NORMAL": 5,

    "MEDIUM": 7,

    "HIGH": 10,

    "CRITICAL": 15

}





# ==========================================

# EXPOSURE WEIGHTS

# ==========================================



EXPOSURE_WEIGHTS = {

    "INTERNAL": 0,

    "EXTERNAL": 20

}





# ==========================================

# CONFIDENCE WEIGHTS

# ==========================================



CONFIDENCE_WEIGHTS = {

    "LOW": 2,

    "MEDIUM": 4,

    "HIGH": 5,

    "UNKNOWN": 0

}


# Security Finding categories that provide context/assessment quality only.
# They are stored and reported, but they must not create or strengthen an
# attack path by themselves.
CONTEXT_ONLY_SECURITY_CATEGORIES = {
    "WEB_APPLICATION_SURFACE",
    "LIMITED_VERSION_EVIDENCE",
    "LOW_CONFIDENCE_OS_DETECTION",
    "LARGE_ATTACK_SURFACE"
}

# NETWORK/SERVICE findings produced by the current scanner primarily describe
# exposed services already represented by open/sensitive-port evidence.
# Excluding them here prevents the same exposure from being counted twice.
ATTACK_EVIDENCE_FINDING_TYPES = {
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

# PUBLIC FUNCTION:

# GENERATE ATTACK GRAPH

# ==========================================



def generate_attack_graph(

    assets,

    created_by=None

):

    """

    Generate a complete AttackLens attack

    graph from normalized Asset documents.



    Parameters

    ----------

    assets:

        List of Asset documents.



    created_by:

        Owner identifier associated with the

        generated graph.



    Returns

    -------

    dict

        Attack graph containing nodes, edges,

        paths, and statistics.

    """



    graph = create_attack_graph_document(

        created_by=created_by

    )





    # ======================================

    # NORMALIZE ASSET INPUT

    # ======================================



    normalized_assets = normalize_assets(

        assets,

        created_by=created_by

    )





    # ======================================

    # BUILD ASSET NODES

    # ======================================



    asset_nodes = []



    asset_lookup = {}





    for asset in normalized_assets:



        node = build_asset_node(

            asset

        )



        if node is None:



            continue



        asset_nodes.append(

            node

        )



        asset_lookup[

            node["id"]

        ] = asset





    # ======================================

    # NO ASSETS

    # ======================================



    if not asset_nodes:



        graph["nodes"] = []



        graph["edges"] = []



        graph["paths"] = []



        graph["statistics"] = (

            create_graph_statistics(

                nodes=[],

                edges=[],

                paths=[]

            )

        )



        return graph





    # ======================================

    # GRAPH NODES

    # ======================================



    nodes = list(

        asset_nodes

    )





    # ======================================

    # EXTERNAL ATTACKER NODE

    # ======================================



    external_assets = [

        asset

        for asset in normalized_assets

        if normalize_exposure(

            asset.get(

                "exposure"

            )

        )

        == "EXTERNAL"

    ]





    if external_assets:



        attacker_node = (

            create_external_attacker_node()

        )



        nodes.insert(

            0,

            attacker_node

        )





    # ======================================

    # BUILD EDGES

    # ======================================



    edges = []





    # ======================================

    # EXTERNAL ENTRY EDGES

    # ======================================



    if external_assets:



        entry_edges = (

            generate_external_entry_edges(

                external_assets

            )

        )



        edges.extend(

            entry_edges

        )





    # ======================================

    # ASSET RELATIONSHIP EDGES

    # ======================================



    relationship_edges = (

        generate_asset_relationships(

            normalized_assets

        )

    )



    edges.extend(

        relationship_edges

    )





    # ======================================

    # SERVICE-LEVEL ENTRY ROUTES

    # ======================================
    #
    # Single-host attack paths are generated later from concrete service +
    # finding evidence. We intentionally do NOT create Asset -> Asset self
    # edges merely because a host has many vulnerabilities.


    # ======================================

    # DEDUPLICATE EDGES

    # ======================================



    edges = deduplicate_edges(

        edges

    )





    # ======================================

    # DISCOVER PATHS

    # ======================================



    paths = discover_attack_paths(

        nodes=nodes,

        edges=edges,

        asset_lookup=asset_lookup

    )

    # Build evidence-backed service entry routes for scanned assets. These
    # routes explain *how* an attack could plausibly begin without claiming
    # successful exploitation or fabricating lateral movement.
    paths.extend(generate_service_entry_paths(normalized_assets))
    paths = deduplicate_paths(paths)



    # ======================================

    # SORT PATHS

    # ======================================



    paths = sort_attack_paths(

        paths

    )[:3]





    # ======================================

    # COMPLETE GRAPH

    # ======================================



    graph["nodes"] = nodes



    graph["edges"] = edges



    graph["paths"] = paths



    graph["statistics"] = (

        create_graph_statistics(

            nodes=nodes,

            edges=edges,

            paths=paths

        )

    )





    return graph





# ==========================================

# NORMALIZE ASSETS

# ==========================================



def normalize_assets(

    assets,

    created_by=None

):

    """

    Normalize, ownership-filter, and deduplicate

    Asset records before graph generation.



    Logical Asset identity:



        created_by + normalized target



    If duplicate historical Asset documents exist

    for the same owner and target, only the newest

    record is allowed into the graph.



    This prevents repeated scans of the same target

    from producing duplicate Attack Graph nodes.

    """



    if not isinstance(

        assets,

        list

    ):



        return []





    unique_assets = {}





    for asset in assets:



        if not isinstance(

            asset,

            dict

        ):



            continue





        # ==================================

        # OWNERSHIP PROTECTION

        # ==================================



        asset_owner = asset.get(

            "created_by"

        )





        if created_by is not None:



            if str(

                asset_owner

            ) != str(

                created_by

            ):



                continue





        # ==================================

        # REQUIRE ASSET ID

        # ==================================



        asset_id = asset.get(

            "_id"

        )





        if asset_id is None:



            continue





        # ==================================

        # REQUIRE TARGET

        # ==================================



        target = str(

            asset.get(

                "target",

                ""

            )

        ).strip()





        if not target:



            continue





        # ==================================

        # LOGICAL ASSET IDENTITY

        # ==================================

        #

        # Asset Inventory uses owner + target as

        # its identity. Keep the Attack Graph

        # consistent with the same rule.

        #

        # Target comparison is case-insensitive

        # so repeated hostname scans cannot create

        # separate logical graph nodes merely due

        # to letter casing.

        # ==================================



        identity = (



            str(

                asset_owner

            ),



            target.lower()



        )





        existing = unique_assets.get(

            identity

        )





        if existing is None:



            unique_assets[

                identity

            ] = asset



            continue





        # ==================================

        # KEEP NEWEST DUPLICATE

        # ==================================



        existing_last_seen = existing.get(

            "last_seen"

        )



        candidate_last_seen = asset.get(

            "last_seen"

        )



        existing_updated_at = existing.get(

            "updated_at"

        )



        candidate_updated_at = asset.get(

            "updated_at"

        )





        replace_existing = False





        try:



            if (

                candidate_last_seen is not None

                and

                (

                    existing_last_seen is None

                    or

                    candidate_last_seen > existing_last_seen

                )

            ):



                replace_existing = True



        except TypeError:



            pass





        if not replace_existing:



            try:



                if (

                    candidate_updated_at is not None

                    and

                    (

                        existing_updated_at is None

                        or

                        candidate_updated_at > existing_updated_at

                    )

                ):



                    replace_existing = True



            except TypeError:



                pass





        # ObjectId string order is used only as a

        # deterministic fallback when timestamps do

        # not distinguish the duplicate documents.



        if (

            not replace_existing

            and

            existing_last_seen == candidate_last_seen

            and

            existing_updated_at == candidate_updated_at

            and

            str(asset_id) > str(

                existing.get(

                    "_id",

                    ""

                )

            )

        ):



            replace_existing = True





        if replace_existing:



            unique_assets[

                identity

            ] = asset





    normalized = list(

        unique_assets.values()

    )





    # ======================================

    # DETERMINISTIC ORDER

    # ======================================



    normalized.sort(

        key=lambda asset: (

            str(

                asset.get(

                    "target",

                    ""

                )

            ).lower(),

            str(

                asset.get(

                    "_id",

                    ""

                )

            )

        )

    )





    return normalized





# ==========================================

# BUILD ASSET NODE

# ==========================================



def build_asset_node(

    asset

):

    """

    Convert a MongoDB Asset document into a

    normalized Attack Path asset node.



    If hostname and target represent the same

    value, hostname is suppressed so the graph

    label does not display the same name twice.

    """



    if not isinstance(

        asset,

        dict

    ):



        return None





    asset_id = asset.get(

        "_id"

    )



    target = str(

        asset.get(

            "target",

            ""

        )

    ).strip()





    if (

        asset_id is None

        or

        not target

    ):



        return None





    # ======================================

    # NORMALIZE HOSTNAME FOR GRAPH LABEL

    # ======================================

    #

    # Nmap may return the scanned hostname as

    # both target and hostname. Showing both in

    # the node label produces output such as:

    #

    #     rapid7.com

    #     rapid7.com

    #

    # Keep the hostname only when it adds new

    # information.

    # ======================================



    raw_hostname = asset.get(

        "hostname"

    )



    hostname = (

        str(raw_hostname).strip()

        if raw_hostname is not None

        else ""

    )





    if (

        not hostname

        or

        hostname.lower() == target.lower()

    ):



        hostname = None





    # ======================================

    # OPEN PORTS

    # ======================================



    open_ports = get_asset_open_ports(asset)





    # ======================================

    # SERVICES

    # ======================================



    services = normalize_list(

        asset.get(

            "services"

        )

    )





    # ======================================

    # VULNERABILITY COUNT

    # ======================================



    vulnerability_count = (

        get_vulnerability_count(

            asset

        )

    )





    return create_asset_node(



        asset_id=asset_id,



        target=target,



        hostname=hostname,



        risk_score=normalize_score(

            asset.get(

                "risk_score"

            )

        ),



        risk_level=normalize_risk_level(

            asset.get(

                "risk_level"

            )

        ),



        criticality=normalize_criticality(

            asset.get(

                "criticality"

            )

        ),



        exposure=normalize_exposure(

            asset.get(

                "exposure"

            )

        ),



        operating_system=asset.get(

            "operating_system"

        ),



        open_ports=open_ports,



        services=services,



        vulnerability_count=(

            vulnerability_count

        )

    )





# ==========================================

# GENERATE EXTERNAL ENTRY EDGES

# ==========================================



def generate_external_entry_edges(

    assets

):

    """

    Create External Attacker -> Asset edges

    only for assets explicitly marked as

    EXTERNAL.

    """



    edges = []





    for asset in assets:



        if not isinstance(

            asset,

            dict

        ):



            continue





        asset_id = asset.get(

            "_id"

        )



        if asset_id is None:



            continue





        if normalize_exposure(

            asset.get(

                "exposure"

            )

        ) != "EXTERNAL":



            continue





        evidence = (

            extract_entry_evidence(

                asset

            )

        )





        confidence = (

            calculate_entry_confidence(

                asset

            )

        )





        score = (

            calculate_asset_attack_score(

                asset,

                confidence=confidence

            )

        )





        edge_id = (

            "external-entry:"

            f"{asset_id}"

        )





        edge = create_attack_edge(



            edge_id=edge_id,



            source="external-attacker",



            target=asset_id,



            relationship=(

                "external_entry"

            ),



            confidence=confidence,



            score=score,



            evidence=evidence



        )





        edges.append(

            edge

        )





    return edges





# ==========================================

# GENERATE SINGLE-ASSET ATTACK EDGES

# ==========================================



def generate_single_asset_attack_edges(assets):
    """Backward-compatible helper.

    AttackLens no longer models a vulnerable host as an Asset -> Asset
    self-edge. Single-host entry possibilities are represented as ranked
    service-level potential attack paths by ``generate_service_entry_paths``.
    """
    return []


def generate_service_entry_paths(assets, max_paths_per_asset=3):
    """Generate ranked, evidence-supported potential entry paths.

    A candidate requires an open service plus at least one finding that can be
    associated with that service by port or service/product evidence. Open
    ports, high risk, or raw vulnerability count alone never create a path.
    The result predicts only the furthest progression supported by available
    evidence and never claims successful exploitation.
    """
    paths = []

    for asset in normalize_list(assets):
        if not isinstance(asset, dict) or asset.get("_id") is None:
            continue

        candidates = []
        for service in get_asset_open_ports(asset):
            candidate = build_service_entry_candidate(asset, service)
            if candidate is not None:
                candidates.append(candidate)

        candidates.sort(key=lambda item: (-item["score"], item["port"], item["protocol"]))

        for candidate in candidates[:max_paths_per_asset]:
            paths.append(build_service_entry_path(asset, candidate))

    return [path for path in paths if isinstance(path, dict)]

def build_service_entry_candidate(asset, service):
    """Build one potential entry-route candidate for an open service."""
    if not isinstance(asset, dict) or not isinstance(service, dict):
        return None

    port = normalize_port_number(service.get("port"))
    if port is None:
        return None

    protocol = str(service.get("protocol", "tcp") or "tcp").strip().lower()
    service_name = str(service.get("service", service.get("name", "")) or "").strip()
    product = str(service.get("product", "") or "").strip()
    version = str(service.get("version", "") or "").strip()
    display_name = product or service_name or SENSITIVE_PORTS.get(port) or f"Port {port}"
    if version and version.lower() not in display_name.lower():
        display_name = f"{display_name} {version}".strip()

    findings = get_findings_for_service(asset, service)
    if not findings:
        return None

    finding_score = 0.0
    confidence_values = []
    summaries = []

    for finding in findings:
        severity = normalize_risk_level(finding.get("severity"))
        confidence = normalize_confidence(finding.get("confidence"))
        confidence_values.append(confidence)
        severity_points = {"CRITICAL": 30, "HIGH": 22, "MEDIUM": 12, "LOW": 5, "UNKNOWN": 2}.get(severity, 2)
        confidence_factor = {"HIGH": 1.0, "MEDIUM": 0.75, "LOW": 0.4, "UNKNOWN": 0.2}.get(confidence, 0.2)
        finding_score += severity_points * confidence_factor
        summary = get_finding_summary(finding)
        if summary and summary not in summaries:
            summaries.append(summary)

    exposure_bonus = 12 if normalize_exposure(asset.get("exposure")) == "EXTERNAL" else 0
    sensitive_bonus = 8 if port in SENSITIVE_PORTS else 0
    score = normalize_score(min(100, finding_score + exposure_bonus + sensitive_bonus))

    if "HIGH" in confidence_values:
        confidence = "HIGH"
    elif "MEDIUM" in confidence_values:
        confidence = "MEDIUM"
    elif "LOW" in confidence_values:
        confidence = "LOW"
    else:
        confidence = "UNKNOWN"

    risk_level = determine_path_risk_level(score)
    target = str(asset.get("target") or asset.get("hostname") or asset.get("_id"))
    entry = f"{display_name} on {protocol.upper()}/{port}"
    impact = build_service_impact_text(service_name, product, port, target)

    return {
        "port": port,
        "protocol": protocol,
        "service": service_name,
        "product": product,
        "version": version,
        "entry_point": entry,
        "score": score,
        "risk_level": risk_level,
        "confidence": confidence,
        "findings": findings,
        "finding_summaries": summaries[:8],
        "explanation": (
            f"{entry} is an evidence-supported potential starting point because "
            f"AttackLens associated {len(findings)} active security finding(s) with this service."
        ),
        "potential_impact": impact,
        "progression": [
            "Potential attacker",
            entry,
            (
                f"Applicable finding: {summaries[0]}"
                if summaries
                else "Applicable vulnerability / security finding"
            ),
            f"Potential access or service impact on {target}"
        ],
        "disclaimer": (
            "Potential path only. Successful exploitation is not verified, and the path "
            "stops at the furthest progression supported by current evidence."
        )
    }

def get_findings_for_service(asset, service):
    """Associate active CVE/non-CVE findings with a discovered service."""
    port = normalize_port_number(service.get("port"))
    tokens = {
        str(service.get(key, "") or "").strip().lower()
        for key in ("service", "name", "product")
        if str(service.get(key, "") or "").strip()
    }
    tokens = {token for token in tokens if len(token) >= 3 and token not in {"http", "https", "tcp", "udp"}}

    findings = []
    seen = set()
    raw_findings = []
    raw_findings.extend(normalize_list(asset.get("vulnerabilities")))
    raw_findings.extend(get_attack_security_findings(asset))

    for finding in raw_findings:
        if not isinstance(finding, dict):
            continue
        status = str(finding.get("status", "potential") or "potential").strip().lower()
        if status in INACTIVE_SECURITY_STATUSES:
            continue

        finding_port = normalize_port_number(finding.get("port"))
        port_match = port is not None and finding_port == port

        searchable = " ".join(
            str(finding.get(key, "") or "").lower()
            for key in (
                "service", "service_name", "product", "affected_product", "title",
                "name", "description", "evidence", "endpoint", "cpe"
            )
        )
        token_match = any(token in searchable for token in tokens)

        if not (port_match or token_match):
            continue

        identity = str(
            finding.get("cve_id")
            or finding.get("finding_id")
            or finding.get("id")
            or get_finding_summary(finding)
        ).strip().lower()
        if not identity or identity in seen:
            continue
        seen.add(identity)
        findings.append(finding)

    return findings

def get_finding_summary(finding):
    """Return a compact human-readable finding label."""
    if not isinstance(finding, dict):
        return ""
    for key in ("cve_id", "title", "name", "category", "finding_id"):
        value = str(finding.get(key, "") or "").strip()
        if value:
            return value
    return "Security finding"

def build_service_impact_text(service_name, product, port, target):
    """Describe potential impact conservatively without asserting compromise."""
    label = product or service_name or SENSITIVE_PORTS.get(port) or f"service on port {port}"
    return (
        f"If an associated weakness in {label} were exploitable, it could affect the "
        f"confidentiality, integrity, or availability of that service and may provide "
        f"a foothold on {target}. Further host or lateral impact is not assumed without "
        "additional relationship evidence."
    )

def build_service_entry_path(asset, candidate):
    """Convert a service candidate into the existing normalized path structure.

    Service-entry paths are conceptual evidence-supported routes rather than
    graph relationships. Therefore they intentionally do not reference a
    synthetic graph edge.
    """
    asset_id = str(asset.get("_id"))
    route_id = f"service-entry:{asset_id}:{candidate['protocol']}:{candidate['port']}"

    evidence = [candidate["explanation"]]
    evidence.extend(candidate["finding_summaries"])
    evidence.append(candidate["potential_impact"])
    evidence.append(candidate["disclaimer"])

    path = create_attack_path(
        path_id=f"path:{route_id}",
        node_ids=[asset_id],
        edge_ids=[],
        score=candidate["score"],
        risk_level=candidate["risk_level"],
        confidence=candidate["confidence"],
        evidence=evidence
    )

    if not isinstance(path, dict):
        return None

    path["path_type"] = "potential_service_entry"
    path["analysis_status"] = "POTENTIAL"
    path["exploitation_verified"] = False
    path["furthest_progression"] = candidate["progression"][-1]
    path["entry_point"] = candidate["entry_point"]
    path["service"] = {
        "port": candidate["port"],
        "protocol": candidate["protocol"],
        "name": candidate["service"],
        "product": candidate["product"],
        "version": candidate["version"]
    }
    path["associated_findings"] = candidate["finding_summaries"]
    path["explanation"] = candidate["explanation"]
    path["potential_impact"] = candidate["potential_impact"]
    path["progression"] = candidate["progression"]
    path["disclaimer"] = candidate["disclaimer"]
    return path


# ==========================================
# EXTRACT ENTRY EVIDENCE
# ==========================================

def extract_entry_evidence(

    asset

):

    """

    Build explainable evidence for an

    externally exposed asset.

    """



    evidence = []





    # ======================================

    # EXPOSURE

    # ======================================



    evidence.append(

        "Asset is explicitly marked as EXTERNAL."

    )





    # ======================================

    # OPEN PORTS

    # ======================================



    open_ports = get_asset_open_ports(asset)





    if open_ports:



        port_numbers = []



        for port in open_ports:



            port_number = (

                normalize_port_number(

                    port.get(

                        "port"

                    )

                )

            )



            if port_number is not None:



                port_numbers.append(

                    port_number

                )





        if port_numbers:



            evidence.append(



                "Asset exposes open ports: "

                +

                ", ".join(

                    str(port)

                    for port in sorted(

                        set(

                            port_numbers

                        )

                    )

                )

                +

                "."



            )





    # ======================================

    # SENSITIVE PORTS

    # ======================================



    sensitive_ports = (

        get_sensitive_open_ports(

            asset

        )

    )





    if sensitive_ports:



        evidence.append(



            "Security-sensitive services are "

            "exposed on port(s): "

            +

            ", ".join(

                str(port)

                for port in sensitive_ports

            )

            +

            "."



        )





    # ======================================

    # VULNERABILITIES

    # ======================================



    vulnerability_count = get_vulnerability_count(asset)
    security_finding_count = get_attack_security_finding_count(asset)
    attack_evidence_count = vulnerability_count + security_finding_count

    if attack_evidence_count > 0:
        evidence.append(
            f"Asset currently contains {attack_evidence_count} "
            "active attack-relevant security finding(s)."
        )





    # ======================================

    # RISK

    # ======================================



    risk_score = normalize_score(

        asset.get(

            "risk_score"

        )

    )



    risk_level = normalize_risk_level(

        asset.get(

            "risk_level"

        )

    )





    if risk_score > 0:



        evidence.append(



            f"Current asset risk is "

            f"{risk_score}/100 "

            f"({risk_level})."



        )





    # ======================================

    # CRITICALITY

    # ======================================



    criticality = normalize_criticality(

        asset.get(

            "criticality"

        )

    )





    if criticality in (

        "HIGH",

        "CRITICAL"

    ):



        evidence.append(



            f"Asset criticality is "

            f"{criticality}."



        )





    return evidence





# ==========================================

# CALCULATE ENTRY CONFIDENCE

# ==========================================



def calculate_entry_confidence(

    asset

):

    """

    Calculate confidence for an external

    attacker entry relationship.

    """



    if normalize_exposure(

        asset.get(

            "exposure"

        )

    ) != "EXTERNAL":



        return "UNKNOWN"





    open_ports = get_asset_open_ports(asset)



    vulnerabilities = (
        get_vulnerability_count(asset)
        + get_attack_security_finding_count(asset)
    )



    sensitive_ports = (

        get_sensitive_open_ports(

            asset

        )

    )





    # Explicit external exposure plus either

    # vulnerabilities or sensitive services

    # provides stronger evidence.



    if (

        vulnerabilities > 0

        or

        sensitive_ports

    ):



        return "HIGH"





    if open_ports:



        return "MEDIUM"





    return "LOW"





# ==========================================

# GENERATE ASSET RELATIONSHIPS

# ==========================================



def generate_asset_relationships(

    assets

):

    """

    Generate conservative potential

    asset-to-asset relationships.



    IMPORTANT:



    Independent Nmap scans do not prove

    network reachability between assets.



    Therefore this function creates an edge

    only when explicit source-to-target

    relationship evidence exists together

    with meaningful target attack-surface

    evidence.



    The resulting relationship is explicitly

    classified as POTENTIAL.

    """



    edges = []





    if len(

        assets

    ) < 2:



        return edges





    # ======================================

    # ORDER ASSETS

    # ======================================



    ordered_assets = sorted(



        assets,



        key=lambda asset: (

            str(

                asset.get(

                    "target",

                    ""

                )

            ).lower(),

            str(

                asset.get(

                    "_id",

                    ""

                )

            )

        )



    )





    # ======================================

    # BUILD DIRECTIONAL RELATIONSHIPS

    # ======================================



    for source in ordered_assets:



        for target in ordered_assets:



            source_id = source.get(

                "_id"

            )



            target_id = target.get(

                "_id"

            )





            if (

                source_id is None

                or

                target_id is None

            ):



                continue





            if str(

                source_id

            ) == str(

                target_id

            ):



                continue





            relationship = (

                evaluate_asset_relationship(

                    source,

                    target

                )

            )





            if not relationship:



                continue





            edge_id = (



                "potential-pivot:"

                f"{source_id}:"

                f"{target_id}"



            )





            edge = create_attack_edge(



                edge_id=edge_id,



                source=source_id,



                target=target_id,



                relationship=(

                    "potential_pivot"

                ),



                confidence=(

                    relationship[

                        "confidence"

                    ]

                ),



                score=(

                    relationship[

                        "score"

                    ]

                ),



                evidence=(

                    relationship[

                        "evidence"

                    ]

                )



            )





            edges.append(

                edge

            )





    return edges





# ==========================================

# EVALUATE ASSET RELATIONSHIP

# ==========================================



def get_explicit_relationship_evidence(
    source,
    target
):
    """
    Return explicit source -> target relationship evidence.

    Independent scan results are not topology evidence. AttackLens therefore
    does not infer lateral movement merely because two assets have open ports,
    vulnerabilities, or high risk.

    Optional source fields supported as explicit relationship evidence:
      reachable_assets, connected_assets, network_neighbors, neighbors,
      and relationships.
    """

    if not isinstance(source, dict) or not isinstance(target, dict):
        return []

    target_identifiers = set()

    for value in (
        target.get("_id"),
        target.get("target"),
        target.get("hostname"),
    ):
        normalized = str(value or "").strip().lower()
        if normalized:
            target_identifiers.add(normalized)

    if not target_identifiers:
        return []

    evidence = []

    def entry_matches(entry):

        if isinstance(entry, (str, int)):
            return str(entry).strip().lower() in target_identifiers

        if not isinstance(entry, dict):
            return False

        for key in (
            "target",
            "target_id",
            "asset_id",
            "id",
            "host",
            "hostname",
            "address",
            "ip",
            "destination",
            "destination_id",
        ):
            value = str(entry.get(key) or "").strip().lower()

            if value and value in target_identifiers:
                return True

        return False

    for field_name in (
        "reachable_assets",
        "connected_assets",
        "network_neighbors",
        "neighbors",
        "relationships",
    ):
        values = source.get(field_name)

        if isinstance(values, dict):
            values = list(values.values())

        if not isinstance(values, (list, tuple, set)):
            continue

        for entry in values:

            if not entry_matches(entry):
                continue

            evidence.append(
                "Source asset explicitly references the target in "
                f"'{field_name}' relationship evidence."
            )

    unique = []
    seen = set()

    for item in evidence:
        key = item.lower()

        if key in seen:
            continue

        seen.add(key)
        unique.append(item)

    return unique


def evaluate_asset_relationship(
    source,
    target
):
    """
    Determine whether evidence supports a POTENTIAL source -> target pivot.

    A multi-asset edge is created only when explicit source-to-target
    relationship/topology evidence exists and the target also has meaningful
    security evidence. The relationship remains potential and does not prove
    successful exploitation or lateral movement.
    """

    if not isinstance(source, dict) or not isinstance(target, dict):
        return None

    source_id = source.get("_id")
    target_id = target.get("_id")

    if source_id is None or target_id is None:
        return None

    if str(source_id) == str(target_id):
        return None

    explicit_relationship_evidence = get_explicit_relationship_evidence(
        source,
        target
    )

    if not explicit_relationship_evidence:
        return None

    target_open_ports = get_asset_open_ports(target)

    if not target_open_ports:
        return None

    target_sensitive_ports = get_sensitive_open_ports(target)
    vulnerability_count = get_vulnerability_count(target)
    security_finding_count = get_attack_security_finding_count(target)
    attack_evidence_count = vulnerability_count + security_finding_count
    target_risk_score = normalize_score(target.get("risk_score"))
    target_risk_level = normalize_risk_level(target.get("risk_level"))

    meaningful_target_evidence = (
        bool(target_sensitive_ports)
        or attack_evidence_count > 0
        or target_risk_level in ("HIGH", "CRITICAL")
    )

    if not meaningful_target_evidence:
        return None

    evidence = list(explicit_relationship_evidence)

    evidence.append(
        "Target asset exposes one or more open network services."
    )

    if target_sensitive_ports:
        evidence.append(
            "Target exposes security-sensitive service port(s): "
            + ", ".join(str(port) for port in target_sensitive_ports)
            + "."
        )

    if attack_evidence_count > 0:
        evidence.append(
            f"Target currently contains {attack_evidence_count} "
            "active attack-relevant security finding(s)."
        )

    if target_risk_score > 0:
        evidence.append(
            f"Target asset risk is {target_risk_score}/100 "
            f"({target_risk_level})."
        )

    evidence.append(
        "Relationship is potential; successful lateral movement "
        "or exploitation has not been verified."
    )

    if attack_evidence_count > 0 and target_sensitive_ports:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    score = calculate_asset_attack_score(
        target,
        confidence=confidence
    )

    return {
        "confidence": confidence,
        "score": score,
        "evidence": evidence
    }


# ==========================================
# CALCULATE ASSET ATTACK SCORE
# ==========================================

def calculate_asset_attack_score(

    asset,

    confidence="UNKNOWN"

):

    """

    Calculate attack-path contribution score

    for an asset.



    Score range:

        0 - 100

    """



    score = 0.0





    # ======================================

    # ASSET RISK

    # Maximum contribution: 30

    # ======================================



    risk_score = normalize_score(

        asset.get(

            "risk_score"

        )

    )



    score += (

        risk_score

        *

        0.30

    )





    # ======================================

    # EXTERNAL EXPOSURE

    # Maximum contribution: 20

    # ======================================



    exposure = normalize_exposure(

        asset.get(

            "exposure"

        )

    )



    score += EXPOSURE_WEIGHTS.get(

        exposure,

        0

    )





    # ======================================

    # CRITICALITY

    # Maximum contribution: 15

    # ======================================



    criticality = (

        normalize_criticality(

            asset.get(

                "criticality"

            )

        )

    )



    score += CRITICALITY_WEIGHTS.get(

        criticality,

        5

    )





    # ======================================

    # VULNERABILITY CONTRIBUTION

    # Maximum contribution: 20

    # ======================================



    vulnerability_score = (

        calculate_vulnerability_contribution(

            asset

        )

    )



    score += vulnerability_score





    # ======================================

    # SENSITIVE SERVICE CONTRIBUTION

    # Maximum contribution: 10

    # ======================================



    sensitive_ports = (

        get_sensitive_open_ports(

            asset

        )

    )





    sensitive_score = min(



        len(

            sensitive_ports

        )

        *

        2,



        10



    )





    score += sensitive_score





    # ======================================

    # CONFIDENCE CONTRIBUTION

    # Maximum contribution: 5

    # ======================================



    confidence = normalize_confidence(

        confidence

    )



    score += CONFIDENCE_WEIGHTS.get(

        confidence,

        0

    )





    return normalize_score(

        score

    )





# ==========================================

# VULNERABILITY CONTRIBUTION

# ==========================================



def calculate_vulnerability_contribution(asset):
    """
    Calculate attack-score contribution from active CVEs and eligible non-CVE
    security findings. Context-only observations and duplicated network/service
    exposure findings are excluded. Maximum contribution: 20 points.
    """
    findings = []

    for vulnerability in normalize_list(asset.get("vulnerabilities")):
        if isinstance(vulnerability, dict):
            findings.append(vulnerability)

    for finding in get_attack_security_findings(asset):
        findings.append(finding)

    if not findings:
        return 0

    contribution = 0.0

    for finding in findings:
        status = str(finding.get("status", "potential")).strip().lower()

        if status in INACTIVE_SECURITY_STATUSES:
            continue

        severity = normalize_risk_level(finding.get("severity"))
        confidence = normalize_confidence(finding.get("confidence"))

        if severity == "CRITICAL":
            base = 5
        elif severity == "HIGH":
            base = 4
        elif severity == "MEDIUM":
            base = 2
        elif severity == "LOW":
            base = 1
        else:
            base = 0.5

        if confidence == "HIGH":
            multiplier = 1.0
        elif confidence == "MEDIUM":
            multiplier = 0.7
        elif confidence == "LOW":
            multiplier = 0.3
        else:
            multiplier = 0.1

        contribution += base * multiplier

    return min(round(contribution, 2), 20)





# ==========================================

# DISCOVER ATTACK PATHS

# ==========================================



def discover_attack_paths(nodes, edges, asset_lookup=None, max_depth=5):
    """Discover relationship-backed external and multi-asset progression paths.

    Single-host service entry routes are generated separately. This traversal
    only follows real graph relationships; it never converts an Asset -> Asset
    self-loop into an attack path.
    """
    if not isinstance(nodes, list) or not isinstance(edges, list):
        return []
    if asset_lookup is None:
        asset_lookup = {}

    node_ids = {
        str(node.get("id")) for node in nodes
        if isinstance(node, dict) and node.get("id") is not None
    }
    if "external-attacker" not in node_ids:
        return []

    adjacency = {}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        source = str(edge.get("source", "")).strip()
        target = str(edge.get("target", "")).strip()
        if not source or not target or source == target:
            continue
        adjacency.setdefault(source, []).append(edge)

    for source in adjacency:
        adjacency[source].sort(
            key=lambda edge: (-normalize_score(edge.get("score")), str(edge.get("target", "")))
        )

    paths = []

    def walk(current_node, node_path, edge_path, visited):
        if len(edge_path) >= max_depth:
            if edge_path:
                path = build_attack_path(node_path, edge_path, asset_lookup)
                if path is not None:
                    paths.append(path)
            return

        outgoing_edges = adjacency.get(current_node, [])
        if not outgoing_edges:
            if edge_path:
                path = build_attack_path(node_path, edge_path, asset_lookup)
                if path is not None:
                    paths.append(path)
            return

        extended = False
        for edge in outgoing_edges:
            target = str(edge.get("target", "")).strip()
            if target in visited:
                continue
            extended = True
            walk(target, node_path + [target], edge_path + [edge], visited | {target})

        if not extended and edge_path:
            path = build_attack_path(node_path, edge_path, asset_lookup)
            if path is not None:
                paths.append(path)

    walk("external-attacker", ["external-attacker"], [], {"external-attacker"})
    return deduplicate_paths(paths)





# ==========================================

# BUILD ATTACK PATH

# ==========================================



def build_attack_path(

    node_ids,

    edges,

    asset_lookup=None

):

    """

    Convert a traversal into a normalized

    attack path document.

    """



    if not edges:



        return None





    if asset_lookup is None:



        asset_lookup = {}





    edge_ids = [



        str(

            edge.get(

                "id"

            )

        )



        for edge in edges



        if isinstance(

            edge,

            dict

        )



    ]





    if not edge_ids:



        return None





    # ======================================

    # PATH SCORE

    # ======================================



    score = calculate_path_score(

        edges

    )





    # ======================================

    # RISK LEVEL

    # ======================================



    risk_level = (

        determine_path_risk_level(

            score

        )

    )





    # ======================================

    # CONFIDENCE

    # ======================================



    confidence = (

        calculate_path_confidence(

            edges

        )

    )





    # ======================================

    # PATH EVIDENCE

    # ======================================



    evidence = []





    for edge in edges:



        if not isinstance(

            edge,

            dict

        ):



            continue





        relationship = str(

            edge.get(

                "relationship",

                ""

            )

        ).strip()





        source = str(

            edge.get(

                "source",

                ""

            )

        ).strip()



        target = str(

            edge.get(

                "target",

                ""

            )

        ).strip()





        if relationship:



            source_label = get_human_readable_node_label(

                source,

                asset_lookup

            )



            target_label = get_human_readable_node_label(

                target,

                asset_lookup

            )



            if (

                relationship

                ==

                "potential_single_asset_entry"

                and

                source

                and

                source == target

            ):



                evidence.append(

                    f"{source_label}: "

                    "potential single-host entry path"

                )



            else:



                evidence.append(

                    f"{source_label} -> {target_label}: "

                    f"{humanize_relationship(relationship)}"

                )





        edge_evidence = normalize_list(

            edge.get(

                "evidence"

            )

        )





        for item in edge_evidence:



            text = str(

                item

            ).strip()



            if text:



                evidence.append(

                    text

                )





    # ======================================

    # PATH ID

    # ======================================



    path_id = (

        "path:"

        +

        "->".join(

            str(

                node_id

            )

            for node_id in node_ids

        )

    )





    return create_attack_path(



        path_id=path_id,



        node_ids=node_ids,



        edge_ids=edge_ids,



        score=score,



        risk_level=risk_level,



        confidence=confidence,



        evidence=evidence



    )





# ==========================================

# HUMAN-READABLE PATH LABELS

# ==========================================



def get_human_readable_node_label(

    node_id,

    asset_lookup=None

):

    """

    Resolve an internal graph node identifier to a

    human-readable target/hostname for evidence only.



    Internal IDs remain unchanged in graph structure.

    """



    normalized_id = str(

        node_id or ""

    ).strip()



    if normalized_id == "external-attacker":

        return "External Attacker"



    if not isinstance(

        asset_lookup,

        dict

    ):

        return normalized_id or "Unknown Asset"



    asset = (

        asset_lookup.get(normalized_id)

        or

        asset_lookup.get(node_id)

    )



    if not isinstance(

        asset,

        dict

    ):

        return normalized_id or "Unknown Asset"



    target = str(

        asset.get("target", "")

    ).strip()



    hostname = str(

        asset.get("hostname", "")

        or

        ""

    ).strip()



    if target:

        return target



    if hostname:

        return hostname



    return normalized_id or "Unknown Asset"





def humanize_relationship(

    relationship

):

    """

    Convert an internal relationship key into a

    readable evidence label.

    """



    value = str(

        relationship or ""

    ).strip()



    labels = {

        "external_entry": "external entry",

        "potential_pivot": "potential pivot",

        "potential_single_asset_entry": (

            "potential single-host entry path"

        )

    }



    if value in labels:

        return labels[value]



    return value.replace("_", " ").strip()





# ==========================================

# CALCULATE PATH SCORE

# ==========================================



def calculate_path_score(

    edges

):

    """

    Calculate the overall attack path score.



    Current strategy:

    - strongest edge receives greatest weight

    - additional edges increase path exposure

    - result is capped at 100

    """



    if not isinstance(

        edges,

        list

    ):



        return 0





    scores = []





    for edge in edges:



        if not isinstance(

            edge,

            dict

        ):



            continue



        scores.append(

            normalize_score(

                edge.get(

                    "score"

                )

            )

        )





    if not scores:



        return 0





    # Strongest relationship drives the path.



    strongest = max(

        scores

    )





    # Remaining steps add smaller incremental

    # risk without linearly inflating long

    # paths.



    remaining = sum(

        score

        for score in scores

        if score != strongest

    )





    path_score = (



        strongest

        +

        (

            remaining

            *

            0.25

        )



    )





    return normalize_score(

        path_score

    )





# ==========================================

# DETERMINE PATH RISK LEVEL

# ==========================================



def determine_path_risk_level(

    score

):

    """

    Convert a 0-100 attack path score to the

    standard AttackLens risk level.

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

# CALCULATE PATH CONFIDENCE

# ==========================================



def calculate_path_confidence(

    edges

):

    """

    Determine overall path confidence.



    A path can only be as confident as its

    weakest relationship.

    """



    if not isinstance(

        edges,

        list

    ):



        return "UNKNOWN"





    confidence_levels = []





    for edge in edges:



        if not isinstance(

            edge,

            dict

        ):



            continue





        confidence_levels.append(

            normalize_confidence(

                edge.get(

                    "confidence"

                )

            )

        )





    if not confidence_levels:



        return "UNKNOWN"





    # ======================================

    # LOWEST CONFIDENCE WINS

    # ======================================



    if (

        "UNKNOWN"

        in confidence_levels

    ):



        return "UNKNOWN"





    if "LOW" in confidence_levels:



        return "LOW"





    if "MEDIUM" in confidence_levels:



        return "MEDIUM"





    return "HIGH"





# ==========================================

# SORT ATTACK PATHS

# ==========================================



def sort_attack_paths(

    paths

):

    """

    Return deterministic path ordering.



    Highest risk paths appear first.

    """



    if not isinstance(

        paths,

        list

    ):



        return []





    return sorted(



        paths,



        key=lambda path: (



            -normalize_score(

                path.get(

                    "score"

                )

            ),



            -RISK_LEVEL_ORDER.get(

                normalize_risk_level(

                    path.get(

                        "risk_level"

                    )

                ),

                0

            ),



            str(

                path.get(

                    "id",

                    ""

                )

            )



        )



    )





# ==========================================

# DEDUPLICATE EDGES

# ==========================================



def deduplicate_edges(

    edges

):

    """

    Deduplicate graph edges by ID.

    """



    if not isinstance(

        edges,

        list

    ):



        return []





    unique = []



    seen = set()





    for edge in edges:



        if not isinstance(

            edge,

            dict

        ):



            continue





        edge_id = str(

            edge.get(

                "id",

                ""

            )

        ).strip()





        if not edge_id:



            continue





        if edge_id in seen:



            continue





        seen.add(

            edge_id

        )



        unique.append(

            edge

        )





    return unique





# ==========================================

# DEDUPLICATE PATHS

# ==========================================



def deduplicate_paths(

    paths

):

    """

    Deduplicate generated attack paths.

    """



    if not isinstance(

        paths,

        list

    ):



        return []





    unique = []



    seen = set()





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





        if not path_id:



            continue





        if path_id in seen:



            continue





        seen.add(

            path_id

        )



        unique.append(

            path

        )





    return unique





# ==========================================

# GET OPEN PORTS

# ==========================================



def get_open_ports(

    ports

):

    """

    Return normalized currently open port

    records.

    """



    ports = normalize_list(

        ports

    )





    open_ports = []



    seen = set()





    for port in ports:



        if not isinstance(

            port,

            dict

        ):



            continue





        state = str(

            port.get(

                "state",

                ""

            )

        ).strip().lower()





        if state != "open":



            continue





        port_number = (

            normalize_port_number(

                port.get(

                    "port"

                )

            )

        )





        if port_number is None:



            continue





        protocol = str(

            port.get(

                "protocol",

                "tcp"

            )

        ).strip().lower()





        key = (

            port_number,

            protocol

        )





        if key in seen:



            continue





        seen.add(

            key

        )





        normalized_port = dict(

            port

        )



        normalized_port[

            "port"

        ] = port_number



        normalized_port[

            "protocol"

        ] = protocol



        normalized_port[

            "state"

        ] = "open"





        open_ports.append(

            normalized_port

        )





    open_ports.sort(



        key=lambda port: (



            port.get(

                "port",

                0

            ),



            port.get(

                "protocol",

                ""

            )



        )



    )





    return open_ports





# ==========================================

# GET ASSET OPEN PORTS

# ==========================================



def get_asset_open_ports(asset):

    """

    Return open-port records from an Asset document.



    AttackLens has evolved across scan/asset versions, so

    network evidence may be stored in \`\`ports\`\`, \`\`services\`\`

    or \`\`open_ports\`\`.  The attack-path engine accepts all

    three representations and merges them conservatively.



    This prevents a valid single-host attack path from being

    missed merely because the Asset document uses a different

    scan-result field name.

    """



    if not isinstance(asset, dict):

        return []



    candidates = []



    # Primary/current representation.

    candidates.extend(normalize_list(asset.get("ports")))



    # Some scan snapshots store service records directly.

    candidates.extend(normalize_list(asset.get("services")))



    # Compatibility with assets that store only port numbers

    # or compact open-port dictionaries.

    raw_open_ports = normalize_list(asset.get("open_ports"))



    for item in raw_open_ports:

        if isinstance(item, dict):

            record = dict(item)

            record.setdefault("state", "open")

            candidates.append(record)

        else:

            port_number = normalize_port_number(item)

            if port_number is not None:

                candidates.append({

                    "port": port_number,

                    "protocol": "tcp",

                    "state": "open"

                })



    # Service records produced by some Nmap parsers do not

    # repeat state because only open services are persisted.

    normalized_candidates = []



    for item in candidates:

        if not isinstance(item, dict):

            continue



        record = dict(item)



        if record.get("state") in (None, ""):

            record["state"] = "open"



        normalized_candidates.append(record)



    return get_open_ports(normalized_candidates)





# ==========================================

# GET SENSITIVE OPEN PORTS

# ==========================================



def get_sensitive_open_ports(

    asset

):

    """

    Return sensitive open port numbers from

    an Asset document.

    """



    open_ports = get_asset_open_ports(asset)





    sensitive = []





    for port in open_ports:



        port_number = (

            normalize_port_number(

                port.get(

                    "port"

                )

            )

        )





        if (

            port_number

            in

            SENSITIVE_PORTS

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
# GET ATTACK-RELEVANT SECURITY FINDINGS
# ==========================================

def get_attack_security_findings(asset):
    """
    Return active non-CVE findings that are suitable as attack-path evidence.

    Context-only observations are excluded. NETWORK/SERVICE exposure findings
    are also excluded because open and sensitive ports already represent that
    evidence in this engine.
    """
    if not isinstance(asset, dict):
        return []

    eligible = []
    seen = set()

    for finding in normalize_list(asset.get("security_findings")):
        if not isinstance(finding, dict):
            continue

        finding_type = str(
            finding.get("finding_type", finding.get("type", ""))
        ).strip().upper()

        category = str(finding.get("category", "")).strip().upper()
        status = str(finding.get("status", "potential")).strip().lower()

        if finding_type not in ATTACK_EVIDENCE_FINDING_TYPES:
            continue

        if category in CONTEXT_ONLY_SECURITY_CATEGORIES:
            continue

        if status in INACTIVE_SECURITY_STATUSES:
            continue

        key = (
            str(finding.get("finding_id", "")).strip().lower(),
            finding_type,
            category,
            str(finding.get("target", "")).strip().lower(),
            normalize_port_number(finding.get("port")),
            str(finding.get("endpoint", "")).strip().lower(),
            str(finding.get("parameter", "")).strip().lower(),
            str(finding.get("title", "")).strip().lower()
        )

        if key in seen:
            continue

        seen.add(key)
        eligible.append(finding)

    return eligible


def get_attack_security_finding_count(asset):
    """Return the number of active attack-relevant non-CVE findings."""
    return len(get_attack_security_findings(asset))


# ==========================================

# GET VULNERABILITY COUNT

# ==========================================



def get_vulnerability_count(

    asset

):

    """

    Safely determine an Asset's current

    vulnerability count.

    """



    stored_count = asset.get(

        "vulnerability_count"

    )





    try:



        stored_count = int(

            stored_count

        )



    except (

        TypeError,

        ValueError

    ):



        stored_count = None





    if (

        stored_count is not None

        and

        stored_count >= 0

    ):



        return stored_count





    vulnerabilities = normalize_list(

        asset.get(

            "vulnerabilities"

        )

    )





    return len(

        vulnerabilities

    )





# ==========================================

# NORMALIZE EXPOSURE

# ==========================================



def normalize_exposure(

    value

):

    """

    Normalize Asset exposure.

    """



    if value is None:



        return "INTERNAL"





    exposure = str(

        value

    ).strip().upper()





    if exposure not in (

        "INTERNAL",

        "EXTERNAL"

    ):



        return "INTERNAL"





    return exposure





# ==========================================

# NORMALIZE CRITICALITY

# ==========================================



def normalize_criticality(

    value

):

    """

    Normalize Asset criticality.

    """



    if value is None:



        return "NORMAL"





    criticality = str(

        value

    ).strip().upper()





    # Keep compatibility with potential

    # historic MEDIUM values while the

    # current Asset UI may use NORMAL.



    if criticality not in (

        "LOW",

        "NORMAL",

        "MEDIUM",

        "HIGH",

        "CRITICAL"

    ):



        return "NORMAL"





    return criticality





# ==========================================

# NORMALIZE CONFIDENCE

# ==========================================



def normalize_confidence(

    value

):

    """

    Normalize attack relationship confidence.

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

# NORMALIZE PORT NUMBER

# ==========================================



def normalize_port_number(

    value

):

    """

    Convert a port value into a valid integer.

    """



    try:



        port_number = int(

            value

        )



    except (

        TypeError,

        ValueError

    ):



        return None





    if (

        port_number < 1

        or

        port_number > 65535

    ):



        return None





    return port_number





# ==========================================

# NORMALIZE LIST

# ==========================================



def normalize_list(

    value

):

    """

    Convert invalid list values into an empty

    list.

    """



    if isinstance(

        value,

        list

    ):



        return value

    return []
