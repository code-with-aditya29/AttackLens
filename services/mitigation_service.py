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



    21,     # FTP

    22,     # SSH

    23,     # Telnet

    25,     # SMTP

    53,     # DNS

    110,    # POP3

    111,    # RPCBind

    135,    # MSRPC

    139,    # NetBIOS / SMB

    445,    # SMB

    512,    # rexec

    513,    # rlogin

    514,    # rsh

    1099,   # Java RMI

    1433,   # Microsoft SQL Server

    1521,   # Oracle Database

    1524,   # Bind shell / backdoor-style service

    2049,   # NFS

    2121,   # Alternate FTP

    3306,   # MySQL

    3389,   # RDP

    5432,   # PostgreSQL

    5900,   # VNC

    6000,   # X11

    6379,   # Redis

    6667,   # IRC

    8009,   # AJP

    8180,   # Alternate HTTP / Tomcat

    27017   # MongoDB

}

# Unified security findings eligible for direct remediation recommendations.
# Context-only observations remain reportable but do not become vulnerabilities.
CONTEXT_ONLY_SECURITY_CATEGORIES = {
    "WEB_APPLICATION_SURFACE",
    "LIMITED_VERSION_EVIDENCE",
    "LOW_CONFIDENCE_OS_DETECTION",
    "LARGE_ATTACK_SURFACE"
}

# NETWORK/SERVICE findings from the current scanner primarily represent
# exposures already handled by sensitive-service recommendations.
SECURITY_REMEDIATION_FINDING_TYPES = {
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
        generate_security_finding_recommendations(
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

    Build the highest known defensive significance

    score for each asset.



    Scores are indexed by both human-readable target

    and internal asset ID. This prevents priority loss

    when Defense Analysis represents an item by asset_id

    while Mitigation works from the asset target.

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



        score = normalize_score(

            item.get(

                "score",

                0

            )

        )



        keys = []



        target = str(

            item.get(

                "target",

                ""

            )

            or

            ""

        ).strip()



        asset_id = str(

            item.get(

                "asset_id",

                ""

            )

            or

            ""

        ).strip()



        if target:



            keys.append(

                target

            )



        if asset_id:



            keys.append(

                asset_id

            )



        for key in keys:



            scores[

                key

            ] = max(

                scores.get(

                    key,

                    0

                ),

                score

            )



    return scores



# ==========================================

# GET ASSET DEFENSE SCORE

# ==========================================



def get_asset_defense_score(

    asset,

    defense_scores

):

    """

    Return the highest Defense Analysis score

    associated with an asset by target or asset ID.

    """



    if not isinstance(

        defense_scores,

        dict

    ):



        return 0



    target = get_asset_target(

        asset

    )



    asset_id = get_asset_id(

        asset

    )



    return normalize_score(

        max(

            defense_scores.get(

                target,

                0

            )

            if target

            else 0,

            defense_scores.get(

                asset_id,

                0

            )

            if asset_id

            else 0

        )

    )





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



        defense_score = get_asset_defense_score(

            asset,

            defense_scores

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



        defense_score = get_asset_defense_score(

            asset,

            defense_scores

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



        defense_score = get_asset_defense_score(

            asset,

            defense_scores

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
# UNIFIED SECURITY FINDING RECOMMENDATIONS
# ==========================================

def generate_security_finding_recommendations(
    assets,
    defense_scores=None
):
    """
    Generate remediation recommendations for active, attack-relevant non-CVE
    security findings.

    These recommendations remain separate from CVE remediation so AttackLens
    does not present configuration/application weaknesses as CVEs.
    """

    if not isinstance(defense_scores, dict):
        defense_scores = {}

    recommendations = []

    for asset in assets:
        findings = get_mitigation_security_findings(asset)

        if not findings:
            continue

        target = get_asset_target(asset)
        asset_id = get_asset_id(asset)
        risk_score = normalize_risk_score(asset.get("risk_score"))
        defense_score = get_asset_defense_score(asset, defense_scores)

        grouped = {}

        for finding in findings:
            finding_type = normalize_text(
                finding.get(
                    "finding_type",
                    finding.get("type")
                )
            ).upper()

            category = normalize_text(
                finding.get("category"),
                default="security_weakness"
            ).upper()

            group_key = (
                finding_type,
                category
            )

            grouped.setdefault(
                group_key,
                []
            ).append(finding)

        for (finding_type, category), group_findings in grouped.items():
            highest_severity = get_highest_vulnerability_severity(
                group_findings
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

            priority_level = determine_priority_level(score)
            confidence = get_highest_finding_confidence(group_findings)
            finding_ids = extract_security_finding_ids(group_findings)
            related_ports = extract_security_finding_ports(group_findings)

            evidence = [
                (
                    f"{len(group_findings)} active {finding_type or 'SECURITY'} "
                    "security finding(s) support this recommendation."
                ),
                (
                    "Highest identified finding severity: "
                    f"{highest_severity}."
                )
            ]

            for finding in group_findings[:3]:
                finding_evidence = normalize_evidence(
                    finding.get("evidence")
                )

                for item in finding_evidence[:2]:
                    if item not in evidence:
                        evidence.append(item)

            title, description, actions, expected_effect = (
                build_security_finding_remediation(
                    finding_type=finding_type,
                    category=category,
                    findings=group_findings
                )
            )

            recommendation = create_mitigation_recommendation(
                recommendation_id=(
                    "security-finding-remediation:"
                    f"{asset_id or target}:"
                    f"{finding_type.lower() or 'security'}:"
                    f"{category.lower() or 'weakness'}"
                ),
                category="security_finding_remediation",
                title=title,
                description=description,
                target=target,
                asset_id=asset_id,
                priority_level=priority_level,
                score=score,
                confidence=confidence,
                evidence=evidence,
                actions=actions,
                expected_effect=expected_effect,
                related_finding_ids=finding_ids,
                related_ports=related_ports
            )

            recommendations.append(recommendation)

    return recommendations


def build_security_finding_remediation(
    finding_type,
    category,
    findings
):
    """
    Return conservative remediation text for a supported non-CVE finding.
    Recommendations are based only on the finding domain/category and do not
    invent an exploit, CVE, patch, or guaranteed outcome.
    """

    category_text = normalize_text(category).upper()

    if finding_type == "WEB":
        if "SQL" in category_text:
            return (
                "Review Potential SQL Injection Weakness",
                (
                    "AttackLens identified web-input evidence consistent with "
                    "a potential SQL injection weakness."
                ),
                [
                    "Review the affected endpoint and parameter identified in the finding evidence.",
                    "Use parameterized queries or prepared statements for database operations.",
                    "Apply server-side input validation appropriate to the expected data type.",
                    "Re-test the affected endpoint in the authorized environment after remediation."
                ],
                "Reduced likelihood that untrusted web input can alter database query behavior."
            )

        if "XSS" in category_text or "CROSS_SITE_SCRIPT" in category_text:
            return (
                "Review Potential Cross-Site Scripting Weakness",
                (
                    "AttackLens identified web-output evidence consistent with "
                    "a potential cross-site scripting weakness."
                ),
                [
                    "Review the affected endpoint, parameter, and output context.",
                    "Apply context-appropriate output encoding before rendering untrusted data.",
                    "Use server-side input validation as an additional control.",
                    "Re-test the affected endpoint in the authorized environment after remediation."
                ],
                "Reduced likelihood that untrusted input is interpreted as executable browser content."
            )

        if "CSRF" in category_text:
            return (
                "Review Potential CSRF Protection Weakness",
                (
                    "AttackLens identified a state-changing web interaction "
                    "that may require stronger anti-CSRF protection."
                ),
                [
                    "Verify that state-changing requests require an unpredictable anti-CSRF token.",
                    "Validate anti-CSRF tokens on the server for the relevant request.",
                    "Review SameSite cookie settings as a defense-in-depth control.",
                    "Re-test the affected workflow after remediation."
                ],
                "Improved resistance to unauthorized cross-site state-changing requests."
            )

        if "IDOR" in category_text or "OBJECT" in category_text:
            return (
                "Review Potential Object-Level Authorization Weakness",
                (
                    "AttackLens identified authorization-related evidence that "
                    "requires validation for a potential IDOR-style weakness."
                ),
                [
                    "Review server-side authorization for the affected object or resource.",
                    "Verify access decisions using the authenticated user's permissions rather than object identifiers alone.",
                    "Test authorized and unauthorized user contexts in the controlled environment.",
                    "Document the result as confirmed or rejected after manual validation."
                ],
                "Reduced risk of unauthorized access to application objects or records."
            )

        if "HEADER" in category_text:
            return (
                "Strengthen Web Security Headers",
                (
                    "AttackLens identified a web security-header configuration "
                    "that should be reviewed."
                ),
                [
                    "Review the specific missing or weak header recorded in the finding evidence.",
                    "Configure the relevant response header at the application or reverse-proxy layer.",
                    "Avoid enabling controls that conflict with required application functionality.",
                    "Re-scan the web service to verify the resulting response headers."
                ],
                "Improved browser-side security posture for the affected web service."
            )

        if "COOKIE" in category_text:
            return (
                "Strengthen Web Cookie Security",
                (
                    "AttackLens identified cookie-security configuration evidence "
                    "that should be reviewed."
                ),
                [
                    "Review the affected cookie and its intended use.",
                    "Apply Secure, HttpOnly, and SameSite attributes where appropriate.",
                    "Ensure sensitive cookies are transmitted only over protected transport.",
                    "Re-test the affected application workflow after the change."
                ],
                "Reduced exposure of sensitive session or application cookies."
            )

        return (
            "Review Identified Web Application Weakness",
            (
                "AttackLens identified a web application security finding that "
                "requires targeted remediation or validation."
            ),
            [
                "Review the affected endpoint, method, parameter, and evidence recorded by AttackLens.",
                "Apply a server-side control appropriate to the confirmed weakness.",
                "Avoid treating a potential finding as confirmed until supporting evidence is validated.",
                "Re-test the affected web functionality after remediation."
            ],
            "Reduced exposure to the identified web application weakness after validated remediation."
        )

    if finding_type == "APPLICATION":
        return (
            "Review Identified Application Security Weakness",
            (
                "AttackLens identified a security weakness associated with an "
                "application or software service."
            ),
            [
                "Review the affected product, version, service, and finding evidence.",
                "Apply vendor-supported hardening, configuration changes, or upgrades where appropriate.",
                "Restrict unnecessary access to the affected application service.",
                "Re-scan the service after remediation."
            ],
            "Reduced exposure to the identified application or software weakness."
        )

    if finding_type in {"HOST", "OS"}:
        return (
            "Harden Host and Operating System Security",
            (
                "AttackLens identified host or operating-system security evidence "
                "that should be reviewed."
            ),
            [
                "Review the specific host or operating-system evidence recorded in the finding.",
                "Apply supported hardening or configuration changes appropriate to the affected system.",
                "Remove or restrict unnecessary host-level exposure where operationally safe.",
                "Re-scan the host after remediation."
            ],
            "Improved host or operating-system security posture after validated hardening."
        )

    return (
        "Review Identified Security Configuration Weakness",
        (
            "AttackLens identified a security configuration finding that "
            "requires review."
        ),
        [
            "Review the affected component and the configuration evidence recorded by AttackLens.",
            "Apply the least-permissive configuration that still supports required functionality.",
            "Document any intentionally accepted risk where remediation is not appropriate.",
            "Re-scan after configuration changes."
        ],
        "Reduced exposure associated with the identified security configuration weakness."
    )


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



        # A single-host synthetic relationship represents

        # an exposed attack surface, not evidence of lateral

        # reachability between two distinct assets. Service

        # and attack-path recommendations handle that case.

        finding_type_normalized = finding_type



        if (

            "single_asset"

            in finding_type_normalized

            or

            "single-host"

            in title

            or

            "single host"

            in title

        ):



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



        asset_risk_score = normalize_risk_score(

            target_asset.get(

                "risk_score"

            )

        )



        defense_score = get_asset_defense_score(

            target_asset,

            build_defense_score_index(

                defense_analysis

            )

        )



        recommendation_score = normalize_score(

            max(

                path_score,

                asset_risk_score,

                defense_score

            )

        )



        priority_level = (

            determine_priority_level(

                recommendation_score

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



        evidence.append(

            (

                "Affected asset risk score "

                f"is {asset_risk_score}/100."

            )

        )



        if defense_score > 0:



            evidence.append(

                (

                    "Highest associated Defense Analysis "

                    f"score is {defense_score}/100."

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

                    recommendation_score,



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



    Accepts AttackLens Asset evidence stored under

    ports, open_ports, or services so Mitigation uses

    the same observed service surface as Attack Path

    and Defense Analysis.

    """



    if not isinstance(

        asset,

        dict

    ):



        return []



    source_records = []



    for field_name in (

        "ports",

        "open_ports",

        "services"

    ):



        value = asset.get(

            field_name

        )



        if isinstance(

            value,

            list

        ):



            source_records.append(

                (

                    field_name,

                    value

                )

            )



    open_ports = set()



    for field_name, records in source_records:



        for port_data in records:



            if isinstance(

                port_data,

                dict

            ):



                state = str(

                    port_data.get(

                        "state",

                        ""

                    )

                    or

                    ""

                ).strip().lower()



                if (

                    field_name == "ports"

                    and

                    state != "open"

                ):



                    continue



                if (

                    field_name != "ports"

                    and

                    state

                    and

                    state != "open"

                ):



                    continue



                port = normalize_port_number(

                    port_data.get(

                        "port",

                        port_data.get(

                            "port_number"

                        )

                    )

                )



            else:



                if field_name != "open_ports":



                    continue



                port = normalize_port_number(

                    port_data

                )



            if port is None:



                continue



            open_ports.add(

                port

            )



    return sorted(

        open_ports

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
# GET MITIGATION SECURITY FINDINGS
# ==========================================

def get_mitigation_security_findings(asset):
    """
    Return active non-CVE findings that justify direct mitigation advice.

    Context-only observations are excluded. NETWORK/SERVICE findings are also
    excluded because sensitive-service recommendations already cover the
    directly observed exposure represented by the current scanner.
    """

    if not isinstance(asset, dict):
        return []

    findings = asset.get("security_findings")

    if not isinstance(findings, list):
        return []

    current = []
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

        status = normalize_text(
            finding.get("status"),
            default="potential"
        ).lower()

        if finding_type not in SECURITY_REMEDIATION_FINDING_TYPES:
            continue

        if category in CONTEXT_ONLY_SECURITY_CATEGORIES:
            continue

        if status in INACTIVE_SECURITY_STATUSES:
            continue

        key = (
            normalize_text(finding.get("finding_id")).lower(),
            finding_type,
            category,
            normalize_text(finding.get("target")).lower(),
            normalize_port_number(finding.get("port")),
            normalize_text(finding.get("endpoint")).lower(),
            normalize_text(finding.get("method")).lower(),
            normalize_text(finding.get("parameter")).lower(),
            normalize_text(finding.get("title")).lower()
        )

        if key in seen:
            continue

        seen.add(key)
        current.append(finding)

    return current


def extract_security_finding_ids(findings):
    """Return unique security-finding identifiers already present in evidence."""

    ids = []
    seen = set()

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        finding_id = normalize_text(
            finding.get(
                "finding_id",
                finding.get("id")
            )
        )

        if not finding_id or finding_id in seen:
            continue

        seen.add(finding_id)
        ids.append(finding_id)

    return ids


def extract_security_finding_ports(findings):
    """Return unique valid ports associated with the supplied findings."""

    ports = set()

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        port = normalize_port_number(
            finding.get("port")
        )

        if port is not None:
            ports.add(port)

    return sorted(ports)


def get_highest_finding_confidence(findings):
    """Return the strongest confidence value present in the supplied findings."""

    rank = {
        "UNKNOWN": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3
    }

    highest = "UNKNOWN"

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        confidence = normalize_confidence(
            finding.get("confidence")
        )

        if rank.get(confidence, 0) > rank.get(highest, 0):
            highest = confidence

    return highest


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



    current = []



    for vulnerability in vulnerabilities:



        if not isinstance(

            vulnerability,

            dict

        ):



            continue



        status = str(

            vulnerability.get(

                "status",

                "potential"

            )

            or

            "potential"

        ).strip().lower()



        if status in {

            "resolved",

            "rejected"

        }:



            continue



        current.append(

            vulnerability

        )



    return current





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
# NORMALIZE TEXT
# ==========================================

def normalize_text(value, default=""):
    """Normalize optional scalar text without inventing evidence."""

    text = str(
        value
        if value is not None
        else default
    ).strip()

    return text or str(default).strip()


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