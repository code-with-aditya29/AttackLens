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

from datetime import datetime, timezone
from math import isfinite
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from models.report_model import (
    create_report_document,
    create_report_scope,
    create_executive_summary,
    create_report_readiness,
    create_report_statistics
)

from services.attack_path_service import generate_attack_graph
from services.defense_analysis_service import generate_defense_analysis
from services.mitigation_service import generate_mitigation_recommendations
from services.risk_comparison_service import generate_risk_comparison


# ============================================================
# REPORT TIMEZONE
# ============================================================

DEFAULT_REPORT_TIMEZONE = "UTC"


def normalize_timezone_name(timezone_name):
    """
    Validate an IANA timezone name.

    Examples:
        Asia/Kolkata
        America/New_York
        America/Toronto
        Asia/Tokyo

    The browser/client should supply the user's timezone.
    AttackLens must not infer report timezone from the scan target.
    """

    if timezone_name is None:
        return DEFAULT_REPORT_TIMEZONE

    timezone_name = str(timezone_name).strip()

    if not timezone_name:
        return DEFAULT_REPORT_TIMEZONE

    try:
        ZoneInfo(timezone_name)
        return timezone_name
    except (ZoneInfoNotFoundError, ValueError, TypeError):
        return DEFAULT_REPORT_TIMEZONE


def get_report_timezone(timezone_name=None):
    """Return a validated ZoneInfo object."""

    normalized = normalize_timezone_name(timezone_name)

    try:
        return ZoneInfo(normalized)
    except (ZoneInfoNotFoundError, ValueError, TypeError):
        return timezone.utc


def get_local_report_datetime(timezone_name=None, value=None):
    """
    Convert a datetime to the selected report timezone.

    If no datetime is supplied, the current UTC time is used first
    and then converted to the user's timezone.
    """

    report_timezone = get_report_timezone(timezone_name)

    if value is None:
        value = datetime.now(timezone.utc)

    elif isinstance(value, str):
        value = parse_datetime(value)

    if not isinstance(value, datetime):
        value = datetime.now(timezone.utc)

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.astimezone(report_timezone)


def parse_datetime(value):
    """Safely parse common ISO-8601 datetime strings."""

    if not isinstance(value, str):
        return None

    value = value.strip()

    if not value:
        return None

    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def build_report_time_metadata(timezone_name=None):
    """
    Build timezone-aware report-generation metadata.

    UTC is retained internally for audit consistency while local time
    is provided for presentation.
    """

    normalized_timezone = normalize_timezone_name(timezone_name)
    generated_utc = datetime.now(timezone.utc)
    generated_local = get_local_report_datetime(
        timezone_name=normalized_timezone,
        value=generated_utc
    )

    return {
        "timezone": normalized_timezone,
        "generated_at_utc": generated_utc.isoformat(),
        "generated_at_local": generated_local.isoformat(),
        "generated_at_display": format_report_datetime(
            generated_local,
            normalized_timezone
        )
    }


def format_report_datetime(value, timezone_name=None):
    """
    Produce a human-readable local report timestamp.

    Example:
        05 October 2026, 20:55 IST
    """

    if not isinstance(value, datetime):
        value = get_local_report_datetime(
            timezone_name=timezone_name,
            value=value
        )

    timezone_label = value.tzname()

    if not timezone_label:
        timezone_label = normalize_timezone_name(timezone_name)

    return (
        f"{value.strftime('%d %B %Y, %H:%M')} "
        f"{timezone_label}"
    )


# ============================================================
# SCAN-SPECIFIC REPORT ASSET
# ============================================================

def build_report_asset_from_scan(scan, asset_context=None):
    """
    Convert one completed scan document into the asset-shaped
    snapshot expected by the existing AttackLens report pipeline.

    Historical security evidence is taken from the selected scan.
    Current Asset Inventory data is used only for manual context
    such as criticality and exposure.
    """

    if not isinstance(scan, dict):
        return None

    target = str(scan.get("target", "")).strip()

    if not target:
        return None

    if not isinstance(asset_context, dict):
        asset_context = {}

    ports = scan.get("ports", [])
    services = scan.get("services", [])
    vulnerabilities = scan.get("vulnerabilities", [])
    security_findings = scan.get("security_findings", [])

    if not isinstance(ports, list):
        ports = []

    if not isinstance(services, list):
        services = []

    if not isinstance(vulnerabilities, list):
        vulnerabilities = []

    if not isinstance(security_findings, list):
        security_findings = []

    scan_id = scan.get("_id")

    scan_timestamp = (
        scan.get("completed_at")
        or scan.get("created_at")
    )

    return {
        "_id": scan_id,
        "scan_id": scan_id,
        "latest_scan_id": scan_id,
        "target": target,
        "created_by": scan.get("created_by"),
        "scan_profile": scan.get("scan_profile"),
        "scan_status": scan.get("status"),
        "created_at": scan.get("created_at"),
        "started_at": scan.get("started_at"),
        "completed_at": scan.get("completed_at"),
        "first_seen": scan_timestamp,
        "last_seen": scan_timestamp,
        "hostname": scan.get("hostname"),
        "host_status": scan.get("host_status", "unknown"),
        "mac_address": scan.get("mac_address"),
        "ports": ports,
        "open_ports": extract_open_port_numbers(
            ports=ports,
            services=services
        ),
        "services": services,
        "os_detection": scan.get("os_detection"),
        "os_accuracy": scan.get("os_accuracy"),
        "vulnerabilities": vulnerabilities,
        "vulnerability_count": len(vulnerabilities),
        "security_findings": security_findings,
        "security_finding_count": len(security_findings),
        "highest_severity": scan.get("highest_severity"),
        "risk_score": scan.get("risk_score"),
        "risk_level": scan.get("risk_level"),
        "risk_breakdown": scan.get("risk_breakdown"),
        "criticality": asset_context.get("criticality", "Normal"),
        "exposure": asset_context.get("exposure", "Unknown")
    }


# ============================================================
# MAIN REPORT GENERATOR
# ============================================================

def generate_report_data(
    assets=None,
    attack_graph=None,
    defense_analysis=None,
    mitigation_analysis=None,
    risk_comparison=None,
    created_by=None,
    timezone_name=None,
    scan_metadata=None,
    report_id=None,
    report_number=None,
    db=None
):
    """
    Generate the complete normalized AttackLens report data.

    Existing analysis results may be supplied by the caller.

    If they are not supplied, this service invokes the existing
    AttackLens analysis pipeline in the correct order.

    timezone_name should be the user's IANA timezone supplied by
    the client/browser, for example Asia/Kolkata.

    The returned document is suitable for:
    - Reports page
    - PDF generation
    - Future report-history storage
    """

    assets = normalize_assets(assets)

    # --------------------------------------------------------
    # ATTACK PATH ANALYSIS
    # --------------------------------------------------------

    if not isinstance(attack_graph, dict):
        attack_graph = generate_attack_graph(
            assets=assets,
            created_by=created_by
        )

    attack_graph = normalize_document(attack_graph)

    # --------------------------------------------------------
    # DEFENSE ANALYSIS
    # --------------------------------------------------------

    if not isinstance(defense_analysis, dict):
        defense_analysis = generate_defense_analysis(
            assets=assets,
            attack_graph=attack_graph,
            created_by=created_by
        )

    defense_analysis = normalize_document(defense_analysis)

    # --------------------------------------------------------
    # MITIGATION ANALYSIS
    # --------------------------------------------------------

    if not isinstance(mitigation_analysis, dict):
        mitigation_analysis = generate_mitigation_recommendations(
            assets=assets,
            attack_graph=attack_graph,
            defense_analysis=defense_analysis,
            created_by=created_by
        )

    mitigation_analysis = normalize_document(mitigation_analysis)

    # --------------------------------------------------------
    # RISK COMPARISON
    # --------------------------------------------------------

    if not isinstance(risk_comparison, dict):
        risk_comparison = generate_risk_comparison(
            assets=assets,
            attack_graph=attack_graph,
            defense_analysis=defense_analysis,
            mitigation_analysis=mitigation_analysis,
            created_by=created_by
        )

    risk_comparison = normalize_document(risk_comparison)

    # --------------------------------------------------------
    # HUMAN-READABLE ASSET REFERENCES
    # --------------------------------------------------------

    attack_graph = attach_asset_reference_map(
        attack_graph=attack_graph,
        assets=assets
    )

    # --------------------------------------------------------
    # REPORT COMPONENTS
    # --------------------------------------------------------

    vulnerability_summary = build_vulnerability_summary(assets)
    security_finding_summary = build_security_finding_summary(assets)

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

    executive_summary = build_executive_summary(statistics)
    scope = build_report_scope(assets)
    time_metadata = build_report_time_metadata(timezone_name)
    scan_metadata = build_report_scan_metadata(assets, scan_metadata)

    # Report identity is presentation/audit metadata, not security evidence.
    # The route should pass the application's MongoDB database for persistent
    # sequential numbering, or pass a previously saved report_id on re-export.
    report_target = scan_metadata.get("target")
    if not report_target and len(scope.get("targets", [])) == 1:
        report_target = scope["targets"][0]

    if report_id is None and report_number is None and db is not None and report_target:
        report_number = allocate_report_number(db)


    # --------------------------------------------------------
    # FINAL REPORT
    # --------------------------------------------------------

    report = create_report_document(
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
        statistics=statistics,
        security_finding_summary=security_finding_summary,
        scan_metadata=scan_metadata,
        report_id=report_id,
        report_number=report_number,
        report_target=report_target,
        report_timezone="Asia/Kolkata",
        generated_at=datetime.fromisoformat(time_metadata["generated_at_utc"])
    )

    # Keep timezone/presentation metadata outside the security
    # calculations so it cannot affect analysis results.
    if isinstance(report, dict):
        report["timezone"] = time_metadata["timezone"]
        report["generated_at_utc"] = time_metadata["generated_at_utc"]
        report["generated_at_local"] = time_metadata["generated_at_local"]
        report["generated_at_display"] = time_metadata["generated_at_display"]
        # Retain the original top-level alias for older Reports/PDF consumers.
        report["security_finding_summary"] = security_finding_summary

    return report


# ============================================================
# PERSISTENT REPORT NUMBER ALLOCATION
# ============================================================

def allocate_report_number(db):
    """Atomically allocate a report number from MongoDB.

    Uses one global counter, so AL-001, AL-002, ... are not reused
    after a report is deleted. MongoDB must be available; no unsafe
    in-memory or collection-count fallback is used.
    """
    from pymongo import ReturnDocument

    counter = db["report_counters"].find_one_and_update(
        {"_id": "attacklens_report_number"},
        {"$inc": {"sequence": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    if not isinstance(counter, dict) or not isinstance(counter.get("sequence"), int):
        raise RuntimeError("Could not allocate a persistent report number")
    return counter["sequence"]


# ============================================================
# SELECTED SCAN METADATA
# ============================================================

def build_report_scan_metadata(assets, scan_metadata=None):
    """Preserve the caller's selected-scan identity without mixing scans.

    When the caller supplies explicit metadata, it takes precedence.
    Otherwise only metadata present on the selected report asset is used.
    No current inventory evidence or unrelated scan is queried here.
    """
    metadata = dict(scan_metadata) if isinstance(scan_metadata, dict) else {}
    if len(assets) == 1 and isinstance(assets[0], dict):
        asset = assets[0]
        for destination, source in (
            ("scan_id", "scan_id"),
            ("target", "target"),
            ("scan_profile", "scan_profile"),
            ("scan_status", "scan_status"),
            ("created_at", "created_at"),
            ("started_at", "started_at"),
            ("completed_at", "completed_at"),
        ):
            if metadata.get(destination) is None and asset.get(source) is not None:
                metadata[destination] = asset[source]
    return metadata


# ============================================================
# REPORT PRESENTATION NORMALIZATION
# ============================================================

def attach_asset_reference_map(attack_graph, assets):
    """
    Attach presentation-only mappings from internal asset IDs
    to human-readable targets/hostnames without changing graph
    nodes, edges, paths, scores, or security conclusions.
    """

    attack_graph = normalize_document(attack_graph)
    assets = normalize_assets(assets)
    asset_references = {}

    for asset in assets:
        target = get_asset_target(asset)

        hostname = str(
            asset.get("hostname") or ""
        ).strip()

        if (
            hostname
            and target
            and hostname.lower() == target.lower()
        ):
            hostname = ""

        reference = {
            "target": target,
            "hostname": hostname or None
        }

        for key in (
            "_id",
            "scan_id",
            "latest_scan_id"
        ):
            value = asset.get(key)

            if value is None:
                continue

            normalized = str(value).strip()

            if normalized:
                asset_references.setdefault(
                    normalized,
                    reference
                )

    normalized_graph = dict(attack_graph)
    normalized_graph["asset_references"] = asset_references

    return normalized_graph


def extract_open_port_numbers(ports=None, services=None):
    """
    Normalize unique observed open port numbers from the
    selected scan snapshot. No unobserved port is inferred.
    """

    open_ports = []
    seen = set()

    collections = (
        ("ports", ports),
        ("services", services)
    )

    for source_name, records in collections:
        if not isinstance(records, list):
            continue

        for record in records:
            if not isinstance(record, dict):
                continue

            state = str(
                record.get("state", "")
            ).strip().lower()

            if source_name == "ports":
                if state != "open":
                    continue
            elif state and state != "open":
                continue

            port = (
                record.get("port")
                if record.get("port") is not None
                else record.get("port_number")
            )

            try:
                port = int(port)
            except (TypeError, ValueError):
                continue

            if not 1 <= port <= 65535:
                continue

            if port in seen:
                continue

            seen.add(port)
            open_ports.append(port)

    return open_ports


# ============================================================
# REPORT SCOPE
# ============================================================

def build_report_scope(assets):
    """Build the authorized environment scope represented by the report."""

    targets = []

    for asset in assets:
        target = get_asset_target(asset)

        if target and target not in targets:
            targets.append(target)

    return create_report_scope(
        asset_count=len(assets),
        target_count=len(targets),
        targets=targets,
        analysis_source="AttackLens Analysis"
    )


# ============================================================
# EXECUTIVE SUMMARY
# ============================================================

def build_executive_summary(statistics):
    """Build a compact executive summary from normalized report statistics."""

    statistics = normalize_document(statistics)

    return create_executive_summary(
        overall_risk_score=statistics.get(
            "current_risk_score"
        ),
        overall_risk_level=statistics.get(
            "current_risk_level"
        ),
        asset_count=statistics.get(
            "total_assets", 0
        ),
        vulnerability_count=statistics.get(
            "total_vulnerabilities", 0
        ),
        attack_path_count=statistics.get(
            "attack_paths", 0
        ),
        defense_finding_count=statistics.get(
            "defense_findings", 0
        ),
        recommendation_count=statistics.get(
            "recommendations", 0
        ),
        projected_risk_score=statistics.get(
            "projected_risk_score"
        ),
        projected_risk_level=statistics.get(
            "projected_risk_level"
        ),
        projected_reduction=statistics.get(
            "risk_reduction", 0
        ),
        projected_reduction_percentage=statistics.get(
            "risk_reduction_percentage", 0
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

    A valid analysis containing zero attack paths or zero
    vulnerabilities is still considered completed analysis.

    Report generation requires at least one authorized asset.
    """

    has_assets = bool(assets)

    # An analysis dictionary, including {}, represents supplied analysis.
    # A report still requires at least one authorized asset.
    attack_path_ready = has_assets and isinstance(attack_graph, dict)
    defense_ready = has_assets and isinstance(defense_analysis, dict)
    mitigation_ready = has_assets and isinstance(mitigation_analysis, dict)
    comparison_ready = has_assets and isinstance(risk_comparison, dict)

    # Readiness is distinct from a measured risk score: unknown risk
    # scores must remain None in report statistics.
    risk_assessment_ready = has_assets

    return create_report_readiness(
        asset_inventory=has_assets,
        risk_assessment=risk_assessment_ready,
        attack_path_analysis=attack_path_ready,
        defense_analysis=defense_ready,
        mitigation_recommendations=mitigation_ready,
        risk_comparison=comparison_ready,
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
    Build summary statistics displayed on the Reports page
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
            len(assets)
        )
    )

    # The Executive Summary and the CVE table must count the same
    # evidence: CVE records actually present in the selected scan assets.
    # Risk-comparison metrics may count a broader set of actionable findings
    # (including non-CVE weaknesses), so they are not a reliable CVE total.
    cve_summary = build_vulnerability_summary(assets)
    total_vulnerabilities = cve_summary["vulnerability_count"]
    vulnerable_assets = cve_summary["vulnerable_assets"]

    open_ports = safe_integer(
        current_state.get(
            "open_ports",
            count_open_ports(assets)
        )
    )

    attack_paths = safe_integer(
        current_state.get(
            "attack_paths",
            count_attack_paths(attack_graph)
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

    # Unknown scores remain unavailable, rather than becoming 0 / LOW.
    current_risk_score = optional_risk_score(current_state.get("risk_score"))
    current_risk_level = optional_risk_level(current_state.get("risk_level"))
    projected_risk_score = optional_risk_score(projected_state.get("risk_score"))
    projected_risk_level = optional_risk_level(projected_state.get("risk_level"))

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

    report_statistics = create_report_statistics(
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

    # Keep broader risk-model counts visible for auditing without
    # presenting them as confirmed CVE vulnerabilities. These additions
    # do not alter the risk engine or any existing statistic fields.
    if isinstance(report_statistics, dict):
        report_statistics["security_finding_count"] = sum(
            len(get_asset_security_findings(asset)) for asset in assets
        )
        report_statistics["risk_model_finding_count"] = safe_integer(
            current_state.get("vulnerability_count", 0)
        )
        report_statistics["cve_vulnerability_count"] = total_vulnerabilities

    return report_statistics


# ============================================================
# CVE VULNERABILITY SUMMARY
# ============================================================

def build_vulnerability_summary(assets):
    """
    Build the traditional CVE vulnerability summary.

    This section remains separate from non-CVE security findings.
    """

    vulnerability_count = 0
    vulnerable_assets = 0
    affected_targets = []
    findings = []

    for asset in assets:
        asset_findings = get_asset_vulnerabilities(asset)

        if asset_findings:
            vulnerable_assets += 1
            target = get_asset_target(asset)

            if target and target not in affected_targets:
                affected_targets.append(target)

        vulnerability_count += len(asset_findings)

        for finding in asset_findings:
            findings.append({
                "target": get_asset_target(asset),
                "finding": finding
            })

    return {
        "vulnerability_count": vulnerability_count,
        "vulnerable_assets": vulnerable_assets,
        "affected_targets": affected_targets,
        "findings": findings
    }


# ============================================================
# NON-CVE SECURITY FINDING SUMMARY
# ============================================================

def build_security_finding_summary(assets):
    """
    Build a separate summary for AttackLens unified non-CVE
    security findings.

    Findings are not converted into CVEs and are not mixed into
    the traditional CVE vulnerability table.
    """

    finding_count = 0
    affected_assets = 0
    affected_targets = []
    findings = []
    type_counts = {}
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0
    }

    for asset in assets:
        asset_findings = get_asset_security_findings(asset)

        if asset_findings:
            affected_assets += 1
            target = get_asset_target(asset)

            if target and target not in affected_targets:
                affected_targets.append(target)

        finding_count += len(asset_findings)

        for finding in asset_findings:
            finding_type = str(
                finding.get(
                    "finding_type",
                    finding.get("type", "UNKNOWN")
                )
            ).strip().upper() or "UNKNOWN"

            severity = str(
                finding.get("severity", "UNKNOWN")
            ).strip().upper()

            if severity not in severity_counts:
                severity = "UNKNOWN"

            type_counts[finding_type] = (
                type_counts.get(finding_type, 0) + 1
            )

            severity_counts[severity] += 1

            findings.append({
                "target": get_asset_target(asset),
                "finding": finding
            })

    return {
        "security_finding_count": finding_count,
        "affected_assets": affected_assets,
        "affected_targets": affected_targets,
        "type_counts": type_counts,
        "severity_counts": severity_counts,
        "findings": findings
    }


# ============================================================
# ASSET HELPERS
# ============================================================

def get_asset_target(asset):
    """Extract the primary target identifier from an asset."""

    if not isinstance(asset, dict):
        return None

    possible_keys = (
        "target",
        "ip_address",
        "ip",
        "host"
    )

    for key in possible_keys:
        value = asset.get(key)

        if value is None:
            continue

        normalized = str(value).strip()

        if normalized:
            return normalized

    return None


def get_asset_vulnerabilities(asset):
    """
    Return CVE vulnerability records explicitly present on an asset.

    Multiple historically used field names remain supported for
    backward compatibility.
    """

    if not isinstance(asset, dict):
        return []

    possible_keys = (
        "vulnerabilities",
        "cves"
    )

    for key in possible_keys:
        value = asset.get(key)

        if isinstance(value, list):
            return [
                item
                for item in value
                if isinstance(item, dict)
            ]

    return []


def get_asset_security_findings(asset):
    """Return unified non-CVE security findings present on an asset."""

    if not isinstance(asset, dict):
        return []

    findings = asset.get(
        "security_findings",
        []
    )

    if not isinstance(findings, list):
        return []

    return [
        finding
        for finding in findings
        if isinstance(finding, dict)
    ]


def count_open_ports(assets):
    """
    Count open ports across assets.

    Ports are counted per asset. Duplicate representations of
    the same port on a single asset are counted once.
    """

    total = 0

    for asset in assets:
        if not isinstance(asset, dict):
            continue

        ports = asset.get("ports")

        if not isinstance(ports, list):
            continue

        open_ports = set()

        for port_data in ports:
            if not isinstance(port_data, dict):
                continue

            state = str(
                port_data.get(
                    "state",
                    ""
                )
            ).strip().lower()

            if state != "open":
                continue

            port = port_data.get("port")

            try:
                port = int(port)
            except (TypeError, ValueError):
                continue

            if 1 <= port <= 65535:
                open_ports.add(port)

        total += len(open_ports)

    return total


# ============================================================
# ATTACK PATH HELPERS
# ============================================================

def count_attack_paths(attack_graph):
    """Count attack paths contained in an attack graph."""

    paths = get_list(
        attack_graph,
        "paths"
    )

    return len(paths)


# ============================================================
# DEFENSE ANALYSIS HELPERS
# ============================================================

def count_defense_findings(defense_analysis):
    """Count defense-analysis findings."""

    findings = get_list(
        defense_analysis,
        "findings"
    )

    if findings:
        return len(findings)

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

def count_recommendations(mitigation_analysis):
    """Count mitigation recommendations."""

    recommendations = get_list(
        mitigation_analysis,
        "recommendations"
    )

    if recommendations:
        return len(recommendations)

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

def normalize_assets(assets):
    """
    Safely normalize the asset collection without modifying
    existing working asset documents.
    """

    if not isinstance(assets, list):
        return []

    normalized = []

    for asset in assets:
        if not isinstance(asset, dict):
            continue

        normalized.append(asset)

    return normalized


def normalize_document(document):
    """Ensure an analysis result is represented as a dictionary."""

    if isinstance(document, dict):
        return document

    return {}


# ============================================================
# DICTIONARY HELPERS
# ============================================================

def get_dictionary(document, key):
    """Safely retrieve a nested dictionary."""

    if not isinstance(document, dict):
        return {}

    value = document.get(key)

    if not isinstance(value, dict):
        return {}

    return value


def get_list(document, key):
    """Safely retrieve a nested list."""

    if not isinstance(document, dict):
        return []

    value = document.get(key)

    if not isinstance(value, list):
        return []

    return value


# ============================================================
# NUMBER HELPERS
# ============================================================

def safe_integer(value):
    """Convert a value to a non-negative integer."""

    try:
        normalized = int(value)
    except (TypeError, ValueError, OverflowError):
        return 0

    return max(0, normalized)


def safe_number(value):
    """Convert a value to a non-negative floating-point number."""

    try:
        normalized = float(value)
    except (TypeError, ValueError, OverflowError):
        return 0.0

    if not isfinite(normalized):
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

def safe_risk_level(value):
    """Normalize an AttackLens risk level."""

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


def optional_risk_score(value):
    """Return None for absent/invalid risk evidence, preserving valid zero."""
    if value is None or isinstance(value, bool):
        return None
    try:
        score = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not isfinite(score):
        return None
    return round(max(0.0, min(100.0, score)), 2)


def is_valid_risk_score(value):
    return optional_risk_score(value) is not None


def optional_risk_level(value):
    """Return None when a classification was not actually calculated."""
    if not isinstance(value, str):
        return None
    level = value.strip().upper()
    return level if level in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else None
