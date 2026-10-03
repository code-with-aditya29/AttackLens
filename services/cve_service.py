# ==========================================
# ATTACKLENS
# CVE / NVD SERVICE
# ==========================================

import os
import time
import requests


# ==========================================
# NVD CONFIGURATION
# ==========================================

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

DEFAULT_RESULTS_PER_PAGE = 10

MAX_RESULTS_PER_PAGE = 100

REQUEST_TIMEOUT = 30


# ==========================================
# TEXT NORMALIZATION
# ==========================================

def normalize_text(value):
    """
    Convert a value into clean text.
    """

    if value is None:
        return ""

    return str(value).strip()


# ==========================================
# RESULTS PER PAGE NORMALIZATION
# ==========================================

def normalize_results_per_page(
    results_per_page
):
    """
    Ensure NVD resultsPerPage is a valid
    positive integer.
    """

    try:
        value = int(
            results_per_page
        )

    except (
        TypeError,
        ValueError
    ):
        value = DEFAULT_RESULTS_PER_PAGE

    if value <= 0:
        value = DEFAULT_RESULTS_PER_PAGE

    return min(
        value,
        MAX_RESULTS_PER_PAGE
    )


# ==========================================
# NVD API KEY
# ==========================================

def get_nvd_api_key():
    """
    Read optional NVD API key.

    Supported environment variable:

        NVD_API_KEY
    """

    api_key = os.getenv(
        "NVD_API_KEY"
    )

    if not api_key:
        return None

    api_key = str(
        api_key
    ).strip()

    return api_key or None


# ==========================================
# NVD HEADERS
# ==========================================

def build_nvd_headers():
    """
    Build HTTP headers for NVD requests.
    """

    headers = {
        "User-Agent": "AttackLens/1.0",
        "Accept": "application/json"
    }

    api_key = get_nvd_api_key()

    if api_key:

        headers["apiKey"] = api_key

    return headers


# ==========================================
# CVSS SEVERITY FROM SCORE
# ==========================================

def severity_from_score(
    score
):
    """
    Convert a CVSS score into a severity
    when NVD does not provide one.
    """

    try:
        score = float(
            score
        )

    except (
        TypeError,
        ValueError
    ):
        return "UNKNOWN"

    if score >= 9.0:
        return "CRITICAL"

    if score >= 7.0:
        return "HIGH"

    if score >= 4.0:
        return "MEDIUM"

    if score > 0:
        return "LOW"

    return "NONE"


# ==========================================
# CVSS EXTRACTION
# ==========================================

def extract_cvss(
    metrics
):
    """
    Extract the most useful CVSS information
    available from an NVD CVE record.

    Preference:

        CVSS v4.0
        CVSS v3.1
        CVSS v3.0
        CVSS v2
    """

    if not isinstance(
        metrics,
        dict
    ):
        return {
            "score": None,
            "severity": "UNKNOWN",
            "vector": None,
            "version": None
        }

    metric_order = (
        (
            "cvssMetricV40",
            "4.0"
        ),
        (
            "cvssMetricV31",
            "3.1"
        ),
        (
            "cvssMetricV30",
            "3.0"
        ),
        (
            "cvssMetricV2",
            "2.0"
        )
    )

    for metric_name, version in metric_order:

        entries = metrics.get(
            metric_name
        )

        if not isinstance(
            entries,
            list
        ):
            continue

        if not entries:
            continue

        # Prefer Primary NVD metric where
        # available.
        selected = None

        for entry in entries:

            if not isinstance(
                entry,
                dict
            ):
                continue

            if (
                str(
                    entry.get(
                        "type",
                        ""
                    )
                ).upper()
                == "PRIMARY"
            ):
                selected = entry
                break

        if selected is None:

            for entry in entries:

                if isinstance(
                    entry,
                    dict
                ):
                    selected = entry
                    break

        if not selected:
            continue

        cvss_data = selected.get(
            "cvssData",
            {}
        )

        if not isinstance(
            cvss_data,
            dict
        ):
            cvss_data = {}

        score = cvss_data.get(
            "baseScore"
        )

        severity = cvss_data.get(
            "baseSeverity"
        )

        # CVSS v2 may expose severity outside
        # cvssData.
        if not severity:

            severity = selected.get(
                "baseSeverity"
            )

        if not severity:

            severity = severity_from_score(
                score
            )

        vector = cvss_data.get(
            "vectorString"
        )

        return {
            "score": score,
            "severity": str(
                severity
            ).upper(),
            "vector": vector,
            "version": version
        }

    return {
        "score": None,
        "severity": "UNKNOWN",
        "vector": None,
        "version": None
    }


# ==========================================
# DESCRIPTION EXTRACTION
# ==========================================

def extract_description(
    descriptions
):
    """
    Prefer the English NVD description.
    """

    if not isinstance(
        descriptions,
        list
    ):
        return ""

    for item in descriptions:

        if not isinstance(
            item,
            dict
        ):
            continue

        if (
            item.get(
                "lang"
            )
            == "en"
        ):

            return normalize_text(
                item.get(
                    "value"
                )
            )

    for item in descriptions:

        if not isinstance(
            item,
            dict
        ):
            continue

        value = normalize_text(
            item.get(
                "value"
            )
        )

        if value:
            return value

    return ""


# ==========================================
# REFERENCE EXTRACTION
# ==========================================

def extract_references(
    references
):
    """
    Extract reference URLs from NVD.
    """

    output = []

    if not isinstance(
        references,
        list
    ):
        return output

    for reference in references:

        if not isinstance(
            reference,
            dict
        ):
            continue

        url = normalize_text(
            reference.get(
                "url"
            )
        )

        if not url:
            continue

        if url not in output:

            output.append(
                url
            )

    return output


# ==========================================
# CPE MATCH NORMALIZATION
# ==========================================

def normalize_cpe_match(
    cpe_match
):
    """
    Normalize an NVD CPE match while
    preserving version constraints required
    by vulnerability_service.py.
    """

    if not isinstance(
        cpe_match,
        dict
    ):
        return None

    criteria = normalize_text(
        cpe_match.get(
            "criteria"
        )
    )

    if not criteria:
        return None

    return {
        "criteria": criteria,

        "vulnerable": bool(
            cpe_match.get(
                "vulnerable",
                False
            )
        ),

        "match_criteria_id": (
            cpe_match.get(
                "matchCriteriaId"
            )
        ),

        "version_start_including": (
            cpe_match.get(
                "versionStartIncluding"
            )
        ),

        "version_start_excluding": (
            cpe_match.get(
                "versionStartExcluding"
            )
        ),

        "version_end_including": (
            cpe_match.get(
                "versionEndIncluding"
            )
        ),

        "version_end_excluding": (
            cpe_match.get(
                "versionEndExcluding"
            )
        )
    }


# ==========================================
# CONFIGURATION NODE WALKER
# ==========================================

def walk_configuration_node(
    node,
    output
):
    """
    Recursively extract CPE matches from an
    NVD configuration node.
    """

    if not isinstance(
        node,
        dict
    ):
        return

    cpe_matches = node.get(
        "cpeMatch",
        []
    )

    if isinstance(
        cpe_matches,
        list
    ):

        for cpe_match in cpe_matches:

            normalized = normalize_cpe_match(
                cpe_match
            )

            if normalized:

                output.append(
                    normalized
                )

    children = node.get(
        "nodes",
        []
    )

    if isinstance(
        children,
        list
    ):

        for child in children:

            walk_configuration_node(
                child,
                output
            )


# ==========================================
# CONFIGURATION CPE EXTRACTION
# ==========================================

def extract_configuration_cpes(
    configurations
):
    """
    Extract all CPE matches from NVD
    configurations.

    Both vulnerable and non-vulnerable CPEs
    are retained because platform context may
    be required by vulnerability_service.py.
    """

    output = []

    if not isinstance(
        configurations,
        list
    ):
        return output

    for configuration in configurations:

        if not isinstance(
            configuration,
            dict
        ):
            continue

        nodes = configuration.get(
            "nodes",
            []
        )

        if not isinstance(
            nodes,
            list
        ):
            continue

        for node in nodes:

            walk_configuration_node(
                node,
                output
            )

    return output


# ==========================================
# AFFECTED CPE EXTRACTION
# ==========================================

def extract_affected_cpes(
    configuration_cpes
):
    """
    Return vulnerable CPE entries only.

    These are the CPEs describing affected
    products according to NVD configuration
    data.
    """

    if not isinstance(
        configuration_cpes,
        list
    ):
        return []

    return [
        item
        for item in configuration_cpes
        if (
            isinstance(
                item,
                dict
            )
            and item.get(
                "vulnerable"
            ) is True
        )
    ]


# ==========================================
# CPE PARSER
# ==========================================

def parse_cpe23(
    criteria
):
    """
    Parse the basic fields of a CPE 2.3 URI.

    Example:

        cpe:2.3:a:vsftpd:vsftpd:2.3.4:*:*:*:*:*:*:*
    """

    criteria = normalize_text(
        criteria
    )

    if not criteria.startswith(
        "cpe:2.3:"
    ):
        return None

    parts = criteria.split(
        ":"
    )

    if len(parts) < 6:
        return None

    return {
        "part": (
            parts[2]
            if len(parts) > 2
            else ""
        ),

        "vendor": (
            parts[3]
            if len(parts) > 3
            else ""
        ),

        "product": (
            parts[4]
            if len(parts) > 4
            else ""
        ),

        "version": (
            parts[5]
            if len(parts) > 5
            else ""
        ),

        "criteria": criteria
    }


# ==========================================
# AFFECTED PRODUCT EXTRACTION
# ==========================================

def extract_affected_products(
    affected_cpes
):
    """
    Build product metadata from vulnerable
    CPE entries.

    This is retained for compatibility with
    vulnerability_service.py.
    """

    products = []

    seen = set()

    if not isinstance(
        affected_cpes,
        list
    ):
        return products

    for item in affected_cpes:

        if not isinstance(
            item,
            dict
        ):
            continue

        parsed = parse_cpe23(
            item.get(
                "criteria"
            )
        )

        if not parsed:
            continue

        product = normalize_text(
            parsed.get(
                "product"
            )
        )

        vendor = normalize_text(
            parsed.get(
                "vendor"
            )
        )

        if not product:
            continue

        key = (
            vendor.lower(),
            product.lower()
        )

        if key in seen:
            continue

        seen.add(
            key
        )

        products.append(
            {
                "vendor": vendor,
                "product": product
            }
        )

    return products


# ==========================================
# NORMALIZE NVD CVE
# ==========================================

def normalize_nvd_cve(
    cve
):
    """
    Convert a raw NVD CVE object into the
    structure used by AttackLens.
    """

    if not isinstance(
        cve,
        dict
    ):
        return None

    cve_id = normalize_text(
        cve.get(
            "id"
        )
    ).upper()

    if not cve_id:
        return None

    cvss = extract_cvss(
        cve.get(
            "metrics",
            {}
        )
    )

    configurations = cve.get(
        "configurations",
        []
    )

    if not isinstance(
        configurations,
        list
    ):
        configurations = []

    configuration_cpes = (
        extract_configuration_cpes(
            configurations
        )
    )

    affected_cpes = (
        extract_affected_cpes(
            configuration_cpes
        )
    )

    affected_products = (
        extract_affected_products(
            affected_cpes
        )
    )

    return {
        "cve_id": cve_id,

        "description": extract_description(
            cve.get(
                "descriptions",
                []
            )
        ),

        "severity": cvss.get(
            "severity",
            "UNKNOWN"
        ),

        "cvss_score": cvss.get(
            "score"
        ),

        "cvss_vector": cvss.get(
            "vector"
        ),

        "cvss_version": cvss.get(
            "version"
        ),

        "vuln_status": cve.get(
            "vulnStatus"
        ),

        "published": cve.get(
            "published"
        ),

        "last_modified": cve.get(
            "lastModified"
        ),

        "references": extract_references(
            cve.get(
                "references",
                []
            )
        ),

        # Raw NVD configuration tree retained
        # for defensible applicability analysis.
        "configurations": configurations,

        # Flattened complete configuration CPE
        # set, including platform context.
        "configuration_cpes": (
            configuration_cpes
        ),

        # Vulnerable=True CPE entries.
        "affected_cpes": affected_cpes,

        # Convenience product metadata.
        "affected_products": (
            affected_products
        )
    }


# ==========================================
# NVD SEARCH
# ==========================================

def search_cves(
    keyword,
    results_per_page=10
):
    """
    Search the official NVD CVE API using
    keywordSearch.

    Returns normalized CVE candidate records.

    IMPORTANT:

    A keyword match is candidate discovery
    only. It is NOT proof of applicability.
    """

    keyword = normalize_text(
        keyword
    )

    if not keyword:
        return []

    limit = normalize_results_per_page(
        results_per_page
    )

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": limit
    }

    headers = build_nvd_headers()

    try:

        response = requests.get(
            NVD_API_URL,
            params=params,
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )

        response.raise_for_status()

        payload = response.json()

    except (
        requests.RequestException,
        ValueError
    ):

        return []

    vulnerabilities = payload.get(
        "vulnerabilities",
        []
    )

    if not isinstance(
        vulnerabilities,
        list
    ):
        return []

    results = []

    for vulnerability in vulnerabilities:

        if not isinstance(
            vulnerability,
            dict
        ):
            continue

        raw_cve = vulnerability.get(
            "cve"
        )

        normalized = normalize_nvd_cve(
            raw_cve
        )

        if normalized:

            results.append(
                normalized
            )

    return results


# ==========================================
# PRODUCT SEARCH QUERY BUILDER
# ==========================================

def build_product_search_queries(
    product
):
    """
    Build conservative product search
    variants.

    The exact Nmap product string is always
    preserved.

    Only a few common Nmap naming variations
    are added.
    """

    product = normalize_text(
        product
    )

    if not product:
        return []

    queries = [
        product
    ]

    lower_product = product.lower()

    aliases = []

    # --------------------------------------
    # APACHE
    # --------------------------------------

    if "apache" in lower_product:

        aliases.extend(
            [
                "Apache HTTP Server",
                "Apache httpd"
            ]
        )

    # --------------------------------------
    # OPENSSH
    # --------------------------------------

    if "openssh" in lower_product:

        aliases.append(
            "OpenSSH"
        )

    # --------------------------------------
    # VSFTPD
    # --------------------------------------

    if "vsftpd" in lower_product:

        aliases.append(
            "vsftpd"
        )

    # --------------------------------------
    # SAMBA
    # --------------------------------------

    if "samba" in lower_product:

        aliases.append(
            "Samba"
        )

    # --------------------------------------
    # MYSQL
    # --------------------------------------

    if "mysql" in lower_product:

        aliases.append(
            "MySQL"
        )

    # --------------------------------------
    # POSTGRESQL
    # --------------------------------------

    if (
        "postgresql" in lower_product
        or "postgres" in lower_product
    ):

        aliases.append(
            "PostgreSQL"
        )

    # --------------------------------------
    # PROFTPD
    # --------------------------------------

    if "proftpd" in lower_product:

        aliases.append(
            "ProFTPD"
        )

    # --------------------------------------
    # TOMCAT
    # --------------------------------------

    if "tomcat" in lower_product:

        aliases.append(
            "Apache Tomcat"
        )

    # --------------------------------------
    # DISTCCD
    # --------------------------------------

    if "distccd" in lower_product:

        aliases.append(
            "distcc"
        )

    for alias in aliases:

        alias = normalize_text(
            alias
        )

        if (
            alias
            and alias not in queries
        ):

            queries.append(
                alias
            )

    return queries


# ==========================================
# SERVICE SEARCH HELPER
# ==========================================

def search_service_cves(
    product,
    version=None,
    results_per_page=10
):
    """
    Retrieve NVD CVE candidates for a service
    discovered by Nmap.

    DESIGN:

    1. Product + detected version is searched
       first.

    2. Product-only searches provide broader
       fallback candidate discovery.

    3. Keyword results remain candidates.

    4. vulnerability_service.py determines
       actual applicability using CPE product,
       version ranges and platform context.

    5. Duplicate CVEs are removed.
    """

    # ======================================
    # VALIDATE PRODUCT
    # ======================================

    product = normalize_text(
        product
    )

    if not product:
        return []

    # ======================================
    # NORMALIZE VERSION
    # ======================================

    normalized_version = normalize_text(
        version
    )

    if normalized_version.lower() in (
        "",
        "-",
        "*",
        "unknown",
        "none",
        "n/a"
    ):

        normalized_version = None

    # ======================================
    # REQUESTED LIMIT
    # ======================================

    requested_limit = (
        normalize_results_per_page(
            results_per_page
        )
    )

    # ======================================
    # CANDIDATE POOL
    # ======================================

    candidate_limit = max(
        requested_limit * 5,
        50
    )

    candidate_limit = min(
        candidate_limit,
        MAX_RESULTS_PER_PAGE
    )

    # ======================================
    # BUILD QUERIES
    # ======================================

    queries = []

    # --------------------------------------
    # PRODUCT + VERSION FIRST
    # --------------------------------------

    if normalized_version:

        version_query = (
            f"{product} "
            f"{normalized_version}"
        ).strip()

        if version_query:

            queries.append(
                version_query
            )

    # --------------------------------------
    # PRODUCT FALLBACKS
    # --------------------------------------

    for query in (
        build_product_search_queries(
            product
        )
    ):

        query = normalize_text(
            query
        )

        if (
            query
            and query not in queries
        ):

            queries.append(
                query
            )

    # --------------------------------------
    # GUARANTEE ORIGINAL PRODUCT
    # --------------------------------------

    if product not in queries:

        queries.append(
            product
        )

    # ======================================
    # RETRIEVE CANDIDATES
    # ======================================

    combined_results = []

    seen_cves = set()

    for query in queries:

        try:

            cve_results = search_cves(
                keyword=query,
                results_per_page=candidate_limit
            )

        except Exception:

            continue

        if not isinstance(
            cve_results,
            list
        ):
            continue

        for cve in cve_results:

            if not isinstance(
                cve,
                dict
            ):
                continue

            cve_id = normalize_text(
                cve.get(
                    "cve_id"
                )
            ).upper()

            if not cve_id:
                continue

            if cve_id in seen_cves:
                continue

            seen_cves.add(
                cve_id
            )

            combined_results.append(
                cve
            )

            if (
                len(combined_results)
                >= candidate_limit
            ):

                return combined_results

        # Small delay between fallback queries
        # to reduce unnecessary NVD request
        # pressure when no API key is configured.
        if len(queries) > 1:

            time.sleep(
                0.6
            )

    return combined_results