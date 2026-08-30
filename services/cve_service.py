import requests

from flask import current_app


# ==========================================
# NVD CVE SERVICE
# ==========================================


def build_nvd_headers():
    """
    Build HTTP headers for the NVD API.

    If an API key is configured, include it.

    The NVD API can work without an API key,
    but requests are subject to stricter
    rate limits.
    """

    headers = {
        "Accept": "application/json"
    }


    api_key = current_app.config.get(
        "NVD_API_KEY"
    )


    if api_key:

        headers[
            "apiKey"
        ] = api_key


    return headers


# ==========================================
# SEARCH CVES
# ==========================================


def search_cves(
    keyword,
    results_per_page=10
):
    """
    Search the NVD CVE API using a keyword.

    Example:

        "Werkzeug 3.1.8"

    Returns:

        List of normalized CVE dictionaries.
    """

    if not keyword:

        return []


    keyword = str(
        keyword
    ).strip()


    if not keyword:

        return []


    base_url = current_app.config.get(
        "NVD_API_BASE_URL"
    )


    timeout = current_app.config.get(
        "HTTP_TIMEOUT",
        10
    )


    if not base_url:

        current_app.logger.warning(
            "NVD API base URL is not configured."
        )

        return []


    params = {

        "keywordSearch": keyword,

        "resultsPerPage": (
            results_per_page
        )

    }


    headers = build_nvd_headers()


    try:

        response = requests.get(

            base_url,

            params=params,

            headers=headers,

            timeout=timeout

        )


        response.raise_for_status()


        data = response.json()


        vulnerabilities = data.get(

            "vulnerabilities",

            []

        )


        normalized_results = []


        for vulnerability in vulnerabilities:

            cve_data = vulnerability.get(

                "cve",

                {}

            )


            normalized_cve = normalize_cve(
                cve_data
            )


            if normalized_cve:

                normalized_results.append(
                    normalized_cve
                )


        return normalized_results


    except requests.Timeout as error:

        current_app.logger.warning(

            "NVD API request timed out: %s",

            error

        )


        return []


    except requests.RequestException as error:

        current_app.logger.warning(

            "NVD API request failed: %s",

            error

        )


        return []


    except ValueError as error:

        current_app.logger.warning(

            "Invalid NVD API response: %s",

            error

        )


        return []


    except Exception as error:

        current_app.logger.warning(

            "Unexpected NVD processing error: %s",

            error

        )


        return []


# ==========================================
# NORMALIZE CVE
# ==========================================


def normalize_cve(
    cve_data
):
    """
    Convert raw NVD CVE data into a smaller
    AttackLens-friendly structure.

    The returned data still represents a
    CVE candidate.

    Final applicability validation is done
    inside vulnerability_service.py.
    """

    if not cve_data:

        return None


    cve_id = cve_data.get(
        "id"
    )


    if not cve_id:

        return None


    description = extract_description(
        cve_data
    )


    cvss_score, severity, cvss_version = (
        extract_cvss(
            cve_data
        )
    )


    references = extract_references(
        cve_data
    )


    configurations = extract_configurations(
        cve_data
    )


    affected_cpes = extract_affected_cpes(
        configurations
    )


    affected_products = extract_affected_products(
        affected_cpes
    )


    return {

        "cve_id": cve_id,

        "description": description,

        "cvss_score": cvss_score,

        "severity": severity,

        "cvss_version": cvss_version,

        "references": references,

        "affected_cpes": affected_cpes,

        "affected_products": affected_products

    }


# ==========================================
# DESCRIPTION EXTRACTION
# ==========================================


def extract_description(
    cve_data
):
    """
    Extract the English CVE description.
    """

    descriptions = cve_data.get(

        "descriptions",

        []

    )


    for description in descriptions:

        if (

            description.get(
                "lang"
            )

            ==

            "en"

        ):

            return description.get(

                "value",

                ""

            )


    return ""


# ==========================================
# CVSS EXTRACTION
# ==========================================


def extract_cvss(
    cve_data
):
    """
    Extract the best available CVSS score.

    Preference:

        CVSS v4.0
        CVSS v3.1
        CVSS v3.0
        CVSS v2.0

    Returns:

        (
            base_score,
            severity,
            cvss_version
        )
    """

    metrics = cve_data.get(

        "metrics",

        {}

    )


    metric_priority = [

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

    ]


    for (
        metric_name,
        cvss_version
    ) in metric_priority:

        metric_list = metrics.get(

            metric_name,

            []

        )


        if not metric_list:

            continue


        # Prefer a Primary metric when
        # available.

        metric = select_best_metric(
            metric_list
        )


        cvss_data = metric.get(

            "cvssData",

            {}

        )


        base_score = cvss_data.get(
            "baseScore"
        )


        severity = cvss_data.get(
            "baseSeverity"
        )


        if not severity:

            severity = metric.get(
                "baseSeverity"
            )


        severity = normalize_severity(
            severity
        )


        return (

            base_score,

            severity,

            cvss_version

        )


    return (

        None,

        "UNKNOWN",

        None

    )


# ==========================================
# SELECT BEST CVSS METRIC
# ==========================================


def select_best_metric(
    metric_list
):
    """
    Prefer NVD Primary metrics when available.

    Otherwise, use the first available metric.
    """

    for metric in metric_list:

        metric_type = str(
            metric.get(
                "type",
                ""
            )
        ).strip().upper()


        if metric_type == "PRIMARY":

            return metric


    return metric_list[0]


# ==========================================
# NORMALIZE SEVERITY
# ==========================================


def normalize_severity(
    severity
):
    """
    Normalize CVSS severity values.
    """

    if not severity:

        return "UNKNOWN"


    normalized = str(
        severity
    ).strip().upper()


    allowed = {

        "CRITICAL",

        "HIGH",

        "MEDIUM",

        "LOW",

        "NONE",

        "UNKNOWN"

    }


    if normalized not in allowed:

        return "UNKNOWN"


    return normalized


# ==========================================
# REFERENCES EXTRACTION
# ==========================================


def extract_references(
    cve_data,
    limit=5
):
    """
    Extract a limited number of useful
    CVE reference URLs.
    """

    references = cve_data.get(

        "references",

        []

    )


    normalized_references = []


    for reference in references:

        url = reference.get(
            "url"
        )


        if not url:

            continue


        if url in normalized_references:

            continue


        normalized_references.append(
            url
        )


        if (
            len(
                normalized_references
            )
            >=
            limit
        ):

            break


    return normalized_references


# ==========================================
# CONFIGURATION EXTRACTION
# ==========================================


def extract_configurations(
    cve_data
):
    """
    Extract NVD configuration nodes.

    These nodes contain CPE information and
    version applicability data used later by
    vulnerability_service.py.
    """

    configurations = cve_data.get(

        "configurations",

        []

    )


    if not isinstance(
        configurations,
        list
    ):

        return []


    return configurations


# ==========================================
# AFFECTED CPE EXTRACTION
# ==========================================


def extract_affected_cpes(
    configurations
):
    """
    Extract vulnerable CPE entries from NVD
    configuration nodes.

    Returned structure includes:

        criteria
        vulnerable
        versionStartIncluding
        versionStartExcluding
        versionEndIncluding
        versionEndExcluding
    """

    affected_cpes = []


    if not configurations:

        return affected_cpes


    for configuration in configurations:

        nodes = configuration.get(

            "nodes",

            []

        )


        extract_cpes_from_nodes(

            nodes=nodes,

            affected_cpes=affected_cpes

        )


    return affected_cpes


# ==========================================
# RECURSIVE CPE NODE EXTRACTION
# ==========================================


def extract_cpes_from_nodes(
    nodes,
    affected_cpes
):
    """
    Recursively walk NVD configuration nodes.
    """

    if not isinstance(
        nodes,
        list
    ):

        return


    for node in nodes:

        cpe_matches = node.get(

            "cpeMatch",

            []

        )


        for cpe_match in cpe_matches:

            vulnerable = cpe_match.get(

                "vulnerable",

                False

            )


            criteria = cpe_match.get(
                "criteria"
            )


            if not criteria:

                continue


            # Only retain vulnerable
            # application/platform entries.

            if vulnerable is not True:

                continue


            affected_cpes.append({

                "criteria": criteria,

                "vulnerable": True,

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

            })


        child_nodes = node.get(

            "nodes",

            []

        )


        if child_nodes:

            extract_cpes_from_nodes(

                nodes=child_nodes,

                affected_cpes=affected_cpes

            )


# ==========================================
# AFFECTED PRODUCT EXTRACTION
# ==========================================


def extract_affected_products(
    affected_cpes
):
    """
    Parse useful fields from affected CPEs.

    Typical CPE 2.3 format:

        cpe:2.3:a:vendor:product:version:...

    Part values:

        a = application
        o = operating system
        h = hardware
    """

    affected_products = []


    seen = set()


    for cpe in affected_cpes:

        criteria = cpe.get(
            "criteria"
        )


        parsed = parse_cpe(
            criteria
        )


        if not parsed:

            continue


        product_key = (

            parsed.get(
                "part"
            ),

            parsed.get(
                "vendor"
            ),

            parsed.get(
                "product"
            ),

            parsed.get(
                "version"
            ),

            cpe.get(
                "version_start_including"
            ),

            cpe.get(
                "version_start_excluding"
            ),

            cpe.get(
                "version_end_including"
            ),

            cpe.get(
                "version_end_excluding"
            )

        )


        if product_key in seen:

            continue


        seen.add(
            product_key
        )


        affected_products.append({

            "part": parsed.get(
                "part"
            ),

            "vendor": parsed.get(
                "vendor"
            ),

            "product": parsed.get(
                "product"
            ),

            "version": parsed.get(
                "version"
            ),

            "version_start_including": (
                cpe.get(
                    "version_start_including"
                )
            ),

            "version_start_excluding": (
                cpe.get(
                    "version_start_excluding"
                )
            ),

            "version_end_including": (
                cpe.get(
                    "version_end_including"
                )
            ),

            "version_end_excluding": (
                cpe.get(
                    "version_end_excluding"
                )
            ),

            "criteria": criteria

        })


    return affected_products


# ==========================================
# CPE PARSER
# ==========================================


def parse_cpe(
    cpe_string
):
    """
    Parse basic CPE 2.3 components.

    Example:

        cpe:2.3:a:palletsprojects:werkzeug:3.1.0:...

    Returns:

        {
            "part": "a",
            "vendor": "palletsprojects",
            "product": "werkzeug",
            "version": "3.1.0"
        }
    """

    if not cpe_string:

        return None


    parts = str(
        cpe_string
    ).split(":")


    if len(parts) < 6:

        return None


    if (
        parts[0]
        !=
        "cpe"
    ):

        return None


    if (
        parts[1]
        !=
        "2.3"
    ):

        return None


    return {

        "part": normalize_cpe_value(
            parts[2]
        ),

        "vendor": normalize_cpe_value(
            parts[3]
        ),

        "product": normalize_cpe_value(
            parts[4]
        ),

        "version": normalize_cpe_value(
            parts[5]
        )

    }


# ==========================================
# NORMALIZE CPE VALUE
# ==========================================


def normalize_cpe_value(
    value
):
    """
    Normalize CPE values.

    "*" and "-" represent unspecified or
    non-applicable values.
    """

    if value in (
        "*",
        "-",
        ""
    ):

        return None


    return (
        str(value)
        .replace("\\", "")
        .replace("_", " ")
        .strip()
        .lower()
    )


# ==========================================
# SERVICE SEARCH HELPER
# ==========================================


def search_service_cves(
    product,
    version=None,
    results_per_page=10
):
    """
    Search NVD for CVE candidates related
    to a discovered service.

    Example:

        product:
            Werkzeug httpd

        version:
            3.1.8

    Keyword:

        Werkzeug httpd 3.1.8

    IMPORTANT:

        This function only retrieves CVE
        candidates.

        Final product/version/platform
        validation is performed inside
        vulnerability_service.py.
    """

    if not product:

        return []


    product = str(
        product
    ).strip()


    if not product:

        return []


    search_parts = [
        product
    ]


    if version:

        version = str(
            version
        ).strip()


        if version:

            search_parts.append(
                version
            )


    keyword = " ".join(
        search_parts
    )


    return search_cves(

        keyword=keyword,

        results_per_page=results_per_page

    )