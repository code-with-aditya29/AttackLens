# ==========================================
# ATTACKLENS
# SECURITY SCANNER SERVICE
# ==========================================
#
# Provides additional security analysis for:
#
# 1. Applications / software
# 2. Network / services
# 3. Host / operating-system context
#
# Existing CVE analysis remains inside:
#
#     vulnerability_service.py
#     cve_service.py
#
# This service complements that pipeline.
#
# IMPORTANT:
#
# - Does not invent vulnerabilities.
# - Does not invent CVEs.
# - Does not claim exploitation.
# - Findings are based only on observed
#   Nmap evidence or conservative security
#   conditions.
# - Active web checks will be added as a
#   separate internal stage later.
# ==========================================


from models.security_finding_model import (
    create_security_finding
)


# ==========================================
# SECURITY-SENSITIVE SERVICES
# ==========================================

SENSITIVE_SERVICE_RULES = {

    21: {
        "category": "FTP_EXPOSURE",
        "title": "FTP Service Exposed",
        "severity": "MEDIUM",
        "description": (
            "An FTP service was detected. FTP may expose "
            "credentials or data when plaintext authentication "
            "or unencrypted transfer is used."
        )
    },

    23: {
        "category": "INSECURE_PROTOCOL",
        "title": "Telnet Service Exposed",
        "severity": "HIGH",
        "description": (
            "A Telnet service was detected. Telnet normally "
            "transmits authentication and session data without "
            "modern transport encryption."
        )
    },

    69: {
        "category": "TFTP_EXPOSURE",
        "title": "TFTP Service Exposed",
        "severity": "MEDIUM",
        "description": (
            "A TFTP service was detected. TFTP provides very "
            "limited authentication and security controls."
        )
    },

    111: {
        "category": "RPC_EXPOSURE",
        "title": "RPCBind Service Exposed",
        "severity": "MEDIUM",
        "description": (
            "RPCBind was detected and may reveal RPC services "
            "available on the host."
        )
    },

    135: {
        "category": "RPC_EXPOSURE",
        "title": "Microsoft RPC Service Exposed",
        "severity": "MEDIUM",
        "description": (
            "Microsoft RPC is exposed and contributes to the "
            "host's remotely reachable attack surface."
        )
    },

    139: {
        "category": "SMB_EXPOSURE",
        "title": "NetBIOS/SMB Service Exposed",
        "severity": "MEDIUM",
        "description": (
            "NetBIOS/SMB-related network access was detected."
        )
    },

    445: {
        "category": "SMB_EXPOSURE",
        "title": "SMB Service Exposed",
        "severity": "HIGH",
        "description": (
            "SMB is reachable on the target and represents a "
            "security-sensitive remote service."
        )
    },

    512: {
        "category": "INSECURE_REMOTE_SERVICE",
        "title": "rexec Service Exposed",
        "severity": "HIGH",
        "description": (
            "The legacy rexec remote execution service was "
            "detected."
        )
    },

    513: {
        "category": "INSECURE_REMOTE_SERVICE",
        "title": "rlogin Service Exposed",
        "severity": "HIGH",
        "description": (
            "The legacy rlogin remote access service was "
            "detected."
        )
    },

    514: {
        "category": "INSECURE_REMOTE_SERVICE",
        "title": "rsh Service Exposed",
        "severity": "HIGH",
        "description": (
            "The legacy rsh remote shell service was detected."
        )
    },

    1099: {
        "category": "JAVA_RMI_EXPOSURE",
        "title": "Java RMI Service Exposed",
        "severity": "MEDIUM",
        "description": (
            "A Java RMI service was detected and contributes "
            "to the remotely reachable application surface."
        )
    },

    1433: {
        "category": "DATABASE_EXPOSURE",
        "title": "Microsoft SQL Server Service Exposed",
        "severity": "HIGH",
        "description": (
            "A Microsoft SQL Server service is reachable over "
            "the network."
        )
    },

    1521: {
        "category": "DATABASE_EXPOSURE",
        "title": "Oracle Database Service Exposed",
        "severity": "HIGH",
        "description": (
            "An Oracle database listener is reachable over "
            "the network."
        )
    },

    1524: {
        "category": "SUSPICIOUS_SERVICE_EXPOSURE",
        "title": "Security-Sensitive Service on TCP/1524",
        "severity": "HIGH",
        "description": (
            "TCP port 1524 is open. This port is associated "
            "with security-sensitive services in vulnerable "
            "lab environments and requires investigation."
        )
    },

    2049: {
        "category": "NFS_EXPOSURE",
        "title": "NFS Service Exposed",
        "severity": "MEDIUM",
        "description": (
            "Network File System access was detected."
        )
    },

    3306: {
        "category": "DATABASE_EXPOSURE",
        "title": "MySQL Service Exposed",
        "severity": "HIGH",
        "description": (
            "A MySQL database service is reachable over the "
            "network."
        )
    },

    3389: {
        "category": "REMOTE_ACCESS_EXPOSURE",
        "title": "Remote Desktop Service Exposed",
        "severity": "MEDIUM",
        "description": (
            "A Remote Desktop service is reachable on the "
            "target."
        )
    },

    5432: {
        "category": "DATABASE_EXPOSURE",
        "title": "PostgreSQL Service Exposed",
        "severity": "HIGH",
        "description": (
            "A PostgreSQL database service is reachable over "
            "the network."
        )
    },

    5900: {
        "category": "REMOTE_ACCESS_EXPOSURE",
        "title": "VNC Service Exposed",
        "severity": "HIGH",
        "description": (
            "A VNC remote desktop service is reachable on the "
            "target."
        )
    },

    6000: {
        "category": "X11_EXPOSURE",
        "title": "X11 Service Exposed",
        "severity": "MEDIUM",
        "description": (
            "An X11 service was detected and may increase the "
            "remote attack surface."
        )
    },

    6379: {
        "category": "DATABASE_EXPOSURE",
        "title": "Redis Service Exposed",
        "severity": "HIGH",
        "description": (
            "A Redis service is reachable over the network."
        )
    },

    8009: {
        "category": "APPLICATION_SERVICE_EXPOSURE",
        "title": "AJP Service Exposed",
        "severity": "MEDIUM",
        "description": (
            "An Apache JServ Protocol service was detected."
        )
    },

    27017: {
        "category": "DATABASE_EXPOSURE",
        "title": "MongoDB Service Exposed",
        "severity": "HIGH",
        "description": (
            "A MongoDB database service is reachable over the "
            "network."
        )
    }
}


# ==========================================
# WEB SERVICE PORTS
# ==========================================

COMMON_WEB_PORTS = {
    80,
    443,
    8000,
    8008,
    8080,
    8081,
    8180,
    8443,
    8888
}


# ==========================================
# WEB SERVICE NAMES
# ==========================================

WEB_SERVICE_NAMES = {
    "http",
    "https",
    "http-proxy",
    "http-alt",
    "https-alt",
    "ssl/http",
    "ssl/https"
}


# ==========================================
# MAIN SECURITY ANALYSIS ENGINE
# ==========================================

def analyze_security_findings(
    target,
    ports=None,
    services=None,
    os_detection=None,
    os_accuracy=None,
    created_by=None
):
    """
    Run AttackLens non-CVE security analysis.

    This function is the central entry point
    intended for routes/scan.py.

    It currently performs:

        Network/service exposure analysis
        Application/service analysis
        Host/OS contextual analysis
        Web-service discovery/context analysis

    Existing NVD/CVE findings remain generated
    by vulnerability_service.py.

    Returns:
        List of normalized security findings.
    """

    ports = normalize_list(
        ports
    )

    services = normalize_list(
        services
    )

    findings = []

    # ======================================
    # NETWORK / SERVICE ANALYSIS
    # ======================================

    findings.extend(
        analyze_network_services(
            target=target,
            ports=ports,
            services=services,
            created_by=created_by
        )
    )

    # ======================================
    # APPLICATION / SOFTWARE ANALYSIS
    # ======================================

    findings.extend(
        analyze_application_services(
            target=target,
            services=services,
            created_by=created_by
        )
    )

    # ======================================
    # HOST / OS ANALYSIS
    # ======================================

    findings.extend(
        analyze_host_security(
            target=target,
            ports=ports,
            services=services,
            os_detection=os_detection,
            os_accuracy=os_accuracy,
            created_by=created_by
        )
    )

    # ======================================
    # WEB SERVICE ANALYSIS
    # ======================================
    #
    # At this stage this identifies reachable
    # web application surfaces only.
    #
    # Active SQLi / XSS / CSRF / IDOR checks
    # will be implemented inside this service
    # after this base integration is tested.
    # ======================================

    findings.extend(
        analyze_web_services(
            target=target,
            ports=ports,
            services=services,
            created_by=created_by
        )
    )

    # ======================================
    # DEDUPLICATE
    # ======================================

    return deduplicate_findings(
        findings
    )


# ==========================================
# NETWORK / SERVICE ANALYSIS
# ==========================================

def analyze_network_services(
    target,
    ports,
    services,
    created_by=None
):
    """
    Analyze open network services for
    observable security-sensitive exposure.

    IMPORTANT:

    An open port alone does not prove a
    software vulnerability.

    These findings describe observable
    exposure conditions.
    """

    findings = []

    service_index = build_service_index(
        services
    )

    for port_record in ports:

        if not isinstance(
            port_record,
            dict
        ):

            continue

        if not is_open_port(
            port_record
        ):

            continue

        port_number = normalize_port_number(
            port_record.get(
                "port"
            )
        )

        if port_number is None:

            continue

        rule = SENSITIVE_SERVICE_RULES.get(
            port_number
        )

        if not rule:

            continue

        service_record = (
            service_index.get(
                port_number,
                {}
            )
        )

        service_name = (
            first_value(
                service_record.get("name"),
                service_record.get("service"),
                port_record.get("service")
            )
        )

        product = (
            first_value(
                service_record.get("product"),
                port_record.get("product")
            )
        )

        version = (
            first_value(
                service_record.get("version"),
                port_record.get("version")
            )
        )

        protocol = (
            first_value(
                port_record.get("protocol"),
                "tcp"
            )
        )

        evidence = [
            (
                f"{str(protocol).upper()}/"
                f"{port_number} was observed open."
            )
        ]

        if service_name:

            evidence.append(
                f"Detected service: {service_name}."
            )

        if product:

            product_evidence = (
                f"Detected product: {product}"
            )

            if version:

                product_evidence += (
                    f" {version}"
                )

            product_evidence += "."

            evidence.append(
                product_evidence
            )

        findings.append(
            create_security_finding(
                finding_type="SERVICE",
                category=rule.get(
                    "category"
                ),
                title=rule.get(
                    "title"
                ),
                description=rule.get(
                    "description",
                    ""
                ),
                target=target,
                port=port_number,
                protocol=protocol,
                service=service_name,
                product=product,
                version=version,
                severity=rule.get(
                    "severity",
                    "MEDIUM"
                ),
                confidence="HIGH",
                status="OBSERVED",
                evidence=evidence,
                evidence_source="Nmap",
                metadata={
                    "analysis_type":
                        "service_exposure",
                    "observed_open_port":
                        True
                },
                created_by=created_by
            )
        )

    return findings


# ==========================================
# APPLICATION / SOFTWARE ANALYSIS
# ==========================================

def analyze_application_services(
    target,
    services,
    created_by=None
):
    """
    Analyze discovered application/software
    services.

    This function does NOT duplicate the NVD
    CVE engine.

    It currently records only conservative
    application security observations that
    can be supported by discovery evidence.
    """

    findings = []

    for service in services:

        if not isinstance(
            service,
            dict
        ):

            continue

        port = normalize_port_number(
            service.get(
                "port"
            )
        )

        service_name = first_value(
            service.get("name"),
            service.get("service")
        )

        product = normalize_optional_text(
            service.get(
                "product"
            )
        )

        version = normalize_optional_text(
            service.get(
                "version"
            )
        )

        # ==================================
        # PRODUCT DETECTED WITHOUT VERSION
        # ==================================
        #
        # This is not called a vulnerability.
        #
        # Missing version evidence reduces
        # confidence in version-specific
        # vulnerability assessment.
        # ==================================

        if (
            product
            and
            not version
        ):

            findings.append(
                create_security_finding(
                    finding_type="APPLICATION",
                    category=(
                        "LIMITED_VERSION_EVIDENCE"
                    ),
                    title=(
                        "Application Version "
                        "Could Not Be Determined"
                    ),
                    description=(
                        "AttackLens identified an "
                        "application or service product "
                        "but could not determine its "
                        "version. Version-specific "
                        "vulnerability assessment may "
                        "therefore be limited."
                    ),
                    target=target,
                    port=port,
                    service=service_name,
                    product=product,
                    version=None,
                    severity="LOW",
                    confidence="HIGH",
                    status="OBSERVED",
                    evidence=[
                        (
                            f"Detected product: "
                            f"{product}."
                        ),
                        (
                            "No product version was "
                            "reported by Nmap."
                        )
                    ],
                    evidence_source="Nmap",
                    metadata={
                        "analysis_type":
                            "application_inventory",
                        "version_detected":
                            False
                    },
                    created_by=created_by
                )
            )

    return findings


# ==========================================
# HOST / OS SECURITY ANALYSIS
# ==========================================

def analyze_host_security(
    target,
    ports,
    services,
    os_detection=None,
    os_accuracy=None,
    created_by=None
):
    """
    Analyze host/OS security context using
    observable Nmap evidence.

    This is not a credentialed host audit.

    Therefore it must not claim local patch,
    registry, package, permission, or kernel
    vulnerabilities without evidence.
    """

    findings = []

    os_name = normalize_optional_text(
        os_detection
    )

    accuracy = normalize_accuracy(
        os_accuracy
    )

    # ======================================
    # OS FINGERPRINT UNCERTAIN
    # ======================================

    if os_name and accuracy is not None:

        if accuracy < 80:

            findings.append(
                create_security_finding(
                    finding_type="OS",
                    category=(
                        "LOW_CONFIDENCE_OS_DETECTION"
                    ),
                    title=(
                        "Operating System Detection "
                        "Has Limited Confidence"
                    ),
                    description=(
                        "The operating-system fingerprint "
                        "was detected with limited accuracy. "
                        "OS-specific security conclusions "
                        "should therefore be treated "
                        "conservatively."
                    ),
                    target=target,
                    operating_system=os_name,
                    severity="LOW",
                    confidence="HIGH",
                    status="OBSERVED",
                    evidence=[
                        (
                            f"Detected OS: {os_name}."
                        ),
                        (
                            f"Nmap OS detection accuracy: "
                            f"{accuracy}%."
                        )
                    ],
                    evidence_source="Nmap",
                    metadata={
                        "analysis_type":
                            "os_context",
                        "os_accuracy":
                            accuracy
                    },
                    created_by=created_by
                )
            )

    # ======================================
    # LARGE HOST ATTACK SURFACE
    # ======================================

    open_ports = []

    for port_record in ports:

        if not isinstance(
            port_record,
            dict
        ):

            continue

        if not is_open_port(
            port_record
        ):

            continue

        port_number = normalize_port_number(
            port_record.get(
                "port"
            )
        )

        if port_number is not None:

            open_ports.append(
                port_number
            )

    open_ports = sorted(
        set(
            open_ports
        )
    )

    if len(open_ports) >= 10:

        findings.append(
            create_security_finding(
                finding_type="HOST",
                category="LARGE_ATTACK_SURFACE",
                title=(
                    "Large Network Attack Surface "
                    "Observed"
                ),
                description=(
                    "The host exposes a relatively large "
                    "number of network services. This is "
                    "an attack-surface observation rather "
                    "than proof that each service is "
                    "vulnerable."
                ),
                target=target,
                operating_system=os_name,
                severity="MEDIUM",
                confidence="HIGH",
                status="OBSERVED",
                evidence=[
                    (
                        f"{len(open_ports)} open network "
                        f"ports were observed."
                    ),
                    (
                        "Observed ports: "
                        +
                        ", ".join(
                            str(port)
                            for port in open_ports
                        )
                        +
                        "."
                    )
                ],
                evidence_source="Nmap",
                metadata={
                    "analysis_type":
                        "host_attack_surface",
                    "open_port_count":
                        len(open_ports),
                    "open_ports":
                        open_ports
                },
                created_by=created_by
            )
        )

    return findings


# ==========================================
# WEB SERVICE ANALYSIS
# ==========================================

def analyze_web_services(
    target,
    ports,
    services,
    created_by=None
):
    """
    Identify discovered web application
    surfaces.

    IMPORTANT:

    This stage does not yet claim SQLi, XSS,
    CSRF, or IDOR.

    Those checks require controlled HTTP
    request/response evidence and will be
    added after this integration layer is
    confirmed working.
    """

    findings = []

    service_index = build_service_index(
        services
    )

    seen = set()

    for port_record in ports:

        if not isinstance(
            port_record,
            dict
        ):

            continue

        if not is_open_port(
            port_record
        ):

            continue

        port = normalize_port_number(
            port_record.get(
                "port"
            )
        )

        if port is None:

            continue

        service_record = (
            service_index.get(
                port,
                {}
            )
        )

        service_name = first_value(
            service_record.get("name"),
            service_record.get("service"),
            port_record.get("service")
        )

        normalized_service = (
            str(
                service_name
                or
                ""
            )
            .strip()
            .lower()
        )

        is_web = (
            port in COMMON_WEB_PORTS
            or
            normalized_service
            in WEB_SERVICE_NAMES
            or
            "http" in normalized_service
        )

        if not is_web:

            continue

        key = (
            str(target),
            port
        )

        if key in seen:

            continue

        seen.add(
            key
        )

        product = first_value(
            service_record.get("product"),
            port_record.get("product")
        )

        version = first_value(
            service_record.get("version"),
            port_record.get("version")
        )

        protocol = first_value(
            port_record.get("protocol"),
            "tcp"
        )

        web_scheme = determine_web_scheme(
            port=port,
            service_name=service_name
        )

        findings.append(
            create_security_finding(
                finding_type="APPLICATION",
                category="WEB_APPLICATION_SURFACE",
                title="Web Application Surface Detected",
                description=(
                    "AttackLens detected an HTTP/HTTPS "
                    "application surface. This finding "
                    "records the discovered application "
                    "surface and does not by itself claim "
                    "a web vulnerability."
                ),
                target=target,
                port=port,
                protocol=protocol,
                service=service_name,
                product=product,
                version=version,
                severity="LOW",
                confidence="HIGH",
                status="OBSERVED",
                evidence=[
                    (
                        f"Web-capable service observed "
                        f"on port {port}."
                    )
                ],
                evidence_source="Nmap",
                metadata={
                    "analysis_type":
                        "web_surface_discovery",
                    "scheme":
                        web_scheme,
                    "active_web_testing":
                        False
                },
                created_by=created_by
            )
        )

    return findings


# ==========================================
# BUILD SERVICE INDEX
# ==========================================

def build_service_index(
    services
):
    """
    Index discovered services by port.
    """

    index = {}

    for service in services:

        if not isinstance(
            service,
            dict
        ):

            continue

        port = normalize_port_number(
            service.get(
                "port"
            )
        )

        if port is None:

            continue

        index[
            port
        ] = service

    return index


# ==========================================
# DETERMINE WEB SCHEME
# ==========================================

def determine_web_scheme(
    port,
    service_name=None
):
    """
    Conservatively determine whether a
    discovered web service likely uses
    HTTP or HTTPS.
    """

    service_name = (
        str(
            service_name
            or
            ""
        )
        .strip()
        .lower()
    )

    if (
        port in {
            443,
            8443
        }
        or
        "https" in service_name
        or
        service_name.startswith(
            "ssl/"
        )
    ):

        return "https"

    return "http"


# ==========================================
# IS OPEN PORT
# ==========================================

def is_open_port(
    port_record
):
    """
    Determine whether a Nmap port record
    represents an open service.

    Current AttackLens persists only open
    services in many cases, so missing state
    is treated as open for compatibility.
    """

    if not isinstance(
        port_record,
        dict
    ):

        return False

    state = port_record.get(
        "state"
    )

    if state is None:

        return True

    return (
        str(
            state
        )
        .strip()
        .lower()
        ==
        "open"
    )


# ==========================================
# DEDUPLICATE FINDINGS
# ==========================================

def deduplicate_findings(
    findings
):
    """
    Remove duplicate findings while retaining
    findings that refer to different ports,
    products, endpoints, or parameters.
    """

    if not isinstance(
        findings,
        list
    ):

        return []

    normalized = []

    seen = set()

    for finding in findings:

        if not isinstance(
            finding,
            dict
        ):

            continue

        key = (
            normalize_key(
                finding.get(
                    "finding_type"
                )
            ),
            normalize_key(
                finding.get(
                    "category"
                )
            ),
            normalize_key(
                finding.get(
                    "target"
                )
            ),
            normalize_port_number(
                finding.get(
                    "port"
                )
            ),
            normalize_key(
                finding.get(
                    "service"
                )
            ),
            normalize_key(
                finding.get(
                    "product"
                )
            ),
            normalize_key(
                finding.get(
                    "version"
                )
            ),
            normalize_key(
                finding.get(
                    "endpoint"
                )
            ),
            normalize_key(
                finding.get(
                    "parameter"
                )
            )
        )

        if key in seen:

            continue

        seen.add(
            key
        )

        normalized.append(
            finding
        )

    return normalized


# ==========================================
# NORMALIZE LIST
# ==========================================

def normalize_list(
    value
):
    """
    Safely normalize list input.
    """

    if isinstance(
        value,
        list
    ):

        return value

    return []


# ==========================================
# NORMALIZE PORT NUMBER
# ==========================================

def normalize_port_number(
    value
):
    """
    Normalize a valid TCP/UDP port.
    """

    if value is None:

        return None

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
# NORMALIZE OS ACCURACY
# ==========================================

def normalize_accuracy(
    value
):
    """
    Normalize Nmap OS accuracy percentage.
    """

    if value is None:

        return None

    try:

        accuracy = int(
            value
        )

    except (
        TypeError,
        ValueError
    ):

        return None

    return max(
        0,
        min(
            100,
            accuracy
        )
    )


# ==========================================
# NORMALIZE OPTIONAL TEXT
# ==========================================

def normalize_optional_text(
    value
):
    """
    Normalize optional text.
    """

    if value is None:

        return None

    value = str(
        value
    ).strip()

    if not value:

        return None

    return value


# ==========================================
# FIRST NON-EMPTY VALUE
# ==========================================

def first_value(
    *values
):
    """
    Return the first meaningful value.
    """

    for value in values:

        if value is None:

            continue

        if isinstance(
            value,
            str
        ):

            value = value.strip()

            if not value:

                continue

        return value

    return None


# ==========================================
# NORMALIZE DEDUPLICATION KEY
# ==========================================

def normalize_key(
    value
):
    """
    Normalize text used in finding identity.
    """

    if value is None:

        return ""

    return (
        str(
            value
        )
        .strip()
        .lower()
    )