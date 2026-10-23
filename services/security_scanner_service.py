"""AttackLens non-CVE security scanner.



Minor-project scope: conservative network/service, application/software,



host/OS and bounded web-application checks. Existing CVE/NVD analysis remains



in vulnerability_service.py and cve_service.py.



The web stage uses safe GET/HEAD-style observation and limited GET parameter



probes only. It does not submit POST forms, authenticate, brute-force, exploit,



or claim compromise. SQLi/XSS findings require response evidence; CSRF and



IDOR are reported as potential/manual-verification findings where appropriate.



"""



import html



import re



import ssl



from html.parser import HTMLParser



from urllib.error import HTTPError, URLError



from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse



from urllib.request import Request, urlopen



from models.security_finding_model import create_security_finding



HTTP_TIMEOUT = 4



MAX_WEB_PAGES = 8



MAX_PARAMETERS_PER_PAGE = 6



MAX_RESPONSE_BYTES = 512_000



USER_AGENT = "AttackLens/1.0 Authorized-Security-Assessment"



SENSITIVE_SERVICE_RULES = {



    21: ("FTP_EXPOSURE", "FTP Service Exposed", "MEDIUM", "FTP is reachable and may use plaintext authentication or transfer."),



    23: ("INSECURE_PROTOCOL", "Telnet Service Exposed", "HIGH", "Telnet normally transmits authentication and session data without modern transport encryption."),



    69: ("TFTP_EXPOSURE", "TFTP Service Exposed", "MEDIUM", "TFTP provides limited authentication and security controls."),



    111: ("RPC_EXPOSURE", "RPCBind Service Exposed", "MEDIUM", "RPCBind may reveal remotely available RPC services."),



    135: ("RPC_EXPOSURE", "Microsoft RPC Service Exposed", "MEDIUM", "Microsoft RPC contributes to the remotely reachable attack surface."),



    139: ("SMB_EXPOSURE", "NetBIOS/SMB Service Exposed", "MEDIUM", "NetBIOS/SMB-related network access was detected."),



    445: ("SMB_EXPOSURE", "SMB Service Exposed", "HIGH", "SMB is reachable and represents a security-sensitive remote service."),



    512: ("INSECURE_REMOTE_SERVICE", "rexec Service Exposed", "HIGH", "The legacy rexec remote execution service was detected."),



    513: ("INSECURE_REMOTE_SERVICE", "rlogin Service Exposed", "HIGH", "The legacy rlogin remote access service was detected."),



    514: ("INSECURE_REMOTE_SERVICE", "rsh Service Exposed", "HIGH", "The legacy rsh remote shell service was detected."),



    1099: ("JAVA_RMI_EXPOSURE", "Java RMI Service Exposed", "MEDIUM", "Java RMI contributes to the remotely reachable application surface."),



    1433: ("DATABASE_EXPOSURE", "Microsoft SQL Server Service Exposed", "HIGH", "Microsoft SQL Server is reachable over the network."),



    1521: ("DATABASE_EXPOSURE", "Oracle Database Service Exposed", "HIGH", "An Oracle database listener is reachable over the network."),



    1524: ("SUSPICIOUS_SERVICE_EXPOSURE", "Security-Sensitive Service on TCP/1524", "HIGH", "TCP/1524 is security-sensitive in vulnerable lab environments and requires investigation."),



    2049: ("NFS_EXPOSURE", "NFS Service Exposed", "MEDIUM", "Network File System access was detected."),



    3306: ("DATABASE_EXPOSURE", "MySQL Service Exposed", "HIGH", "A MySQL database service is reachable over the network."),



    3389: ("REMOTE_ACCESS_EXPOSURE", "Remote Desktop Service Exposed", "MEDIUM", "A Remote Desktop service is reachable on the target."),



    5432: ("DATABASE_EXPOSURE", "PostgreSQL Service Exposed", "HIGH", "A PostgreSQL database service is reachable over the network."),



    5900: ("REMOTE_ACCESS_EXPOSURE", "VNC Service Exposed", "HIGH", "A VNC remote desktop service is reachable on the target."),



    6000: ("X11_EXPOSURE", "X11 Service Exposed", "MEDIUM", "An X11 service was detected and increases remote attack surface."),



    6379: ("DATABASE_EXPOSURE", "Redis Service Exposed", "HIGH", "A Redis service is reachable over the network."),



    8009: ("APPLICATION_SERVICE_EXPOSURE", "AJP Service Exposed", "MEDIUM", "An Apache JServ Protocol service was detected."),



    27017: ("DATABASE_EXPOSURE", "MongoDB Service Exposed", "HIGH", "A MongoDB service is reachable over the network."),



}



COMMON_WEB_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8180, 8443, 8888}



WEB_SERVICE_NAMES = {"http", "https", "http-proxy", "http-alt", "https-alt", "ssl/http", "ssl/https"}



CONTEXT_ONLY_WEB_CATEGORIES = {"WEB_APPLICATION_SURFACE"}



SQL_ERROR_PATTERNS = (



    "sql syntax", "mysql_fetch", "mysqli_", "you have an error in your sql syntax",



    "unclosed quotation mark", "quoted string not properly terminated", "ora-01756",



    "postgresql query failed", "pg_query(", "sqlite error", "sqlite3.operationalerror",



    "microsoft ole db provider for sql server", "odbc sql server driver", "jdbc exception",



)



CSRF_TOKEN_HINTS = ("csrf", "xsrf", "authenticity_token", "requesttoken", "verificationtoken", "nonce")



IDOR_PARAMETER_HINTS = {"id", "uid", "user", "userid", "user_id", "account", "accountid", "account_id", "order", "orderid", "order_id", "record", "recordid", "record_id", "document", "doc", "file"}



class WebPageParser(HTMLParser):



    def __init__(self):



        super().__init__()



        self.links = []



        self.forms = []



        self._form = None



    def handle_starttag(self, tag, attrs):



        attrs = dict(attrs)



        tag = tag.lower()



        if tag == "a" and attrs.get("href"):



            self.links.append(attrs["href"])



        elif tag == "form":



            self._form = {"action": attrs.get("action", ""), "method": attrs.get("method", "get").lower(), "inputs": []}



        elif tag == "input" and self._form is not None:



            self._form["inputs"].append({"name": attrs.get("name"), "type": attrs.get("type", "text").lower(), "value": attrs.get("value", "")})



    def handle_endtag(self, tag):



        if tag.lower() == "form" and self._form is not None:



            self.forms.append(self._form)



            self._form = None



def analyze_security_findings(target, ports=None, services=None, os_detection=None, os_accuracy=None, created_by=None):



    """Central non-CVE analysis entry point used by routes/scan.py."""



    ports, services = normalize_list(ports), normalize_list(services)



    findings = []



    findings.extend(analyze_network_services(target, ports, services, created_by))



    findings.extend(analyze_application_services(target, services, created_by))



    findings.extend(analyze_host_security(target, ports, services, os_detection, os_accuracy, created_by))



    findings.extend(analyze_web_services(target, ports, services, created_by))



    return deduplicate_findings(findings)



def analyze_network_services(target, ports, services, created_by=None):



    """Record observable security-sensitive network/service exposure."""



    findings, service_index = [], build_service_index(services)



    for port_record in ports:



        if not isinstance(port_record, dict) or not is_open_port(port_record):



            continue



        port = normalize_port_number(port_record.get("port"))



        if port is None or port not in SENSITIVE_SERVICE_RULES:



            continue



        category, title, severity, description = SENSITIVE_SERVICE_RULES[port]



        service = service_index.get(port, {})



        name = first_value(service.get("name"), service.get("service"), port_record.get("service"))



        product = first_value(service.get("product"), port_record.get("product"))



        version = first_value(service.get("version"), port_record.get("version"))



        protocol = first_value(port_record.get("protocol"), "tcp")



        evidence = [f"{str(protocol).upper()}/{port} was observed open."]



        if name:



            evidence.append(f"Detected service: {name}.")



        if product:



            evidence.append(f"Detected product: {product}{' ' + str(version) if version else ''}.")



        findings.append(create_security_finding(



            finding_type="SERVICE", category=category, title=title, description=description,



            target=target, port=port, protocol=protocol, service=name, product=product, version=version,



            severity=severity, confidence="HIGH", status="OBSERVED", evidence=evidence,



            evidence_source="Nmap", metadata={"analysis_type": "service_exposure", "observed_open_port": True},



            created_by=created_by,



        ))



    return findings



def analyze_application_services(target, services, created_by=None):



    """Analyze discovered non-web and web-facing software without duplicating CVE lookup."""



    findings = []



    for service in services:



        if not isinstance(service, dict):



            continue



        port = normalize_port_number(service.get("port"))



        name = first_value(service.get("name"), service.get("service"))



        product = normalize_optional_text(service.get("product"))



        version = normalize_optional_text(service.get("version"))



        if product and not version:



            findings.append(create_security_finding(



                finding_type="APPLICATION", category="LIMITED_VERSION_EVIDENCE",



                title="Application Version Could Not Be Determined",



                description="A product was identified but its version could not be determined, limiting version-specific assessment.",



                target=target, port=port, service=name, product=product, severity="LOW", confidence="HIGH",



                status="OBSERVED", evidence=[f"Detected product: {product}.", "No product version was reported by Nmap."],



                evidence_source="Nmap", metadata={"analysis_type": "application_inventory", "version_detected": False},



                created_by=created_by,



            ))



    return findings



def analyze_host_security(target, ports, services, os_detection=None, os_accuracy=None, created_by=None):



    """Analyze host/OS context. This is not a credentialed local host audit."""



    findings = []



    os_name, accuracy = normalize_optional_text(os_detection), normalize_accuracy(os_accuracy)



    if os_name and accuracy is not None and accuracy < 80:



        findings.append(create_security_finding(



            finding_type="OS", category="LOW_CONFIDENCE_OS_DETECTION",



            title="Operating System Detection Has Limited Confidence",



            description="The OS fingerprint has limited accuracy; OS-specific conclusions should be treated conservatively.",



            target=target, operating_system=os_name, severity="LOW", confidence="HIGH", status="OBSERVED",



            evidence=[f"Detected OS: {os_name}.", f"Nmap OS detection accuracy: {accuracy}%."] ,



            evidence_source="Nmap", metadata={"analysis_type": "os_context", "os_accuracy": accuracy}, created_by=created_by,



        ))



    open_ports = sorted({p for p in (normalize_port_number(x.get("port")) for x in ports if isinstance(x, dict) and is_open_port(x)) if p is not None})



    if len(open_ports) >= 10:



        findings.append(create_security_finding(



            finding_type="HOST", category="LARGE_ATTACK_SURFACE", title="Large Network Attack Surface Observed",



            description="The host exposes a relatively large number of network services; this is an attack-surface observation, not proof each service is vulnerable.",



            target=target, operating_system=os_name, severity="MEDIUM", confidence="HIGH", status="OBSERVED",



            evidence=[f"{len(open_ports)} open network ports were observed.", "Observed ports: " + ", ".join(map(str, open_ports)) + "."],



            evidence_source="Nmap", metadata={"analysis_type": "host_attack_surface", "open_port_count": len(open_ports), "open_ports": open_ports},



            created_by=created_by,



        ))



    return findings



def analyze_web_services(target, ports, services, created_by=None):



    """Discover web surfaces and run bounded, non-destructive HTTP checks."""



    findings, service_index, seen = [], build_service_index(services), set()



    for port_record in ports:



        if not isinstance(port_record, dict) or not is_open_port(port_record):



            continue



        port = normalize_port_number(port_record.get("port"))



        if port is None:



            continue



        service = service_index.get(port, {})



        name = first_value(service.get("name"), service.get("service"), port_record.get("service"))



        normalized_name = normalize_key(name)



        if not (port in COMMON_WEB_PORTS or normalized_name in WEB_SERVICE_NAMES or "http" in normalized_name):



            continue



        key = (str(target), port)



        if key in seen:



            continue



        seen.add(key)



        product = first_value(service.get("product"), port_record.get("product"))



        version = first_value(service.get("version"), port_record.get("version"))



        protocol = first_value(port_record.get("protocol"), "tcp")



        scheme = determine_web_scheme(port, name)



        base_url = build_base_url(target, port, scheme)



        findings.append(create_security_finding(



            finding_type="APPLICATION", category="WEB_APPLICATION_SURFACE", title="Web Application Surface Detected",



            description="AttackLens detected an HTTP/HTTPS application surface. This records exposure and does not by itself claim a vulnerability.",



            target=target, port=port, protocol=protocol, service=name, product=product, version=version,



            endpoint=base_url, severity="LOW", confidence="HIGH", status="OBSERVED",



            evidence=[f"Web-capable service observed on port {port}."], evidence_source="Nmap",



            metadata={"analysis_type": "web_surface_discovery", "scheme": scheme, "active_web_testing": True}, created_by=created_by,



        ))



        findings.extend(run_bounded_web_checks(target, port, protocol, name, product, version, base_url, created_by))



    return findings



def run_bounded_web_checks(target, port, protocol, service, product, version, base_url, created_by=None):

    """Perform bounded, same-origin HTTP checks without authentication or state-changing requests."""

    findings = []

    first = fetch_url(base_url)

    if not first:

        return findings



    base_origin = urlparse(base_url)

    queue = [base_url]

    queued = {normalize_crawl_url(base_url)}

    responses = {normalize_crawl_url(base_url): first}

    visited = set()



    while queue and len(visited) < MAX_WEB_PAGES:

        page_url = queue.pop(0)

        page_key = normalize_crawl_url(page_url)

        if not page_key or page_key in visited:

            continue



        response = responses.pop(page_key, None) or fetch_url(page_url)

        if not response:

            visited.add(page_key)

            continue

        visited.add(page_key)



        findings.extend(analyze_http_response_security(

            target, port, protocol, service, product, version, page_url, response, created_by

        ))

        findings.extend(analyze_forms_for_csrf(

            target, port, service, product, version, page_url, response, created_by

        ))

        findings.extend(analyze_idor_candidates(

            target, port, service, product, version, page_url, created_by

        ))

        findings.extend(run_get_parameter_checks(

            target, port, service, product, version, page_url, response, created_by

        ))

        findings.extend(run_get_form_checks(

            target, port, service, product, version, page_url, response, created_by

        ))



        parser = parse_html(response.get("body", ""))

        for href in parser.links:

            candidate = normalize_crawl_url(urljoin(page_url, href))

            if not candidate or candidate in queued or candidate in visited:

                continue

            parsed = urlparse(candidate)

            if parsed.scheme not in {"http", "https"} or parsed.netloc != base_origin.netloc:

                continue

            queued.add(candidate)

            queue.append(candidate)

            if len(queued) >= MAX_WEB_PAGES:

                break



    return deduplicate_findings(findings)





def run_get_form_checks(target, port, service, product, version, page_url, response, created_by=None):

    """Build bounded GET requests from discovered GET forms and reuse the existing evidence checks."""

    findings = []

    parser = parse_html(response.get("body", ""))

    for form in parser.forms:

        if str(form.get("method", "get")).lower() != "get":

            continue

        action = urljoin(page_url, form.get("action") or page_url)

        if urlparse(action).netloc != urlparse(page_url).netloc:

            continue

        pairs = []

        for field in form.get("inputs", []):

            name = normalize_optional_text(field.get("name"))

            field_type = normalize_key(field.get("type"))

            if not name or field_type in {"submit", "button", "reset", "file", "image"}:

                continue

            pairs.append((name, field.get("value", "")))

            if len(pairs) >= MAX_PARAMETERS_PER_PAGE:

                break

        if not pairs:

            continue

        parsed = urlparse(action)

        existing = parse_qsl(parsed.query, keep_blank_values=True)

        form_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, urlencode(existing + pairs), ""))

        baseline = fetch_url(form_url)

        if not baseline:

            continue

        findings.extend(analyze_idor_candidates(target, port, service, product, version, form_url, created_by))

        findings.extend(run_get_parameter_checks(target, port, service, product, version, form_url, baseline, created_by))

    return findings



def normalize_crawl_url(url):

    """Normalize an HTTP(S) URL for bounded same-origin crawl deduplication."""

    try:

        parsed = urlparse(str(url or "").strip())

    except ValueError:

        return ""

    if parsed.scheme not in {"http", "https"} or not parsed.netloc:

        return ""

    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", parsed.query, ""))



def analyze_http_response_security(target, port, protocol, service, product, version, endpoint, response, created_by=None):



    findings = []



    if not isinstance(response, dict):
        return findings

    headers = response.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}

    lower = {str(k).lower(): str(v) for k, v in headers.items()}



    scheme = urlparse(endpoint).scheme.lower()



    # HTTPS requests currently use an unverified TLS context for lab
    # compatibility. Record this limitation rather than implying trust.
    if scheme == "https" and response.get("tls_certificate_verified") is False:
        findings.append(create_security_finding(
            finding_type="CONFIGURATION", category="TLS_CERTIFICATE_NOT_VERIFIED",
            title="TLS Certificate Trust Not Verified by Scanner",
            description="The scanner retrieved this HTTPS response without validating the server certificate. This is a scan limitation, not proof of a server vulnerability.",
            target=target, port=port, protocol=protocol, service=service,
            product=product, version=version, endpoint=endpoint,
            severity="LOW", confidence="HIGH", status="POTENTIAL",
            evidence=["HTTPS certificate chain and hostname were not verified by AttackLens."],
            evidence_source="Scanner transport configuration",
            metadata={"analysis_type": "scanner_limitation", "manual_verification_required": True},
            created_by=created_by,
        ))



    missing = []



    if "content-security-policy" not in lower:



        missing.append("Content-Security-Policy")



    if "x-content-type-options" not in lower:



        missing.append("X-Content-Type-Options")



    if "x-frame-options" not in lower and "frame-ancestors" not in lower.get("content-security-policy", "").lower():



        missing.append("X-Frame-Options/frame-ancestors")



    if scheme == "https" and "strict-transport-security" not in lower:



        missing.append("Strict-Transport-Security")



    if missing:



        findings.append(create_security_finding(



            finding_type="CONFIGURATION", category="MISSING_SECURITY_HEADERS", title="Recommended HTTP Security Headers Missing",



            description="The observed HTTP response is missing the specific defensive browser headers listed in the evidence. This does not imply all security headers are absent.", target=target, port=port,



            protocol=protocol, service=service, product=product, version=version, endpoint=endpoint,



            severity="LOW", confidence="HIGH", status="OBSERVED", evidence=["Missing headers: " + ", ".join(missing) + "."],



            evidence_source="HTTP response headers", metadata={"analysis_type": "web_configuration", "missing_headers": missing}, created_by=created_by,



        ))



    cookies = response.get("set_cookies") or []
    if not isinstance(cookies, (list, tuple)):
        cookies = [str(cookies)]

    for cookie in cookies[:10]:



        lc = cookie.lower()



        weaknesses = []



        if "httponly" not in lc:



            weaknesses.append("HttpOnly missing")



        if scheme == "https" and "secure" not in lc:



            weaknesses.append("Secure missing")



        if "samesite=" not in lc:



            weaknesses.append("SameSite missing")



        if weaknesses:



            cookie_name = cookie.split("=", 1)[0].strip() or "cookie"



            findings.append(create_security_finding(



                finding_type="CONFIGURATION", category="INSECURE_COOKIE_ATTRIBUTES", title="Cookie Security Attributes Missing",



                description="A response cookie is missing one or more recommended security attributes.", target=target, port=port,



                service=service, product=product, version=version, endpoint=endpoint, parameter=cookie_name,



                severity="LOW", confidence="HIGH", status="OBSERVED", evidence=[f"Cookie {cookie_name}: " + ", ".join(weaknesses) + "."],



                evidence_source="HTTP Set-Cookie header", metadata={"analysis_type": "web_configuration", "cookie_name": cookie_name, "weaknesses": weaknesses},



                created_by=created_by,



            ))



    return findings



def analyze_forms_for_csrf(target, port, service, product, version, page_url, response, created_by=None):



    parser = parse_html(response.get("body", ""))



    findings = []



    for form in parser.forms:



        if form.get("method", "get").lower() not in {"post", "put", "patch", "delete"}:



            continue



        names = {normalize_key(x.get("name")) for x in form.get("inputs", []) if x.get("name")}



        if any(any(hint in name for hint in CSRF_TOKEN_HINTS) for name in names):



            continue



        endpoint = urljoin(page_url, form.get("action") or page_url)



        findings.append(create_security_finding(



            finding_type="WEB", category="POTENTIAL_CSRF", title="Potential CSRF Protection Weakness",



            description="A state-changing form has no recognizable CSRF token field in the observed HTML. This passive check cannot determine whether server-side CSRF protection is enforced; manual verification is required.",



            target=target, port=port, service=service, product=product, version=version, endpoint=endpoint,



            method=form.get("method", "post").upper(), severity="MEDIUM", confidence="MEDIUM", status="POTENTIAL",



            evidence=["State-changing form detected.", "No recognizable CSRF token field was identified in the observed form markup.", "Server-side CSRF enforcement was not tested."],



            evidence_source="HTTP/HTML analysis", metadata={"analysis_type": "bounded_web_check", "manual_verification_required": True}, created_by=created_by,



        ))



    return findings



def analyze_idor_candidates(target, port, service, product, version, page_url, created_by=None):



    parsed = urlparse(page_url)



    findings = []



    for name, value in parse_qsl(parsed.query, keep_blank_values=True):



        if normalize_key(name) in IDOR_PARAMETER_HINTS and str(value).isdigit():



            findings.append(create_security_finding(



                finding_type="WEB", category="POTENTIAL_IDOR", title="Potential IDOR Candidate Requires Manual Verification",



                description="A direct numeric object identifier was observed in a request parameter. Authorization bypass is not proven and requires manual verification.",



                target=target, port=port, service=service, product=product, version=version, endpoint=page_url,



                method="GET", parameter=name, severity="MEDIUM", confidence="LOW", status="POTENTIAL",



                evidence=[f"Numeric object-like parameter observed: {name}={value}."], evidence_source="HTTP URL analysis",



                metadata={"analysis_type": "bounded_web_check", "manual_verification_required": True, "identifier_value": value}, created_by=created_by,



            ))



    return findings



def run_get_parameter_checks(target, port, service, product, version, page_url, baseline, created_by=None):



    """Limited GET-only SQLi/XSS probes. Never submits POST forms or mutates server state intentionally."""



    parsed = urlparse(page_url)



    params = parse_qsl(parsed.query, keep_blank_values=True)



    if not params:



        return []



    findings = []



    for index, (name, value) in enumerate(params[:MAX_PARAMETERS_PER_PAGE]):



        marker = "ALXSS29"



        xss_value = marker + "<svg>"



        xss_url = replace_query_parameter(page_url, name, xss_value)



        xss_response = fetch_url(xss_url)



        if xss_response and marker in xss_response.get("body", ""):



            body = xss_response.get("body", "")



            raw_reflection = xss_value in body or html.escape(xss_value, quote=False) in body



            findings.append(create_security_finding(



                finding_type="WEB", category="POTENTIAL_REFLECTED_XSS", title="Potential Reflected XSS Input Reflection",



                description="A controlled marker supplied through a GET parameter was reflected in the response. Reflection alone does not prove script execution.",



                target=target, port=port, service=service, product=product, version=version, endpoint=page_url,



                method="GET", parameter=name, severity="MEDIUM", confidence="MEDIUM" if raw_reflection else "LOW", status="POTENTIAL",



                evidence=[f"Controlled marker was reflected for parameter '{name}'.", "No browser script execution was attempted."],



                evidence_source="Bounded HTTP GET probe", metadata={"analysis_type": "bounded_web_check", "manual_verification_required": True}, created_by=created_by,



            ))



        sqli_value = str(value) + "'"



        sqli_url = replace_query_parameter(page_url, name, sqli_value)



        sqli_response = fetch_url(sqli_url)



        if sqli_response:



            base_body = baseline.get("body", "").lower()



            test_body = sqli_response.get("body", "").lower()



            new_errors = [p for p in SQL_ERROR_PATTERNS if p in test_body and p not in base_body]



            if new_errors:



                findings.append(create_security_finding(



                    finding_type="WEB", category="POTENTIAL_SQL_INJECTION", title="Potential SQL Injection Error Evidence",



                    description="A quote-based GET parameter probe produced database-error evidence not present in the baseline response. This is evidence of a potential SQL injection condition, not proof of exploitation.",



                    target=target, port=port, service=service, product=product, version=version, endpoint=page_url,



                    method="GET", parameter=name, severity="HIGH", confidence="HIGH", status="POTENTIAL",



                    evidence=[f"Database-error pattern appeared after probing parameter '{name}'.", f"Observed pattern: {new_errors[0]}."],



                    evidence_source="Bounded HTTP GET probe", metadata={"analysis_type": "bounded_web_check", "manual_verification_required": True}, created_by=created_by,



                ))



    return findings



def discover_web_pages(base_url, response):

    """Return bounded same-origin links from one response; retained for compatibility/tests."""

    parser = parse_html(response.get("body", ""))

    base = urlparse(base_url)

    pages = [normalize_crawl_url(base_url)]

    for href in parser.links:

        clean = normalize_crawl_url(urljoin(base_url, href))

        if not clean:

            continue

        parsed = urlparse(clean)

        if parsed.netloc != base.netloc or clean in pages:

            continue

        pages.append(clean)

        if len(pages) >= MAX_WEB_PAGES:

            break

    return pages



def fetch_url(url):



    try:



        request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"})



        context = ssl._create_unverified_context() if urlparse(url).scheme == "https" else None



        with urlopen(request, timeout=HTTP_TIMEOUT, context=context) as response:



            content_type = response.headers.get("Content-Type", "")



            raw = response.read(MAX_RESPONSE_BYTES)



            charset = response.headers.get_content_charset() or "utf-8"



            body = raw.decode(charset, errors="replace") if ("text" in content_type.lower() or "html" in content_type.lower() or not content_type) else ""



            return {"status": response.getcode(), "headers": dict(response.headers.items()), "set_cookies": response.headers.get_all("Set-Cookie") or [], "body": body, "url": response.geturl(), "tls_certificate_verified": False if urlparse(response.geturl()).scheme == "https" else None}



    except HTTPError as exc:



        try:



            raw = exc.read(MAX_RESPONSE_BYTES)



            body = raw.decode("utf-8", errors="replace")



        except Exception:



            body = ""



        return {"status": exc.code, "headers": dict(exc.headers.items()) if exc.headers else {}, "set_cookies": (exc.headers.get_all("Set-Cookie") or []) if exc.headers else [], "body": body, "url": url, "tls_certificate_verified": False if urlparse(url).scheme == "https" else None}



    except (URLError, TimeoutError, ValueError, OSError):



        return None



def parse_html(body):



    parser = WebPageParser()



    try:



        parser.feed(body or "")



    except Exception:



        pass



    return parser



def replace_query_parameter(url, parameter, new_value):



    parsed = urlparse(url)



    pairs = parse_qsl(parsed.query, keep_blank_values=True)



    replaced, done = [], False



    for name, value in pairs:



        if name == parameter and not done:



            replaced.append((name, new_value)); done = True



        else:



            replaced.append((name, value))



    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(replaced), parsed.fragment))



def build_base_url(target, port, scheme):



    target = str(target or "").strip()



    parsed = urlparse(target if "://" in target else f"{scheme}://{target}")



    host = parsed.hostname or target



    default_port = 443 if scheme == "https" else 80



    netloc = host if port == default_port else f"{host}:{port}"



    return urlunparse((scheme, netloc, "/", "", "", ""))



def build_service_index(services):



    index = {}



    for service in services:



        if isinstance(service, dict):



            port = normalize_port_number(service.get("port"))



            if port is not None:



                index[port] = service



    return index



def determine_web_scheme(port, service_name=None):



    name = normalize_key(service_name)



    return "https" if port in {443, 8443} or "https" in name or name.startswith("ssl/") else "http"



def is_open_port(port_record):



    if not isinstance(port_record, dict):



        return False



    state = port_record.get("state")



    return True if state is None else normalize_key(state) == "open"



def deduplicate_findings(findings):



    if not isinstance(findings, list):



        return []



    result, seen = [], set()



    for finding in findings:



        if not isinstance(finding, dict):



            continue



        key = (



            normalize_key(finding.get("finding_type")), normalize_key(finding.get("category")),



            normalize_key(finding.get("target")), normalize_port_number(finding.get("port")),



            normalize_key(finding.get("service")), normalize_key(finding.get("product")), normalize_key(finding.get("version")),



            normalize_key(finding.get("endpoint")), normalize_key(finding.get("method")), normalize_key(finding.get("parameter")),



            normalize_key(finding.get("title")),



        )



        if key not in seen:



            seen.add(key); result.append(finding)



    return result



def normalize_list(value):



    return value if isinstance(value, list) else []



def normalize_port_number(value):



    try:



        port = int(value)



        return port if 1 <= port <= 65535 else None



    except (TypeError, ValueError):



        return None



def normalize_accuracy(value):



    try:



        return max(0, min(100, int(value))) if value is not None else None



    except (TypeError, ValueError):



        return None



def normalize_optional_text(value):



    if value is None:



        return None



    value = str(value).strip()



    return value or None



def first_value(*values):



    for value in values:



        if value is None:



            continue



        if isinstance(value, str):



            value = value.strip()



            if not value:



                continue



        return value



    return None



def normalize_key(value):



    return "" if value is None else str(value).strip().lower()
