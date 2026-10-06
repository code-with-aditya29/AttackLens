import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET


# ==========================================
# CHECK NMAP INSTALLATION
# ==========================================

def check_nmap_installed():
    try:
        result = subprocess.run(
            ["nmap", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ==========================================
# GET NMAP COMMAND
# ==========================================

def get_nmap_command(target, scan_profile, output_file):
    """
    Build the Nmap command used by AttackLens.

    Profiles intentionally retain their original
    purpose while improving fingerprint quality.

    quick:
        Fast port/service discovery.

    standard:
        Normal vulnerability-assessment profile
        with OS and stronger version detection.

    detailed:
        Strongest service fingerprinting profile
        used for controlled lab assessment.
    """

    # ======================================
    # QUICK SCAN
    # ======================================

    if scan_profile == "quick":
        return [
            "nmap",
            "-F",
            "-sV",
            "--version-intensity",
            "5",
            "-oX",
            output_file,
            target
        ]

    # ======================================
    # DETAILED SCAN
    # ======================================

    if scan_profile == "detailed":
        return [
            "nmap",
            "-sV",
            "--version-all",
            "-O",
            "-Pn",
            "-oX",
            output_file,
            target
        ]

    # ======================================
    # STANDARD SCAN
    # ======================================

    return [
        "nmap",
        "-sV",
        "--version-intensity",
        "7",
        "-O",
        "-oX",
        output_file,
        target
    ]


# ==========================================
# RUN NMAP SCAN
# ==========================================

def run_nmap_scan(target, scan_profile):
    # ======================================
    # CHECK NMAP
    # ======================================

    if not check_nmap_installed():
        return {
            "success": False,
            "message": (
                "Nmap is not installed or "
                "not available in PATH."
            )
        }

    temp_file = None

    try:
        # ==================================
        # CREATE TEMP XML FILE
        # ==================================

        temp_file = tempfile.NamedTemporaryFile(
            suffix=".xml",
            delete=False
        )

        output_file = temp_file.name
        temp_file.close()

        # ==================================
        # BUILD NMAP COMMAND
        # ==================================

        command = get_nmap_command(
            target=target,
            scan_profile=scan_profile,
            output_file=output_file
        )

        # ==================================
        # RUN NMAP
        # ==================================

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300
        )

        # ==================================
        # CHECK XML OUTPUT
        # ==================================

        if not os.path.exists(output_file):
            return {
                "success": False,
                "message": (
                    "Nmap did not generate "
                    "scan results."
                )
            }

        # ==================================
        # PARSE NMAP RESULTS
        # ==================================

        scan_results = parse_nmap_xml(output_file)

        # ==================================
        # HANDLE NMAP ERROR
        # ==================================

        if result.returncode not in [0, 1]:
            scan_results["success"] = False
            scan_results["message"] = (
                result.stderr.strip()
                or
                "Nmap scan failed."
            )
            return scan_results

        # ==================================
        # SUCCESS
        # ==================================

        scan_results["success"] = True
        scan_results["message"] = (
            "Nmap scan completed successfully."
        )

        return scan_results

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "message": (
                "Scan timed out. The target may "
                "be unreachable or taking too "
                "long to respond."
            )
        }

    except Exception as error:
        return {
            "success": False,
            "message": (
                f"Nmap scan failed: {str(error)}"
            )
        }

    finally:
        # ==================================
        # REMOVE TEMP XML FILE
        # ==================================

        if temp_file:
            try:
                if os.path.exists(temp_file.name):
                    os.remove(temp_file.name)
            except Exception:
                pass


# ==========================================
# PARSE NMAP XML
# ==========================================

def parse_nmap_xml(xml_file):
    """
    Parse Nmap XML into the normalized AttackLens
    scan structure.

    Important:
    This parser preserves the existing fields used
    by AttackLens while also retaining richer Nmap
    fingerprint evidence such as:

        service CPE
        service vendor
        extra information
        service tunnel
        detection method
        detection confidence
        OS CPE
        OS class information

    CPE information is evidence only. This service
    does not determine whether a CVE is applicable.
    """

    results = {
        # ==================================
        # HOST INFORMATION
        # ==================================

        "hostname": None,
        "host_status": "unknown",
        "mac_address": None,

        # ==================================
        # NETWORK INFORMATION
        # ==================================

        "ports": [],
        "services": [],

        # ==================================
        # OS INFORMATION
        # ==================================

        "os_detection": None,
        "os_accuracy": None,

        # Rich OS evidence for downstream use.
        "os_cpes": [],
        "os_classes": [],
        "os_matches": []
    }

    # ======================================
    # LOAD XML
    # ======================================

    tree = ET.parse(xml_file)
    root = tree.getroot()

    # ======================================
    # GET FIRST HOST
    # ======================================

    host = root.find("host")

    if host is None:
        return results

    # ======================================
    # HOST STATUS
    # ======================================

    status = host.find("status")

    if status is not None:
        results["host_status"] = clean_text(
            status.get("state")
        ) or "unknown"

    # ======================================
    # HOSTNAME
    # ======================================

    hostname = host.find("./hostnames/hostname")

    if hostname is not None:
        results["hostname"] = clean_text(
            hostname.get("name")
        )

    # ======================================
    # MAC ADDRESS
    # ======================================

    addresses = host.findall("address")

    for address in addresses:
        if address.get("addrtype") == "mac":
            results["mac_address"] = clean_text(
                address.get("addr")
            )
            break

    # ======================================
    # OPEN PORTS
    # ======================================

    ports = host.findall("./ports/port")

    for port in ports:
        state_element = port.find("state")
        service_element = port.find("service")

        port_state = (
            clean_text(state_element.get("state"))
            if state_element is not None
            else "unknown"
        )

        # Only save open ports.
        if port_state != "open":
            continue

        port_number = safe_int(
            port.get("portid")
        )

        if port_number is None:
            continue

        protocol = clean_text(
            port.get("protocol")
        )

        # ==================================
        # SERVICE INFORMATION
        # ==================================

        service_data = parse_service_element(
            service_element
        )

        service_name = service_data["name"]
        product = service_data["product"]
        version = service_data["version"]

        # ==================================
        # PORT DATA
        # ==================================

        port_data = {
            # Existing fields.
            "port": port_number,
            "protocol": protocol,
            "state": port_state,
            "service": service_name,
            "product": product,
            "version": version,

            # Rich service evidence.
            "vendor": service_data["vendor"],
            "extrainfo": service_data["extrainfo"],
            "hostname": service_data["hostname"],
            "ostype": service_data["ostype"],
            "devicetype": service_data["devicetype"],
            "tunnel": service_data["tunnel"],
            "service_method": service_data["method"],
            "service_conf": service_data["conf"],
            "cpe": service_data["cpe"],
            "cpes": service_data["cpes"]
        }

        results["ports"].append(port_data)

        # ==================================
        # SERVICE DATA
        # ==================================

        results["services"].append({
            # Existing fields.
            "port": port_number,
            "name": service_name,
            "product": product,
            "version": version,

            # Useful compatibility aliases.
            "service": service_name,
            "protocol": protocol,
            "state": port_state,

            # Rich fingerprint evidence.
            "vendor": service_data["vendor"],
            "extrainfo": service_data["extrainfo"],
            "hostname": service_data["hostname"],
            "ostype": service_data["ostype"],
            "devicetype": service_data["devicetype"],
            "tunnel": service_data["tunnel"],
            "method": service_data["method"],
            "conf": service_data["conf"],
            "cpe": service_data["cpe"],
            "cpes": service_data["cpes"]
        })

    # ======================================
    # OPERATING SYSTEM DETECTION
    # ======================================

    parse_os_information(
        host=host,
        results=results
    )

    return results


# ==========================================
# PARSE SERVICE ELEMENT
# ==========================================

def parse_service_element(service_element):
    """
    Extract service fingerprint information from
    an Nmap <service> element.

    Nmap can provide considerably more evidence
    than product/version alone. Preserve that
    evidence for CVE applicability and reporting.
    """

    empty_result = {
        "name": None,
        "product": None,
        "version": None,
        "vendor": None,
        "extrainfo": None,
        "hostname": None,
        "ostype": None,
        "devicetype": None,
        "tunnel": None,
        "method": None,
        "conf": None,
        "cpe": None,
        "cpes": []
    }

    if service_element is None:
        return empty_result

    service_name = clean_text(
        service_element.get("name")
    )

    product = clean_text(
        service_element.get("product")
    )

    version = clean_text(
        service_element.get("version")
    )

    extrainfo = clean_text(
        service_element.get("extrainfo")
    )

    service_hostname = clean_text(
        service_element.get("hostname")
    )

    ostype = clean_text(
        service_element.get("ostype")
    )

    devicetype = clean_text(
        service_element.get("devicetype")
    )

    tunnel = clean_text(
        service_element.get("tunnel")
    )

    method = clean_text(
        service_element.get("method")
    )

    conf = normalize_confidence(
        service_element.get("conf")
    )

    # ======================================
    # SERVICE CPES
    # ======================================

    cpes = []

    for cpe_element in service_element.findall("cpe"):
        cpe_value = normalize_cpe(
            cpe_element.text
        )

        if cpe_value and cpe_value not in cpes:
            cpes.append(cpe_value)

    primary_cpe = choose_primary_cpe(
        cpes=cpes,
        preferred_part="a"
    )

    # ======================================
    # VENDOR FROM CPE
    # ======================================

    vendor = extract_cpe_vendor(
        primary_cpe
    )

    return {
        "name": service_name,
        "product": product,
        "version": version,
        "vendor": vendor,
        "extrainfo": extrainfo,
        "hostname": service_hostname,
        "ostype": ostype,
        "devicetype": devicetype,
        "tunnel": tunnel,
        "method": method,
        "conf": conf,
        "cpe": primary_cpe,
        "cpes": cpes
    }


# ==========================================
# PARSE OS INFORMATION
# ==========================================

def parse_os_information(host, results):
    """
    Preserve the original os_detection/os_accuracy
    contract while retaining richer OS matches,
    classes and CPE evidence.
    """

    if host is None or not isinstance(results, dict):
        return

    os_matches = host.findall("./os/osmatch")

    parsed_matches = []
    all_os_classes = []
    all_os_cpes = []

    for os_match in os_matches:
        match_name = clean_text(
            os_match.get("name")
        )

        match_accuracy = normalize_confidence(
            os_match.get("accuracy")
        )

        match_line = safe_int(
            os_match.get("line")
        )

        match_classes = []

        for os_class in os_match.findall("osclass"):
            class_cpes = []

            for cpe_element in os_class.findall("cpe"):
                cpe_value = normalize_cpe(
                    cpe_element.text
                )

                if (
                    cpe_value
                    and
                    cpe_value not in class_cpes
                ):
                    class_cpes.append(cpe_value)

                if (
                    cpe_value
                    and
                    cpe_value not in all_os_cpes
                ):
                    all_os_cpes.append(cpe_value)

            class_data = {
                "type": clean_text(
                    os_class.get("type")
                ),
                "vendor": clean_text(
                    os_class.get("vendor")
                ),
                "osfamily": clean_text(
                    os_class.get("osfamily")
                ),
                "osgen": clean_text(
                    os_class.get("osgen")
                ),
                "accuracy": normalize_confidence(
                    os_class.get("accuracy")
                ),
                "cpe": choose_primary_cpe(
                    cpes=class_cpes,
                    preferred_part="o"
                ),
                "cpes": class_cpes
            }

            match_classes.append(class_data)
            all_os_classes.append(class_data)

        parsed_matches.append({
            "name": match_name,
            "accuracy": match_accuracy,
            "line": match_line,
            "os_classes": match_classes
        })

    # ======================================
    # PRIMARY OS MATCH
    # ======================================

    if parsed_matches:
        # Nmap normally returns strongest matches
        # first, but explicitly select the highest
        # reported accuracy when possible.
        primary_match = max(
            parsed_matches,
            key=lambda item: (
                item.get("accuracy")
                if isinstance(
                    item.get("accuracy"),
                    int
                )
                else -1
            )
        )

        results["os_detection"] = (
            primary_match.get("name")
        )

        results["os_accuracy"] = (
            primary_match.get("accuracy")
        )

    results["os_matches"] = parsed_matches
    results["os_classes"] = deduplicate_os_classes(
        all_os_classes
    )
    results["os_cpes"] = deduplicate_strings(
        all_os_cpes
    )


# ==========================================
# CPE NORMALIZATION
# ==========================================

def normalize_cpe(value):
    """
    Normalize a CPE emitted by Nmap.

    Nmap commonly emits CPE 2.3 URI binding style:

        cpe:/a:vendor:product:version

    NVD primarily uses formatted CPE 2.3 strings:

        cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*

    AttackLens converts the common Nmap URI form
    into CPE 2.3 format so downstream services
    receive a consistent representation.

    Existing CPE 2.3 strings are retained.
    """

    value = clean_text(value)

    if not value:
        return None

    if value.startswith("cpe:2.3:"):
        return value

    if not value.startswith("cpe:/"):
        return value

    body = value[len("cpe:/"):]
    parts = body.split(":")

    # CPE URI binding:
    # part:vendor:product:version:update:edition:language
    while len(parts) < 7:
        parts.append("*")

    part = normalize_cpe_component(
        parts[0] if len(parts) > 0 else "*"
    )
    vendor = normalize_cpe_component(
        parts[1] if len(parts) > 1 else "*"
    )
    product = normalize_cpe_component(
        parts[2] if len(parts) > 2 else "*"
    )
    version = normalize_cpe_component(
        parts[3] if len(parts) > 3 else "*"
    )
    update = normalize_cpe_component(
        parts[4] if len(parts) > 4 else "*"
    )
    edition = normalize_cpe_component(
        parts[5] if len(parts) > 5 else "*"
    )
    language = normalize_cpe_component(
        parts[6] if len(parts) > 6 else "*"
    )

    # CPE 2.3 requires 11 components after cpe:2.3.
    return (
        "cpe:2.3:"
        f"{part}:"
        f"{vendor}:"
        f"{product}:"
        f"{version}:"
        f"{update}:"
        f"{edition}:"
        f"{language}:"
        "*:*:*:*"
    )


# ==========================================
# NORMALIZE CPE COMPONENT
# ==========================================

def normalize_cpe_component(value):
    if value is None:
        return "*"

    value = str(value).strip()

    if value in ("", "-", "*"):
        return value or "*"

    return value


# ==========================================
# CHOOSE PRIMARY CPE
# ==========================================

def choose_primary_cpe(cpes, preferred_part=None):
    """
    Choose a stable primary CPE while retaining the
    complete CPE list separately.

    For service fingerprints, application CPEs are
    preferred. For OS fingerprints, OS CPEs are
    preferred.
    """

    if not isinstance(cpes, list):
        return None

    valid_cpes = [
        cpe
        for cpe in cpes
        if isinstance(cpe, str) and cpe.strip()
    ]

    if not valid_cpes:
        return None

    if preferred_part:
        prefix = f"cpe:2.3:{preferred_part}:"

        for cpe in valid_cpes:
            if cpe.startswith(prefix):
                return cpe

    return valid_cpes[0]


# ==========================================
# EXTRACT CPE VENDOR
# ==========================================

def extract_cpe_vendor(cpe):
    """
    Extract the vendor component from a normalized
    CPE 2.3 string.
    """

    if not cpe:
        return None

    cpe = str(cpe).strip()

    if not cpe.startswith("cpe:2.3:"):
        return None

    parts = cpe.split(":")

    if len(parts) <= 3:
        return None

    vendor = parts[3].strip()

    if vendor in ("", "*", "-"):
        return None

    return vendor


# ==========================================
# NORMALIZE CONFIDENCE
# ==========================================

def normalize_confidence(value):
    """
    Convert Nmap confidence/accuracy fields to an
    integer when possible.

    Service 'conf' is normally 0-10.
    OS accuracy is normally 0-100.
    """

    if value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return clean_text(value)


# ==========================================
# SAFE INTEGER
# ==========================================

def safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# ==========================================
# CLEAN TEXT
# ==========================================

def clean_text(value):
    if value is None:
        return None

    value = str(value).strip()

    return value or None


# ==========================================
# DEDUPLICATE STRINGS
# ==========================================

def deduplicate_strings(values):
    if not isinstance(values, list):
        return []

    output = []
    seen = set()

    for value in values:
        value = clean_text(value)

        if not value:
            continue

        if value in seen:
            continue

        seen.add(value)
        output.append(value)

    return output


# ==========================================
# DEDUPLICATE OS CLASSES
# ==========================================

def deduplicate_os_classes(classes):
    if not isinstance(classes, list):
        return []

    output = []
    seen = set()

    for item in classes:
        if not isinstance(item, dict):
            continue

        key = (
            clean_text(item.get("type")),
            clean_text(item.get("vendor")),
            clean_text(item.get("osfamily")),
            clean_text(item.get("osgen")),
            item.get("accuracy"),
            clean_text(item.get("cpe"))
        )

        if key in seen:
            continue

        seen.add(key)
        output.append(item)

    return output