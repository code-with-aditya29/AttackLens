import subprocess
import xml.etree.ElementTree as ET


# ==========================================
# CHECK NMAP INSTALLATION
# ==========================================

def check_nmap_installed():

    try:

        result = subprocess.run(

            [
                "nmap",
                "--version"
            ],

            capture_output=True,

            text=True,

            timeout=10

        )

        return result.returncode == 0

    except (
        FileNotFoundError,
        subprocess.TimeoutExpired
    ):

        return False


# ==========================================
# GET NMAP COMMAND
# ==========================================

def get_nmap_command(
    target,
    scan_profile
):

    base_command = [

        "nmap",

        "-oX",
        "-",

        "--reason"

    ]


    # ======================================
    # QUICK SCAN
    # ======================================

    if scan_profile == "quick":

        return base_command + [

            "-T3",

            "-F",

            target

        ]


    # ======================================
    # STANDARD SCAN
    # ======================================

    if scan_profile == "standard":

        return base_command + [

            "-T3",

            "-sT",

            "-sV",

            target

        ]


    # ======================================
    # DETAILED SCAN
    # ======================================

    if scan_profile == "detailed":

        return base_command + [

            "-T3",

            "-sT",

            "-sV",

            "-O",

            target

        ]


    # ======================================
    # INVALID PROFILE
    # ======================================

    raise ValueError(

        "Invalid scan profile."

    )


# ==========================================
# PARSE NMAP XML RESULTS
# ==========================================

def parse_nmap_results(
    xml_output
):

    results = {

        "ports": [],

        "services": [],

        "os_detection": None

    }


    try:

        root = ET.fromstring(

            xml_output

        )

    except ET.ParseError:

        raise ValueError(

            "Unable to parse Nmap scan results."

        )


    # ======================================
    # FIND HOST
    # ======================================

    host = root.find(

        "host"

    )


    if host is None:

        return results


    # ======================================
    # PARSE OPEN PORTS
    # ======================================

    ports_element = host.find(

        "ports"

    )


    if ports_element is not None:

        for port in ports_element.findall(

            "port"

        ):

            state_element = port.find(

                "state"

            )


            if state_element is None:

                continue


            state = state_element.get(

                "state"

            )


            # Only save open ports

            if state != "open":

                continue


            port_id = port.get(

                "portid"

            )


            protocol = port.get(

                "protocol"

            )


            service_element = port.find(

                "service"

            )


            service_name = None

            product = None

            version = None


            if service_element is not None:

                service_name = service_element.get(

                    "name"

                )


                product = service_element.get(

                    "product"

                )


                version = service_element.get(

                    "version"

                )


            # ==============================
            # PORT DATA
            # ==============================

            port_data = {

                "port": int(

                    port_id

                ),

                "protocol": protocol,

                "state": state

            }


            results["ports"].append(

                port_data

            )


            # ==============================
            # SERVICE DATA
            # ==============================

            service_data = {

                "port": int(

                    port_id

                ),

                "protocol": protocol,

                "service": service_name,

                "product": product,

                "version": version

            }


            results["services"].append(

                service_data

            )


    # ======================================
    # PARSE OS DETECTION
    # ======================================

    os_element = host.find(

        "os"

    )


    if os_element is not None:

        os_matches = os_element.findall(

            "osmatch"

        )


        if os_matches:

            best_match = os_matches[0]


            results["os_detection"] = {

                "name": best_match.get(

                    "name"

                ),

                "accuracy": best_match.get(

                    "accuracy"

                )

            }


    return results


# ==========================================
# RUN NMAP SCAN
# ==========================================

def run_nmap_scan(
    target,
    scan_profile
):

    if not check_nmap_installed():

        raise RuntimeError(

            "Nmap is not installed or is not available in the system PATH."

        )


    command = get_nmap_command(

        target=target,

        scan_profile=scan_profile

    )


    try:

        # ==================================
        # EXECUTE NMAP
        # ==================================

        result = subprocess.run(

            command,

            capture_output=True,

            text=True,

            timeout=300

        )


        # ==================================
        # CHECK EXECUTION ERROR
        # ==================================

        if not result.stdout:

            error_message = result.stderr.strip()


            if not error_message:

                error_message = (

                    "Nmap did not return any scan results."

                )


            raise RuntimeError(

                error_message

            )


        # ==================================
        # PARSE XML RESULTS
        # ==================================

        scan_results = parse_nmap_results(

            result.stdout

        )


        return scan_results


    except subprocess.TimeoutExpired:

        raise RuntimeError(

            "The scan exceeded the maximum allowed execution time."

        )


    except FileNotFoundError:

        raise RuntimeError(

            "Nmap executable was not found."

        )