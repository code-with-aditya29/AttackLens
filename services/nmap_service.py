import subprocess
import xml.etree.ElementTree as ET
import tempfile
import os


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
    scan_profile,
    output_file
):

    # ======================================
    # QUICK SCAN
    # ======================================

    if scan_profile == "quick":

        return [

            "nmap",

            "-F",

            "-sV",

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

        "-O",

        "-oX",

        output_file,

        target

    ]


# ==========================================
# RUN NMAP SCAN
# ==========================================

def run_nmap_scan(
    target,
    scan_profile
):

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

        if not os.path.exists(

            output_file

        ):

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

        scan_results = parse_nmap_xml(

            output_file

        )


        # ==================================
        # HANDLE NMAP ERROR
        # ==================================

        if result.returncode not in [

            0,

            1

        ]:

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

                if os.path.exists(

                    temp_file.name

                ):

                    os.remove(

                        temp_file.name

                    )

            except Exception:

                pass


# ==========================================
# PARSE NMAP XML
# ==========================================

def parse_nmap_xml(
    xml_file
):

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

        "os_accuracy": None

    }


    # ======================================
    # LOAD XML
    # ======================================

    tree = ET.parse(

        xml_file

    )


    root = tree.getroot()


    # ======================================
    # GET FIRST HOST
    # ======================================

    host = root.find(

        "host"

    )


    if host is None:

        return results


    # ======================================
    # HOST STATUS
    # ======================================

    status = host.find(

        "status"

    )


    if status is not None:

        results["host_status"] = (

            status.get(

                "state",

                "unknown"

            )

        )


    # ======================================
    # HOSTNAME
    # ======================================

    hostname = host.find(

        "./hostnames/hostname"

    )


    if hostname is not None:

        results["hostname"] = (

            hostname.get(

                "name"

            )

        )


    # ======================================
    # MAC ADDRESS
    # ======================================

    addresses = host.findall(

        "address"

    )


    for address in addresses:

        if address.get(

            "addrtype"

        ) == "mac":

            results["mac_address"] = (

                address.get(

                    "addr"

                )

            )


            break


    # ======================================
    # OPEN PORTS
    # ======================================

    ports = host.findall(

        "./ports/port"

    )


    for port in ports:

        state_element = port.find(

            "state"

        )


        service_element = port.find(

            "service"

        )


        port_state = (

            state_element.get(

                "state"

            )

            if state_element is not None

            else "unknown"

        )


        # Only save open ports

        if port_state != "open":

            continue


        # ==================================
        # SERVICE INFORMATION
        # ==================================

        service_name = None

        product = None

        version = None


        if service_element is not None:

            service_name = (

                service_element.get(

                    "name"

                )

            )


            product = (

                service_element.get(

                    "product"

                )

            )


            version = (

                service_element.get(

                    "version"

                )

            )


        # ==================================
        # PORT DATA
        # ==================================

        port_data = {

            "port": int(

                port.get(

                    "portid"

                )

            ),

            "protocol": port.get(

                "protocol"

            ),

            "state": port_state,

            "service": service_name,

            "product": product,

            "version": version

        }


        results["ports"].append(

            port_data

        )


        # ==================================
        # SERVICE DATA
        # ==================================

        results["services"].append({

            "port": int(

                port.get(

                    "portid"

                )

            ),

            "name": service_name,

            "product": product,

            "version": version

        })


    # ======================================
    # OPERATING SYSTEM DETECTION
    # ======================================

    os_match = host.find(

        "./os/osmatch"

    )


    if os_match is not None:

        results["os_detection"] = (

            os_match.get(

                "name"

            )

        )


        accuracy = os_match.get(

            "accuracy"

        )


        if accuracy:

            try:

                results["os_accuracy"] = (

                    int(

                        accuracy

                    )

                )

            except ValueError:

                results["os_accuracy"] = (

                    accuracy

                )


    return results