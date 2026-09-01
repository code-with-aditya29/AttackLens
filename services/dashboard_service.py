# ==========================================
# DASHBOARD SERVICE
# ==========================================
#
# This service prepares security statistics
# for the AttackLens dashboard.
#
# IMPORTANT:
#
# The dashboard uses the "assets" collection
# because an Asset represents the CURRENT
# state of a discovered system.
#
# Scan records are historical events and
# therefore should not be counted directly
# when calculating the current security
# posture.
# ==========================================


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
# GET DASHBOARD STATISTICS
# ==========================================

def get_dashboard_stats(
    db,
    created_by=None
):
    """
    Build the current AttackLens dashboard
    statistics from the Asset Inventory.

    Parameters
    ----------
    db:
        MongoDB database instance.

    created_by:
        Optional owner identifier.

        When provided, only assets belonging
        to that user are included.

        When None, all assets are included.
        This can later be used for a Super
        Admin/global dashboard if required.

    Returns
    -------
    dict
        Dashboard statistics.
    """

    # ======================================
    # BUILD OWNERSHIP FILTER
    # ======================================

    query = {}

    if created_by is not None:

        query["created_by"] = created_by


    # ======================================
    # LOAD CURRENT ASSETS
    # ======================================

    try:

        assets = list(
            db.assets.find(
                query
            )
        )

    except Exception as error:

        print(
            "Dashboard statistics warning: "
            f"{error}"
        )

        return get_empty_dashboard_stats()


    # ======================================
    # INITIAL STATISTICS
    # ======================================

    total_assets = len(
        assets
    )

    open_services = 0

    open_ports = 0

    vulnerable_assets = 0

    total_vulnerabilities = 0

    high_risk_assets = 0

    critical_risk_assets = 0

    highest_risk_score = None

    highest_risk_level = "UNKNOWN"


    # ======================================
    # PROCESS ASSETS
    # ======================================

    for asset in assets:

        # ==================================
        # OPEN PORTS
        # ==================================

        asset_ports = normalize_list(
            asset.get(
                "ports"
            )
        )

        current_open_ports = get_open_ports(
            asset_ports
        )

        open_ports += len(
            current_open_ports
        )


        # ==================================
        # OPEN SERVICES
        # ==================================

        asset_services = normalize_list(
            asset.get(
                "services"
            )
        )

        open_services += count_open_services(
            asset_services,
            current_open_ports
        )


        # ==================================
        # VULNERABILITIES
        # ==================================

        vulnerabilities = normalize_list(
            asset.get(
                "vulnerabilities"
            )
        )

        vulnerability_count = get_vulnerability_count(
            asset,
            vulnerabilities
        )

        total_vulnerabilities += (
            vulnerability_count
        )

        if vulnerability_count > 0:

            vulnerable_assets += 1


        # ==================================
        # RISK INFORMATION
        # ==================================

        risk_score = normalize_risk_score(
            asset.get(
                "risk_score"
            )
        )

        risk_level = normalize_risk_level(
            asset.get(
                "risk_level"
            )
        )


        # ==================================
        # HIGH / CRITICAL RISK ASSETS
        # ==================================

        if risk_level == "HIGH":

            high_risk_assets += 1

        elif risk_level == "CRITICAL":

            critical_risk_assets += 1


        # ==================================
        # OVERALL DASHBOARD RISK
        # ==================================
        #
        # For the current baseline,
        # AttackLens uses the HIGHEST
        # current asset risk score as the
        # environment-level dashboard risk.
        #
        # This avoids hiding a dangerous
        # asset behind an average score.
        # ==================================

        if risk_score is not None:

            if (
                highest_risk_score is None
                or
                risk_score > highest_risk_score
            ):

                highest_risk_score = (
                    risk_score
                )

                highest_risk_level = (
                    risk_level
                )

            elif (
                risk_score
                ==
                highest_risk_score
            ):

                # If two assets have the
                # same score, retain the
                # more severe risk level.

                if (
                    RISK_LEVEL_ORDER.get(
                        risk_level,
                        0
                    )
                    >
                    RISK_LEVEL_ORDER.get(
                        highest_risk_level,
                        0
                    )
                ):

                    highest_risk_level = (
                        risk_level
                    )


    # ======================================
    # NORMALIZE EMPTY RISK STATE
    # ======================================

    if highest_risk_score is None:

        highest_risk_level = None


    # ======================================
    # ATTACK PATHS
    # ======================================
    #
    # Attack Path Engine has not yet been
    # implemented.
    #
    # Do NOT fabricate attack paths.
    #
    # Once the Attack Path Engine is added,
    # this value will be replaced with real
    # generated path data.
    # ======================================

    attack_paths = 0


    # ======================================
    # RETURN DASHBOARD DATA
    # ======================================

    return {

        "total_assets": total_assets,

        "open_services": open_services,

        "open_ports": open_ports,

        "vulnerable_assets": (
            vulnerable_assets
        ),

        "total_vulnerabilities": (
            total_vulnerabilities
        ),

        "high_risk_assets": (
            high_risk_assets
        ),

        "critical_risk_assets": (
            critical_risk_assets
        ),

        "risk_score": (
            highest_risk_score
        ),

        "risk_level": (
            highest_risk_level
        ),

        "attack_paths": (
            attack_paths
        )
    }


# ==========================================
# GET EMPTY DASHBOARD STATISTICS
# ==========================================

def get_empty_dashboard_stats():
    """
    Return a safe empty dashboard structure.

    This prevents the dashboard template from
    failing if MongoDB statistics cannot be
    loaded.
    """

    return {

        "total_assets": 0,

        "open_services": 0,

        "open_ports": 0,

        "vulnerable_assets": 0,

        "total_vulnerabilities": 0,

        "high_risk_assets": 0,

        "critical_risk_assets": 0,

        "risk_score": None,

        "risk_level": None,

        "attack_paths": 0
    }


# ==========================================
# NORMALIZE LIST
# ==========================================

def normalize_list(
    value
):
    """
    Return the value when it is a list.

    Invalid or missing values are converted
    to an empty list.
    """

    if isinstance(
        value,
        list
    ):

        return value

    return []


# ==========================================
# GET OPEN PORTS
# ==========================================

def get_open_ports(
    ports
):
    """
    Return only ports whose current state
    is OPEN.
    """

    open_port_records = []

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

        if state == "open":

            open_port_records.append(
                port
            )

    return open_port_records


# ==========================================
# COUNT OPEN SERVICES
# ==========================================

def count_open_services(
    services,
    open_ports
):
    """
    Count services associated with currently
    open ports.

    The scan service records normally contain
    the service port number, allowing the
    dashboard to avoid counting services from
    closed ports.

    If no usable port relationship exists,
    only valid service records are counted.
    """

    if not services:

        return 0


    # ======================================
    # BUILD OPEN PORT NUMBER SET
    # ======================================

    open_port_numbers = set()

    for port in open_ports:

        if not isinstance(
            port,
            dict
        ):

            continue

        port_number = normalize_port_number(
            port.get(
                "port"
            )
        )

        if port_number is not None:

            open_port_numbers.add(
                port_number
            )


    # ======================================
    # COUNT SERVICES
    # ======================================

    service_count = 0

    seen_services = set()


    for service in services:

        if not isinstance(
            service,
            dict
        ):

            continue


        service_port = normalize_port_number(
            service.get(
                "port"
            )
        )

        service_name = str(
            service.get(
                "name",
                ""
            )
        ).strip().lower()


        # ==================================
        # REQUIRE A MEANINGFUL SERVICE
        # ==================================

        if (
            service_port is None
            and
            not service_name
        ):

            continue


        # ==================================
        # CHECK OPEN PORT RELATIONSHIP
        # ==================================

        if open_port_numbers:

            if (
                service_port
                not in
                open_port_numbers
            ):

                continue


        # ==================================
        # DEDUPLICATE SERVICE
        # ==================================

        service_key = (
            service_port,
            service_name
        )

        if service_key in seen_services:

            continue

        seen_services.add(
            service_key
        )

        service_count += 1


    return service_count


# ==========================================
# NORMALIZE PORT NUMBER
# ==========================================

def normalize_port_number(
    value
):
    """
    Convert a port value into an integer when
    possible.
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
# GET VULNERABILITY COUNT
# ==========================================

def get_vulnerability_count(
    asset,
    vulnerabilities
):
    """
    Determine the current vulnerability
    count for an asset.

    The stored vulnerability_count is used
    when valid.

    The vulnerability list is used as a safe
    fallback.
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


    return len(
        vulnerabilities
    )


# ==========================================
# NORMALIZE RISK SCORE
# ==========================================

def normalize_risk_score(
    value
):
    """
    Normalize a stored risk score into the
    AttackLens 0-100 range.
    """

    if value is None:

        return None


    try:

        score = float(
            value
        )

    except (
        TypeError,
        ValueError
    ):

        return None


    score = max(
        0.0,
        min(
            100.0,
            score
        )
    )


    # Preserve integer presentation when the
    # stored value is effectively an integer.

    if score.is_integer():

        return int(
            score
        )

    return round(
        score,
        2
    )


# ==========================================
# NORMALIZE RISK LEVEL
# ==========================================

def normalize_risk_level(
    value
):
    """
    Normalize the asset risk level.
    """

    if value is None:

        return "UNKNOWN"


    risk_level = str(
        value
    ).strip().upper()


    if risk_level not in (
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ):

        return "UNKNOWN"

    return risk_level