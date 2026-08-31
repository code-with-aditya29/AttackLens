# ==========================================
# ATTACKLENS
# ASSET SERVICE
# ==========================================

from datetime import (
    datetime,
    timezone
)

from bson import ObjectId


from models.asset_model import (
    create_asset_document
)


# ==========================================
# NORMALIZE LIST
# ==========================================

def normalize_list(
    value
):
    """
    Ensure fields expected to be lists
    always remain lists.
    """

    if isinstance(
        value,
        list
    ):
        return value

    return []


# ==========================================
# NORMALIZE DATETIME
# ==========================================

def normalize_datetime(
    value
):
    """
    Normalize a datetime value to UTC.

    PyMongo commonly returns UTC datetimes
    without timezone information unless
    tz_aware is enabled.

    This helper allows safe comparisons
    between naive and timezone-aware values.
    """

    if not isinstance(
        value,
        datetime
    ):
        return None


    if value.tzinfo is None:

        return value.replace(
            tzinfo=timezone.utc
        )


    return value.astimezone(
        timezone.utc
    )


# ==========================================
# GET SCAN TIMESTAMP
# ==========================================

def get_scan_timestamp(
    scan
):
    """
    Return the best timestamp representing
    when a scan occurred.

    Priority:

        completed_at
        created_at
        started_at
        ObjectId generation time

    A very old fallback is used only when
    no usable timestamp exists.
    """

    if not isinstance(
        scan,
        dict
    ):

        return datetime.min.replace(
            tzinfo=timezone.utc
        )


    timestamp_fields = [

        "completed_at",
        "created_at",
        "started_at"

    ]


    for field in timestamp_fields:

        value = normalize_datetime(
            scan.get(
                field
            )
        )


        if value is not None:

            return value


    # ======================================
    # OBJECTID FALLBACK
    # ======================================

    scan_id = scan.get(
        "_id"
    )


    if isinstance(
        scan_id,
        ObjectId
    ):

        return scan_id.generation_time


    # ======================================
    # FINAL FALLBACK
    # ======================================

    return datetime.min.replace(
        tzinfo=timezone.utc
    )


# ==========================================
# GET OPEN PORTS
# ==========================================

def get_open_ports(
    ports
):
    """
    Return only ports whose state is open.
    """

    ports = normalize_list(
        ports
    )


    open_ports = []


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

            open_ports.append(
                port
            )


    return open_ports


# ==========================================
# NORMALIZE RISK LEVEL
# ==========================================

def normalize_risk_level(
    risk_level
):
    """
    Normalize Risk Engine level.
    """

    if not risk_level:

        return None


    normalized = str(
        risk_level
    ).strip().upper()


    allowed_levels = {

        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"

    }


    if normalized not in allowed_levels:

        return None


    return normalized


# ==========================================
# BUILD ASSET UPDATE FROM SCAN
# ==========================================

def build_asset_update_from_scan(
    scan
):
    """
    Convert a completed AttackLens scan
    into normalized asset information.

    This contains scan-controlled fields only.

    User-controlled fields such as:

        criticality
        exposure

    are deliberately NOT included here.
    """

    if not isinstance(
        scan,
        dict
    ):

        return None


    target = str(

        scan.get(
            "target",
            ""
        )

    ).strip()


    if not target:

        return None


    ports = normalize_list(

        scan.get(
            "ports",
            []
        )

    )


    open_ports = get_open_ports(
        ports
    )


    services = normalize_list(

        scan.get(
            "services",
            []
        )

    )


    vulnerabilities = normalize_list(

        scan.get(
            "vulnerabilities",
            []
        )

    )


    scan_time = get_scan_timestamp(
        scan
    )


    return {

        # ==================================
        # BASIC INFORMATION
        # ==================================

        "target": target,

        "hostname": scan.get(
            "hostname"
        ),

        "host_status": scan.get(
            "host_status",
            "unknown"
        ),

        "mac_address": scan.get(
            "mac_address"
        ),


        # ==================================
        # OPERATING SYSTEM
        # ==================================

        "operating_system": scan.get(
            "os_detection"
        ),

        "os_accuracy": scan.get(
            "os_accuracy"
        ),


        # ==================================
        # NETWORK INFORMATION
        # ==================================

        "ports": open_ports,

        "open_port_count": len(
            open_ports
        ),

        "services": services,

        "service_count": len(
            services
        ),


        # ==================================
        # SECURITY INFORMATION
        # ==================================

        "vulnerabilities": vulnerabilities,

        "vulnerability_count": len(
            vulnerabilities
        ),

        "highest_severity": scan.get(
            "highest_severity"
        ),

        "risk_score": scan.get(
            "risk_score"
        ),

        "risk_level": normalize_risk_level(

            scan.get(
                "risk_level"
            )

        ),

        "risk_breakdown": scan.get(
            "risk_breakdown"
        ),


        # ==================================
        # SOURCE SCAN INFORMATION
        # ==================================

        "latest_scan_id": scan.get(
            "_id"
        ),

        "latest_scan_profile": scan.get(
            "scan_profile"
        ),

        "last_seen": scan_time,

        "updated_at": datetime.now(
            timezone.utc
        )
    }


# ==========================================
# UPSERT ASSET FROM SCAN
# ==========================================

def upsert_asset_from_scan(
    db,
    scan
):
    """
    Create or update an Asset from a
    completed scan.

    Identity:

        created_by + target

    Rules:

    1. Only completed scans are accepted.

    2. first_seen always represents the
       earliest known scan.

    3. An older scan can update first_seen,
       but cannot overwrite the current
       asset snapshot.

    4. A newer scan becomes the current
       asset representation.

    5. Manual Asset Context fields are
       preserved.
    """

    if not isinstance(
        scan,
        dict
    ):

        return None


    # ======================================
    # COMPLETED SCANS ONLY
    # ======================================

    if scan.get(
        "status"
    ) != "completed":

        return None


    target = str(

        scan.get(
            "target",
            ""
        )

    ).strip()


    created_by = scan.get(
        "created_by"
    )


    if not target or not created_by:

        return None


    scan_time = get_scan_timestamp(
        scan
    )


    asset_update = (
        build_asset_update_from_scan(
            scan
        )
    )


    if not asset_update:

        return None


    # ======================================
    # FIND EXISTING ASSET
    # ======================================

    existing_asset = db.assets.find_one(

        {
            "target": target,
            "created_by": created_by
        }

    )


    # ======================================
    # CREATE NEW ASSET
    # ======================================

    if not existing_asset:

        asset = create_asset_document(

            target=target,

            created_by=created_by

        )


        asset.update(
            asset_update
        )


        # The asset's first and last discovery
        # timestamps initially come from the
        # first completed scan.

        asset[
            "first_seen"
        ] = scan_time


        asset[
            "last_seen"
        ] = scan_time


        result = db.assets.insert_one(
            asset
        )


        asset[
            "_id"
        ] = result.inserted_id


        return asset


    # ======================================
    # EXISTING ASSET TIMESTAMPS
    # ======================================

    existing_first_seen = (
        normalize_datetime(

            existing_asset.get(
                "first_seen"
            )

        )
    )


    existing_last_seen = (
        normalize_datetime(

            existing_asset.get(
                "last_seen"
            )

        )
    )


    # ======================================
    # DETERMINE EARLIEST FIRST SEEN
    # ======================================

    if existing_first_seen is None:

        first_seen = scan_time

    else:

        first_seen = min(

            existing_first_seen,

            scan_time

        )


    # ======================================
    # OLDER SCAN
    # ======================================
    #
    # If this scan occurred before the
    # currently stored asset snapshot,
    # update only first_seen.
    #
    # Do NOT overwrite:
    #
    # hostname
    # OS
    # ports
    # services
    # CVEs
    # risk
    # latest_scan_id
    # criticality
    # exposure
    # ======================================

    if (
        existing_last_seen is not None
        and
        scan_time < existing_last_seen
    ):

        db.assets.update_one(

            {
                "_id": existing_asset[
                    "_id"
                ]
            },

            {
                "$set": {

                    "first_seen": first_seen,

                    "updated_at": datetime.now(
                        timezone.utc
                    )
                }
            }

        )


        return db.assets.find_one(

            {
                "_id": existing_asset[
                    "_id"
                ]
            }

        )


    # ======================================
    # NEWEST / SAME-TIME SCAN
    # ======================================
    #
    # Update the current representation.
    #
    # criticality and exposure are absent
    # from asset_update, therefore manual
    # values remain untouched.
    # ======================================

    asset_update[
        "first_seen"
    ] = first_seen


    asset_update[
        "last_seen"
    ] = scan_time


    db.assets.update_one(

        {
            "_id": existing_asset[
                "_id"
            ]
        },

        {
            "$set": asset_update
        }

    )


    return db.assets.find_one(

        {
            "_id": existing_asset[
                "_id"
            ]
        }

    )


# ==========================================
# SYNC ASSETS FROM COMPLETED SCANS
# ==========================================

def sync_assets_from_completed_scans(
    db,
    created_by=None
):
    """
    Rebuild/refresh Asset state from all
    completed scans currently in MongoDB.

    Each unique:

        created_by + target

    becomes one Asset.

    Earliest scan:
        establishes first_seen

    Latest scan:
        establishes current state

    This approach is deterministic and does
    not depend on MongoDB sort behavior when
    some historical records have missing
    timestamp fields.
    """

    query = {
        "status": "completed"
    }


    if created_by is not None:

        query[
            "created_by"
        ] = created_by


    scans = list(

        db.scans.find(
            query
        )

    )


    # ======================================
    # GROUP SCANS BY ASSET IDENTITY
    # ======================================

    asset_groups = {}


    for scan in scans:

        if not isinstance(
            scan,
            dict
        ):

            continue


        target = str(

            scan.get(
                "target",
                ""
            )

        ).strip()


        owner = scan.get(
            "created_by"
        )


        if not target or not owner:

            continue


        group_key = (

            str(
                owner
            ),

            target

        )


        if group_key not in asset_groups:

            asset_groups[
                group_key
            ] = []


        asset_groups[
            group_key
        ].append(
            scan
        )


    synced_count = 0


    # ======================================
    # PROCESS EACH ASSET
    # ======================================

    for group_scans in asset_groups.values():

        if not group_scans:

            continue


        # Sort explicitly using our normalized
        # timestamp helper.

        ordered_scans = sorted(

            group_scans,

            key=get_scan_timestamp

        )


        earliest_scan = (
            ordered_scans[
                0
            ]
        )


        latest_scan = (
            ordered_scans[
                -1
            ]
        )


        earliest_time = get_scan_timestamp(
            earliest_scan
        )


        latest_time = get_scan_timestamp(
            latest_scan
        )


        # ==================================
        # CURRENT STATE FROM LATEST SCAN
        # ==================================

        asset = upsert_asset_from_scan(

            db=db,

            scan=latest_scan

        )


        if not asset:

            continue


        # ==================================
        # FORCE CORRECT DISCOVERY RANGE
        # ==================================
        #
        # This also repairs assets created by
        # the initial Assets implementation
        # where first_seen represented asset
        # document creation time.
        # ==================================

        db.assets.update_one(

            {
                "_id": asset[
                    "_id"
                ]
            },

            {
                "$set": {

                    "first_seen": earliest_time,

                    "last_seen": latest_time
                }
            }

        )


        synced_count += 1


    return synced_count


# ==========================================
# GET ASSETS
# ==========================================

def get_assets(
    db,
    created_by=None,
    limit=200
):
    """
    Return assets visible to the current user.
    """

    query = {}


    if created_by is not None:

        query[
            "created_by"
        ] = created_by


    assets = (

        db.assets.find(
            query
        )

        .sort(
            "last_seen",
            -1
        )

        .limit(
            limit
        )

    )


    return list(
        assets
    )


# ==========================================
# GET SINGLE ASSET
# ==========================================

def get_asset_by_id(
    db,
    asset_id,
    created_by=None
):
    """
    Return one asset with ownership
    protection.
    """

    if not ObjectId.is_valid(
        asset_id
    ):

        return None


    query = {

        "_id": ObjectId(
            asset_id
        )

    }


    if created_by is not None:

        query[
            "created_by"
        ] = created_by


    return db.assets.find_one(
        query
    )


# ==========================================
# GET ASSET BY TARGET
# ==========================================

def get_asset_by_target(
    db,
    target,
    created_by=None
):
    """
    Find an asset using its target.
    """

    target = str(
        target
    ).strip()


    if not target:

        return None


    query = {
        "target": target
    }


    if created_by is not None:

        query[
            "created_by"
        ] = created_by


    return db.assets.find_one(
        query
    )


# ==========================================
# GET ASSET STATISTICS
# ==========================================

def get_asset_statistics(
    assets
):
    """
    Build Asset Inventory summary
    statistics.
    """

    assets = normalize_list(
        assets
    )


    statistics = {

        "total_assets": len(
            assets
        ),

        "critical_assets": 0,

        "high_risk_assets": 0,

        "vulnerable_assets": 0,

        "total_open_ports": 0,

        "total_vulnerabilities": 0
    }


    for asset in assets:

        if not isinstance(
            asset,
            dict
        ):

            continue


        criticality = str(

            asset.get(
                "criticality",
                "NORMAL"
            )

        ).upper()


        risk_level = str(

            asset.get(
                "risk_level",
                ""
            )

        ).upper()


        vulnerability_count = asset.get(

            "vulnerability_count",

            0

        )


        open_port_count = asset.get(

            "open_port_count",

            0

        )


        # ==================================
        # SAFE INTEGER VALUES
        # ==================================

        try:

            vulnerability_count = int(

                vulnerability_count
                or 0

            )

        except (
            TypeError,
            ValueError
        ):

            vulnerability_count = 0


        try:

            open_port_count = int(

                open_port_count
                or 0

            )

        except (
            TypeError,
            ValueError
        ):

            open_port_count = 0


        # ==================================
        # STATISTICS
        # ==================================

        if criticality == "CRITICAL":

            statistics[
                "critical_assets"
            ] += 1


        if risk_level in {

            "HIGH",
            "CRITICAL"

        }:

            statistics[
                "high_risk_assets"
            ] += 1


        if vulnerability_count > 0:

            statistics[
                "vulnerable_assets"
            ] += 1


        statistics[
            "total_open_ports"
        ] += open_port_count


        statistics[
            "total_vulnerabilities"
        ] += vulnerability_count


    return statistics


# ==========================================
# UPDATE ASSET CONTEXT
# ==========================================

def update_asset_context(
    db,
    asset_id,
    criticality,
    exposure,
    created_by=None
):
    """
    Update user-controlled Asset Context.

    These values will later influence the
    Attack Path Engine and Defense Analysis.
    """

    if not ObjectId.is_valid(
        asset_id
    ):

        return False


    criticality = str(
        criticality
    ).strip().upper()


    exposure = str(
        exposure
    ).strip().upper()


    allowed_criticality = {

        "LOW",
        "NORMAL",
        "HIGH",
        "CRITICAL"

    }


    allowed_exposure = {

        "INTERNAL",
        "EXTERNAL",
        "UNKNOWN"

    }


    if criticality not in allowed_criticality:

        return False


    if exposure not in allowed_exposure:

        return False


    query = {

        "_id": ObjectId(
            asset_id
        )

    }


    if created_by is not None:

        query[
            "created_by"
        ] = created_by


    result = db.assets.update_one(

        query,

        {
            "$set": {

                "criticality": criticality,

                "exposure": exposure,

                "updated_at": datetime.now(
                    timezone.utc
                )
            }
        }

    )


    return (
        result.matched_count
        == 1
    )