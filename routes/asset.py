# ==========================================
# ATTACKLENS
# ASSET ROUTES
# ==========================================

from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    current_app,
    session,
    request
)


from routes.auth import (
    login_required
)


from services.asset_service import (
    sync_assets_from_completed_scans,
    get_assets,
    get_asset_by_id,
    get_asset_statistics,
    update_asset_context
)


# ==========================================
# ASSET BLUEPRINT
# ==========================================

asset_bp = Blueprint(

    "asset",

    __name__

)


# ==========================================
# ASSET INVENTORY
# ==========================================

@asset_bp.route(
    "/assets"
)
@login_required
def asset_inventory():
    """
    Display normalized assets discovered from
    completed AttackLens scans.
    """

    db = current_app.config[
        "MONGO_DB"
    ]


    # ======================================
    # OWNERSHIP FILTER
    # ======================================

    owner_filter = (
        get_asset_owner_filter()
    )


    # ======================================
    # SYNC EXISTING COMPLETED SCANS
    # ======================================
    #
    # During the first Assets implementation
    # we build the inventory from scans already
    # stored in MongoDB.
    #
    # Later, scan completion can directly call
    # upsert_asset_from_scan().
    # ======================================

    try:

        sync_assets_from_completed_scans(

            db=db,

            created_by=owner_filter
        )

    except Exception as error:

        print(
            "Asset synchronization warning:",
            error
        )


    # ======================================
    # LOAD ASSETS
    # ======================================

    assets = get_assets(

        db=db,

        created_by=owner_filter,

        limit=200
    )


    # ======================================
    # BUILD SUMMARY
    # ======================================

    asset_stats = (
        get_asset_statistics(
            assets
        )
    )


    return render_template(

        "assets.html",

        assets=assets,

        asset_stats=asset_stats,

        current_page="assets"
    )


# ==========================================
# ASSET DETAILS
# ==========================================

@asset_bp.route(
    "/assets/<asset_id>"
)
@login_required
def asset_details(
    asset_id
):
    """
    Display detailed information about a
    single asset.
    """

    db = current_app.config[
        "MONGO_DB"
    ]


    asset = get_asset_by_id(

        db=db,

        asset_id=asset_id,

        created_by=get_asset_owner_filter()
    )


    if not asset:

        flash(
            "Asset not found or you do not "
            "have permission to view it.",
            "error"
        )


        return redirect(
            url_for(
                "asset.asset_inventory"
            )
        )


    return render_template(

        "asset_details.html",

        asset=asset,

        current_page="assets"
    )


# ==========================================
# UPDATE ASSET CONTEXT
# ==========================================

@asset_bp.route(
    "/assets/<asset_id>/context",
    methods=[
        "POST"
    ]
)
@login_required
def update_context(
    asset_id
):
    """
    Update asset criticality and exposure.

    These values will later be used by the
    Attack Path Engine.
    """

    criticality = request.form.get(
        "criticality",
        "NORMAL"
    )


    exposure = request.form.get(
        "exposure",
        "UNKNOWN"
    )


    db = current_app.config[
        "MONGO_DB"
    ]


    updated = update_asset_context(

        db=db,

        asset_id=asset_id,

        criticality=criticality,

        exposure=exposure,

        created_by=get_asset_owner_filter()
    )


    if updated:

        flash(
            "Asset context updated successfully.",
            "success"
        )

    else:

        flash(
            "Unable to update asset context.",
            "error"
        )


    return redirect(

        url_for(
            "asset.asset_details",
            asset_id=asset_id
        )

    )


# ==========================================
# GET CURRENT USER ID
# ==========================================

def session_user_id():

    return session.get(
        "admin_id"
    )


# ==========================================
# ASSET OWNERSHIP FILTER
# ==========================================

def get_asset_owner_filter():
    """
    Super Admin:
        Can access all assets.

    Normal Admin:
        Can access only assets generated from
        their own scans.
    """

    if session.get(
        "role"
    ) == "super_admin":

        return None


    return session_user_id()