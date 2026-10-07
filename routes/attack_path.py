# ==========================================
# ATTACK PATH ROUTES
# ==========================================
#
# This route connects the Attack Path Engine
# with the Flask application.
#
# Responsibilities:
#
# 1. Require authentication.
# 2. Load authorized Asset records.
# 3. Allow the user to select a host/IP.
# 4. Validate the selected asset belongs to
#    the logged-in user.
# 5. Generate the attack graph only for the
#    selected authorized asset.
# 6. Pass graph data to the template.
#
# IMPORTANT:
#
# Attack-path generation itself remains in:
#
# services/attack_path_service.py
#
# This route contains only selection,
# authorization, and presentation logic.
# ==========================================


from flask import (
    Blueprint,
    current_app,
    render_template,
    session,
    flash,
    redirect,
    request,
    url_for
)


from routes.auth import (
    login_required
)


from services.attack_path_service import (
    generate_attack_graph
)


# ==========================================
# CREATE BLUEPRINT
# ==========================================

attack_path_bp = Blueprint(
    "attack_path",
    __name__
)


# ==========================================
# EMPTY ATTACK GRAPH
# ==========================================

def create_empty_attack_graph():
    """
    Return an empty graph structure for the
    Attack Path page when no host has been
    selected yet.

    This allows the page and host selector to
    render without generating attack paths
    across every asset automatically.
    """

    return {
        "nodes": [],
        "edges": [],
        "paths": [],
        "statistics": {
            "total_assets": 0,
            "total_nodes": 0,
            "total_edges": 0,
            "total_paths": 0
        }
    }


# ==========================================
# NORMALIZE ASSET ID
# ==========================================

def normalize_asset_id(value):
    """
    Convert an asset identifier into a safe
    comparable string.

    MongoDB ObjectId values and string IDs can
    therefore be compared without requiring the
    route to assume one particular ID type.
    """

    if value is None:
        return ""

    return str(value).strip()


# ==========================================
# FIND AUTHORIZED SELECTED ASSET
# ==========================================

def find_authorized_asset(
    assets,
    selected_asset_id
):
    """
    Find the selected asset only inside the
    already-authorized asset collection.

    The asset ID supplied through the query
    string is never used to perform an
    unrestricted database lookup.

    This prevents a user from selecting another
    user's asset by manually modifying the URL.
    """

    selected_id = normalize_asset_id(
        selected_asset_id
    )

    if not selected_id:
        return None

    for asset in assets:

        if not isinstance(
            asset,
            dict
        ):
            continue

        asset_id = normalize_asset_id(
            asset.get("_id")
        )

        if (
            asset_id
            and asset_id == selected_id
        ):
            return asset

    return None


# ==========================================
# ATTACK PATH PAGE
# ==========================================

@attack_path_bp.route(
    "/attack-paths"
)
@login_required
def attack_paths():
    """
    Display potential attack paths for one
    selected authorized asset belonging to
    the current user.

    The page first loads the user's Asset
    Inventory.

    When the user selects a host/IP, only that
    authorized asset is supplied to the Attack
    Path Engine.
    """


    # ======================================
    # GET DATABASE
    # ======================================

    db = current_app.config.get(
        "MONGO_DB"
    )


    if db is None:

        flash(
            "Database connection is not available.",
            "error"
        )

        return redirect(
            url_for(
                "home"
            )
        )


    # ======================================
    # GET CURRENT USER
    # ======================================

    current_user_id = session.get(
        "admin_id"
    )


    if not current_user_id:

        flash(
            "Unable to determine the current user.",
            "error"
        )

        return redirect(
            url_for(
                "home"
            )
        )


    # ======================================
    # LOAD AUTHORIZED ASSETS
    # ======================================
    #
    # Only assets belonging to the logged-in
    # user are loaded.
    #
    # Host selection is performed exclusively
    # against this authorized collection.
    #
    # This prevents cross-user asset access
    # through query-string manipulation.
    # ======================================

    try:

        available_assets = list(

            db.assets.find(

                {
                    "created_by": (
                        current_user_id
                    )
                }

            )

        )


    except Exception as error:

        current_app.logger.exception(
            "Attack Path asset loading failed: %s",
            error
        )

        flash(
            "Unable to load assets for attack path analysis.",
            "error"
        )

        return redirect(
            url_for(
                "home"
            )
        )


    # ======================================
    # SORT AVAILABLE ASSETS
    # ======================================
    #
    # Sorting gives the host selector a stable,
    # predictable order.
    # ======================================

    available_assets.sort(
        key=lambda asset: (
            str(
                asset.get(
                    "target",
                    ""
                )
            ).lower(),
            str(
                asset.get(
                    "hostname",
                    ""
                )
            ).lower()
        )
    )


    # ======================================
    # GET SELECTED ASSET ID
    # ======================================
    #
    # Example:
    #
    # /attack-paths?asset_id=<asset-id>
    #
    # The value is treated only as a selection
    # request. Authorization is performed below.
    # ======================================

    selected_asset_id = (
        request.args.get(
            "asset_id",
            ""
        )
        or ""
    ).strip()


    # ======================================
    # FIND AUTHORIZED SELECTED ASSET
    # ======================================

    selected_asset = None


    if selected_asset_id:

        selected_asset = (
            find_authorized_asset(
                available_assets,
                selected_asset_id
            )
        )


        # ==================================
        # INVALID / UNAUTHORIZED ASSET
        # ==================================
        #
        # Do not reveal whether the supplied
        # identifier belongs to another user.
        #
        # Simply reject it as unavailable.
        # ==================================

        if selected_asset is None:

            current_app.logger.warning(
                "Rejected unavailable Attack Path "
                "asset selection for user %s",
                current_user_id
            )

            flash(
                "The selected host is not available "
                "for your attack path analysis.",
                "error"
            )

            return redirect(
                url_for(
                    "attack_path.attack_paths"
                )
            )


    # ======================================
    # DEFAULT EMPTY GRAPH
    # ======================================
    #
    # Do not automatically combine all assets.
    #
    # The user must explicitly select the host
    # they want AttackLens to analyze.
    # ======================================

    attack_graph = (
        create_empty_attack_graph()
    )


    # ======================================
    # GENERATE SELECTED HOST ATTACK GRAPH
    # ======================================
    #
    # Only one authorized asset is supplied.
    #
    # The Attack Path Engine still performs its
    # own ownership checks as an additional
    # defense-in-depth control.
    # ======================================

    if selected_asset is not None:

        try:

            attack_graph = (
                generate_attack_graph(

                    assets=[
                        selected_asset
                    ],

                    created_by=(
                        current_user_id
                    )

                )
            )


        except Exception as error:

            current_app.logger.exception(
                "Attack Path generation failed "
                "for selected asset %s: %s",
                selected_asset_id,
                error
            )

            flash(
                "Unable to generate attack path "
                "analysis for the selected host.",
                "error"
            )

            attack_graph = (
                create_empty_attack_graph()
            )


    # ======================================
    # VALIDATE GRAPH RESULT
    # ======================================
    #
    # Protect the template from an unexpected
    # service return value.
    # ======================================

    if not isinstance(
        attack_graph,
        dict
    ):

        current_app.logger.error(
            "Attack Path Engine returned an "
            "invalid graph result."
        )

        attack_graph = (
            create_empty_attack_graph()
        )


    # ======================================
    # GRAPH DATA
    # ======================================

    graph_statistics = (
        attack_graph.get(
            "statistics",
            {}
        )
    )


    if not isinstance(
        graph_statistics,
        dict
    ):

        graph_statistics = {}


    graph_nodes = (
        attack_graph.get(
            "nodes",
            []
        )
    )


    if not isinstance(
        graph_nodes,
        list
    ):

        graph_nodes = []


    graph_edges = (
        attack_graph.get(
            "edges",
            []
        )
    )


    if not isinstance(
        graph_edges,
        list
    ):

        graph_edges = []


    attack_paths_data = (
        attack_graph.get(
            "paths",
            []
        )
    )


    if not isinstance(
        attack_paths_data,
        list
    ):

        attack_paths_data = []


    # ======================================
    # NORMALIZE STATISTICS
    # ======================================
    #
    # Keep page counters synchronized with the
    # actual data passed to the template.
    # ======================================

    graph_statistics.setdefault(
        "total_assets",
        (
            1
            if selected_asset is not None
            else 0
        )
    )

    graph_statistics.setdefault(
        "total_nodes",
        len(
            graph_nodes
        )
    )

    graph_statistics.setdefault(
        "total_edges",
        len(
            graph_edges
        )
    )

    graph_statistics.setdefault(
        "total_paths",
        len(
            attack_paths_data
        )
    )


    # ======================================
    # RENDER PAGE
    # ======================================

    return render_template(

        "attack_paths.html",

        current_page=(
            "attack_paths"
        ),

        # ----------------------------------
        # HOST SELECTION
        # ----------------------------------

        available_assets=(
            available_assets
        ),

        selected_asset_id=(
            selected_asset_id
        ),

        selected_asset=(
            selected_asset
        ),

        # ----------------------------------
        # ATTACK GRAPH
        # ----------------------------------

        attack_graph=(
            attack_graph
        ),

        graph_statistics=(
            graph_statistics
        ),

        graph_nodes=(
            graph_nodes
        ),

        graph_edges=(
            graph_edges
        ),

        attack_paths=(
            attack_paths_data
        )

    )