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
# 3. Generate the attack graph.
# 4. Pass graph data to the template.
#
# IMPORTANT:
#
# Attack-path generation itself remains in:
#
# services/attack_path_service.py
#
# This route should contain minimal business
# logic.
# ==========================================


from flask import (
    Blueprint,
    current_app,
    render_template,
    session,
    flash,
    redirect,
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
# ATTACK PATH PAGE
# ==========================================

@attack_path_bp.route(
    "/attack-paths"
)
@login_required
def attack_paths():
    """
    Display potential attack paths generated
    from the current user's Asset Inventory.
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
    # Attack paths are currently generated
    # only from assets belonging to the
    # logged-in user.
    #
    # This prevents accidental relationships
    # from being generated between assets
    # owned by different users.
    #
    # Super Admin cross-user/global analysis
    # can be introduced later using isolated
    # per-owner graphs.
    # ======================================

    try:

        assets = list(

            db.assets.find(

                {
                    "created_by": (
                        current_user_id
                    )
                }

            )

        )

    except Exception as error:

        print(
            "Attack Path asset loading "
            f"warning: {error}"
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
    # GENERATE ATTACK GRAPH
    # ======================================

    try:

        attack_graph = (
            generate_attack_graph(

                assets=assets,

                created_by=(
                    current_user_id
                )

            )
        )

    except Exception as error:

        print(
            "Attack Path generation "
            f"warning: {error}"
        )

        flash(
            "Unable to generate attack path analysis.",
            "error"
        )

        return redirect(
            url_for(
                "home"
            )
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

    graph_nodes = (
        attack_graph.get(
            "nodes",
            []
        )
    )

    graph_edges = (
        attack_graph.get(
            "edges",
            []
        )
    )

    attack_paths = (
        attack_graph.get(
            "paths",
            []
        )
    )


    # ======================================
    # RENDER PAGE
    # ======================================

    return render_template(

        "attack_paths.html",

        current_page="attack_paths",

        attack_graph=attack_graph,

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
            attack_paths
        )

    )