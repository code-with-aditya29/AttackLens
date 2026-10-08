
# ==========================================
# DEFENSE ANALYSIS ROUTES
# ==========================================
#
# This route connects the Defense Analysis
# Engine with the Flask application.
#
# Responsibilities:
#
# 1. Require authentication.
# 2. Load authorized Asset Inventory data.
# 3. Generate the Attack Graph.
# 4. Generate Defense Analysis results.
# 5. Pass normalized data to the template.
#
# IMPORTANT:
#
# Attack-path generation remains inside:
#
# services/attack_path_service.py
#
# Defense-analysis logic remains inside:
#
# services/defense_analysis_service.py
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
    url_for,
    request
)


from routes.auth import (
    login_required
)


from services.attack_path_service import (
    generate_attack_graph
)


from services.defense_analysis_service import (
    generate_defense_analysis
)


# ==========================================
# CREATE BLUEPRINT
# ==========================================

defense_analysis_bp = Blueprint(
    "defense_analysis",
    __name__
)


# ==========================================
# DEFENSE ANALYSIS PAGE
# ==========================================

@defense_analysis_bp.route(
    "/defense-analysis"
)
@login_required
def defense_analysis():
    """
    Display Defense Analysis results generated
    from the current user's Asset Inventory
    and Attack Path graph.
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
    # Defense Analysis must only use assets
    # belonging to the logged-in user.
    #
    # This keeps ownership isolation aligned
    # with the Attack Path Engine.
    # ======================================

    try:

        assets = list(

            db.assets.find(

                {
                    "created_by":
                        current_user_id
                }

            )

        )

    except Exception as error:

        print(
            "Defense Analysis asset loading "
            f"warning: {error}"
        )

        flash(
            "Unable to load assets for defense analysis.",
            "error"
        )

        return redirect(
            url_for(
                "home"
            )
        )


    # ======================================
    # HOST / ASSET SELECTION
    # ======================================
    #
    # Preserve the complete authorized asset
    # list for the dropdown.
    #
    # Only an asset belonging to the current
    # user may be selected.
    #
    # No selection means all assets.
    # ======================================

    available_assets = sorted(

        assets,

        key=lambda asset: (

            str(
                asset.get(
                    "target",
                    ""
                )
            ).lower(),

            str(
                asset.get(
                    "_id",
                    ""
                )
            )

        )

    )


    selected_asset_id = (

        request.args.get(
            "asset_id",
            "all"
        )

        or "all"

    ).strip()


    selected_asset = None


    if selected_asset_id.lower() == "all":

        selected_asset_id = "all"

    else:

        selected_assets = [

            asset

            for asset in available_assets

            if str(
                asset.get("_id")
            ) == selected_asset_id

        ]


        if not selected_assets:

            flash(
                "Selected asset was not found "
                "or is not accessible.",
                "error"
            )

            return redirect(
                url_for(
                    "defense_analysis.defense_analysis"
                )
            )


        selected_asset = selected_assets[0]

        assets = selected_assets


    # ======================================
    # GENERATE ATTACK GRAPH
    # ======================================
    #
    # Defense Analysis depends on the same
    # Attack Path Engine output used by the
    # Attack Paths page.
    #
    # The selected asset scope is passed
    # to the Attack Path Engine.
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
            "Defense Analysis attack graph "
            f"warning: {error}"
        )

        flash(
            "Unable to generate attack graph for defense analysis.",
            "error"
        )

        return redirect(
            url_for(
                "home"
            )
        )


    # ======================================
    # GENERATE DEFENSE ANALYSIS
    # ======================================

    try:

        defense_analysis_result = (
            generate_defense_analysis(

                assets=assets,

                attack_graph=(
                    attack_graph
                ),

                created_by=(
                    current_user_id
                )

            )
        )

    except Exception as error:

        print(
            "Defense Analysis generation "
            f"warning: {error}"
        )

        flash(
            "Unable to generate defense analysis.",
            "error"
        )

        return redirect(
            url_for(
                "home"
            )
        )


    # ======================================
    # EXTRACT DEFENSE DATA
    # ======================================

    defense_statistics = (
        defense_analysis_result.get(
            "statistics",
            {}
        )
    )


    defense_findings = (
        defense_analysis_result.get(
            "findings",
            []
        )
    )


    defense_priorities = (
        defense_analysis_result.get(
            "priorities",
            []
        )
    )


    # ======================================
    # ATTACK GRAPH CONTEXT
    # ======================================

    graph_statistics = (
        attack_graph.get(
            "statistics",
            {}
        )
    )


    attack_paths = (
        attack_graph.get(
            "paths",
            []
        )
    )


    graph_edges = (
        attack_graph.get(
            "edges",
            []
        )
    )


    graph_nodes = (
        attack_graph.get(
            "nodes",
            []
        )
    )


    # ======================================
    # RENDER PAGE
    # ======================================

    return render_template(

        "defense_analysis.html",

        current_page=(
            "defense_analysis"
        ),

        defense_analysis=(
            defense_analysis_result
        ),

        defense_statistics=(
            defense_statistics
        ),

        defense_findings=(
            defense_findings
        ),

        defense_priorities=(
            defense_priorities
        ),

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
            attack_paths
        ),

        # ==================================
        # HOST SELECTION TEMPLATE VARIABLES
        # ==================================

        available_assets=(
            available_assets
        ),

        selected_asset_id=(
            selected_asset_id
        ),

        selected_asset=(
            selected_asset
        ),

        analyzed_asset_count=(
            len(assets)
        )

    )


# ==========================================
# END OF DEFENSE ANALYSIS ROUTES
# ==========================================
