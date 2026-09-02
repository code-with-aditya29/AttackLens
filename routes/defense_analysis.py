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
    url_for
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
    # GENERATE ATTACK GRAPH
    # ======================================
    #
    # Defense Analysis depends on the same
    # Attack Path Engine output used by the
    # Attack Paths page.
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
        )

    )