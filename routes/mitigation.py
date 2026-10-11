
# ==========================================
# MITIGATION ROUTES
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

from services.mitigation_service import (
    generate_mitigation_recommendations
)


# ==========================================
# BLUEPRINT
# ==========================================

mitigation_bp = Blueprint(
    "mitigation",
    __name__
)


# ==========================================
# MITIGATION PAGE
# ==========================================

@mitigation_bp.route(
    "/mitigation"
)
@login_required
def mitigation():
    """
    Generate evidence-based mitigation
    recommendations for assets belonging
    to the currently authenticated user.

    Supports:
    - All authorized assets
    - Individual authorized asset selection
    - Attack graph generation
    - Defense analysis
    - Mitigation recommendations
    - Owner isolation
    """

    try:

        # ==================================
        # DATABASE CONNECTION
        # ==================================

        db = current_app.config.get(
            "MONGO_DB"
        )

        if db is None:

            raise RuntimeError(
                "MongoDB connection is not available."
            )

        # ==================================
        # CURRENT USER
        # ==================================

        current_user_id = session.get(
            "admin_id"
        )

        if not current_user_id:

            flash(
                "Your session is invalid. "
                "Please log in again.",
                "error"
            )

            return redirect(
                url_for(
                    "auth.login"
                )
            )

        # ==================================
        # LOAD CURRENT USER ASSETS
        # ==================================

        available_assets = list(
            db.assets.find(
                {
                    "created_by":
                        current_user_id
                }
            )
        )

        # ==================================
        # READ SELECTED ASSET
        # ==================================

        selected_asset_id = (
            request.args.get(
                "asset_id",
                "all"
            )
            or "all"
        ).strip()

        selected_asset = None

        # ==================================
        # FILTER AUTHORIZED ASSETS
        # ==================================

        if selected_asset_id.lower() == "all":

            selected_asset_id = "all"

            assets = available_assets

        else:

            selected_asset = next(
                (
                    asset
                    for asset in available_assets
                    if str(
                        asset.get(
                            "_id",
                            ""
                        )
                    ) == selected_asset_id
                ),
                None
            )

            if selected_asset is None:

                flash(
                    "The selected asset was not found "
                    "or you do not have permission "
                    "to access it.",
                    "error"
                )

                return redirect(
                    url_for(
                        "mitigation.mitigation",
                        asset_id="all"
                    )
                )

            assets = [
                selected_asset
            ]

        analyzed_asset_count = len(
            assets
        )

        # ==================================
        # GENERATE ATTACK GRAPH
        # ==================================

        attack_graph = (
            generate_attack_graph(
                assets=assets,
                created_by=current_user_id
            )
        )

        # ==================================
        # GENERATE DEFENSE ANALYSIS
        # ==================================

        defense_analysis = (
            generate_defense_analysis(
                assets=assets,
                attack_graph=attack_graph,
                created_by=current_user_id
            )
        )

        # ==================================
        # GENERATE MITIGATION
        # ==================================

        mitigation_analysis = (
            generate_mitigation_recommendations(
                assets=assets,
                defense_analysis=defense_analysis,
                attack_graph=attack_graph,
                created_by=current_user_id
            )
        )

        # ==================================
        # NORMALIZE RESULTS
        # ==================================

        recommendations = (
            mitigation_analysis.get(
                "recommendations",
                []
            )
        )

        statistics = (
            mitigation_analysis.get(
                "statistics",
                {}
            )
        )

        graph_statistics = (
            attack_graph.get(
                "statistics",
                {}
            )
        )

        defense_statistics = (
            defense_analysis.get(
                "statistics",
                {}
            )
        )

        # ==================================
        # RENDER PAGE
        # ==================================

        return render_template(
            "mitigation.html",

            current_page="mitigation",

            mitigation_analysis=
                mitigation_analysis,

            recommendations=
                recommendations,

            mitigation_statistics=
                statistics,

            graph_statistics=
                graph_statistics,

            defense_statistics=
                defense_statistics,

            available_assets=
                available_assets,

            selected_asset_id=
                selected_asset_id,

            selected_asset=
                selected_asset,

            analyzed_asset_count=
                analyzed_asset_count
        )

    except Exception as error:

        current_app.logger.exception(
            "Mitigation analysis failed: %s",
            error
        )

        flash(
            "Mitigation recommendations could "
            "not be generated.",
            "error"
        )

        return redirect(
            url_for(
                "home"
            )
        )