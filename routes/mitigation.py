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
    Generate mitigation recommendations for
    assets belonging to the current user.
    """

    try:

        db = current_app.config.get(
            "MONGO_DB"
        )

        if db is None:

            raise RuntimeError(
                "MongoDB connection is not available."
            )

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

        assets = list(
            db.assets.find(
                {
                    "created_by":
                        current_user_id
                }
            )
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
                defense_analysis.get(
                    "statistics",
                    {}
                )
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