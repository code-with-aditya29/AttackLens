# ==========================================
# RISK COMPARISON ROUTES
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

from services.risk_comparison_service import (
    generate_risk_comparison
)


# ==========================================
# CREATE BLUEPRINT
# ==========================================

risk_comparison_bp = Blueprint(
    "risk_comparison",
    __name__
)


# ==========================================
# RISK COMPARISON PAGE
# ==========================================

@risk_comparison_bp.route(
    "/risk-comparison"
)
@login_required
def risk_comparison():

    try:

        # ==================================
        # GET DATABASE
        # ==================================

        db = current_app.config.get(
            "MONGO_DB"
        )

        if db is None:

            raise RuntimeError(
                "MongoDB database is unavailable."
            )


        # ==================================
        # GET CURRENT USER
        # ==================================

        current_user_id = session.get(
            "admin_id"
        )

        if not current_user_id:

            flash(
                "Unable to identify the current user.",
                "error"
            )

            return redirect(
                url_for(
                    "home"
                )
            )


        # ==================================
        # LOAD CURRENT USER ASSETS
        # ==========================================

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
        # ==========================================

        attack_graph = (
            generate_attack_graph(
                assets=assets,
                created_by=current_user_id
            )
        )


        # ==================================
        # GENERATE DEFENSE ANALYSIS
        # ==========================================

        defense_analysis = (
            generate_defense_analysis(
                assets=assets,
                attack_graph=attack_graph,
                created_by=current_user_id
            )
        )


        # ==================================
        # GENERATE MITIGATION RECOMMENDATIONS
        # ==========================================

        mitigation_analysis = (
            generate_mitigation_recommendations(
                assets=assets,
                defense_analysis=defense_analysis,
                attack_graph=attack_graph,
                created_by=current_user_id
            )
        )


        # ==================================
        # GENERATE RISK COMPARISON
        # ==========================================

        comparison = (
            generate_risk_comparison(
                assets=assets,
                attack_graph=attack_graph,
                defense_analysis=defense_analysis,
                mitigation_analysis=mitigation_analysis,
                created_by=current_user_id
            )
        )


        # ==================================
        # SAFE COMPARISON DOCUMENT
        # ==========================================

        if not isinstance(
            comparison,
            dict
        ):

            comparison = {}


        # ==================================
        # CURRENT STATE
        # ==========================================

        current_state = comparison.get(
            "current_state",
            {}
        )

        if not isinstance(
            current_state,
            dict
        ):

            current_state = {}


        # ==================================
        # PROJECTED STATE
        # ==========================================

        projected_state = comparison.get(
            "projected_state",
            {}
        )

        if not isinstance(
            projected_state,
            dict
        ):

            projected_state = {}


        # ==================================
        # REDUCTION
        # ==========================================

        reduction = comparison.get(
            "reduction",
            {}
        )

        if not isinstance(
            reduction,
            dict
        ):

            reduction = {}


        # ==================================
        # STATISTICS
        # ==========================================

        statistics = comparison.get(
            "statistics",
            {}
        )

        if not isinstance(
            statistics,
            dict
        ):

            statistics = {}


        # ==================================
        # RENDER PAGE
        # ==========================================

        return render_template(
            "risk_comparison.html",

            current_page=
                "risk_comparison",

            comparison=
                comparison,

            current_state=
                current_state,

            projected_state=
                projected_state,

            reduction=
                reduction,

            statistics=
                statistics,

            mitigation_analysis=
                mitigation_analysis,

            defense_analysis=
                defense_analysis
        )


    except Exception as error:

        # ==================================
        # LOG COMPLETE ERROR
        # ==========================================

        current_app.logger.exception(
            "Risk Comparison generation failed: %s",
            error
        )


        # ==================================
        # USER MESSAGE
        # ==========================================

        flash(
            "Unable to generate the Risk Comparison. "
            "Please verify the available security "
            "analysis data and try again.",
            "error"
        )


        # ==================================
        # RETURN TO DASHBOARD
        # ==========================================

        return redirect(
            url_for(
                "home"
            )
        )