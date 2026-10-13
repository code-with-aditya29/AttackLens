

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

# SAFE DATA HELPERS

# ==========================================



def _safe_dict(value):

    """

    Return a dictionary or an empty dictionary.

    """



    if isinstance(value, dict):

        return value



    return {}





def _safe_list(value):

    """

    Return a list or an empty list.

    """



    if isinstance(value, list):

        return value



    return []





# ==========================================

# ASSET IDENTIFICATION HELPERS

# ==========================================



def _asset_id(asset):

    """

    Return the asset's internal identifier as text.



    The internal identifier is used only for matching

    and selection. It should not be the primary label

    shown to users.

    """



    if not isinstance(asset, dict):

        return ""



    identifier = asset.get("_id")



    if identifier is None:

        identifier = asset.get("asset_id")



    if identifier is None:

        identifier = asset.get("id")



    if identifier is None:

        return ""



    return str(identifier)





def _first_nonempty_text(*values):

    """

    Return the first meaningful text value.

    """



    for value in values:



        if value is None:

            continue



        if isinstance(value, str):



            cleaned = value.strip()



            if cleaned:

                return cleaned



        elif isinstance(value, (int, float)):



            return str(value)



    return ""





def _asset_display_name(asset):

    """

    Build a human-readable asset label.



    Prefer the actual hostname, asset name,

    target or IP address.



    Never invent a hostname or service identity.

    """



    if not isinstance(asset, dict):

        return "Unnamed Asset"



    name = _first_nonempty_text(

        asset.get("hostname"),

        asset.get("host_name"),

        asset.get("asset_name"),

        asset.get("name"),

        asset.get("target"),

        asset.get("target_ip"),

        asset.get("ip_address"),

        asset.get("ip"),

        asset.get("host")

    )



    if name:

        return name



    return "Unnamed Asset"





def _asset_address(asset):

    """

    Return a recognizable network address

    when one is available.

    """



    if not isinstance(asset, dict):

        return ""



    return _first_nonempty_text(

        asset.get("ip_address"),

        asset.get("target_ip"),

        asset.get("ip"),

        asset.get("target"),

        asset.get("host")

    )





def _asset_display_info(asset):

    """

    Prepare safe, readable information for

    the Risk Comparison interface.

    """



    return {

        "id": _asset_id(asset),

        "name": _asset_display_name(asset),

        "address": _asset_address(asset)

    }





# ==========================================

# EMPTY RISK COMPARISON DATA

# ==========================================



def _empty_comparison():

    """

    Return a consistent empty comparison.



    This is used when no asset has been selected

    or when the current user has no assets.

    """



    return {

        "current_state": {},

        "projected_state": {},

        "reduction": {},

        "statistics": {},

        "executive_assessment": {},

        "risk_reduction_details": [],

        "residual_risks": [],

        "disrupted_attack_paths": [],

        "remaining_attack_paths": [],

        "mitigation_impact": [],

        "asset_comparisons": [],

        "projection_assumptions": [],

        "verification_steps": [],

        "applied_recommendations": []

    }





# ==========================================

# PREPARE TEMPLATE DATA

# ==========================================



def _render_risk_comparison(

    comparison,

    mitigation_analysis,

    defense_analysis,

    available_assets,

    selected_asset,

    selected_asset_info

):

    """

    Render the Risk Comparison page.



    Preserve the original template variables

    and provide the additional asset-selection

    and detailed-analysis variables.

    """



    # ==================================

    # SAFE COMPARISON DOCUMENT

    # ==================================



    comparison = _safe_dict(

        comparison

    )



    # ==================================

    # CURRENT STATE

    # ==================================



    current_state = _safe_dict(

        comparison.get(

            "current_state",

            {}

        )

    )



    # ==================================

    # PROJECTED STATE

    # ==================================



    projected_state = _safe_dict(

        comparison.get(

            "projected_state",

            {}

        )

    )



    # ==================================

    # REDUCTION

    # ==================================



    reduction = _safe_dict(

        comparison.get(

            "reduction",

            {}

        )

    )



    # ==================================

    # STATISTICS

    # ==================================



    statistics = _safe_dict(

        comparison.get(

            "statistics",

            {}

        )

    )



    # ==================================

    # EXECUTIVE ASSESSMENT

    # ==================================



    executive_assessment = _safe_dict(

        comparison.get(

            "executive_assessment",

            {}

        )

    )



    # ==================================

    # RISK REDUCTION DETAILS

    # ==================================



    risk_reduction_details = _safe_list(

        comparison.get(

            "risk_reduction_details",

            []

        )

    )



    # ==================================

    # RESIDUAL RISKS

    # ==================================



    residual_risks = _safe_list(

        comparison.get(

            "residual_risks",

            []

        )

    )



    # ==================================

    # DISRUPTED ATTACK PATHS

    # ==================================



    disrupted_attack_paths = _safe_list(

        comparison.get(

            "disrupted_attack_paths",

            []

        )

    )



    # ==================================

    # REMAINING ATTACK PATHS

    # ==================================



    remaining_attack_paths = _safe_list(

        comparison.get(

            "remaining_attack_paths",

            []

        )

    )



    # ==================================

    # MITIGATION IMPACT

    # ==================================



    mitigation_impact = _safe_list(

        comparison.get(

            "mitigation_impact",

            []

        )

    )



    # ==================================

    # ASSET COMPARISONS

    # ==================================



    asset_comparisons = _safe_list(

        comparison.get(

            "asset_comparisons",

            []

        )

    )



    # ==================================

    # PROJECTION ASSUMPTIONS

    # ==================================



    projection_assumptions = _safe_list(

        comparison.get(

            "projection_assumptions",

            []

        )

    )



    # ==================================

    # VERIFICATION STEPS

    # ==================================



    verification_steps = _safe_list(

        comparison.get(

            "verification_steps",

            []

        )

    )



    # ==================================

    # APPLIED RECOMMENDATION REFERENCES

    # ==================================



    # These are projection inputs, not

    # verified or implemented changes.



    applied_recommendations = _safe_list(

        comparison.get(

            "applied_recommendations",

            []

        )

    )



    # ==================================

    # RENDER PAGE

    # ==================================



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

            defense_analysis,



        executive_assessment=

            executive_assessment,



        risk_reduction_details=

            risk_reduction_details,



        residual_risks=

            residual_risks,



        disrupted_attack_paths=

            disrupted_attack_paths,



        remaining_attack_paths=

            remaining_attack_paths,



        mitigation_impact=

            mitigation_impact,



        asset_comparisons=

            asset_comparisons,



        projection_assumptions=

            projection_assumptions,



        verification_steps=

            verification_steps,



        applied_recommendations=

            applied_recommendations,



        # ==================================

        # NEW SINGLE-ASSET VARIABLES

        # ==================================



        available_assets=

            available_assets,



        selected_asset=

            selected_asset,



        selected_asset_info=

            selected_asset_info,



        selected_asset_id=

            selected_asset_info.get(

                "id",

                ""

            ),



        selected_asset_name=

            selected_asset_info.get(

                "name",

                ""

            ),



        selected_asset_address=

            selected_asset_info.get(

                "address",

                ""

            ),



        has_selected_asset=

            bool(selected_asset)

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

        # ==================================



        # Owner isolation is enforced by

        # the database query itself.



        assets = list(

            db.assets.find(

                {

                    "created_by":

                        current_user_id

                }

            )

        )



        # ==================================

        # PREPARE ASSET SELECTION OPTIONS

        # ==================================



        available_assets = []



        for asset in assets:



            asset_info = _asset_display_info(

                asset

            )



            if asset_info["id"]:



                available_assets.append(

                    asset_info

                )



        # ==================================

        # READ SELECTED ASSET FROM URL

        # ==================================



        # Example:

        # /risk-comparison?asset_id=<asset-id>

        #

        # The parameter is an identifier,

        # not an unrestricted database query.



        requested_asset_id = (

            request.args.get(

                "asset_id",

                "",

                type=str

            ) or ""

        ).strip()



        # ==================================

        # HANDLE NO AVAILABLE ASSETS

        # ==================================



        if not assets:



            return _render_risk_comparison(

                comparison=_empty_comparison(),



                mitigation_analysis={},



                defense_analysis={},



                available_assets=

                    available_assets,



                selected_asset=None,



                selected_asset_info={

                    "id": "",

                    "name": "",

                    "address": ""

                }

            )



        # ==================================

        # SELECT ONLY ONE OWNED ASSET

        # ==================================



        selected_asset = None



        if requested_asset_id:



            for asset in assets:



                if (

                    _asset_id(asset)

                    == requested_asset_id

                ):



                    selected_asset = asset



                    break



            # ==================================

            # REJECT UNKNOWN OR FOREIGN ASSET

            # ==================================



            if selected_asset is None:



                flash(

                    "The selected asset is unavailable "

                    "or you do not have permission "

                    "to access it.",

                    "error"

                )



                return redirect(

                    url_for(

                        "risk_comparison.risk_comparison"

                    )

                )



        else:



            # ==================================

            # NO AUTOMATIC ASSET SELECTION

            # ==================================



            # The initial page must not silently

            # analyze assets[0]. Wait until the

            # user explicitly chooses an asset.



            return _render_risk_comparison(

                comparison=_empty_comparison(),

                mitigation_analysis={},

                defense_analysis={},

                available_assets=available_assets,

                selected_asset=None,

                selected_asset_info={

                    "id": "",

                    "name": "",

                    "address": ""

                }

            )



        # ==================================

        # PREPARE SELECTED ASSET INFORMATION

        # ==================================



        selected_asset_info = (

            _asset_display_info(

                selected_asset

            )

        )



        # ==================================

        # SINGLE-ASSET ANALYSIS INPUT

        # ==================================



        # This is the important correction.

        #

        # All downstream services receive

        # exactly one selected asset.

        #

        # We do not pass the full user's

        # asset collection to the pipeline.



        selected_assets = [

            selected_asset

        ]



        # ==================================

        # GENERATE ATTACK GRAPH

        # ==================================



        attack_graph = (

            generate_attack_graph(

                assets=selected_assets,

                created_by=current_user_id

            )

        )



        # ==================================

        # GENERATE DEFENSE ANALYSIS

        # ==================================



        defense_analysis = (

            generate_defense_analysis(

                assets=selected_assets,

                attack_graph=attack_graph,

                created_by=current_user_id

            )

        )



        # ==================================

        # GENERATE MITIGATION RECOMMENDATIONS

        # ==================================



        mitigation_analysis = (

            generate_mitigation_recommendations(

                assets=selected_assets,

                defense_analysis=defense_analysis,

                attack_graph=attack_graph,

                created_by=current_user_id

            )

        )



        # ==================================

        # GENERATE RISK COMPARISON

        # ==================================



        comparison = (

            generate_risk_comparison(

                assets=selected_assets,

                attack_graph=attack_graph,

                defense_analysis=defense_analysis,

                mitigation_analysis=mitigation_analysis,

                created_by=current_user_id

            )

        )



        # ==================================

        # SAFE COMPARISON DOCUMENT

        # ==================================



        if not isinstance(

            comparison,

            dict

        ):



            comparison = {}



        # ==================================

        # RENDER SELECTED ASSET ANALYSIS

        # ==================================



        return _render_risk_comparison(

            comparison=comparison,



            mitigation_analysis=

                mitigation_analysis,



            defense_analysis=

                defense_analysis,



            available_assets=

                available_assets,



            selected_asset=

                selected_asset,



            selected_asset_info=

                selected_asset_info

        )



    except Exception as error:



        # ==================================

        # LOG COMPLETE ERROR

        # ==================================



        current_app.logger.exception(

            "Risk Comparison generation failed: %s",

            error

        )



        # ==================================

        # USER MESSAGE

        # ==================================



        flash(

            "Unable to generate the Risk Comparison. "

            "Please verify the available security "

            "analysis data and try again.",

            "error"

        )



        # ==================================

        # RETURN TO DASHBOARD

        # ==================================



        return redirect(

            url_for(

                "home"

            )

        )
