from dotenv import load_dotenv


# ==========================================
# LOAD ENVIRONMENT VARIABLES
# ==========================================

load_dotenv(
    override=True
)


from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    session
)

from pymongo import MongoClient


from config import Config


# ==========================================
# ROUTE BLUEPRINTS
# ==========================================

from routes.scan import scan_bp

from routes.auth import (
    auth_bp,
    login_required
)

from routes.admin import admin_bp

from routes.asset import asset_bp

from routes.attack_path import (
    attack_path_bp
)

from routes.defense_analysis import (
    defense_analysis_bp
)

from routes.mitigation import (
    mitigation_bp
)

from routes.risk_comparison import (
    risk_comparison_bp
)

from routes.report import (
    report_bp
)


# ==========================================
# DASHBOARD SERVICE
# ==========================================
#
# Dashboard statistics are prepared by:
#
# services/dashboard_service.py
#
# This includes:
#
# - Current asset count
# - Open service count
# - Open port count
# - Vulnerability statistics
# - Highest observed asset risk
# - Real Attack Path count generated through
#   the existing Attack Path Engine
#
# Attack-path generation itself remains in:
#
# services/attack_path_service.py
#
# ==========================================

from services.dashboard_service import (
    get_dashboard_stats
)


# ==========================================
# CREATE APPLICATION
# ==========================================

def create_app():

    # ======================================
    # CREATE FLASK APPLICATION
    # ======================================

    app = Flask(
        __name__
    )


    # ======================================
    # LOAD CONFIGURATION
    # ======================================

    app.config.from_object(
        Config
    )


    # ======================================
    # CONNECT TO MONGODB ATLAS
    # ======================================

    try:

        client = MongoClient(

            app.config["MONGO_URI"],

            serverSelectionTimeoutMS=10000

        )


        # ==================================
        # TEST DATABASE CONNECTION
        # ==================================

        client.admin.command(
            "ping"
        )


        print(
            "MongoDB Atlas connected successfully!"
        )


        # ==================================
        # STORE CLIENT
        # ==================================

        app.config[
            "MONGO_CLIENT"
        ] = client


        # ==================================
        # SELECT DATABASE
        # ==================================

        db = client.get_database(

            app.config[
                "MONGO_DB_NAME"
            ]

        )


        # ==================================
        # STORE DATABASE
        # ==================================

        app.config[
            "MONGO_DB"
        ] = db


        # ==================================
        # CREATE DATABASE INDEXES
        # ==================================

        create_database_indexes(
            db
        )


    except Exception as error:

        print(

            "MongoDB connection failed: "
            f"{error}"

        )

        raise


    # ======================================
    # REGISTER BLUEPRINTS
    # ======================================

    app.register_blueprint(
        auth_bp
    )


    app.register_blueprint(
        admin_bp
    )


    app.register_blueprint(
        scan_bp
    )


    # ======================================
    # ASSET BLUEPRINT
    # ======================================
    #
    # Asset functionality is handled by:
    #
    # routes/asset.py
    #
    # Main endpoint:
    #
    # asset.asset_inventory
    # ======================================

    app.register_blueprint(
        asset_bp
    )


    # ======================================
    # ATTACK PATH BLUEPRINT
    # ======================================
    #
    # Attack Path functionality is handled
    # by:
    #
    # routes/attack_path.py
    #
    # Endpoint:
    #
    # attack_path.attack_paths
    #
    # Actual graph/path generation remains in:
    #
    # services/attack_path_service.py
    #
    # The previous placeholder route in
    # app.py has been removed.
    # ======================================

    app.register_blueprint(
        attack_path_bp
    )


    # ======================================
    # DEFENSE ANALYSIS BLUEPRINT
    # ======================================
    #
    # Defense Analysis functionality is
    # handled by:
    #
    # routes/defense_analysis.py
    #
    # Endpoint:
    #
    # defense_analysis.defense_analysis
    #
    # The previous placeholder route in
    # app.py has been removed.
    # ======================================

    app.register_blueprint(
        defense_analysis_bp
    )


    # ======================================
    # MITIGATION BLUEPRINT
    # ======================================
    #
    # Mitigation Recommendations are handled
    # by:
    #
    # routes/mitigation.py
    #
    # Endpoint:
    #
    # mitigation.mitigation
    #
    # No duplicate /mitigation route should
    # exist in app.py.
    # ======================================

    app.register_blueprint(
        mitigation_bp
    )


    # ======================================
    # RISK COMPARISON BLUEPRINT
    # ======================================
    #
    # Before vs After Risk Comparison is
    # handled by:
    #
    # routes/risk_comparison.py
    #
    # Endpoint:
    #
    # risk_comparison.risk_comparison
    #
    # The route generates a comparison
    # between the current security state
    # and the projected post-mitigation
    # security state.
    #
    # No duplicate /risk-comparison route
    # should exist in app.py.
    # ======================================

    app.register_blueprint(
        risk_comparison_bp
    )


    # ======================================
    # REPORTS BLUEPRINT
    # ======================================
    #
    # Security Assessment Reports are
    # handled by:
    #
    # routes/report.py
    #
    # Endpoints:
    #
    # report.reports
    # report.generate_report
    #
    # The Reports route collects only the
    # authenticated user's owned assets and
    # delegates report construction to the
    # report service.
    #
    # No duplicate /reports route should
    # exist in app.py.
    # ======================================

    app.register_blueprint(
        report_bp
    )


    # ======================================
    # DASHBOARD / HOME
    # ======================================

    @app.route("/")
    @login_required
    def home():

        # ==================================
        # GET CURRENT USER INFORMATION
        # ==================================

        current_user_id = session.get(
            "admin_id"
        )

        current_user_role = session.get(
            "role"
        )


        # ==================================
        # DASHBOARD OWNERSHIP FILTER
        # ==================================
        #
        # Normal Admin:
        #
        # Only assets created by the logged-in
        # user are included.
        #
        # The Dashboard Service also uses the
        # same owner-scoped assets to calculate
        # the real Attack Path count.
        #
        #
        # Super Admin:
        #
        # Global asset statistics are shown.
        #
        # Attack-path calculation remains
        # owner-isolated inside the Dashboard
        # Service so assets belonging to
        # different users are never combined
        # into one attack graph.
        #
        #
        # This keeps dashboard ownership
        # behavior aligned with the existing
        # AttackLens access model.
        # ==================================

        if current_user_role == "super_admin":

            dashboard_stats = (
                get_dashboard_stats(
                    db
                )
            )

        else:

            dashboard_stats = (
                get_dashboard_stats(
                    db,
                    created_by=current_user_id
                )
            )


        # ==================================
        # RENDER DASHBOARD
        # ==================================
        #
        # dashboard_stats now contains:
        #
        # total_assets
        # open_services
        # open_ports
        # vulnerable_assets
        # total_vulnerabilities
        # high_risk_assets
        # critical_risk_assets
        # risk_score
        # risk_level
        # attack_paths
        #
        # ==================================

        return render_template(

            "index.html",

            current_page="dashboard",

            dashboard_stats=dashboard_stats

        )


    # ======================================
    # NEW SCAN
    # ======================================
    #
    # Dashboard "New Scan" button uses
    # this endpoint.
    #
    # Actual scan processing remains inside
    # routes/scan.py.
    # ======================================

    @app.route(
        "/new-scan"
    )
    @login_required
    def new_scan():

        return redirect(

            url_for(
                "scan.scan_target"
            )

        )


    # ======================================
    # ASSETS
    # ======================================
    #
    # The Assets route is handled by:
    #
    # routes/asset.py
    #
    # Endpoint:
    #
    # asset.asset_inventory
    #
    # No duplicate /assets route should
    # exist here.
    # ======================================


    # ======================================
    # ATTACK PATHS
    # ======================================
    #
    # Attack Path Analysis is handled by:
    #
    # routes/attack_path.py
    #
    # Endpoint:
    #
    # attack_path.attack_paths
    #
    # Graph and path generation is handled by:
    #
    # services/attack_path_service.py
    #
    # No duplicate /attack-paths route
    # should exist here.
    # ======================================


    # ======================================
    # DEFENSE ANALYSIS
    # ======================================
    #
    # Defense Analysis is now handled by:
    #
    # routes/defense_analysis.py
    #
    # Endpoint:
    #
    # defense_analysis.defense_analysis
    #
    # No duplicate /defense-analysis route
    # should exist here.
    # ======================================


    # ======================================
    # MITIGATION
    # ======================================
    #
    # Mitigation Recommendations are handled
    # by:
    #
    # routes/mitigation.py
    #
    # Endpoint:
    #
    # mitigation.mitigation
    #
    # No duplicate /mitigation route should
    # exist here.
    # ======================================


    # ======================================
    # RISK COMPARISON
    # ======================================
    #
    # Before vs After Risk Comparison is
    # handled by:
    #
    # routes/risk_comparison.py
    #
    # Endpoint:
    #
    # risk_comparison.risk_comparison
    #
    # No duplicate /risk-comparison route
    # should exist here.
    # ======================================


    # ======================================
    # REPORTS
    # ======================================
    #
    # Security Assessment Reports are
    # handled by:
    #
    # routes/report.py
    #
    # Endpoints:
    #
    # report.reports
    # report.generate_report
    #
    # No duplicate /reports route should
    # exist here.
    # ======================================


    # ======================================
    # RETURN APPLICATION
    # ======================================

    return app


# ==========================================
# CREATE DATABASE INDEXES
# ==========================================

def create_database_indexes(
    db
):

    try:

        # ==================================
        # ADMIN INDEX
        # ==================================

        db.admins.create_index(

            "email",

            unique=True

        )


        # ==================================
        # SCAN INDEXES
        # ==================================

        db.scans.create_index(
            "created_by"
        )


        db.scans.create_index(
            "created_at"
        )


        db.scans.create_index(
            "status"
        )


        db.scans.create_index(

            [
                (
                    "created_by",
                    1
                ),

                (
                    "created_at",
                    -1
                )
            ]

        )


        # ==================================
        # ASSET INDEXES
        # ==================================

        db.assets.create_index(
            "created_by"
        )


        db.assets.create_index(
            "last_seen"
        )


        db.assets.create_index(
            "risk_level"
        )


        db.assets.create_index(

            [
                (
                    "created_by",
                    1
                ),

                (
                    "target",
                    1
                )
            ],

            unique=True

        )


        print(
            "MongoDB indexes verified successfully!"
        )


    except Exception as error:

        # Index failure should not prevent
        # application startup.

        print(

            "MongoDB index warning: "
            f"{error}"

        )


# ==========================================
# CREATE APPLICATION INSTANCE
# ==========================================

app = create_app()


# ==========================================
# RUN APPLICATION
# ==========================================

if __name__ == "__main__":

    app.run(

        debug=True,

        use_reloader=False

    )