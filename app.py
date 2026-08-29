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
    url_for
)

from pymongo import MongoClient


from config import Config


from routes.scan import scan_bp

from routes.auth import (
    auth_bp,
    login_required
)

from routes.admin import admin_bp


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
    # DASHBOARD / HOME
    # ======================================

    @app.route("/")
    @login_required
    def home():

        return render_template(

            "index.html",

            current_page="dashboard"

        )


    # ======================================
    # NEW SCAN
    # ======================================
    #
    # Dashboard "New Scan" button will use
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

    @app.route(
        "/assets"
    )
    @login_required
    def assets():

        return render_template(

            "assets.html",

            current_page="assets"

        )


    # ======================================
    # ATTACK PATHS
    # ======================================

    @app.route(
        "/attack-paths"
    )
    @login_required
    def attack_paths():

        return render_template(

            "attack_paths.html",

            current_page="attack_paths"

        )


    # ======================================
    # DEFENSE ANALYSIS
    # ======================================

    @app.route(
        "/defense-analysis"
    )
    @login_required
    def defense_analysis():

        return render_template(

            "defense_analysis.html",

            current_page="defense_analysis"

        )


    # ======================================
    # REPORTS
    # ======================================

    @app.route(
        "/reports"
    )
    @login_required
    def reports():

        return render_template(

            "reports.html",

            current_page="reports"

        )


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