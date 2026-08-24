from dotenv import load_dotenv

# Load environment variables first
load_dotenv(override=True)

from flask import Flask, app, render_template
from pymongo import MongoClient

from config import Config

from routes.scan import scan_bp
from routes.auth import (
    auth_bp,
    login_required
    
)

from routes.admin import admin_bp


# =================================
# CREATE APPLICATION
# =================================

def create_app():

    # Create Flask application
    app = Flask(__name__)

    # Load configuration
    app.config.from_object(Config)


    # =================================
    # CONNECT TO MONGODB ATLAS
    # =================================

    try:

        client = MongoClient(
            app.config["MONGO_URI"],
            serverSelectionTimeoutMS=10000
        )

        # Test MongoDB connection
        client.admin.command("ping")

        print(
            "MongoDB Atlas connected successfully!"
        )

        # Store MongoDB client
        app.config["MONGO_CLIENT"] = client

        # Select AttackLens database
        db = client.get_database(
            app.config["MONGO_DB_NAME"]
        )

        # Store database connection
        app.config["MONGO_DB"] = db


    except Exception as e:

        print(
            f"MongoDB connection failed: {e}"
        )

        raise


    # =================================
    # REGISTER BLUEPRINTS
    # =================================

    app.register_blueprint(
        auth_bp
    )

    app.register_blueprint(
        admin_bp
    )

    app.register_blueprint(
    scan_bp
    )

    # =================================
    # DASHBOARD / HOME
    # =================================

    @app.route("/")
    @login_required
    def home():

        return render_template(
            "index.html",
            current_page="dashboard"
        )


    # =================================
    # SCAN TARGET
    # =================================

    @app.route("/scan")
    @login_required
    def scan():

        return render_template(
            "scan.html",
            current_page="scan"
        )


    # =================================
    # ASSETS
    # =================================

    @app.route("/assets")
    @login_required
    def assets():

        return render_template(
            "assets.html",
            current_page="assets"
        )


    # =================================
    # ATTACK PATHS
    # =================================

    @app.route("/attack-paths")
    @login_required
    def attack_paths():

        return render_template(
            "attack_paths.html",
            current_page="attack_paths"
        )


    # =================================
    # DEFENSE ANALYSIS
    # =================================

    @app.route("/defense-analysis")
    @login_required
    def defense_analysis():

        return render_template(
            "defense_analysis.html",
            current_page="defense_analysis"
        )


    # =================================
    # REPORTS
    # =================================

    @app.route("/reports")
    @login_required
    def reports():

        return render_template(
            "reports.html",
            current_page="reports"
        )


    # =================================
    # RETURN APPLICATION
    # =================================

    return app


# =================================
# CREATE APPLICATION INSTANCE
# =================================

app = create_app()


# =================================
# RUN APPLICATION
# =================================

if __name__ == "__main__":
    app.run(
        debug=True,
        use_reloader=False
    )