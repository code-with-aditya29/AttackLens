from dotenv import load_dotenv

# Load .env FIRST
load_dotenv()

from flask import Flask, render_template
from pymongo import MongoClient

from config import Config



# Load environment variables from .env
load_dotenv()


def create_app():
    app = Flask(__name__)

    # Load configuration
    app.config.from_object(Config)

    # Connect to MongoDB Atlas
    try:
        client = MongoClient(app.config["MONGO_URI"])

        # Test MongoDB connection
        client.admin.command("ping")

        print("MongoDB Atlas connected successfully!")

        # Store MongoDB client
        app.config["MONGO_CLIENT"] = client

        # Select AttackLens database
        db = client["attacklens"]

        # Store database reference
        app.config["MONGO_DB"] = db

        print("AttackLens database selected successfully!")

    except Exception as e:
        print(f"MongoDB connection failed: {e}")


    # Dashboard / Home
    @app.route("/")
    def home():
        return render_template(
            "index.html",
            current_page="dashboard"
        )


    # Scan page
    @app.route("/scan")
    def scan():
        return render_template(
            "scan.html",
            current_page="scan"
        )


    # Assets page
    @app.route("/assets")
    def assets():
        return render_template(
            "assets.html",
            current_page="assets"
        )


    # Attack Paths page
    @app.route("/attack-paths")
    def attack_paths():
        return render_template(
            "attack_paths.html",
            current_page="attack_paths"
        )


    # Defense Analysis page
    @app.route("/defense-analysis")
    def defense_analysis():
        return render_template(
            "defense_analysis.html",
            current_page="defense_analysis"
        )


    # Reports page
    @app.route("/reports")
    def reports():
        return render_template(
            "reports.html",
            current_page="reports"
        )


    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        debug=True,
        use_reloader=False
    )