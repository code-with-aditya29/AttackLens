from flask import Flask, render_template

from config import Config


def create_app():
    app = Flask(__name__)

    # Load application configuration
    app.config.from_object(Config)

    # Dashboard route
    @app.route("/")
    def index():
        return render_template(
            "index.html",
            current_page="dashboard"
        )

    # Scan Target route
    @app.route("/scan")
    def scan():
        return render_template(
            "scan.html",
            current_page="scan"
        )

    # Assets route
    @app.route("/assets")
    def assets():
        return render_template(
            "assets.html",
            current_page="assets"
        )

    # Attack Paths route
    @app.route("/attack-paths")
    def attack_paths():
        return render_template(
            "attack_paths.html",
            current_page="attack_paths"
        )

    # Defense Analysis route
    @app.route("/defense-analysis")
    def defense_analysis():
        return render_template(
            "defense_analysis.html",
            current_page="defense_analysis"
        )

    # Reports route
    @app.route("/reports")
    def reports():
        return render_template(
            "reports.html",
            current_page="reports"
        )

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)