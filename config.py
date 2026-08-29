import os


class Config:

    # ==========================================
    # FLASK SECURITY
    # ==========================================

    SECRET_KEY = os.getenv(
        "SECRET_KEY"
    )


    # ==========================================
    # MONGODB ATLAS
    # ==========================================

    MONGO_URI = os.getenv(
        "MONGO_URI"
    )

    MONGO_DB_NAME = os.getenv(
        "MONGO_DB_NAME",
        "attacklens"
    )


    # ==========================================
    # NVD / CVE CONFIGURATION
    # ==========================================

    # API key is loaded securely from .env.
    # Never place the actual API key here.

    NVD_API_KEY = os.getenv(
        "NVD_API_KEY"
    )

    NVD_API_BASE_URL = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
    )


    # ==========================================
    # NMAP CONFIGURATION
    # ==========================================

    NMAP_PATH = os.getenv(
        "NMAP_PATH",
        "nmap"
    )

    SCAN_TIMEOUT = int(
        os.getenv(
            "SCAN_TIMEOUT",
            "300"
        )
    )


    # ==========================================
    # HTTP ENUMERATION CONFIGURATION
    # ==========================================

    HTTP_TIMEOUT = int(
        os.getenv(
            "HTTP_TIMEOUT",
            "10"
        )
    )


    # ==========================================
    # SESSION SECURITY
    # ==========================================

    SESSION_COOKIE_HTTPONLY = True

    SESSION_COOKIE_SAMESITE = "Lax"

    # False while developing locally over HTTP.
    # Change to True when deployed using HTTPS.

    SESSION_COOKIE_SECURE = False


    # ==========================================
    # REQUEST SIZE PROTECTION
    # ==========================================

    MAX_CONTENT_LENGTH = (
        2 * 1024 * 1024
    )