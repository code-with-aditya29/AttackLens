import os


class Config:

    SECRET_KEY = os.getenv("SECRET_KEY")

    MONGO_URI = os.getenv("MONGO_URI")

    MONGO_DB_NAME = os.getenv(
        "MONGO_DB_NAME",
        "attacklens"
    )