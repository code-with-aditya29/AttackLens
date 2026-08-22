
from pymongo import MongoClient
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv
import os


# =================================
# LOAD ENVIRONMENT VARIABLES
# =================================

load_dotenv()


# =================================
# CONNECT TO MONGODB
# =================================

client = MongoClient(
    os.getenv("MONGO_URI")
)

db = client[
    os.getenv(
        "MONGO_DB_NAME",
        "attacklens"
    )
]


# =================================
# NEW SUPER ADMIN DETAILS
# =================================

USERNAME = "Aditya"

EMAIL = "attacklenss@gmail.com"

PASSWORD = "attacklens_v1"


# =================================
# CHECK IF ADMIN ALREADY EXISTS
# =================================

admin = db.admins.find_one(
    {
        "email": EMAIL
    }
)


# =================================
# UPDATE OR CREATE ADMIN
# =================================

if admin:

    db.admins.update_one(

        {
            "_id": admin["_id"]
        },

        {
            "$set": {

                "username": USERNAME,

                "email": EMAIL,

                "password": generate_password_hash(
                    PASSWORD
                ),

                "role": "super_admin"

            }

        }

    )

    print(
        "Existing Super Admin updated successfully!"
    )


else:

    db.admins.insert_one(

        {

            "username": USERNAME,

            "email": EMAIL,

            "password": generate_password_hash(
                PASSWORD
            ),

            "role": "super_admin"

        }

    )

    print(
        "New Super Admin created successfully!"
    )


# =================================
# CLOSE CONNECTION
# =================================

client.close()

