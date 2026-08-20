from dotenv import load_dotenv

# Load .env BEFORE importing Config
load_dotenv()

from datetime import datetime
from getpass import getpass

from pymongo import MongoClient
from werkzeug.security import generate_password_hash

from config import Config

def create_super_admin():

    try:
        # Connect to MongoDB Atlas
        client = MongoClient(Config.MONGO_URI)

        # Test the connection
        client.admin.command("ping")

        print("MongoDB Atlas connected successfully!\n")

        # Select AttackLens database
        db = client["attacklens"]

        # Select users collection
        users = db["users"]

        # Prevent multiple Super Admin accounts
        existing_super_admin = users.find_one(
            {"role": "super_admin"}
        )

        if existing_super_admin:
            print("A Super Admin already exists.")
            return

        # Get Super Admin details
        username = input("Enter Super Admin username: ").strip()
        email = input("Enter Super Admin email: ").strip()

        # Basic validation
        if not username or not email:
            print("Username and email cannot be empty.")
            return

        # Check duplicate username
        if users.find_one({"username": username}):
            print("This username already exists.")
            return

        # Check duplicate email
        if users.find_one({"email": email}):
            print("This email already exists.")
            return

        # Hidden password input
        password = getpass("Enter Super Admin password: ")
        confirm_password = getpass("Confirm Super Admin password: ")

        # Check password confirmation
        if password != confirm_password:
            print("Passwords do not match.")
            return

        # Basic password validation
        if len(password) < 8:
            print("Password must be at least 8 characters long.")
            return

        # Create Super Admin document
        super_admin = {
            "username": username,
            "email": email,
            "password": generate_password_hash(password),
            "role": "super_admin",
            "permissions": ["all"],
            "status": "active",
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }

        # Insert into MongoDB
        result = users.insert_one(super_admin)

        print("\nSuper Admin created successfully!")
        print(f"User ID: {result.inserted_id}")

    except Exception as e:
        print(f"Error creating Super Admin: {e}")


if __name__ == "__main__":
    create_super_admin()