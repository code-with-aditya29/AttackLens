
from dotenv import load_dotenv

# Load .env before importing Config
load_dotenv()

from datetime import datetime
from getpass import getpass

from pymongo import MongoClient
from werkzeug.security import generate_password_hash

from config import Config


def create_admin():

    try:
        # Connect to MongoDB Atlas
        client = MongoClient(Config.MONGO_URI)

        # Test connection
        client.admin.command("ping")

        print("MongoDB Atlas connected successfully!\n")

        # Select AttackLens database and users collection
        db = client["attacklens"]
        users = db["users"]

        # Get Admin details
        username = input("Enter Admin username: ").strip()
        email = input("Enter Admin email: ").strip()

        # Validate required fields
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
        password = getpass("Enter Admin password: ")
        confirm_password = getpass("Confirm Admin password: ")

        # Validate password confirmation
        if password != confirm_password:
            print("Passwords do not match.")
            return

        # Basic password validation
        if len(password) < 8:
            print("Password must be at least 8 characters long.")
            return

        # Available permissions
        available_permissions = [
            "scan_target",
            "assets",
            "attack_paths",
            "defense_analysis",
            "reports"
        ]

        print("\nAvailable permissions:")

        for number, permission in enumerate(
            available_permissions,
            start=1
        ):
            print(f"{number}. {permission}")

        # Select permissions
        selected = input(
            "\nEnter permission numbers separated by commas "
            "(Example: 1,2,5): "
        ).strip()

        selected_permissions = []

        if selected:
            try:
                selected_numbers = [
                    int(number.strip())
                    for number in selected.split(",")
                ]

                for number in selected_numbers:
                    if 1 <= number <= len(available_permissions):
                        permission = available_permissions[number - 1]

                        if permission not in selected_permissions:
                            selected_permissions.append(permission)

            except ValueError:
                print("Invalid permission selection.")
                return

        # Require at least one permission
        if not selected_permissions:
            print("At least one permission must be assigned.")
            return

        # Create Admin document
        admin = {
            "username": username,
            "email": email,
            "password": generate_password_hash(password),
            "role": "admin",
            "permissions": selected_permissions,
            "status": "active",
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }

        # Insert Admin into MongoDB
        result = users.insert_one(admin)

        print("\nAdmin created successfully!")
        print(f"User ID: {result.inserted_id}")
        print(f"Assigned permissions: {selected_permissions}")

    except Exception as e:
        print(f"Error creating Admin: {e}")


if __name__ == "__main__":
    create_admin()

