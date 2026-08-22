from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    current_app
)

from werkzeug.security import (
    check_password_hash,
    generate_password_hash
)

from functools import wraps
from bson import ObjectId
from datetime import datetime


auth_bp = Blueprint(
    "auth",
    __name__
)


# ==========================================
# LOGIN REQUIRED DECORATOR
# ==========================================

def login_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if "admin_id" not in session:

            flash(
                "Please login to access this page.",
                "error"
            )

            return redirect(
                url_for("auth.login")
            )

        return f(*args, **kwargs)

    return decorated_function


# ==========================================
# SUPER ADMIN REQUIRED DECORATOR
# ==========================================

def super_admin_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if "admin_id" not in session:

            flash(
                "Please login first.",
                "error"
            )

            return redirect(
                url_for("auth.login")
            )

        if session.get("role") != "super_admin":

            flash(
                "You do not have permission to access this page.",
                "error"
            )

            return redirect(
                url_for("home")
            )

        return f(*args, **kwargs)

    return decorated_function


# ==========================================
# LOGIN
# ==========================================

@auth_bp.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if "admin_id" in session:

        return redirect(
            url_for("home")
        )

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        if not email or not password:

            flash(
                "Email and password are required.",
                "error"
            )

            return render_template(
                "login.html"
            )

        db = current_app.config["MONGO_DB"]

        admin = db.admins.find_one(
            {
                "email": email
            }
        )

        if admin and check_password_hash(
            admin["password"],
            password
        ):

            session["admin_id"] = str(
                admin["_id"]
            )

            session["username"] = admin.get(
                "username",
                "Admin"
            )

            session["role"] = admin.get(
                "role",
                "admin"
            )

            flash(
                "Login successful!",
                "success"
            )

            return redirect(
                url_for("home")
            )

        flash(
            "Invalid email or password.",
            "error"
        )

    return render_template(
        "login.html"
    )


# ==========================================
# LOGOUT
# ==========================================

@auth_bp.route(
    "/logout"
)
@login_required
def logout():

    session.clear()

    flash(
        "You have been logged out successfully.",
        "success"
    )

    return redirect(
        url_for("auth.login")
    )


# ==========================================
# ADMIN MANAGEMENT
# ==========================================

@auth_bp.route(
    "/admin-management"
)
@super_admin_required
def admin_management():

    db = current_app.config["MONGO_DB"]

    admins = list(
        db.admins.find().sort(
            "created_at",
            -1
        )
    )

    return render_template(
        "admin_management.html",
        admins=admins,
        current_page="admin_management"
    )


# ==========================================
# ADD ADMIN
# ==========================================

@auth_bp.route(
    "/admin-management/add",
    methods=["GET", "POST"]
)
@super_admin_required
def add_admin():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        db = current_app.config["MONGO_DB"]


        # ----------------------------------
        # VALIDATE REQUIRED FIELDS
        # ----------------------------------

        if not all([
            username,
            email,
            password,
            confirm_password
        ]):

            flash(
                "All fields are required.",
                "error"
            )

            return redirect(
                url_for("auth.add_admin")
            )


        # ----------------------------------
        # PASSWORD VALIDATION
        # ----------------------------------

        if len(password) < 8:

            flash(
                "Password must be at least 8 characters long.",
                "error"
            )

            return redirect(
                url_for("auth.add_admin")
            )


        # ----------------------------------
        # CONFIRM PASSWORD
        # ----------------------------------

        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "error"
            )

            return redirect(
                url_for("auth.add_admin")
            )


        # ----------------------------------
        # CHECK DUPLICATE EMAIL
        # ----------------------------------

        existing_admin = db.admins.find_one(
            {
                "email": email
            }
        )

        if existing_admin:

            flash(
                "An admin with this email already exists.",
                "error"
            )

            return redirect(
                url_for("auth.add_admin")
            )


        # ----------------------------------
        # CREATE ADMIN
        # ----------------------------------

        db.admins.insert_one({

            "username": username,

            "email": email,

            "password": generate_password_hash(
                password
            ),

            "role": "admin",

            "created_at": datetime.utcnow()

        })


        flash(
            "New admin created successfully!",
            "success"
        )

        return redirect(
            url_for("auth.admin_management")
        )


    return render_template(
        "add_admin.html",
        current_page="admin_management"
    )


# ==========================================
# EDIT ADMIN
# ==========================================

@auth_bp.route(
    "/admin-management/edit/<admin_id>",
    methods=["GET", "POST"]
)
@super_admin_required
def edit_admin(admin_id):

    db = current_app.config["MONGO_DB"]


    # ----------------------------------
    # VALIDATE OBJECT ID
    # ----------------------------------

    try:

        admin = db.admins.find_one(
            {
                "_id": ObjectId(admin_id)
            }
        )

    except Exception:

        flash(
            "Invalid admin ID.",
            "error"
        )

        return redirect(
            url_for("auth.admin_management")
        )


    # ----------------------------------
    # CHECK ADMIN EXISTS
    # ----------------------------------

    if not admin:

        flash(
            "Administrator not found.",
            "error"
        )

        return redirect(
            url_for("auth.admin_management")
        )


    # ----------------------------------
    # PROTECT SUPER ADMIN
    # ----------------------------------

    if admin.get("role") == "super_admin":

        flash(
            "Super Admin account cannot be edited.",
            "error"
        )

        return redirect(
            url_for("auth.admin_management")
        )


    # ==================================
    # UPDATE ADMIN
    # ==================================

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )


        # ----------------------------------
        # VALIDATE REQUIRED FIELDS
        # ----------------------------------

        if not username or not email:

            flash(
                "Username and email are required.",
                "error"
            )

            return redirect(
                url_for(
                    "auth.edit_admin",
                    admin_id=admin_id
                )
            )


        # ----------------------------------
        # CHECK DUPLICATE EMAIL
        # ----------------------------------

        existing_admin = db.admins.find_one(

            {
                "email": email,

                "_id": {
                    "$ne": ObjectId(admin_id)
                }
            }

        )


        if existing_admin:

            flash(
                "Another administrator already uses this email.",
                "error"
            )

            return redirect(
                url_for(
                    "auth.edit_admin",
                    admin_id=admin_id
                )
            )


        # ----------------------------------
        # UPDATE DATA
        # ----------------------------------

        update_data = {

            "username": username,

            "email": email

        }


        # ----------------------------------
        # OPTIONAL PASSWORD CHANGE
        # ----------------------------------

        if password:

            if len(password) < 8:

                flash(
                    "Password must be at least 8 characters long.",
                    "error"
                )

                return redirect(
                    url_for(
                        "auth.edit_admin",
                        admin_id=admin_id
                    )
                )


            if password != confirm_password:

                flash(
                    "Passwords do not match.",
                    "error"
                )

                return redirect(
                    url_for(
                        "auth.edit_admin",
                        admin_id=admin_id
                    )
                )


            update_data["password"] = generate_password_hash(
                password
            )


        # ----------------------------------
        # UPDATE DATABASE
        # ----------------------------------

        db.admins.update_one(

            {
                "_id": ObjectId(admin_id)
            },

            {
                "$set": update_data
            }

        )


        flash(
            "Administrator updated successfully.",
            "success"
        )


        return redirect(
            url_for("auth.admin_management")
        )


    # ==================================
    # SHOW EDIT PAGE
    # ==================================

    return render_template(

        "edit_admin.html",

        admin=admin,

        current_page="admin_management"

    )


# ==========================================
# DELETE ADMIN
# ==========================================

@auth_bp.route(
    "/admin-management/delete/<admin_id>",
    methods=["POST"]
)
@super_admin_required
def delete_admin(admin_id):

    db = current_app.config["MONGO_DB"]


    # ----------------------------------
    # VALIDATE OBJECT ID
    # ----------------------------------

    try:

        admin = db.admins.find_one(
            {
                "_id": ObjectId(admin_id)
            }
        )

    except Exception:

        flash(
            "Invalid admin ID.",
            "error"
        )

        return redirect(
            url_for("auth.admin_management")
        )


    # ----------------------------------
    # CHECK ADMIN EXISTS
    # ----------------------------------

    if not admin:

        flash(
            "Admin not found.",
            "error"
        )

        return redirect(
            url_for("auth.admin_management")
        )


    # ----------------------------------
    # SUPER ADMIN PROTECTION
    # ----------------------------------

    if admin.get("role") == "super_admin":

        flash(
            "Super Admin account cannot be deleted.",
            "error"
        )

        return redirect(
            url_for("auth.admin_management")
        )


    # ----------------------------------
    # PREVENT SELF DELETION
    # ----------------------------------

    if str(admin["_id"]) == session.get("admin_id"):

        flash(
            "You cannot delete your own account.",
            "error"
        )

        return redirect(
            url_for("auth.admin_management")
        )


    # ----------------------------------
    # DELETE ADMIN
    # ----------------------------------

    db.admins.delete_one(
        {
            "_id": ObjectId(admin_id)
        }
    )


    flash(
        "Admin deleted successfully.",
        "success"
    )


    return redirect(
        url_for("auth.admin_management")
    )