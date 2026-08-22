from datetime import datetime

from bson import ObjectId

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    current_app
)

from werkzeug.security import generate_password_hash

from routes.auth import super_admin_required


admin_bp = Blueprint(
    "admin",
    __name__
)


# =================================
# ADMIN MANAGEMENT
# =================================

@admin_bp.route(
    "/admin-management",
    methods=["GET"]
)
@super_admin_required
def admin_management():

    db = current_app.config["MONGO_DB"]

    admins = list(
        db.users.find(
            {
                "role": "admin"
            }
        ).sort(
            "created_at",
            -1
        )
    )

    return render_template(
        "admin_management.html",
        admins=admins,
        current_page="admin_management"
    )


# =================================
# ADD ADMIN
# =================================

@admin_bp.route(
    "/admin-management/add",
    methods=["POST"]
)
@super_admin_required
def add_admin():

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

    permissions = request.form.getlist(
        "permissions"
    )

    # -----------------------------
    # VALIDATION
    # -----------------------------

    if not username or not email:

        flash(
            "Username and email are required.",
            "error"
        )

        return redirect(
            url_for(
                "admin.admin_management"
            )
        )

    if len(password) < 8:

        flash(
            "Password must be at least 8 characters long.",
            "error"
        )

        return redirect(
            url_for(
                "admin.admin_management"
            )
        )

    if password != confirm_password:

        flash(
            "Passwords do not match.",
            "error"
        )

        return redirect(
            url_for(
                "admin.admin_management"
            )
        )

    db = current_app.config["MONGO_DB"]

    # Check duplicate username
    existing_username = db.users.find_one(
        {
            "username": username
        }
    )

    if existing_username:

        flash(
            "Username already exists.",
            "error"
        )

        return redirect(
            url_for(
                "admin.admin_management"
            )
        )

    # Check duplicate email
    existing_email = db.users.find_one(
        {
            "email": email
        }
    )

    if existing_email:

        flash(
            "Email address already exists.",
            "error"
        )

        return redirect(
            url_for(
                "admin.admin_management"
            )
        )

    # -----------------------------
    # CREATE ADMIN
    # -----------------------------

    new_admin = {

        "username": username,

        "email": email,

        "password": generate_password_hash(
            password
        ),

        "role": "admin",

        "permissions": permissions,

        "status": "active",

        "created_at": datetime.utcnow(),

        "updated_at": datetime.utcnow()

    }

    db.users.insert_one(
        new_admin
    )

    flash(
        f"Admin '{username}' created successfully!",
        "success"
    )

    return redirect(
        url_for(
            "admin.admin_management"
        )
    )


# =================================
# TOGGLE ADMIN STATUS
# =================================

@admin_bp.route(
    "/admin-management/<admin_id>/toggle-status",
    methods=["POST"]
)
@super_admin_required
def toggle_admin_status(admin_id):

    db = current_app.config["MONGO_DB"]

    try:

        admin = db.users.find_one(
            {
                "_id": ObjectId(admin_id),
                "role": "admin"
            }
        )

        if not admin:

            flash(
                "Admin not found.",
                "error"
            )

            return redirect(
                url_for(
                    "admin.admin_management"
                )
            )

        new_status = (
            "inactive"
            if admin.get("status") == "active"
            else "active"
        )

        db.users.update_one(
            {
                "_id": ObjectId(admin_id)
            },
            {
                "$set": {
                    "status": new_status,
                    "updated_at": datetime.utcnow()
                }
            }
        )

        flash(
            f"Admin status changed to {new_status}.",
            "success"
        )

    except Exception:

        flash(
            "Unable to update Admin status.",
            "error"
        )

    return redirect(
        url_for(
            "admin.admin_management"
        )
    )


# =================================
# DELETE ADMIN
# =================================

@admin_bp.route(
    "/admin-management/<admin_id>/delete",
    methods=["POST"]
)
@super_admin_required
def delete_admin(admin_id):

    db = current_app.config["MONGO_DB"]

    try:

        result = db.users.delete_one(
            {
                "_id": ObjectId(admin_id),
                "role": "admin"
            }
        )

        if result.deleted_count == 1:

            flash(
                "Admin deleted successfully.",
                "success"
            )

        else:

            flash(
                "Admin not found.",
                "error"
            )

    except Exception:

        flash(
            "Unable to delete Admin.",
            "error"
        )

    return redirect(
        url_for(
            "admin.admin_management"
        )
    )