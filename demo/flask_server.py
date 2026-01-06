"""
Flask Demo Server using Ab0t Auth.

Run with: flask --app flask_server run --port 5000 --reload
"""

from flask import Flask, jsonify, g

from ab0t_auth.flask import (
    Ab0tAuth,
    get_current_user,
    login_required,
    permission_required,
    permissions_required,
    role_required,
    permission_pattern_required,
)


# =============================================================================
# Configuration
# =============================================================================

AUTH_URL = "https://auth.service.ab0t.com"  # Replace with your Ab0t auth URL


# =============================================================================
# Flask App
# =============================================================================

app = Flask(__name__)
app.config["AB0T_AUTH_URL"] = AUTH_URL
app.config["AB0T_AUTH_EXCLUDE_PATHS"] = ["/", "/health"]

# Initialize Ab0t Auth extension
auth = Ab0tAuth(app, auth_url=AUTH_URL, auto_authenticate=True)


# =============================================================================
# Public Routes
# =============================================================================

@app.route("/")
def root():
    """Public endpoint - no auth required."""
    return jsonify({
        "message": "Welcome to Ab0t Auth Demo (Flask)!",
        "endpoints": {
            "public": ["/", "/health"],
            "protected": ["/me", "/protected"],
            "permissions": ["/users", "/admin", "/reports"],
        },
    })


@app.route("/health")
def health():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "framework": "flask",
        "metrics": auth.metrics.to_dict(),
    })


# =============================================================================
# Protected Routes (Require Authentication)
# =============================================================================

@app.route("/me")
@login_required
def get_me():
    """Get current user info - requires authentication."""
    user = get_current_user()
    return jsonify({
        "user_id": user.user_id,
        "email": user.email,
        "org_id": user.org_id,
        "permissions": list(user.permissions),
        "roles": list(user.roles),
        "auth_method": user.auth_method.value,
    })


@app.route("/protected")
@login_required
def protected_route():
    """Protected endpoint - any authenticated user."""
    user = get_current_user()
    return jsonify({
        "message": f"Hello, {user.email or user.user_id}!",
        "authenticated": True,
    })


@app.route("/context")
@login_required
def get_context():
    """Get full auth context."""
    ctx = g.auth_context
    return jsonify({
        "user_id": ctx.user.user_id if ctx.user else None,
        "is_authenticated": ctx.is_authenticated,
        "request_id": ctx.request_id,
        "timestamp": ctx.timestamp.isoformat(),
    })


# =============================================================================
# Permission-Based Routes
# =============================================================================

@app.route("/users")
@permission_required("users:read")
def list_users():
    """List users - requires 'users:read' permission."""
    user = get_current_user()
    return jsonify({
        "users": [
            {"id": 1, "name": "Alice"},
            {"id": 2, "name": "Bob"},
        ],
        "requested_by": user.user_id,
    })


@app.route("/users", methods=["POST"])
@permission_required("users:write")
def create_user():
    """Create user - requires 'users:write' permission."""
    user = get_current_user()
    return jsonify({
        "created": True,
        "created_by": user.user_id,
    })


@app.route("/users/<int:user_id>", methods=["DELETE"])
@permission_required("users:delete")
def delete_user(user_id):
    """Delete user - requires 'users:delete' permission."""
    user = get_current_user()
    return jsonify({
        "deleted": user_id,
        "deleted_by": user.user_id,
    })


@app.route("/admin")
@permission_required("admin:access")
def admin_panel():
    """Admin panel - requires 'admin:access' permission."""
    user = get_current_user()
    return jsonify({
        "admin": True,
        "user": user.user_id,
        "cache_stats": {
            "hit_rate": auth.metrics.cache_hit_rate,
            "total_validations": auth.metrics.token_validations,
        },
    })


@app.route("/reports")
@permissions_required("reports:read", "data:access", require_all=False)
def get_reports():
    """Reports - requires 'reports:read' OR 'data:access'."""
    user = get_current_user()
    return jsonify({
        "reports": [
            {"id": 1, "title": "Q1 Sales"},
            {"id": 2, "title": "User Growth"},
        ],
        "requested_by": user.user_id,
    })


# =============================================================================
# Role-Based Routes
# =============================================================================

@app.route("/admin/dashboard")
@role_required("admin")
def admin_dashboard():
    """Admin dashboard - requires 'admin' role."""
    user = get_current_user()
    return jsonify({
        "dashboard": "admin",
        "user": user.user_id,
    })


@app.route("/staff")
@role_required("staff")
def staff_area():
    """Staff area - requires 'staff' role."""
    user = get_current_user()
    return jsonify({
        "area": "staff",
        "user": user.user_id,
    })


# =============================================================================
# Pattern-Based Routes
# =============================================================================

@app.route("/admin/settings")
@permission_pattern_required("admin:*")
def admin_settings():
    """Admin settings - requires any 'admin:*' permission."""
    user = get_current_user()
    return jsonify({
        "settings": {
            "theme": "dark",
            "notifications": True,
        },
        "user": user.user_id,
    })


# =============================================================================
# Optional Auth (Manual Check)
# =============================================================================

@app.route("/content")
def get_content():
    """Content that varies based on auth status."""
    user = get_current_user()

    if user:
        return jsonify({
            "content": "Premium content for authenticated users",
            "user": user.user_id,
            "tier": "premium",
        })

    return jsonify({
        "content": "Basic content for anonymous users",
        "tier": "free",
    })


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
