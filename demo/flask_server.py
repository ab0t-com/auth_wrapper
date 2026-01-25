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
# Advanced Authorization (Check Callbacks)
# =============================================================================

# Flask check callbacks receive only the user (request is global).
# Access flask.request for path params, headers, etc.

from flask import request


def can_access_tenant(user):
    """Check if user belongs to the requested tenant."""
    tenant_id = request.view_args.get("tenant_id")
    return user.org_id == tenant_id or user.has_permission("admin:cross_tenant")


def can_access_domain(user):
    """Check if user can access the requested domain scope."""
    domain = request.view_args.get("domain", "")
    scope = domain.split('.')[0]  # e.g., "public" from "public.example.com"

    return user.has_any_permission(
        f"controller.write.services_{scope}",
        "controller.write.services_all",
        "controller.admin",
    )


@app.route("/tenants/<tenant_id>/data")
@login_required(check=can_access_tenant, check_error="Tenant access denied")
def get_tenant_data(tenant_id):
    """
    Tenant-scoped data - uses check callback to verify tenant membership.

    The check callback automatically verifies the user belongs to this tenant
    or has cross-tenant admin permission.
    """
    user = get_current_user()
    return jsonify({
        "tenant_id": tenant_id,
        "user_org": user.org_id,
        "data": {"example": "tenant-specific data"},
    })


@app.route("/<domain>/services", methods=["POST"])
@login_required(check=can_access_domain, check_error="Domain access denied")
def register_domain_service(domain):
    """
    Domain-scoped service registration.

    Uses check callback to verify user has permission for this domain scope.
    For example:
    - User with 'controller.write.services_public' can access public.example.com
    - User with 'controller.write.services_all' can access any domain
    - User with 'controller.admin' can access any domain
    """
    user = get_current_user()
    return jsonify({
        "registered": True,
        "domain": domain,
        "scope": domain.split('.')[0],
        "by_user": user.user_id,
    })


@app.route("/<domain>/services/<service_id>", methods=["DELETE"])
@login_required(check=can_access_domain, check_error="Domain access denied")
def delete_domain_service(domain, service_id):
    """Delete service - reuses same domain access check."""
    user = get_current_user()
    return jsonify({
        "deleted": service_id,
        "domain": domain,
        "by_user": user.user_id,
    })


# Multiple checks with "any" mode (owner OR admin can delete)
def is_resource_owner(user):
    """Check if user owns the resource (simplified)."""
    resource_id = request.view_args.get("resource_id")
    # In real app: check database for ownership
    return resource_id.startswith(user.user_id[:4])


def is_admin_user(user):
    """Check if user is an admin."""
    return user.has_permission("admin:access")


@app.route("/resources/<resource_id>", methods=["DELETE"])
@login_required(
    checks=[is_resource_owner, is_admin_user],
    check_mode="any",  # Owner OR admin can delete
    check_error="Must be owner or admin to delete",
)
def delete_resource(resource_id):
    """Delete resource - owner OR admin can delete."""
    user = get_current_user()
    return jsonify({
        "deleted": resource_id,
        "by_user": user.user_id,
    })


# Multiple checks with "all" mode
def is_verified(user):
    """Check if user is verified."""
    return user.metadata.get("email_verified", True)


def has_premium(user):
    """Check if user has premium subscription."""
    return user.has_permission("premium:access")


@app.route("/premium/features", methods=["POST"])
@login_required(
    checks=[is_verified, has_premium],
    check_mode="all",  # Both must pass
    check_error="Premium subscription with verified account required",
)
def premium_feature():
    """Premium feature - requires verified account AND premium subscription."""
    user = get_current_user()
    return jsonify({
        "feature": "premium",
        "user": user.user_id,
        "access_granted": True,
    })


# Permission decorator with check callback
@app.route("/admin/tenants/<tenant_id>/settings")
@permission_required("admin:settings", check=can_access_tenant, check_error="Tenant access denied")
def admin_tenant_settings(tenant_id):
    """Admin settings for tenant - requires admin permission AND tenant access."""
    user = get_current_user()
    return jsonify({
        "tenant_id": tenant_id,
        "settings": {"theme": "dark"},
        "admin_user": user.user_id,
    })


# =============================================================================
# Alternative: Manual Check in Route (Simple Cases)
# =============================================================================

@app.route("/manual/<domain>/services", methods=["POST"])
@login_required()
def manual_domain_check(domain):
    """
    Alternative approach: manual permission check in route.

    Use this for simple, one-off checks. Use check callbacks for
    reusable logic across multiple routes.
    """
    from flask import abort

    user = get_current_user()
    scope = domain.split('.')[0]

    if not user.has_any_permission(
        f"controller.write.services_{scope}",
        "controller.write.services_all",
        "controller.admin",
    ):
        abort(403, description=f"Not authorized for domain scope: {scope}")

    return jsonify({
        "registered": True,
        "domain": domain,
        "approach": "manual_check",
    })


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
