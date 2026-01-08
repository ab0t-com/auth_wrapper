"""
Tests for auth check callback feature.

Tests the `check` and `checks` parameters for authorization callbacks
across dependencies, decorators, and Flask.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from ab0t_auth.core import AuthenticatedUser, AuthMethod, TokenType
from ab0t_auth.errors import AuthError, PermissionDeniedError
from ab0t_auth.guard import AuthGuard
from ab0t_auth.dependencies import require_auth, require_permission, _run_auth_checks
from ab0t_auth.decorators import protected, permission_required as decorator_permission_required


def add_exception_handlers(app: FastAPI) -> None:
    """Add auth exception handlers to FastAPI app."""
    @app.exception_handler(AuthError)
    async def auth_error_handler(request: Request, exc: AuthError):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.message, "code": exc.code},
        )


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def test_user() -> AuthenticatedUser:
    """User with specific org_id for tenant tests."""
    return AuthenticatedUser(
        user_id="user_123",
        email="test@example.com",
        org_id="tenant_abc",
        permissions=("users:read", "admin:access"),
        roles=("user",),
        auth_method=AuthMethod.JWT,
        token_type=TokenType.BEARER,
    )


@pytest.fixture
def other_tenant_user() -> AuthenticatedUser:
    """User with different org_id."""
    return AuthenticatedUser(
        user_id="user_456",
        email="other@example.com",
        org_id="tenant_xyz",
        permissions=("users:read",),
        roles=("user",),
        auth_method=AuthMethod.JWT,
        token_type=TokenType.BEARER,
    )


@pytest.fixture
def mock_guard(test_user: AuthenticatedUser):
    """Create mock AuthGuard that returns test_user."""
    guard = MagicMock(spec=AuthGuard)
    guard.config = MagicMock()
    guard.config.api_key_header = "X-API-Key"
    guard.config.header_name = "Authorization"

    async def mock_authenticate(auth, api_key):
        from ab0t_auth.core import AuthResult
        return AuthResult.ok(test_user)

    async def mock_authenticate_or_raise(auth, api_key):
        return test_user

    guard.authenticate = AsyncMock(side_effect=mock_authenticate)
    guard.authenticate_or_raise = AsyncMock(side_effect=mock_authenticate_or_raise)
    return guard


# =============================================================================
# Test _run_auth_checks Helper (FastAPI)
# =============================================================================


class TestRunAuthChecks:
    """Tests for _run_auth_checks helper function."""

    @pytest.mark.asyncio
    async def test_no_checks_passes(self, test_user: AuthenticatedUser):
        """No checks provided should pass without error."""
        request = MagicMock(spec=Request)

        # Should not raise
        await _run_auth_checks(
            test_user,
            request,
            check=None,
            checks=None,
            check_mode="all",
            check_error="Failed",
        )

    @pytest.mark.asyncio
    async def test_single_check_passes(self, test_user: AuthenticatedUser):
        """Single passing check should succeed."""
        request = MagicMock(spec=Request)

        def always_pass(user: AuthenticatedUser, req: Request) -> bool:
            return True

        await _run_auth_checks(
            test_user,
            request,
            check=always_pass,
            checks=None,
            check_mode="all",
            check_error="Failed",
        )

    @pytest.mark.asyncio
    async def test_single_check_fails(self, test_user: AuthenticatedUser):
        """Single failing check should raise PermissionDeniedError."""
        request = MagicMock(spec=Request)

        def always_fail(user: AuthenticatedUser, req: Request) -> bool:
            return False

        with pytest.raises(PermissionDeniedError) as exc:
            await _run_auth_checks(
                test_user,
                request,
                check=always_fail,
                checks=None,
                check_mode="all",
                check_error="Custom error message",
            )

        assert exc.value.message == "Custom error message"

    @pytest.mark.asyncio
    async def test_async_check_supported(self, test_user: AuthenticatedUser):
        """Async check functions should be properly awaited."""
        request = MagicMock(spec=Request)

        async def async_check(user: AuthenticatedUser, req: Request) -> bool:
            return True

        # Should not raise
        await _run_auth_checks(
            test_user,
            request,
            check=async_check,
            checks=None,
            check_mode="all",
            check_error="Failed",
        )

    @pytest.mark.asyncio
    async def test_multiple_checks_all_mode_all_pass(self, test_user: AuthenticatedUser):
        """All checks pass in 'all' mode should succeed."""
        request = MagicMock(spec=Request)

        def check1(user: AuthenticatedUser, req: Request) -> bool:
            return True

        def check2(user: AuthenticatedUser, req: Request) -> bool:
            return True

        await _run_auth_checks(
            test_user,
            request,
            check=None,
            checks=[check1, check2],
            check_mode="all",
            check_error="Failed",
        )

    @pytest.mark.asyncio
    async def test_multiple_checks_all_mode_one_fails(self, test_user: AuthenticatedUser):
        """One failing check in 'all' mode should fail."""
        request = MagicMock(spec=Request)

        def check1(user: AuthenticatedUser, req: Request) -> bool:
            return True

        def check2(user: AuthenticatedUser, req: Request) -> bool:
            return False

        with pytest.raises(PermissionDeniedError):
            await _run_auth_checks(
                test_user,
                request,
                check=None,
                checks=[check1, check2],
                check_mode="all",
                check_error="Failed",
            )

    @pytest.mark.asyncio
    async def test_multiple_checks_any_mode_one_passes(self, test_user: AuthenticatedUser):
        """One passing check in 'any' mode should succeed."""
        request = MagicMock(spec=Request)

        def check1(user: AuthenticatedUser, req: Request) -> bool:
            return False

        def check2(user: AuthenticatedUser, req: Request) -> bool:
            return True

        # Should not raise - one check passes
        await _run_auth_checks(
            test_user,
            request,
            check=None,
            checks=[check1, check2],
            check_mode="any",
            check_error="Failed",
        )

    @pytest.mark.asyncio
    async def test_multiple_checks_any_mode_all_fail(self, test_user: AuthenticatedUser):
        """All failing checks in 'any' mode should fail."""
        request = MagicMock(spec=Request)

        def check1(user: AuthenticatedUser, req: Request) -> bool:
            return False

        def check2(user: AuthenticatedUser, req: Request) -> bool:
            return False

        with pytest.raises(PermissionDeniedError):
            await _run_auth_checks(
                test_user,
                request,
                check=None,
                checks=[check1, check2],
                check_mode="any",
                check_error="Failed",
            )

    @pytest.mark.asyncio
    async def test_check_receives_user_and_request(self, test_user: AuthenticatedUser):
        """Check callback should receive user and request objects."""
        request = MagicMock(spec=Request)
        request.path_params = {"tenant_id": "tenant_abc"}

        received_user = None
        received_request = None

        def capture_check(user: AuthenticatedUser, req: Request) -> bool:
            nonlocal received_user, received_request
            received_user = user
            received_request = req
            return True

        await _run_auth_checks(
            test_user,
            request,
            check=capture_check,
            checks=None,
            check_mode="all",
            check_error="Failed",
        )

        assert received_user == test_user
        assert received_request == request

    @pytest.mark.asyncio
    async def test_short_circuit_any_mode(self, test_user: AuthenticatedUser):
        """'any' mode should short-circuit on first success."""
        request = MagicMock(spec=Request)
        check2_called = False

        def check1(user: AuthenticatedUser, req: Request) -> bool:
            return True  # Pass - should short-circuit

        def check2(user: AuthenticatedUser, req: Request) -> bool:
            nonlocal check2_called
            check2_called = True
            return False

        await _run_auth_checks(
            test_user,
            request,
            check=None,
            checks=[check1, check2],
            check_mode="any",
            check_error="Failed",
        )

        assert not check2_called  # Should not have been called

    @pytest.mark.asyncio
    async def test_short_circuit_all_mode(self, test_user: AuthenticatedUser):
        """'all' mode should short-circuit on first failure."""
        request = MagicMock(spec=Request)
        check2_called = False

        def check1(user: AuthenticatedUser, req: Request) -> bool:
            return False  # Fail - should short-circuit

        def check2(user: AuthenticatedUser, req: Request) -> bool:
            nonlocal check2_called
            check2_called = True
            return True

        with pytest.raises(PermissionDeniedError):
            await _run_auth_checks(
                test_user,
                request,
                check=None,
                checks=[check1, check2],
                check_mode="all",
                check_error="Failed",
            )

        assert not check2_called  # Should not have been called


# =============================================================================
# Test require_auth Dependency with Checks
# =============================================================================


class TestRequireAuthWithCheck:
    """Tests for require_auth dependency with check callbacks."""

    def test_require_auth_no_check_backwards_compatible(self, mock_guard: AuthGuard):
        """require_auth without check should work as before."""
        app = FastAPI()

        @app.get("/test")
        async def route(user: AuthenticatedUser = Depends(require_auth(mock_guard))):
            return {"user_id": user.user_id}

        client = TestClient(app)
        response = client.get("/test", headers={"Authorization": "Bearer token"})
        assert response.status_code == 200
        assert response.json()["user_id"] == "user_123"

    def test_require_auth_with_passing_check(self, mock_guard: AuthGuard, test_user: AuthenticatedUser):
        """require_auth with passing check should succeed."""
        app = FastAPI()

        def tenant_check(user: AuthenticatedUser, request: Request) -> bool:
            tenant_id = request.path_params.get("tenant_id")
            return user.org_id == tenant_id

        @app.get("/tenants/{tenant_id}/data")
        async def route(
            tenant_id: str,
            user: AuthenticatedUser = Depends(require_auth(mock_guard, check=tenant_check)),
        ):
            return {"tenant_id": tenant_id, "user_id": user.user_id}

        client = TestClient(app)
        response = client.get(
            "/tenants/tenant_abc/data",
            headers={"Authorization": "Bearer token"},
        )
        assert response.status_code == 200
        assert response.json()["tenant_id"] == "tenant_abc"

    def test_require_auth_with_failing_check(self, mock_guard: AuthGuard, test_user: AuthenticatedUser):
        """require_auth with failing check should return 403."""
        app = FastAPI()
        add_exception_handlers(app)

        def tenant_check(user: AuthenticatedUser, request: Request) -> bool:
            tenant_id = request.path_params.get("tenant_id")
            return user.org_id == tenant_id  # Will fail - user is tenant_abc, path is tenant_xyz

        @app.get("/tenants/{tenant_id}/data")
        async def route(
            tenant_id: str,
            user: AuthenticatedUser = Depends(require_auth(
                mock_guard,
                check=tenant_check,
                check_error="Not authorized for this tenant",
            )),
        ):
            return {"tenant_id": tenant_id}

        client = TestClient(app)
        response = client.get(
            "/tenants/tenant_xyz/data",  # Different tenant
            headers={"Authorization": "Bearer token"},
        )
        assert response.status_code == 403
        assert "Not authorized for this tenant" in response.json()["detail"]

    def test_require_auth_with_multiple_checks_all_mode(self, mock_guard: AuthGuard):
        """require_auth with multiple checks in 'all' mode."""
        app = FastAPI()

        def is_verified(user: AuthenticatedUser, request: Request) -> bool:
            return True

        def has_permission(user: AuthenticatedUser, request: Request) -> bool:
            return user.has_permission("users:read")

        @app.get("/verified-data")
        async def route(
            user: AuthenticatedUser = Depends(require_auth(
                mock_guard,
                checks=[is_verified, has_permission],
                check_mode="all",
            )),
        ):
            return {"ok": True}

        client = TestClient(app)
        response = client.get(
            "/verified-data",
            headers={"Authorization": "Bearer token"},
        )
        assert response.status_code == 200

    def test_require_auth_with_multiple_checks_any_mode(self, mock_guard: AuthGuard):
        """require_auth with multiple checks in 'any' mode."""
        app = FastAPI()

        def is_admin(user: AuthenticatedUser, request: Request) -> bool:
            return user.has_permission("admin:access")

        def is_owner(user: AuthenticatedUser, request: Request) -> bool:
            return False  # Not owner

        @app.get("/resource")
        async def route(
            user: AuthenticatedUser = Depends(require_auth(
                mock_guard,
                checks=[is_admin, is_owner],
                check_mode="any",  # Admin OR owner
            )),
        ):
            return {"ok": True}

        client = TestClient(app)
        response = client.get(
            "/resource",
            headers={"Authorization": "Bearer token"},
        )
        # Should pass because user has admin:access
        assert response.status_code == 200


# =============================================================================
# Test require_permission Dependency with Checks
# =============================================================================


class TestRequirePermissionWithCheck:
    """Tests for require_permission with additional check callbacks."""

    def test_check_runs_after_permission(self, mock_guard: AuthGuard):
        """Check callback should run AFTER permission check passes."""
        app = FastAPI()
        check_called = False

        def additional_check(user: AuthenticatedUser, request: Request) -> bool:
            nonlocal check_called
            check_called = True
            return True

        @app.get("/test")
        async def route(
            user: AuthenticatedUser = Depends(require_permission(
                mock_guard,
                "users:read",
                check=additional_check,
            )),
        ):
            return {"ok": True}

        client = TestClient(app)
        response = client.get("/test", headers={"Authorization": "Bearer token"})
        assert response.status_code == 200
        assert check_called

    def test_permission_fails_check_not_called(self, mock_guard: AuthGuard):
        """If permission check fails, callback should not be called."""
        app = FastAPI()
        add_exception_handlers(app)
        check_called = False

        def additional_check(user: AuthenticatedUser, request: Request) -> bool:
            nonlocal check_called
            check_called = True
            return True

        @app.get("/test")
        async def route(
            user: AuthenticatedUser = Depends(require_permission(
                mock_guard,
                "nonexistent:permission",
                check=additional_check,
            )),
        ):
            return {"ok": True}

        client = TestClient(app)
        response = client.get("/test", headers={"Authorization": "Bearer token"})
        assert response.status_code == 403
        assert not check_called  # Should not have been called


# =============================================================================
# Test Flask Decorators with Checks
# =============================================================================


class TestFlaskDecoratorsWithCheck:
    """Tests for Flask decorator check callbacks."""

    def test_run_auth_checks_sync_single_check_passes(self, test_user: AuthenticatedUser):
        """Flask sync check helper with passing check."""
        from ab0t_auth.flask import _run_auth_checks_sync

        def check(user: AuthenticatedUser) -> bool:
            return True

        # Should not raise
        _run_auth_checks_sync(
            test_user,
            check=check,
            checks=None,
            check_mode="all",
            check_error="Failed",
        )

    def test_run_auth_checks_sync_single_check_fails(self, test_user: AuthenticatedUser):
        """Flask sync check helper with failing check."""
        from ab0t_auth.flask import _run_auth_checks_sync

        def check(user: AuthenticatedUser) -> bool:
            return False

        with pytest.raises(PermissionDeniedError) as exc:
            _run_auth_checks_sync(
                test_user,
                check=check,
                checks=None,
                check_mode="all",
                check_error="Custom Flask error",
            )

        assert exc.value.message == "Custom Flask error"

    def test_run_auth_checks_sync_multiple_any_mode(self, test_user: AuthenticatedUser):
        """Flask sync check helper with 'any' mode."""
        from ab0t_auth.flask import _run_auth_checks_sync

        def check1(user: AuthenticatedUser) -> bool:
            return False

        def check2(user: AuthenticatedUser) -> bool:
            return True  # This one passes

        # Should not raise - one check passes
        _run_auth_checks_sync(
            test_user,
            check=None,
            checks=[check1, check2],
            check_mode="any",
            check_error="Failed",
        )

    def test_run_auth_checks_sync_no_checks(self, test_user: AuthenticatedUser):
        """Flask sync check helper with no checks."""
        from ab0t_auth.flask import _run_auth_checks_sync

        # Should not raise
        _run_auth_checks_sync(
            test_user,
            check=None,
            checks=None,
            check_mode="all",
            check_error="Failed",
        )


# =============================================================================
# Test Real-World Scenarios
# =============================================================================


class TestRealWorldScenarios:
    """Tests for realistic use cases from Issue #9."""

    def test_domain_scoped_permission_check(self, mock_guard: AuthGuard):
        """
        Test the Issue #9 use case: domain-scoped permissions.

        User has controller.write.services_public permission.
        They should be able to access public.example.com domain.
        """
        app = FastAPI()
        add_exception_handlers(app)

        # Create user with scoped permissions
        scoped_user = AuthenticatedUser(
            user_id="user_123",
            email="test@example.com",
            org_id="test_org",
            permissions=(
                "controller.write.services_public",
                "controller.read.services_all",
            ),
            roles=("user",),
            auth_method=AuthMethod.JWT,
            token_type=TokenType.BEARER,
        )

        # Update mock to return scoped user
        async def mock_authenticate_or_raise(auth, api_key):
            return scoped_user

        mock_guard.authenticate_or_raise = AsyncMock(side_effect=mock_authenticate_or_raise)

        def can_access_domain(user: AuthenticatedUser, request: Request) -> bool:
            """Check if user can access the given domain scope."""
            domain = request.path_params.get("domain", "")
            scope = domain.split('.')[0]  # Get first part (public, app, etc.)

            return user.has_any_permission(
                f"controller.write.services_{scope}",
                "controller.write.services_all",
                "controller.admin",
            )

        @app.post("/{domain}/services")
        async def register_service(
            domain: str,
            user: AuthenticatedUser = Depends(require_auth(
                mock_guard,
                check=can_access_domain,
                check_error="Not authorized for this domain",
            )),
        ):
            return {"domain": domain, "registered": True}

        client = TestClient(app)

        # Should succeed - user has controller.write.services_public
        response = client.post(
            "/public.example.com/services",
            headers={"Authorization": "Bearer token"},
        )
        assert response.status_code == 200
        assert response.json()["domain"] == "public.example.com"

        # Should fail - user doesn't have controller.write.services_app
        response = client.post(
            "/app.example.com/services",
            headers={"Authorization": "Bearer token"},
        )
        assert response.status_code == 403

    def test_resource_ownership_check(self, mock_guard: AuthGuard):
        """Test resource ownership pattern."""
        app = FastAPI()

        # Simulate resource ownership lookup
        resources = {
            "res_123": "user_123",  # Owned by test user
            "res_456": "user_other",  # Owned by someone else
        }

        def owns_resource(user: AuthenticatedUser, request: Request) -> bool:
            resource_id = request.path_params.get("resource_id")
            owner_id = resources.get(resource_id)
            return owner_id == user.user_id or user.has_permission("admin:access")

        @app.delete("/resources/{resource_id}")
        async def delete_resource(
            resource_id: str,
            user: AuthenticatedUser = Depends(require_auth(
                mock_guard,
                check=owns_resource,
                check_error="You don't own this resource",
            )),
        ):
            return {"deleted": resource_id}

        client = TestClient(app)

        # Should succeed - user owns res_123
        response = client.delete(
            "/resources/res_123",
            headers={"Authorization": "Bearer token"},
        )
        assert response.status_code == 200

        # Should also succeed - user has admin:access
        response = client.delete(
            "/resources/res_456",
            headers={"Authorization": "Bearer token"},
        )
        assert response.status_code == 200  # Admin override

    def test_multi_tenant_isolation(self, mock_guard: AuthGuard):
        """Test multi-tenant isolation pattern."""
        app = FastAPI()
        add_exception_handlers(app)

        def belongs_to_tenant(user: AuthenticatedUser, request: Request) -> bool:
            tenant_id = request.path_params.get("tenant_id")
            return user.org_id == tenant_id or user.has_permission("super:admin")

        @app.get("/tenants/{tenant_id}/users")
        async def list_tenant_users(
            tenant_id: str,
            user: AuthenticatedUser = Depends(require_auth(
                mock_guard,
                check=belongs_to_tenant,
                check_error="Access denied to this tenant",
            )),
        ):
            return {"tenant_id": tenant_id, "users": []}

        client = TestClient(app)

        # Should succeed - user belongs to tenant_abc
        response = client.get(
            "/tenants/tenant_abc/users",
            headers={"Authorization": "Bearer token"},
        )
        assert response.status_code == 200

        # Should fail - user doesn't belong to other_tenant
        response = client.get(
            "/tenants/other_tenant/users",
            headers={"Authorization": "Bearer token"},
        )
        assert response.status_code == 403


# =============================================================================
# Test Decorator-based API with Checks
# =============================================================================


class TestDecoratorWithCheck:
    """Tests for FastAPI decorator-based API with check callbacks."""

    def test_protected_decorator_with_check(self, mock_guard: AuthGuard):
        """Test @protected decorator with check callback."""
        from ab0t_auth.decorators import protected
        from ab0t_auth.middleware import AuthMiddleware

        app = FastAPI()
        add_exception_handlers(app)
        app.add_middleware(AuthMiddleware, guard=mock_guard)

        def tenant_check(user: AuthenticatedUser, request: Request) -> bool:
            return user.org_id == request.path_params.get("tenant_id")

        # Note: auth_user must have a default value to avoid FastAPI interpreting it
        # as a request body parameter. The @protected decorator injects it at runtime.
        @app.get("/tenants/{tenant_id}/data")
        @protected(mock_guard, check=tenant_check, check_error="Tenant mismatch")
        async def get_tenant_data(request: Request, tenant_id: str, auth_user=None):
            return {"tenant_id": tenant_id, "user_id": auth_user.user_id}

        client = TestClient(app)

        # Should succeed - user org_id matches tenant_abc
        response = client.get(
            "/tenants/tenant_abc/data",
            headers={"Authorization": "Bearer token"},
        )
        assert response.status_code == 200
        assert response.json()["tenant_id"] == "tenant_abc"
        assert response.json()["user_id"] == "user_123"

        # Should fail - user doesn't belong to wrong_tenant
        response = client.get(
            "/tenants/wrong_tenant/data",
            headers={"Authorization": "Bearer token"},
        )
        assert response.status_code == 403
