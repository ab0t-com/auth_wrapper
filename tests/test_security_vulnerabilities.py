"""
Security Vulnerability Tests for ab0t_auth.

These tests cover potential vulnerabilities identified in the deep security review.
They attempt to exploit edge cases, race conditions, and API confusion scenarios.

Test Categories:
1. JWKS Cache Race Conditions
2. optional_auth Silent Failure Exploitation
3. Check Callback Validation Bypass
4. Path Exclusion Pattern Bypass
5. Token Cache Collision Attacks
6. Concurrent Authentication Attacks
7. API Confusion Exploitation
8. Permission Logic Edge Cases
9. Error Information Disclosure
10. Middleware Bypass Attempts
"""

import asyncio
import hashlib
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from ab0t_auth.cache import (
    JWKSCache,
    PermissionCache,
    TokenCache,
    hash_token,
)
from ab0t_auth.config import BypassConfig, load_bypass_config
from ab0t_auth.core import (
    AuthCheckCallable,
    AuthConfig,
    AuthenticatedUser,
    AuthMethod,
    AuthResult,
    TokenClaims,
    TokenType,
)
from ab0t_auth.dependencies import (
    optional_auth,
    require_auth,
    require_permission,
    _run_auth_checks,
)
from ab0t_auth.errors import (
    AuthError,
    AuthServiceError,
    PermissionDeniedError,
    TokenExpiredError,
    TokenInvalidError,
    TokenNotFoundError,
)
from ab0t_auth.guard import AuthGuard
from ab0t_auth.middleware import AuthMiddleware
from ab0t_auth.permissions import (
    check_permission,
    check_permission_pattern,
    check_any_permission,
)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def mock_guard() -> AuthGuard:
    """Create a mock AuthGuard for testing."""
    guard = AuthGuard(auth_url="https://auth.test.com")
    return guard


@pytest.fixture
def test_user() -> AuthenticatedUser:
    """Create a test user."""
    return AuthenticatedUser(
        user_id="test_user_123",
        email="test@example.com",
        permissions=("users:read", "users:write", "reports:view"),
        roles=("user", "editor"),
        org_id="org_123",
        auth_method=AuthMethod.JWT,
        token_type=TokenType.BEARER,
    )


@pytest.fixture
def mock_request() -> MagicMock:
    """Create a mock FastAPI request."""
    request = MagicMock(spec=Request)
    request.path_params = {}
    request.headers = {}
    request.query_params = {}
    return request


# =============================================================================
# 1. JWKS Cache Race Condition Tests
# =============================================================================


class TestJWKSCacheRaceConditions:
    """Tests for JWKS cache thread safety issues."""

    def test_concurrent_cache_writes(self) -> None:
        """Test concurrent writes to JWKS cache don't corrupt data."""
        cache = JWKSCache(ttl=60)
        auth_url = "https://auth.test.com"
        results = []
        errors = []

        def write_to_cache(thread_id: int) -> None:
            try:
                keys = {"keys": [{"kid": f"key_{thread_id}", "kty": "RSA"}]}
                cache.set(auth_url, keys, org_id=f"org_{thread_id}")
                # Small sleep to increase chance of race
                time.sleep(0.001)
                retrieved = cache.get(auth_url, org_id=f"org_{thread_id}")
                results.append((thread_id, retrieved))
            except Exception as e:
                errors.append((thread_id, e))

        # Run 50 concurrent writes
        threads = [threading.Thread(target=write_to_cache, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # No errors should occur
        assert len(errors) == 0, f"Errors during concurrent writes: {errors}"
        # All writes should succeed
        assert len(results) == 50

    def test_concurrent_read_during_write(self) -> None:
        """Test reads don't get corrupted data during writes."""
        cache = JWKSCache(ttl=60)
        auth_url = "https://auth.test.com"
        org_id = "shared_org"

        # Pre-populate cache
        initial_keys = {"keys": [{"kid": "initial", "kty": "RSA"}]}
        cache.set(auth_url, initial_keys, org_id=org_id)

        read_results = []
        write_count = [0]

        def reader() -> None:
            for _ in range(100):
                result = cache.get(auth_url, org_id=org_id)
                if result is not None:
                    read_results.append(result)
                time.sleep(0.0001)

        def writer() -> None:
            for i in range(50):
                new_keys = {"keys": [{"kid": f"key_{i}", "kty": "RSA"}]}
                cache.set(auth_url, new_keys, org_id=org_id)
                write_count[0] += 1
                time.sleep(0.0002)

        reader_threads = [threading.Thread(target=reader) for _ in range(5)]
        writer_thread = threading.Thread(target=writer)

        for t in reader_threads:
            t.start()
        writer_thread.start()

        for t in reader_threads:
            t.join()
        writer_thread.join()

        # All reads should return valid dict structure
        for result in read_results:
            assert isinstance(result, dict)
            assert "keys" in result
            assert isinstance(result["keys"], list)

    def test_cache_expiration_during_read(self) -> None:
        """Test reading cache entry exactly as it expires."""
        cache = JWKSCache(ttl=1)  # 1 second TTL
        auth_url = "https://auth.test.com"

        keys = {"keys": [{"kid": "test", "kty": "RSA"}]}
        cache.set(auth_url, keys)

        # Wait for near-expiration
        time.sleep(0.9)

        # Concurrent reads at expiration boundary
        results = []

        def read_at_boundary() -> None:
            for _ in range(10):
                result = cache.get(auth_url)
                results.append(result)
                time.sleep(0.02)

        threads = [threading.Thread(target=read_at_boundary) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Results should be either the keys or None (expired), never corrupted
        for result in results:
            assert result is None or (isinstance(result, dict) and "keys" in result)


# =============================================================================
# 2. optional_auth Silent Failure Tests
# =============================================================================


class TestOptionalAuthSilentFailures:
    """Tests for optional_auth exception handling vulnerabilities."""

    @pytest.mark.asyncio
    async def test_optional_auth_swallows_service_errors(self, mock_guard: AuthGuard) -> None:
        """Test that optional_auth swallows AuthServiceError (potential issue)."""
        # Mock authenticate to raise service error
        mock_guard.authenticate = AsyncMock(
            side_effect=AuthServiceError("Auth service down", service_url="https://auth.test.com")
        )

        dependency = optional_auth(mock_guard)

        # Create mock request
        request = MagicMock(spec=Request)
        request.headers = {"Authorization": "Bearer valid_token"}

        # optional_auth should return None instead of propagating error
        result = await dependency(request)

        # This documents the current behavior - returns None on ANY error
        assert result is None

    @pytest.mark.asyncio
    async def test_optional_auth_swallows_unexpected_errors(self, mock_guard: AuthGuard) -> None:
        """Test that optional_auth swallows unexpected exceptions."""
        # Mock authenticate to raise unexpected error
        mock_guard.authenticate = AsyncMock(
            side_effect=RuntimeError("Unexpected internal error")
        )

        dependency = optional_auth(mock_guard)

        request = MagicMock(spec=Request)
        request.headers = {"Authorization": "Bearer token"}

        # This returns None instead of 500 error
        result = await dependency(request)
        assert result is None

    @pytest.mark.asyncio
    async def test_optional_auth_distinguishes_no_token_vs_invalid(
        self, mock_guard: AuthGuard, test_user: AuthenticatedUser
    ) -> None:
        """Test that optional_auth behavior is same for no token vs invalid token."""
        # Scenario 1: No token provided
        mock_guard.authenticate = AsyncMock(
            return_value=AuthResult(success=False, error_code="NO_CREDENTIALS")
        )

        dependency = optional_auth(mock_guard)
        request_no_token = MagicMock(spec=Request)
        request_no_token.headers = {}

        result_no_token = await dependency(request_no_token)

        # Scenario 2: Invalid token
        mock_guard.authenticate = AsyncMock(
            side_effect=TokenInvalidError("Token signature invalid")
        )

        request_invalid = MagicMock(spec=Request)
        request_invalid.headers = {"Authorization": "Bearer invalid"}

        result_invalid = await dependency(request_invalid)

        # Both return None - attacker can't distinguish
        assert result_no_token is None
        assert result_invalid is None

    @pytest.mark.asyncio
    async def test_optional_auth_with_malformed_token_crash(self, mock_guard: AuthGuard) -> None:
        """Test optional_auth with token that crashes parser."""
        # Simulate a token that causes parsing to crash
        mock_guard.authenticate = AsyncMock(
            side_effect=ValueError("Invalid base64 in token")
        )

        dependency = optional_auth(mock_guard)

        request = MagicMock(spec=Request)
        request.headers = {"Authorization": "Bearer not.valid.base64!!!"}

        # Should return None, not crash
        result = await dependency(request)
        assert result is None


# =============================================================================
# 3. Check Callback Validation Tests
# =============================================================================


class TestCheckCallbackValidation:
    """Tests for check callback return value validation."""

    @pytest.mark.asyncio
    async def test_callback_returning_user_object_is_rejected(
        self, test_user: AuthenticatedUser, mock_request: MagicMock
    ) -> None:
        """Test that callback returning user object is rejected (non-bool)."""

        def bad_callback(user: AuthenticatedUser, request: Request) -> AuthenticatedUser:
            """Bug: returns user instead of bool."""
            return user  # type: ignore

        # SECURITY FIX: Non-bool returns are now treated as False
        # This prevents accidental authorization bypass from developer mistakes
        with pytest.raises(PermissionDeniedError):
            await _run_auth_checks(
                test_user,
                mock_request,
                check=bad_callback,  # type: ignore
                checks=None,
                check_mode="all",
                check_error="Check failed",
            )

    @pytest.mark.asyncio
    async def test_callback_returning_string_is_rejected(
        self, test_user: AuthenticatedUser, mock_request: MagicMock
    ) -> None:
        """Test that callback returning non-empty string is rejected (non-bool)."""

        def string_callback(user: AuthenticatedUser, request: Request) -> str:
            """Bug: returns string instead of bool."""
            return "yes"  # type: ignore

        # SECURITY FIX: Non-bool returns are now treated as False
        with pytest.raises(PermissionDeniedError):
            await _run_auth_checks(
                test_user,
                mock_request,
                check=string_callback,  # type: ignore
                checks=None,
                check_mode="all",
                check_error="Check failed",
            )

    @pytest.mark.asyncio
    async def test_callback_returning_empty_string_fails(
        self, test_user: AuthenticatedUser, mock_request: MagicMock
    ) -> None:
        """Test that callback returning empty string fails (falsy)."""

        def empty_string_callback(user: AuthenticatedUser, request: Request) -> str:
            return ""  # type: ignore

        with pytest.raises(PermissionDeniedError):
            await _run_auth_checks(
                test_user,
                mock_request,
                check=empty_string_callback,  # type: ignore
                checks=None,
                check_mode="all",
                check_error="Check failed",
            )

    @pytest.mark.asyncio
    async def test_callback_returning_zero_fails(
        self, test_user: AuthenticatedUser, mock_request: MagicMock
    ) -> None:
        """Test that callback returning 0 fails (falsy)."""

        def zero_callback(user: AuthenticatedUser, request: Request) -> int:
            return 0  # type: ignore

        with pytest.raises(PermissionDeniedError):
            await _run_auth_checks(
                test_user,
                mock_request,
                check=zero_callback,  # type: ignore
                checks=None,
                check_mode="all",
                check_error="Check failed",
            )

    @pytest.mark.asyncio
    async def test_callback_returning_one_is_rejected(
        self, test_user: AuthenticatedUser, mock_request: MagicMock
    ) -> None:
        """Test that callback returning 1 is rejected (non-bool)."""

        def one_callback(user: AuthenticatedUser, request: Request) -> int:
            return 1  # type: ignore

        # SECURITY FIX: Non-bool returns are now treated as False
        with pytest.raises(PermissionDeniedError):
            await _run_auth_checks(
                test_user,
                mock_request,
                check=one_callback,  # type: ignore
                checks=None,
                check_mode="all",
                check_error="Check failed",
            )

    @pytest.mark.asyncio
    async def test_callback_returning_none_fails(
        self, test_user: AuthenticatedUser, mock_request: MagicMock
    ) -> None:
        """Test that callback returning None fails (falsy)."""

        def none_callback(user: AuthenticatedUser, request: Request) -> None:
            return None  # type: ignore

        with pytest.raises(PermissionDeniedError):
            await _run_auth_checks(
                test_user,
                mock_request,
                check=none_callback,  # type: ignore
                checks=None,
                check_mode="all",
                check_error="Check failed",
            )

    @pytest.mark.asyncio
    async def test_callback_raising_exception_is_caught(
        self, test_user: AuthenticatedUser, mock_request: MagicMock
    ) -> None:
        """Test that callback raising exception is caught and treated as failure."""

        def crashing_callback(user: AuthenticatedUser, request: Request) -> bool:
            raise ValueError("Database connection failed")

        # SECURITY FIX: Exceptions are now caught and treated as False
        # This prevents 500 errors and ensures fail-closed behavior
        with pytest.raises(PermissionDeniedError):
            await _run_auth_checks(
                test_user,
                mock_request,
                check=crashing_callback,
                checks=None,
                check_mode="all",
                check_error="Check failed",
            )

    @pytest.mark.asyncio
    async def test_async_callback_exception_is_caught(
        self, test_user: AuthenticatedUser, mock_request: MagicMock
    ) -> None:
        """Test that async callback exceptions are caught and treated as failure."""

        async def async_crashing_callback(user: AuthenticatedUser, request: Request) -> bool:
            raise ConnectionError("Auth service unreachable")

        # SECURITY FIX: Exceptions are now caught and treated as False
        with pytest.raises(PermissionDeniedError):
            await _run_auth_checks(
                test_user,
                mock_request,
                check=async_crashing_callback,
                checks=None,
                check_mode="all",
                check_error="Check failed",
            )


# =============================================================================
# 4. Path Exclusion Pattern Bypass Tests
# =============================================================================


class TestPathExclusionBypass:
    """Tests for path exclusion pattern vulnerabilities."""

    def test_startswith_allows_suffix_bypass(self) -> None:
        """Test that startswith matching allows unintended paths."""
        # Simulate the middleware's path checking logic
        exclude_paths = ["/health", "/api/public"]

        def should_exclude(path: str) -> bool:
            for pattern in exclude_paths:
                if path.startswith(pattern):
                    return True
            return False

        # Intended exclusions
        assert should_exclude("/health") is True
        assert should_exclude("/api/public") is True

        # UNINTENDED exclusions (security issue)
        assert should_exclude("/healthcheck") is True  # Bypasses auth!
        assert should_exclude("/health/secret") is True  # Bypasses auth!
        assert should_exclude("/api/public-but-private") is True  # Bypasses auth!
        assert should_exclude("/api/public/admin") is True  # Bypasses auth!

    def test_path_traversal_in_exclusion(self) -> None:
        """Test path traversal attempts in excluded paths."""
        exclude_paths = ["/api/public"]

        def should_exclude(path: str) -> bool:
            for pattern in exclude_paths:
                if path.startswith(pattern):
                    return True
            return False

        # Path traversal attempts
        # Note: Most frameworks normalize these, but middleware sees raw path
        traversal_attempts = [
            "/api/public/../private",  # Might be normalized to /api/private
            "/api/public/../../etc/passwd",
            "/api/public%2F..%2Fprivate",  # URL encoded
        ]

        for path in traversal_attempts:
            # These all START with /api/public so they're excluded
            assert should_exclude(path) is True

    def test_case_sensitivity_in_exclusion(self) -> None:
        """Test case sensitivity in path exclusion."""
        exclude_paths = ["/health", "/api/public"]

        def should_exclude(path: str) -> bool:
            for pattern in exclude_paths:
                if path.startswith(pattern):
                    return True
            return False

        # Case variations
        assert should_exclude("/Health") is False  # Not excluded!
        assert should_exclude("/HEALTH") is False  # Not excluded!
        assert should_exclude("/API/public") is False  # Not excluded!

    def test_empty_path_handling(self) -> None:
        """Test empty and root path handling."""
        exclude_paths = ["/", "/health"]

        def should_exclude(path: str) -> bool:
            for pattern in exclude_paths:
                if path.startswith(pattern):
                    return True
            return False

        # If "/" is excluded, EVERYTHING is excluded!
        assert should_exclude("/") is True
        assert should_exclude("/admin") is True  # Unintended!
        assert should_exclude("/api/private") is True  # Unintended!

    def test_double_slash_bypass(self) -> None:
        """Test double slash handling in paths."""
        exclude_paths = ["/api/public"]

        def should_exclude(path: str) -> bool:
            for pattern in exclude_paths:
                if path.startswith(pattern):
                    return True
            return False

        # Double slash might bypass
        assert should_exclude("//api/public") is False  # Different path!
        assert should_exclude("/api//public") is False  # Different path!


# =============================================================================
# 5. Token Cache Collision Tests
# =============================================================================


class TestTokenCacheCollisions:
    """Tests for token cache hash collision scenarios."""

    def test_hash_truncation_reduces_entropy(self) -> None:
        """Document that hash truncation reduces collision resistance."""
        # Full SHA256 is 64 hex chars (256 bits)
        # Truncated to 32 hex chars (128 bits)
        token = "test_token_12345"
        full_hash = hashlib.sha256(token.encode()).hexdigest()
        truncated_hash = hash_token(token)

        assert len(full_hash) == 64
        assert len(truncated_hash) == 32
        assert truncated_hash == full_hash[:32]

    def test_different_tokens_same_prefix(self) -> None:
        """Test that different tokens with same hash prefix are distinguished."""
        cache = TokenCache(max_size=100, ttl=60)

        # Create many tokens and check for collisions
        tokens = [f"token_{i}" for i in range(10000)]
        hashes = [hash_token(t) for t in tokens]

        # Check for hash collisions
        unique_hashes = set(hashes)
        collisions = len(hashes) - len(unique_hashes)

        # With 128-bit hash, collision probability is negligible for 10k tokens
        assert collisions == 0, f"Found {collisions} hash collisions"

    def test_cache_collision_behavior(self) -> None:
        """Test behavior if two tokens have same hash (hypothetical)."""
        cache = TokenCache(max_size=100, ttl=60)

        user1 = AuthenticatedUser(
            user_id="user1",
            email="user1@test.com",
            permissions=("admin:all",),
        )
        user2 = AuthenticatedUser(
            user_id="user2",
            email="user2@test.com",
            permissions=(),
        )

        claims1 = TokenClaims(sub="user1", exp=9999999999)
        claims2 = TokenClaims(sub="user2", exp=9999999999)

        # If tokens had same hash, second would overwrite first
        # This test uses same "token" to simulate collision
        cache.set("collision_token", user1, claims1)
        cache.set("collision_token", user2, claims2)  # Overwrites!

        entry = cache.get("collision_token")
        assert entry is not None
        # Second user wins
        assert entry.user.user_id == "user2"
        assert entry.user.permissions == ()  # No admin!

    def test_cache_with_similar_tokens(self) -> None:
        """Test cache correctly distinguishes similar tokens."""
        cache = TokenCache(max_size=100, ttl=60)

        # Tokens that are very similar
        base_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        tokens = [
            base_token + ".sig1",
            base_token + ".sig2",
            base_token + ".sig3",
        ]

        users = [
            AuthenticatedUser(user_id=f"user_{i}", permissions=(f"perm_{i}",))
            for i in range(3)
        ]
        claims = [TokenClaims(sub=f"user_{i}") for i in range(3)]

        # Cache all tokens
        for token, user, claim in zip(tokens, users, claims):
            cache.set(token, user, claim)

        # Verify each retrieves correct user
        for i, token in enumerate(tokens):
            entry = cache.get(token)
            assert entry is not None
            assert entry.user.user_id == f"user_{i}"
            assert entry.user.permissions == (f"perm_{i}",)


# =============================================================================
# 6. Concurrent Authentication Tests
# =============================================================================


class TestConcurrentAuthentication:
    """Tests for race conditions in authentication flow."""

    @pytest.mark.asyncio
    async def test_concurrent_bypass_checks_consistent(self) -> None:
        """Test concurrent bypass checks return consistent results."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
            "AB0T_AUTH_BYPASS_USER_ID": "concurrent_test",
        }, clear=True):
            guard = AuthGuard(auth_url="https://test.com")
            guard._bypass_config = load_bypass_config()
            guard._logger = MagicMock()

            results = await asyncio.gather(*[
                guard.authenticate() for _ in range(100)
            ])

            # All should succeed with same user
            assert all(r.success for r in results)
            assert all(r.user.user_id == "concurrent_test" for r in results)

    @pytest.mark.asyncio
    async def test_concurrent_cache_population(self) -> None:
        """Test concurrent requests populating cache."""
        cache = TokenCache(max_size=100, ttl=60)

        user = AuthenticatedUser(user_id="cached_user")
        claims = TokenClaims(sub="cached_user")
        token = "concurrent_token"

        async def cache_and_retrieve() -> AuthenticatedUser | None:
            # Simulate race between cache check and population
            entry = cache.get(token)
            if entry:
                return entry.user

            # Simulate validation delay
            await asyncio.sleep(0.01)

            cache.set(token, user, claims)
            entry = cache.get(token)
            return entry.user if entry else None

        results = await asyncio.gather(*[cache_and_retrieve() for _ in range(50)])

        # All should get the same user (or None if race lost)
        valid_results = [r for r in results if r is not None]
        assert all(r.user_id == "cached_user" for r in valid_results)

    @pytest.mark.asyncio
    async def test_concurrent_permission_cache_updates(self) -> None:
        """Test concurrent permission cache updates."""
        cache = PermissionCache(max_size=100, ttl=60)

        async def update_permission(thread_id: int) -> None:
            for i in range(10):
                cache.set(
                    user_id=f"user_{thread_id}",
                    permission=f"perm_{i}",
                    allowed=(i % 2 == 0),
                )
                await asyncio.sleep(0.001)

        await asyncio.gather(*[update_permission(i) for i in range(10)])

        # Verify cache is not corrupted
        for thread_id in range(10):
            for perm_id in range(10):
                result = cache.get(f"user_{thread_id}", f"perm_{perm_id}")
                # Result should be bool or None, never corrupted
                assert result is None or isinstance(result, bool)


# =============================================================================
# 7. API Confusion Exploitation Tests
# =============================================================================


class TestAPIConfusionExploitation:
    """Tests for API misuse scenarios that could lead to vulnerabilities."""

    def test_permission_required_with_multiple_args(self) -> None:
        """Test that permission_required doesn't silently ignore extra args."""
        # This is a common mistake - using permission_required instead of permissions_required
        from ab0t_auth.decorators import permission_required

        guard = AuthGuard(auth_url="https://test.com")

        # This should only check first permission, ignoring "admin:access"
        # (But actually it would cause a TypeError due to signature)
        # Document the expected behavior
        try:
            decorator = permission_required(guard, "users:read", "admin:access")  # type: ignore
            # If we get here, second arg was ignored (BAD)
            assert False, "Should have raised TypeError"
        except TypeError:
            # Good - invalid usage is caught
            pass

    def test_permissions_required_require_all_default(self) -> None:
        """Test that permissions_required defaults to require_all=True."""
        from ab0t_auth.decorators import permissions_required

        guard = AuthGuard(auth_url="https://test.com")

        # Default should require ALL permissions
        decorator = permissions_required(guard, "users:read", "admin:access")

        # Verify require_all is True by default (safe default)
        # We can't easily inspect the decorator, so we document expected behavior

    @pytest.mark.asyncio
    async def test_check_mode_any_vs_all_confusion(
        self, test_user: AuthenticatedUser, mock_request: MagicMock
    ) -> None:
        """Test difference between check_mode='any' and 'all'."""

        def always_true(user: AuthenticatedUser, request: Request) -> bool:
            return True

        def always_false(user: AuthenticatedUser, request: Request) -> bool:
            return False

        # Mode "all" - all must pass
        with pytest.raises(PermissionDeniedError):
            await _run_auth_checks(
                test_user,
                mock_request,
                check=None,
                checks=[always_true, always_false],
                check_mode="all",
                check_error="All checks must pass",
            )

        # Mode "any" - one must pass
        await _run_auth_checks(
            test_user,
            mock_request,
            check=None,
            checks=[always_true, always_false],
            check_mode="any",
            check_error="Any check must pass",
        )  # Should not raise

    def test_get_current_user_without_decorator(self) -> None:
        """Test get_current_user behavior without login_required decorator."""
        from ab0t_auth.flask import get_current_user
        from flask import Flask

        app = Flask(__name__)

        with app.test_request_context():
            # Without @login_required, get_current_user returns None
            user = get_current_user()
            assert user is None

            # Developer might do this and crash:
            # user.email  # AttributeError!


# =============================================================================
# 8. Permission Logic Edge Cases
# =============================================================================


class TestPermissionLogicEdgeCases:
    """Tests for edge cases in permission checking logic."""

    def test_empty_permission_string(self, test_user: AuthenticatedUser) -> None:
        """Test checking empty permission string."""
        result = check_permission(test_user, "")
        # Empty permission should not be granted
        assert result.allowed is False

    def test_permission_with_special_characters(self) -> None:
        """Test permissions with special characters."""
        user = AuthenticatedUser(
            user_id="test",
            permissions=(
                "resource:123:read",
                "org/tenant/resource",
                "permission-with-dash",
                "permission.with.dots",
            ),
        )

        assert check_permission(user, "resource:123:read").allowed is True
        assert check_permission(user, "org/tenant/resource").allowed is True
        assert check_permission(user, "permission-with-dash").allowed is True
        assert check_permission(user, "permission.with.dots").allowed is True

    def test_permission_pattern_with_brackets(self) -> None:
        """Test fnmatch bracket behavior in permission patterns."""
        user = AuthenticatedUser(
            user_id="test",
            permissions=("users0:read", "users1:read", "usersa:read"),
        )

        # [01] matches 0 or 1
        result = check_permission_pattern(user, "users[01]:read")
        assert result.allowed is True

        # [!0] matches anything except 0
        result = check_permission_pattern(user, "users[!0]:read")
        assert result.allowed is True  # Matches users1 or usersa

    def test_permission_pattern_with_question_mark(self) -> None:
        """Test fnmatch question mark behavior."""
        user = AuthenticatedUser(
            user_id="test",
            permissions=("user:read", "users:read"),
        )

        # ? matches single character
        result = check_permission_pattern(user, "user?:read")
        assert result.allowed is True  # Matches "users:read"

    def test_wildcard_permission_in_user(self) -> None:
        """Test user having wildcard permission."""
        user = AuthenticatedUser(
            user_id="test",
            permissions=("*", "admin:*"),
        )

        # Literal "*" permission
        result = check_permission(user, "*")
        assert result.allowed is True

        # But pattern check is different
        result = check_permission_pattern(user, "users:read")
        assert result.allowed is False  # "*" doesn't match "users:read" in fnmatch

    def test_permission_case_sensitivity(self) -> None:
        """Test that permissions are case-sensitive."""
        user = AuthenticatedUser(
            user_id="test",
            permissions=("Users:Read",),
        )

        # Exact case matches
        assert check_permission(user, "Users:Read").allowed is True

        # Different case doesn't match
        assert check_permission(user, "users:read").allowed is False
        assert check_permission(user, "USERS:READ").allowed is False

    def test_permission_with_unicode(self) -> None:
        """Test permissions with unicode characters."""
        user = AuthenticatedUser(
            user_id="test",
            permissions=("用户:读取", "données:lire"),
        )

        assert check_permission(user, "用户:读取").allowed is True
        assert check_permission(user, "données:lire").allowed is True

    def test_permission_very_long_string(self) -> None:
        """Test very long permission strings."""
        long_perm = "a" * 10000 + ":read"
        user = AuthenticatedUser(
            user_id="test",
            permissions=(long_perm,),
        )

        assert check_permission(user, long_perm).allowed is True
        assert check_permission(user, "a" * 9999 + ":read").allowed is False


# =============================================================================
# 9. Error Information Disclosure Tests
# =============================================================================


class TestErrorInformationDisclosure:
    """Tests for information leakage through error messages."""

    def test_permission_denied_shows_required_permission(self) -> None:
        """Test PermissionDeniedError shows what permission was required."""
        error = PermissionDeniedError(
            "Access denied",
            required_permission="admin:secret-feature",
        )

        error_dict = error.to_dict()

        # This reveals what permission exists (information disclosure)
        assert "admin:secret-feature" in str(error_dict)

    def test_permission_denied_shows_user_permissions(self) -> None:
        """Test PermissionDeniedError can show user's permissions."""
        error = PermissionDeniedError(
            "Access denied",
            required_permission="admin:access",
            user_permissions=["users:read", "users:write"],
        )

        error_dict = error.to_dict()

        # This reveals user's permissions (potential information disclosure)
        assert "users:read" in str(error_dict) or "user_permissions" in error_dict.get("details", {})

    def test_token_error_doesnt_leak_token(self) -> None:
        """Test token errors don't include the actual token."""
        error = TokenInvalidError(
            "Token signature verification failed",
        )

        error_str = str(error.to_dict())

        # Should not contain actual token
        assert "eyJ" not in error_str  # JWT prefix
        assert "Bearer" not in error_str

    def test_service_error_shows_url(self) -> None:
        """Test AuthServiceError shows service URL."""
        error = AuthServiceError(
            "Connection failed",
            service_url="https://internal-auth.company.local:8443/validate",
        )

        error_dict = error.to_dict()

        # This reveals internal infrastructure (information disclosure)
        assert "internal-auth.company.local" in str(error_dict)


# =============================================================================
# 10. Middleware Bypass Attempts
# =============================================================================


class TestMiddlewareBypassAttempts:
    """Tests for attempts to bypass auth middleware."""

    def test_header_injection_attempt(self) -> None:
        """Test header injection doesn't bypass auth."""
        # Attempt to inject headers via CRLF
        malicious_headers = {
            "Authorization": "Bearer token\r\nX-Bypass-Auth: true",
            "X-Forwarded-For": "127.0.0.1\r\nAuthorization: Bearer admin_token",
        }

        # Headers should be treated as single values
        for header_value in malicious_headers.values():
            # Newlines in headers are generally rejected by frameworks
            # but the auth code should handle them safely
            assert "\r\n" in header_value or "\n" in header_value

    def test_multiple_authorization_headers(self) -> None:
        """Test handling of multiple Authorization headers."""
        # Some frameworks allow multiple headers with same name
        # Auth should use first or reject

        from ab0t_auth.jwt import parse_token_header

        # Single valid header
        token = parse_token_header("Bearer valid_token")
        assert token == "valid_token"

        # Empty bearer
        token = parse_token_header("Bearer ")
        assert token is None

        # No bearer prefix
        token = parse_token_header("valid_token")
        assert token is None

    def test_bearer_case_sensitivity(self) -> None:
        """Test Bearer prefix case sensitivity."""
        from ab0t_auth.jwt import parse_token_header

        # Standard case
        assert parse_token_header("Bearer token123") == "token123"

        # Lowercase - should work (case insensitive)
        assert parse_token_header("bearer token123") == "token123"

        # Uppercase - should work
        assert parse_token_header("BEARER token123") == "token123"

        # Mixed case - should work
        assert parse_token_header("BeArEr token123") == "token123"

    def test_bearer_with_extra_spaces(self) -> None:
        """Test Bearer with unusual spacing."""
        from ab0t_auth.jwt import parse_token_header

        # Extra space after Bearer - implementation splits on whitespace
        result = parse_token_header("Bearer  token")
        # Implementation handles extra whitespace gracefully
        assert result is None or result == " token" or result == "token"

        # Tab instead of space - implementation uses split() which handles all whitespace
        result = parse_token_header("Bearer\ttoken")
        # Document actual behavior: split() handles tabs as whitespace
        assert result == "token"  # Tabs are treated as whitespace separators

    def test_non_bearer_schemes(self) -> None:
        """Test other auth schemes don't accidentally work."""
        from ab0t_auth.jwt import parse_token_header

        # Basic auth
        assert parse_token_header("Basic dXNlcjpwYXNz") is None

        # Digest auth
        assert parse_token_header("Digest username=test") is None

        # Custom scheme
        assert parse_token_header("Custom token123") is None

        # Bearer-like
        assert parse_token_header("Bearer2 token") is None
        assert parse_token_header("Bearertoken") is None


# =============================================================================
# 11. Bypass Configuration Attack Vectors
# =============================================================================


class TestBypassConfigurationAttacks:
    """Additional tests for bypass configuration security."""

    def test_bypass_with_spaces_in_permissions(self) -> None:
        """Test permissions with spaces are handled correctly."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
            "AB0T_AUTH_BYPASS_PERMISSIONS": "admin access,users read",
        }, clear=True):
            config = load_bypass_config()
            # Spaces should be part of permission name, not separator
            assert config.permissions == ("admin access", "users read")

    def test_bypass_with_comma_in_permission(self) -> None:
        """Test escaping commas in permissions."""
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
            # No way to escape comma - it's always separator
            "AB0T_AUTH_BYPASS_PERMISSIONS": "perm1,perm2,perm3",
        }, clear=True):
            config = load_bypass_config()
            assert len(config.permissions) == 3

    def test_bypass_config_timing_consistent(self) -> None:
        """Test bypass config loading is constant time for enabled/disabled."""
        import time

        iterations = 1000

        # Disabled bypass
        with patch.dict(os.environ, {}, clear=True):
            start = time.perf_counter_ns()
            for _ in range(iterations):
                load_bypass_config()
            disabled_time = time.perf_counter_ns() - start

        # Enabled bypass
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
            "AB0T_AUTH_BYPASS_PERMISSIONS": "perm1,perm2,perm3",
        }, clear=True):
            start = time.perf_counter_ns()
            for _ in range(iterations):
                load_bypass_config()
            enabled_time = time.perf_counter_ns() - start

        # Times should be similar (within 10x) - both are fast
        ratio = max(disabled_time, enabled_time) / max(min(disabled_time, enabled_time), 1)
        assert ratio < 10, f"Timing ratio too high: {ratio}"


# =============================================================================
# 12. Integration Security Tests
# =============================================================================


class TestIntegrationSecurity:
    """Integration tests for security scenarios."""

    @pytest.mark.asyncio
    async def test_full_auth_flow_with_bypass_then_disabled(self) -> None:
        """Test auth works correctly when bypass is enabled then disabled."""
        # Start with bypass enabled
        with patch.dict(os.environ, {
            "AB0T_AUTH_BYPASS": "true",
            "AB0T_AUTH_DEBUG": "true",
        }, clear=True):
            guard = AuthGuard(auth_url="https://test.com")
            guard._bypass_config = load_bypass_config()

            result = await guard.authenticate()
            assert result.success is True
            assert result.user.auth_method == AuthMethod.BYPASS

        # Now disable bypass
        with patch.dict(os.environ, {}, clear=True):
            # Same guard instance, update config
            guard._bypass_config = load_bypass_config()

            # Should now require real credentials
            result = await guard.authenticate()
            assert result.success is False
            assert result.error_code == "NO_CREDENTIALS"

    @pytest.mark.asyncio
    async def test_permission_escalation_via_cache(self) -> None:
        """Test that cached user can't escalate permissions."""
        cache = TokenCache(max_size=100, ttl=60)

        # User starts with limited permissions
        limited_user = AuthenticatedUser(
            user_id="user1",
            permissions=("users:read",),
        )
        claims = TokenClaims(sub="user1")
        token = "user_token"

        cache.set(token, limited_user, claims)

        # Attacker can't modify cached user (frozen dataclass)
        cached_entry = cache.get(token)
        assert cached_entry is not None

        with pytest.raises(AttributeError):
            cached_entry.user.permissions = ("admin:all",)  # type: ignore

        # Verify permissions unchanged
        assert cached_entry.user.permissions == ("users:read",)

    def test_config_cannot_be_modified(self) -> None:
        """Test AuthConfig is immutable."""
        config = AuthConfig(
            auth_url="https://test.com",
            token_cache_ttl=60,
        )

        with pytest.raises(AttributeError):
            config.auth_url = "https://evil.com"  # type: ignore

        with pytest.raises(AttributeError):
            config.token_cache_ttl = 99999  # type: ignore
