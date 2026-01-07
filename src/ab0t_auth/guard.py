"""
AuthGuard - Main authentication coordinator for Ab0t Auth.

Infrastructure class that manages state and coordinates authentication flow.
Similar to slowapi's Limiter - provides the main interface for the library.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import httpx
from jwt import PyJWKClient

from ab0t_auth.cache import (
    JWKSCache,
    PermissionCache,
    TokenCache,
    create_caches,
)
from ab0t_auth.client import (
    create_http_client,
    validate_api_key,
    validate_token as validate_token_remote,
)
from ab0t_auth.config import AuthSettings, BypassConfig, create_config, load_bypass_config, settings_to_config
from ab0t_auth.core import (
    AuthConfig,
    AuthContext,
    AuthenticatedUser,
    AuthMethod,
    AuthResult,
    TokenClaims,
    TokenType,
)
from ab0t_auth.errors import (
    AuthError,
    ConfigurationError,
    TokenInvalidError,
    TokenNotFoundError,
)
from ab0t_auth.jwt import (
    create_jwk_client,
    parse_token_header,
    validate_token_pipeline,
)
from ab0t_auth.logging import (
    AuthMetrics,
    Timer,
    get_logger,
    log_auth_attempt,
    log_token_validation,
)
from ab0t_auth.permissions import (
    check_permission,
    require_permission_or_raise,
)


class AuthGuard:
    """
    Main authentication guard for FastAPI applications.

    Infrastructure class that coordinates authentication and authorization.
    Manages HTTP clients, caches, and JWKS validation.

    Similar interface to slowapi's Limiter - initialize once, use everywhere.

    Example:
        auth = AuthGuard(auth_url="https://auth.service.ab0t.com")

        @app.get("/protected")
        async def protected(user: AuthenticatedUser = Depends(auth.require_auth())):
            return {"user_id": user.user_id}

        # Or use with decorator
        @app.get("/admin")
        @auth.require_permission("admin:access")
        async def admin_only():
            return {"admin": True}
    """

    def __init__(
        self,
        auth_url: str | None = None,
        *,
        config: AuthConfig | None = None,
        settings: AuthSettings | None = None,
        org_id: str | None = None,
        audience: str | tuple[str, ...] | None = None,
        issuer: str | None = None,
        debug: bool = False,
    ) -> None:
        """
        Initialize AuthGuard.

        Args:
            auth_url: Ab0t auth service URL (required if no config/settings)
            config: Pre-built AuthConfig (takes precedence)
            settings: AuthSettings instance (used if no config)
            org_id: Default organization ID
            audience: Expected JWT audience
            issuer: Expected JWT issuer
            debug: Enable debug logging
        """
        # Build configuration
        if config:
            self._config = config
        elif settings:
            self._config = settings_to_config(settings)
        elif auth_url:
            self._config = create_config(
                auth_url=auth_url,
                org_id=org_id,
                audience=audience,
                issuer=issuer,
                debug=debug,
            )
        else:
            raise ConfigurationError(
                "Must provide auth_url, config, or settings",
                config_key="auth_url",
            )

        # Initialize components
        self._http_client: httpx.AsyncClient | None = None
        self._jwk_client: PyJWKClient | None = None

        # Initialize caches
        self._token_cache, self._permission_cache, self._jwks_cache = create_caches(
            self._config
        )

        # Load bypass configuration (for testing/development)
        self._bypass_config = load_bypass_config()

        # Logging and metrics
        self._logger = get_logger("ab0t_auth.guard")
        self._metrics = AuthMetrics()

        # State tracking
        self._initialized = False

    # =========================================================================
    # Properties
    # =========================================================================

    @property
    def config(self) -> AuthConfig:
        """Get auth configuration."""
        return self._config

    @property
    def metrics(self) -> AuthMetrics:
        """Get auth metrics."""
        return self._metrics

    @property
    def is_initialized(self) -> bool:
        """Check if guard is initialized."""
        return self._initialized

    # =========================================================================
    # Lifecycle Management
    # =========================================================================

    async def initialize(self) -> None:
        """
        Initialize HTTP client and JWKS client.

        Call during application startup.
        """
        if self._initialized:
            return

        self._http_client = create_http_client()

        if self._config.enable_jwt_auth:
            self._jwk_client = create_jwk_client(self._config)

        self._initialized = True
        self._logger.info(
            "AuthGuard initialized",
            auth_url=self._config.auth_url,
            jwt_enabled=self._config.enable_jwt_auth,
            api_key_enabled=self._config.enable_api_key_auth,
        )

    async def shutdown(self) -> None:
        """
        Cleanup resources.

        Call during application shutdown.
        """
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

        self._token_cache.clear()
        self._permission_cache.clear()
        self._jwks_cache.clear()

        self._initialized = False
        self._logger.info("AuthGuard shutdown complete")

    @asynccontextmanager
    async def lifespan(self) -> AsyncIterator[None]:
        """
        Context manager for FastAPI lifespan.

        Example:
            auth = AuthGuard(...)

            @asynccontextmanager
            async def lifespan(app: FastAPI):
                async with auth.lifespan():
                    yield

            app = FastAPI(lifespan=lifespan)
        """
        await self.initialize()
        try:
            yield
        finally:
            await self.shutdown()

    # =========================================================================
    # Core Authentication Methods
    # =========================================================================

    def _check_auth_bypass(self) -> AuthResult | None:
        """
        Check if auth bypass is enabled and return bypass user.

        Returns AuthResult if bypass is active, None otherwise.
        Requires BOTH AB0T_AUTH_BYPASS=true AND AB0T_AUTH_DEBUG=true.
        """
        if not self._bypass_config.enabled:
            return None

        # Log WARNING on every bypass - makes it obvious in logs
        self._logger.warning(
            "AUTH BYPASS ACTIVE",
            event_type="auth_bypass",
            user_id=self._bypass_config.user_id,
            permissions=self._bypass_config.permissions,
            roles=self._bypass_config.roles,
            warning="Not for production use",
        )

        user = AuthenticatedUser(
            user_id=self._bypass_config.user_id,
            email=self._bypass_config.email,
            org_id=self._bypass_config.org_id,
            permissions=self._bypass_config.permissions,
            roles=self._bypass_config.roles,
            auth_method=AuthMethod.BYPASS,
            token_type=TokenType.NONE,
        )

        return AuthResult.ok(user)

    async def authenticate(
        self,
        authorization: str | None = None,
        api_key: str | None = None,
    ) -> AuthResult:
        """
        Authenticate request using token or API key.

        Main authentication entry point.
        Returns AuthResult - check .success before using .user.
        """
        # Check for bypass first (testing/development only)
        bypass_result = self._check_auth_bypass()
        if bypass_result:
            self._metrics.record_auth_attempt(True)
            return bypass_result

        if not self._initialized:
            await self.initialize()

        timer = Timer().start()

        # Try JWT authentication first
        if authorization and self._config.enable_jwt_auth:
            result = await self._authenticate_jwt(authorization)
            timer.stop()

            log_auth_attempt(
                self._logger,
                method="jwt",
                success=result.success,
                user_id=result.user.user_id if result.user else None,
                duration_ms=timer.elapsed_ms,
                error=result.error_message,
            )
            self._metrics.record_auth_attempt(result.success)

            if result.success:
                return result

        # Try API key authentication
        if api_key and self._config.enable_api_key_auth:
            result = await self._authenticate_api_key(api_key)
            timer.stop()

            log_auth_attempt(
                self._logger,
                method="api_key",
                success=result.success,
                user_id=result.user.user_id if result.user else None,
                duration_ms=timer.elapsed_ms,
                error=result.error_message,
            )
            self._metrics.record_auth_attempt(result.success)

            return result

        # No valid credentials
        return AuthResult.fail(
            "NO_CREDENTIALS",
            "No valid authentication credentials provided",
        )

    async def authenticate_or_raise(
        self,
        authorization: str | None = None,
        api_key: str | None = None,
    ) -> AuthenticatedUser:
        """
        Authenticate and return user or raise AuthError.

        Convenience method that raises on failure.
        """
        result = await self.authenticate(authorization, api_key)

        if not result.success or result.user is None:
            if result.error_code == "NO_CREDENTIALS":
                raise TokenNotFoundError(
                    result.error_message or "Authentication required",
                    expected_header=self._config.header_name,
                )
            raise TokenInvalidError(
                result.error_message or "Authentication failed",
                reason=result.error_code,
            )

        return result.user

    async def _authenticate_jwt(self, authorization: str) -> AuthResult:
        """
        Authenticate using JWT token.

        Internal method - handles JWT validation flow.
        """
        # Parse token from header
        token = parse_token_header(authorization, self._config.header_prefix)
        if not token:
            return AuthResult.fail(
                "INVALID_HEADER",
                f"Invalid Authorization header format. Expected: {self._config.header_prefix} <token>",
            )

        # Check cache first
        cached_entry = self._token_cache.get(token)
        if cached_entry:
            self._metrics.record_cache_access(hit=True)
            log_token_validation(
                self._logger,
                valid=True,
                method="jwt",
                user_id=cached_entry.user.user_id,
                cached=True,
            )
            return AuthResult.ok(cached_entry.user)

        self._metrics.record_cache_access(hit=False)

        # Validate token
        try:
            if not self._jwk_client:
                return AuthResult.fail("JWT_DISABLED", "JWT authentication not enabled")

            user, claims = validate_token_pipeline(
                token,
                self._jwk_client,
                self._config,
            )

            # Cache successful validation
            self._token_cache.set(token, user, claims)
            self._metrics.record_token_validation()

            log_token_validation(
                self._logger,
                valid=True,
                method="jwt",
                user_id=user.user_id,
                cached=False,
            )

            return AuthResult.ok(user)

        except AuthError as e:
            log_token_validation(
                self._logger,
                valid=False,
                method="jwt",
                error=str(e),
            )
            return AuthResult.fail(e.code, e.message)

        except Exception as e:
            log_token_validation(
                self._logger,
                valid=False,
                method="jwt",
                error=str(e),
            )
            return AuthResult.fail("VALIDATION_ERROR", str(e))

    async def _authenticate_api_key(self, api_key: str) -> AuthResult:
        """
        Authenticate using API key.

        Internal method - validates API key with Ab0t service.
        """
        if not self._http_client:
            return AuthResult.fail("NOT_INITIALIZED", "AuthGuard not initialized")

        try:
            response = await validate_api_key(
                self._http_client,
                self._config,
                api_key,
            )

            if not response.valid:
                return AuthResult.fail(
                    "INVALID_API_KEY",
                    response.error or "Invalid API key",
                )

            user = AuthenticatedUser(
                user_id=response.user_id or "api_key_user",
                email=response.email,
                org_id=response.org_id,
                permissions=response.permissions,
                auth_method=AuthMethod.API_KEY,
                token_type=TokenType.API_KEY,
            )

            return AuthResult.ok(user)

        except AuthError as e:
            return AuthResult.fail(e.code, e.message)
        except Exception as e:
            return AuthResult.fail("API_KEY_ERROR", str(e))

    # =========================================================================
    # Authorization Methods
    # =========================================================================

    def check_permission(
        self,
        user: AuthenticatedUser,
        permission: str,
    ) -> bool:
        """
        Check if user has permission (client-side).

        Fast, synchronous check using token claims.
        """
        result = check_permission(user, permission)
        self._metrics.record_permission_check(result.allowed)
        return result.allowed

    def require_permission(
        self,
        user: AuthenticatedUser,
        permission: str,
    ) -> None:
        """
        Require permission or raise PermissionDeniedError.

        Synchronous check that raises on denial.
        """
        require_permission_or_raise(user, permission)
        self._metrics.record_permission_check(True)

    # =========================================================================
    # Cache Management
    # =========================================================================

    def invalidate_token(self, token: str) -> bool:
        """
        Invalidate cached token.

        Call when token is known to be revoked.
        """
        return self._token_cache.invalidate(token)

    def invalidate_user_permissions(self, user_id: str) -> int:
        """
        Invalidate cached permissions for user.

        Call when user permissions change.
        """
        return self._permission_cache.invalidate_user(user_id)

    def clear_caches(self) -> None:
        """Clear all caches."""
        self._token_cache.clear()
        self._permission_cache.clear()
        self._jwks_cache.clear()

    # =========================================================================
    # Utility Methods
    # =========================================================================

    def get_context(
        self,
        user: AuthenticatedUser | None,
        token: str | None = None,
        request_id: str | None = None,
    ) -> AuthContext:
        """
        Create auth context for request.

        Utility method for building context objects.
        """
        return AuthContext(
            user=user,
            is_authenticated=user is not None,
            token=token,
            token_type=user.token_type if user else None,
            request_id=request_id,
        )

    def __repr__(self) -> str:
        return (
            f"AuthGuard(auth_url={self._config.auth_url!r}, "
            f"initialized={self._initialized})"
        )
