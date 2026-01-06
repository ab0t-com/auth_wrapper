"""
JWT validation functions for Ab0t Auth.

Pure functions for local JWT validation using JWKS.
Follows RFC 7517 (JWK), RFC 7519 (JWT), and OpenID Connect Discovery.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import jwt
from jwt import PyJWKClient, PyJWKClientError

from ab0t_auth.cache import JWKSCache
from ab0t_auth.core import AuthConfig, AuthenticatedUser, AuthMethod, TokenClaims, TokenType
from ab0t_auth.errors import (
    JWKSFetchError,
    TokenExpiredError,
    TokenInvalidError,
    map_jwt_error,
)


# =============================================================================
# Token Parsing Functions (Pure)
# =============================================================================


def parse_token_header(header_value: str, prefix: str = "Bearer") -> str | None:
    """
    Extract token from Authorization header.

    Pure function - returns None if format invalid.
    """
    if not header_value:
        return None

    parts = header_value.split(maxsplit=1)
    if len(parts) != 2:
        return None

    scheme, token = parts
    if scheme.lower() != prefix.lower():
        return None

    return token if token else None


def decode_token_unverified(token: str) -> TokenClaims:
    """
    Decode token without signature verification.

    WARNING: Only use for inspection, never for authentication.
    Pure function.
    """
    try:
        payload = jwt.decode(
            token,
            options={"verify_signature": False},
        )
        return claims_to_token_claims(payload)
    except jwt.DecodeError as e:
        raise TokenInvalidError(
            "Failed to decode token",
            reason=str(e),
        ) from e


def claims_to_token_claims(payload: dict[str, Any]) -> TokenClaims:
    """
    Convert raw JWT payload to TokenClaims.

    Pure function - transforms data structure.
    """
    # Parse permissions from various formats
    permissions: tuple[str, ...] = ()
    if "permissions" in payload:
        perms = payload["permissions"]
        if isinstance(perms, list):
            permissions = tuple(perms)
    elif "scope" in payload:
        scope = payload["scope"]
        if isinstance(scope, str) and scope:
            permissions = tuple(scope.split())

    # Parse roles
    roles: tuple[str, ...] = ()
    if "roles" in payload:
        r = payload["roles"]
        if isinstance(r, list):
            roles = tuple(r)

    # Handle audience as string or list
    aud = payload.get("aud")
    if isinstance(aud, list):
        aud = tuple(aud)

    return TokenClaims(
        sub=payload.get("sub"),
        email=payload.get("email"),
        org_id=payload.get("org_id"),
        user_id=payload.get("user_id") or payload.get("sub"),
        permissions=permissions,
        roles=roles,
        exp=payload.get("exp"),
        iat=payload.get("iat"),
        nbf=payload.get("nbf"),
        iss=payload.get("iss"),
        aud=aud,
        jti=payload.get("jti"),
        raw=payload,
    )


def token_claims_to_user(claims: TokenClaims, auth_method: AuthMethod = AuthMethod.JWT) -> AuthenticatedUser:
    """
    Convert TokenClaims to AuthenticatedUser.

    Pure function.
    """
    user_id = claims.user_id or claims.sub
    if not user_id:
        raise TokenInvalidError("Token missing user identifier (sub or user_id)")

    return AuthenticatedUser(
        user_id=user_id,
        email=claims.email,
        org_id=claims.org_id,
        permissions=claims.permissions,
        roles=claims.roles,
        auth_method=auth_method,
        token_type=TokenType.BEARER,
        claims=claims,
    )


def is_token_expired(claims: TokenClaims, leeway: int = 0) -> bool:
    """
    Check if token is expired.

    Pure function.
    """
    if claims.exp is None:
        return False

    return time.time() > (claims.exp + leeway)


def is_token_not_yet_valid(claims: TokenClaims, leeway: int = 0) -> bool:
    """
    Check if token is not yet valid (nbf claim).

    Pure function.
    """
    if claims.nbf is None:
        return False

    return time.time() < (claims.nbf - leeway)


# =============================================================================
# JWKS Functions
# =============================================================================


def build_jwks_url(config: AuthConfig) -> str:
    """
    Build JWKS URL from config.

    Pure function.
    """
    if config.org_id:
        return f"{config.auth_url}/organizations/{config.org_id}/.well-known/jwks.json"
    return f"{config.auth_url}/.well-known/jwks.json"


def create_jwk_client(config: AuthConfig) -> PyJWKClient:
    """
    Create PyJWKClient for JWKS-based validation.

    Factory function - creates configured client.
    """
    jwks_url = build_jwks_url(config)
    return PyJWKClient(
        jwks_url,
        cache_jwk_set=True,
        lifespan=config.jwks_cache_ttl,
    )


async def fetch_jwks_async(
    client: httpx.AsyncClient,
    config: AuthConfig,
    cache: JWKSCache | None = None,
) -> dict[str, Any]:
    """
    Fetch JWKS asynchronously with optional caching.

    Async function for non-blocking JWKS retrieval.
    """
    # Check cache first
    if cache:
        cached = cache.get(config.auth_url, config.org_id)
        if cached:
            return cached

    jwks_url = build_jwks_url(config)

    try:
        response = await client.get(jwks_url)
        response.raise_for_status()
        keys = response.json()

        # Update cache
        if cache:
            cache.set(config.auth_url, keys, config.org_id, config.jwks_cache_ttl)

        return keys

    except httpx.HTTPError as e:
        raise JWKSFetchError(
            f"Failed to fetch JWKS: {e}",
            jwks_url=jwks_url,
        ) from e


# =============================================================================
# Token Validation Functions
# =============================================================================


def validate_token_local(
    token: str,
    jwk_client: PyJWKClient,
    config: AuthConfig,
) -> TokenClaims:
    """
    Validate JWT locally using JWKS.

    Pure function (given initialized jwk_client).
    No network calls during validation - uses cached keys.
    """
    try:
        # Get signing key from JWKS
        signing_key = jwk_client.get_signing_key_from_jwt(token)

        # Build decode options
        options: dict[str, bool] = {
            "verify_exp": config.verify_exp,
            "verify_aud": config.verify_aud and config.audience is not None,
            "verify_iss": config.issuer is not None,
        }

        # Prepare audience
        audience: str | list[str] | None = None
        if config.audience:
            if isinstance(config.audience, tuple):
                audience = list(config.audience)
            else:
                audience = config.audience

        # Decode and validate
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=list(config.algorithms),
            audience=audience,
            issuer=config.issuer,
            leeway=config.leeway_seconds,
            options=options,
        )

        return claims_to_token_claims(payload)

    except jwt.ExpiredSignatureError as e:
        raise TokenExpiredError(str(e)) from e
    except PyJWKClientError as e:
        raise JWKSFetchError(str(e)) from e
    except jwt.PyJWTError as e:
        raise map_jwt_error(e) from e


def validate_and_convert(
    token: str,
    jwk_client: PyJWKClient,
    config: AuthConfig,
) -> AuthenticatedUser:
    """
    Validate token and convert to AuthenticatedUser.

    Combines validation and conversion in single operation.
    """
    claims = validate_token_local(token, jwk_client, config)
    return token_claims_to_user(claims)


# =============================================================================
# Token Validation Pipeline (Functional)
# =============================================================================


def validate_token_pipeline(
    token: str,
    jwk_client: PyJWKClient,
    config: AuthConfig,
) -> tuple[AuthenticatedUser, TokenClaims]:
    """
    Full token validation pipeline.

    Returns both user and claims for complete context.
    Pure function given initialized dependencies.
    """
    # Step 1: Validate and decode
    claims = validate_token_local(token, jwk_client, config)

    # Step 2: Additional validation
    if config.verify_exp and is_token_expired(claims, config.leeway_seconds):
        raise TokenExpiredError("Token has expired", expired_at=claims.exp)

    if is_token_not_yet_valid(claims, config.leeway_seconds):
        raise TokenInvalidError("Token is not yet valid", reason="nbf_claim")

    # Step 3: Convert to user
    user = token_claims_to_user(claims)

    return user, claims


# =============================================================================
# Token Introspection (for revocation checks)
# =============================================================================


def should_introspect(claims: TokenClaims, *, introspect_threshold: int = 300) -> bool:
    """
    Determine if token should be introspected for revocation.

    Returns True for tokens close to expiration or long-lived tokens.
    Pure function.
    """
    if claims.exp is None:
        return True  # Always introspect tokens without expiration

    time_until_exp = claims.exp - time.time()

    # Introspect if close to expiration (might be revoked)
    if time_until_exp < introspect_threshold:
        return True

    # Introspect long-lived tokens (more likely to be revoked)
    if claims.iat:
        token_age = time.time() - claims.iat
        if token_age > 3600:  # More than 1 hour old
            return True

    return False
