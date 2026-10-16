"""
Caching layer for Ab0t Auth.

High-performance in-memory caching for tokens, JWKS, and validation results.
Uses TTL-based expiration for security.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

from cachetools import TLRUCache, TTLCache

from ab0t_auth.core import (
    ApiKeyValidationResponse,
    AuthConfig,
    AuthenticatedUser,
    MeshToken,
    TokenClaims,
)

T = TypeVar("T")


# =============================================================================
# Decision-cache defaults (seconds)
# =============================================================================
#
# A decision-cache TTL is a security property: it is the longest a revoked grant / revoked key keeps working on this
# service. These match the Go SDK (auth-sdk-go) so both SDKs behave the same. Every value is configurable and 0
# disables that cache (strict: every call asks the auth service).

DEFAULT_PERMISSION_CACHE_TTL = 15
"""Positive permission decision (allowed=True). Was 30 s up to 0.1.3."""

DEFAULT_PERMISSION_CACHE_NEGATIVE_TTL = 5
"""Negative permission decision (allowed=False). Up to 0.1.3 a denial used the positive TTL."""

DEFAULT_API_KEY_CACHE_TTL = 60
"""Valid API key. Up to 0.1.3 API-key validation was not cached (one auth call per request)."""

DEFAULT_API_KEY_CACHE_NEGATIVE_TTL = 10
"""Rejected API key (the auth service answered: not valid)."""

DEFAULT_API_KEY_CACHE_MAX_SIZE = 10_000


def _monotonic() -> float:
    """Clock for the decision caches (a module-level seam so tests can move time)."""
    return time.monotonic()


def _clamp_negative_ttl(negative_ttl: int | None, positive_ttl: int, default: int) -> int:
    """A negative TTL never exceeds the positive one; None means the default. Pure function."""
    neg = default if negative_ttl is None else negative_ttl
    return max(0, min(neg, positive_ttl))


# =============================================================================
# Cache Entry Types
# =============================================================================


@dataclass(frozen=True, slots=True)
class CacheEntry(Generic[T]):
    """
    Immutable cache entry with metadata.

    Generic over the cached value type.
    """

    value: T
    created_at: float
    expires_at: float
    cache_key: str

    def is_expired(self, now: float | None = None) -> bool:
        """Check if entry has expired."""
        return (now or time.time()) >= self.expires_at


@dataclass(frozen=True, slots=True)
class TokenCacheEntry:
    """Cached token validation result."""

    user: AuthenticatedUser
    claims: TokenClaims
    created_at: float
    expires_at: float


@dataclass(frozen=True, slots=True)
class JWKSCacheEntry:
    """Cached JWKS keys."""

    keys: dict[str, Any]
    created_at: float
    expires_at: float


# =============================================================================
# Cache Key Functions (Pure)
# =============================================================================


def hash_token(token: str) -> str:
    """
    Create cache key from token.

    Uses SHA256 for security - doesn't store actual token.
    Pure function.
    """
    return hashlib.sha256(token.encode()).hexdigest()[:32]


def hash_api_key(api_key: str) -> str:
    """
    Create cache key from an API key.

    Full SHA-256 digest - the raw key is never stored.
    Pure function.
    """
    return hashlib.sha256(api_key.encode()).hexdigest()


def permission_credential_fingerprint(token: str | None, api_key: str | None = None) -> str | None:
    """
    Fingerprint of the credential a permission check is ASKED WITH (permission cache keying).

    Priority matches client.check_permission (Authorization token first, then the API key). Only a SHA-256 prefix is
    kept (hash_token) — the credential itself is never stored. None when there is no credential: such a result must
    not be cached, because it cannot be attributed to a credential.
    Pure function.
    """
    raw = (token or "").strip()
    if raw[:7].lower() == "bearer ":
        raw = raw[7:].strip()
    if not raw:
        raw = (api_key or "").strip()
    return hash_token(raw) if raw else None


def create_permission_cache_key(
    user_id: str,
    permission: str,
    resource_id: str | None,
    credential: str | None = None,
    org_id: str | None = None,
) -> str:
    """
    Create cache key for permission check.

    Permission cache keying: a permission answer belongs to the CREDENTIAL that asked (an API key's own scope, a
    delegation's scope, a login token's user) and to the ORG it was asked in — never to the user id alone. Keyed
    `user_id:cred=<fp>:org=<org>:permission[:resource]` so an owner's (or a wide key's) `allowed` is never served to
    the owner's narrow key, and a narrow key's `denied` never locks the owner out. The user id stays the PREFIX so
    invalidate_user() still clears every credential of that user. A lookup WITHOUT a credential builds the legacy
    `user_id:permission` key, which the library never writes any more — so a user-id-only reader always misses
    (fails over to a real check) instead of reusing another credential's answer.
    Pure function.
    """
    parts = [user_id]
    if credential is not None:
        parts.append(f"cred={credential}")
        parts.append(f"org={org_id or ''}")
    parts.append(permission)
    if resource_id:
        parts.append(resource_id)
    return ":".join(parts)


def create_mesh_token_cache_key(
    client_id: str, resource: str, scope: str, subject_token: str
) -> str:
    """Cache key for a token_for (P3) result.

    Keyed by (client_id, resource, normalized scope, subject token). The subject
    token enters ONLY as a SHA-256 digest (hash_token) — never stored verbatim —
    so a new sign-in is a new key and one person's token is never handed to
    another. Components are length-prefixed so distinct inputs cannot collide.
    Pure function.
    """
    subj = hash_token(subject_token)
    parts = (client_id, resource, scope, subj)
    raw = "\x1e".join(f"{len(p)}:{p}" for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()


def create_jwks_cache_key(auth_url: str, org_id: str | None) -> str:
    """
    Create cache key for JWKS.

    Pure function.
    """
    if org_id:
        return f"jwks:{auth_url}:{org_id}"
    return f"jwks:{auth_url}"


# =============================================================================
# Token Cache
# =============================================================================


@dataclass
class TokenCache:
    """
    Thread-safe token validation cache.

    Uses TTLCache for automatic expiration.
    Infrastructure class - holds state for caching.
    """

    max_size: int = 1000
    ttl: int = 60  # seconds
    _cache: TTLCache[str, TokenCacheEntry] = field(init=False)

    def __post_init__(self) -> None:
        self._cache = TTLCache(maxsize=self.max_size, ttl=self.ttl)

    def get(self, token: str) -> TokenCacheEntry | None:
        """
        Get cached token entry.

        Returns None if not found or expired.

        Security hardening: the TTLCache TTL is cache-wide, so an entry validated shortly before the
        token's `exp` used to be served for the full TTL after the token expired. The per-entry `expires_at` (capped
        at the token's `exp` in set()) is enforced here.
        """
        key = hash_token(token)
        entry = self._cache.get(key)
        if entry is not None and entry.expires_at <= time.time():
            self._cache.pop(key, None)
            return None
        return entry

    def set(
        self,
        token: str,
        user: AuthenticatedUser,
        claims: TokenClaims,
        ttl: int | None = None,
    ) -> None:
        """
        Cache token validation result.

        Uses token hash as key for security. Only called after a SUCCESSFUL validation - a failed validation is never
        cached. The entry is never served past the token's own `exp`; a TTL of 0 disables the cache (no-op).
        """
        effective_ttl = ttl if ttl is not None else self.ttl
        if effective_ttl <= 0:
            return
        key = hash_token(token)
        now = time.time()
        expires_at = now + effective_ttl
        # Never cache a token past its own expiry.
        if claims.exp is not None:
            expires_at = min(expires_at, float(claims.exp))
        if expires_at <= now:
            return

        entry = TokenCacheEntry(
            user=user,
            claims=claims,
            created_at=now,
            expires_at=expires_at,
        )
        self._cache[key] = entry

    def invalidate(self, token: str) -> bool:
        """
        Remove token from cache.

        Returns True if token was cached.
        """
        key = hash_token(token)
        if key in self._cache:
            del self._cache[key]
            return True
        return False

    def clear(self) -> None:
        """Clear all cached tokens."""
        self._cache.clear()

    @property
    def size(self) -> int:
        """Current cache size."""
        return len(self._cache)


# =============================================================================
# Permission Cache
# =============================================================================


@dataclass
class PermissionCache:
    """
    Cache for permission check results (server mode, /permissions/check).

    Permissions are dynamic (grants, revokes, team moves), so the TTL is short: an `allowed` answer is reused for at
    most `ttl` seconds (default 15) and a `denied` answer for at most `negative_ttl` seconds (default 5, never longer
    than `ttl`). `ttl=0` disables the cache. Only answers the auth service actually gave are cached - an auth-service
    error / 429 / 5xx / timeout is never cached (the caller only calls set() on an answer). The ttl is the revocation
    latency: a revoked grant can keep passing on this service for up to `ttl` seconds.
    """

    max_size: int = 5000
    ttl: int = DEFAULT_PERMISSION_CACHE_TTL  # seconds - short for permission changes
    negative_ttl: int | None = None  # None -> DEFAULT_PERMISSION_CACHE_NEGATIVE_TTL, clamped to <= ttl
    _cache: TLRUCache[str, bool] = field(init=False, repr=False)
    _negative_ttl: int = field(init=False, repr=False)
    hits: int = field(default=0, init=False)
    misses: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self._negative_ttl = _clamp_negative_ttl(
            self.negative_ttl, self.ttl, DEFAULT_PERMISSION_CACHE_NEGATIVE_TTL
        )
        self._cache = TLRUCache(
            maxsize=self.max_size,
            ttu=self._time_to_use,
            timer=lambda: _monotonic(),
        )

    def _time_to_use(self, _key: str, allowed: bool, now: float) -> float:
        """Per-entry expiry: positive answers live `ttl`, negative answers `negative_ttl`."""
        return now + (self.ttl if allowed else self._negative_ttl)

    @property
    def enabled(self) -> bool:
        """False when ttl <= 0 (strict mode: every check asks the auth service)."""
        return self.ttl > 0

    @property
    def effective_negative_ttl(self) -> int:
        """The TTL actually applied to a denied answer (after defaulting and clamping to <= ttl)."""
        return self._negative_ttl

    def get(
        self,
        user_id: str,
        permission: str,
        resource_id: str | None = None,
        *,
        credential: str | None = None,
        org_id: str | None = None,
    ) -> bool | None:
        """Get cached permission result for THIS credential in THIS org (see create_permission_cache_key)."""
        key = create_permission_cache_key(user_id, permission, resource_id, credential, org_id)
        value = self._cache.get(key)
        if value is None:
            self.misses += 1
        else:
            self.hits += 1
        return value

    def set(
        self,
        user_id: str,
        permission: str,
        allowed: bool,
        resource_id: str | None = None,
        *,
        credential: str | None = None,
        org_id: str | None = None,
    ) -> None:
        """Cache permission check result for THIS credential in THIS org (no-op when the cache is disabled)."""
        allowed = bool(allowed)
        if not self.enabled or (not allowed and self._negative_ttl <= 0):
            return
        key = create_permission_cache_key(user_id, permission, resource_id, credential, org_id)
        self._cache[key] = allowed

    def invalidate_user(self, user_id: str) -> int:
        """
        Invalidate all cached permissions for a user.

        Returns count of invalidated entries.
        """
        to_delete = [k for k in list(self._cache.keys()) if k.startswith(f"{user_id}:")]
        for key in to_delete:
            self._cache.pop(key, None)
        return len(to_delete)

    def clear(self) -> None:
        """Clear all cached permissions."""
        self._cache.clear()

    @property
    def size(self) -> int:
        """Current cache size."""
        return len(self._cache)


# =============================================================================
# API Key Validation Cache
# =============================================================================


@dataclass
class ApiKeyCache:
    """
    Cache for API-key validation answers (POST /auth/validate-api-key).

    An API key is opaque, so it can only be validated by the auth service. This cache keeps that call off the hot
    path: a VALID key is reused for at most `ttl` seconds (default 60), a key the auth service REJECTED for at most
    `negative_ttl` seconds (default 10, never longer than `ttl`). `ttl=0` disables the cache.

    - Keyed by the SHA-256 of the key; the raw key is never stored.
    - Only a definite answer is cached: valid with a user identity (positive) or not valid (negative). A malformed
      answer (valid but no user id) and every auth-service error / 429 / 5xx / timeout are never cached - the next
      request asks again, and the request that saw the error is refused (fail closed).
    - Bounded (LRU eviction at `max_size`).
    - The ttl is the revocation latency: a revoked key can keep working on this service for up to `ttl` seconds.
    """

    max_size: int = DEFAULT_API_KEY_CACHE_MAX_SIZE
    ttl: int = DEFAULT_API_KEY_CACHE_TTL
    negative_ttl: int | None = None  # None -> DEFAULT_API_KEY_CACHE_NEGATIVE_TTL, clamped to <= ttl
    _cache: TLRUCache[str, ApiKeyValidationResponse] = field(init=False, repr=False)
    _negative_ttl: int = field(init=False, repr=False)
    hits: int = field(default=0, init=False)
    misses: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self._negative_ttl = _clamp_negative_ttl(
            self.negative_ttl, self.ttl, DEFAULT_API_KEY_CACHE_NEGATIVE_TTL
        )
        self._cache = TLRUCache(
            maxsize=self.max_size,
            ttu=self._time_to_use,
            timer=lambda: _monotonic(),
        )

    def _time_to_use(self, _key: str, response: ApiKeyValidationResponse, now: float) -> float:
        """Per-entry expiry: valid keys live `ttl`, rejected keys `negative_ttl`."""
        return now + (self.ttl if response.valid else self._negative_ttl)

    @property
    def enabled(self) -> bool:
        """False when ttl <= 0 (strict mode: every request validates the key with the auth service)."""
        return self.ttl > 0

    @property
    def effective_negative_ttl(self) -> int:
        """The TTL actually applied to a rejected key (after defaulting and clamping to <= ttl)."""
        return self._negative_ttl

    def get(self, api_key: str) -> ApiKeyValidationResponse | None:
        """Return the cached answer for this key, or None if absent/expired/disabled."""
        if not self.enabled:
            return None
        value = self._cache.get(hash_api_key(api_key))
        if value is None:
            self.misses += 1
        else:
            self.hits += 1
        return value

    def set(self, api_key: str, response: ApiKeyValidationResponse) -> None:
        """
        Cache a definite answer from the auth service.

        No-op when the cache is disabled, for a malformed answer (valid but no user id), and for a negative answer
        when negative caching is disabled (`negative_ttl=0`). Never call this for an error.
        """
        if not self.enabled:
            return
        if response.valid:
            if not response.user_id:
                return
        elif self._negative_ttl <= 0:
            return
        self._cache[hash_api_key(api_key)] = response

    def invalidate(self, api_key: str) -> bool:
        """Remove a key's cached answer. Returns True if it was cached."""
        return self._cache.pop(hash_api_key(api_key), None) is not None

    def clear(self) -> None:
        """Clear all cached API-key answers."""
        self._cache.clear()

    @property
    def size(self) -> int:
        """Current cache size."""
        return len(self._cache)


# =============================================================================
# JWKS Cache
# =============================================================================


@dataclass
class JWKSCache:
    """
    Thread-safe cache for JWKS public keys.

    Uses TTLCache for automatic expiration and thread safety.
    Longer TTL since keys change infrequently.
    """

    ttl: int = 300  # 5 minutes default
    max_size: int = 100  # Max number of JWKS entries (per auth_url/org_id combo)
    _cache: TTLCache[str, JWKSCacheEntry] = field(init=False)

    def __post_init__(self) -> None:
        self._cache = TTLCache(maxsize=self.max_size, ttl=self.ttl)

    def get(self, auth_url: str, org_id: str | None = None) -> dict[str, Any] | None:
        """
        Get cached JWKS.

        Returns None if not cached or expired.
        Thread-safe via TTLCache.
        """
        key = create_jwks_cache_key(auth_url, org_id)
        entry = self._cache.get(key)

        if entry is None:
            return None

        return entry.keys

    def set(
        self,
        auth_url: str,
        keys: dict[str, Any],
        org_id: str | None = None,
        ttl: int | None = None,
    ) -> None:
        """
        Cache JWKS keys.

        Thread-safe via TTLCache.
        Note: Per-entry ttl parameter is stored for reference but cache-level TTL applies.
        """
        key = create_jwks_cache_key(auth_url, org_id)
        now = time.time()
        effective_ttl = ttl if ttl is not None else self.ttl

        entry = JWKSCacheEntry(
            keys=keys,
            created_at=now,
            expires_at=now + effective_ttl,
        )
        self._cache[key] = entry

    def invalidate(self, auth_url: str, org_id: str | None = None) -> bool:
        """
        Invalidate cached JWKS.

        Returns True if was cached.
        Thread-safe via TTLCache.
        """
        key = create_jwks_cache_key(auth_url, org_id)
        if key in self._cache:
            del self._cache[key]
            return True
        return False

    def clear(self) -> None:
        """Clear all cached JWKS."""
        self._cache.clear()

    @property
    def size(self) -> int:
        """Current cache size."""
        return len(self._cache)


# =============================================================================
# Mesh Token Cache (token_for / P3)
# =============================================================================


@dataclass(frozen=True, slots=True)
class MeshTokenCacheEntry:
    """A cached mesh token with the instant it stops being served."""

    token: MeshToken
    fresh_until: float


@dataclass
class MeshTokenCache:
    """In-memory cache for token_for results, keyed by
    create_mesh_token_cache_key.

    A token is served until ``margin`` seconds before it expires, and never past
    the person's own token expiry (``subject_exp`` passed to set). Tokens without
    an expiry are not cached, and errors are never cached (set is only called on
    success). Mirrors the Go SDK's TokenFor cache (minus single-flight, which is
    a future nicety).
    """

    max_size: int = 1024
    ttl: int = 900  # cache-wide ceiling; per-entry fresh_until is the real bound
    margin: float = 30.0  # serve until this long before expiry (matches Go/browser SDK)
    _cache: TTLCache[str, MeshTokenCacheEntry] = field(init=False)

    def __post_init__(self) -> None:
        self._cache = TTLCache(maxsize=self.max_size, ttl=self.ttl)

    def get(self, key: str) -> MeshToken | None:
        """Return the cached token for key, or None if absent/stale."""
        entry = self._cache.get(key)
        if entry is None:
            return None
        if time.time() >= entry.fresh_until:
            self._cache.pop(key, None)
            return None
        return entry.token

    def set(self, key: str, token: MeshToken, subject_exp: float | None = None) -> None:
        """Cache a successful token.

        No-op when the token has no expiry, or when it is already within
        ``margin`` of expiry (or of the subject token's expiry).
        """
        if token.expires_at is None:
            return
        fresh_until = token.expires_at - self.margin
        if subject_exp is not None:
            fresh_until = min(fresh_until, subject_exp)
        if time.time() >= fresh_until:
            return
        self._cache[key] = MeshTokenCacheEntry(token=token, fresh_until=fresh_until)

    def clear(self) -> None:
        """Clear all cached mesh tokens."""
        self._cache.clear()

    @property
    def size(self) -> int:
        """Current cache size."""
        return len(self._cache)


# =============================================================================
# Cache Factory Function
# =============================================================================


@dataclass(frozen=True, slots=True)
class DecisionCacheTTLs:
    """Effective decision-cache TTLs (seconds) for a config. 0 = that cache is off."""

    permission: int
    permission_negative: int
    api_key: int
    api_key_negative: int


# The decision-cache TTL env vars, read as a FALLBACK by resolve_cache_ttls so they work however the guard is built
# (AuthGuard(auth_url=...), create_config(...), AuthConfig(...) or AuthSettings()) — not only through AuthSettings.
_TTL_ENV = {
    "permission_cache_ttl": "AB0T_AUTH_PERMISSION_CACHE_TTL",
    "permission_cache_negative_ttl": "AB0T_AUTH_PERMISSION_CACHE_NEGATIVE_TTL",
    "api_key_cache_ttl": "AB0T_AUTH_API_KEY_CACHE_TTL",
    "api_key_cache_negative_ttl": "AB0T_AUTH_API_KEY_CACHE_NEGATIVE_TTL",
}


def _ttl_setting(config: AuthConfig, field_name: str) -> int | None:
    """Explicit config value, else the env var, else None (derive). An unparsable or out-of-range env value raises —
    a typo in an opt-out must not silently leave the cache on (same strictness as AuthSettings)."""
    value = getattr(config, field_name, None)
    if value is not None:
        return int(value)
    env_name = _TTL_ENV[field_name]
    raw = os.environ.get(env_name, "").strip()
    if raw == "":
        return None
    try:
        parsed = int(raw)
    except ValueError:
        raise ValueError(f"{env_name} must be an integer number of seconds (0-300)") from None
    if not 0 <= parsed <= 300:
        raise ValueError(f"{env_name} must be between 0 and 300 seconds")
    return parsed


def resolve_cache_ttls(config: AuthConfig) -> DecisionCacheTTLs:
    """
    Effective decision-cache TTLs for a config.

    Precedence: explicit config value > its AB0T_AUTH_*_CACHE_* env var > derived from `token_cache_ttl` (0 disables).
    The env fallback makes the documented opt-outs work however the guard is built. Derived values, so setting
    `token_cache_ttl=0` still turns every cache off exactly as it did up to 0.1.3:
      permission          = min(token_cache_ttl // 2, 15)   (was min(token_cache_ttl // 2, 30))
      permission_negative = min(5, permission)
      api_key             = min(token_cache_ttl, 60)        (API keys were not cached up to 0.1.3)
      api_key_negative    = min(10, api_key)
    """
    token_ttl = max(0, config.token_cache_ttl)

    perm = _ttl_setting(config, "permission_cache_ttl")
    perm = min(token_ttl // 2, DEFAULT_PERMISSION_CACHE_TTL) if perm is None else max(0, perm)
    perm_neg = _clamp_negative_ttl(
        _ttl_setting(config, "permission_cache_negative_ttl"),
        perm,
        DEFAULT_PERMISSION_CACHE_NEGATIVE_TTL,
    )

    key = _ttl_setting(config, "api_key_cache_ttl")
    key = min(token_ttl, DEFAULT_API_KEY_CACHE_TTL) if key is None else max(0, key)
    key_neg = _clamp_negative_ttl(
        _ttl_setting(config, "api_key_cache_negative_ttl"),
        key,
        DEFAULT_API_KEY_CACHE_NEGATIVE_TTL,
    )

    return DecisionCacheTTLs(
        permission=perm,
        permission_negative=perm_neg,
        api_key=key,
        api_key_negative=key_neg,
    )


def create_caches(config: AuthConfig) -> tuple[TokenCache, PermissionCache, JWKSCache]:
    """
    Create all cache instances from config.

    Factory function for cache initialization. (The API-key cache is created by create_api_key_cache, so this
    function's return shape is unchanged.)
    """
    ttls = resolve_cache_ttls(config)
    token_cache = TokenCache(
        max_size=config.token_cache_max_size,
        ttl=config.token_cache_ttl,
    )
    permission_cache = PermissionCache(
        max_size=config.token_cache_max_size * 5,
        ttl=ttls.permission,
        negative_ttl=ttls.permission_negative,
    )
    jwks_cache = JWKSCache(
        ttl=config.jwks_cache_ttl,
    )

    return token_cache, permission_cache, jwks_cache


def create_api_key_cache(config: AuthConfig) -> ApiKeyCache:
    """
    Create the API-key validation cache from config.

    Factory function.
    """
    ttls = resolve_cache_ttls(config)
    return ApiKeyCache(ttl=ttls.api_key, negative_ttl=ttls.api_key_negative)
