"""
Caching layer for Ab0t Auth.

High-performance in-memory caching for tokens, JWKS, and validation results.
Uses TTL-based expiration for security.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

from cachetools import TTLCache

from ab0t_auth.core import AuthConfig, AuthenticatedUser, MeshToken, TokenClaims

T = TypeVar("T")


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

        Uses token hash as key for security.
        """
        key = hash_token(token)
        now = time.time()
        effective_ttl = ttl if ttl is not None else self.ttl
        expires_at = now + effective_ttl
        # Never cache a token past its own expiry.
        if claims.exp is not None:
            expires_at = min(expires_at, float(claims.exp))

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
    Cache for permission check results.

    Short TTL since permissions can change.
    """

    max_size: int = 5000
    ttl: int = 30  # seconds - short for permission changes
    _cache: TTLCache[str, bool] = field(init=False)

    def __post_init__(self) -> None:
        self._cache = TTLCache(maxsize=self.max_size, ttl=self.ttl)

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
        return self._cache.get(key)

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
        """Cache permission check result for THIS credential in THIS org."""
        key = create_permission_cache_key(user_id, permission, resource_id, credential, org_id)
        self._cache[key] = allowed

    def invalidate_user(self, user_id: str) -> int:
        """
        Invalidate all cached permissions for a user.

        Returns count of invalidated entries.
        """
        to_delete = [k for k in self._cache.keys() if k.startswith(f"{user_id}:")]
        for key in to_delete:
            del self._cache[key]
        return len(to_delete)

    def clear(self) -> None:
        """Clear all cached permissions."""
        self._cache.clear()


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


def create_caches(config: AuthConfig) -> tuple[TokenCache, PermissionCache, JWKSCache]:
    """
    Create all cache instances from config.

    Factory function for cache initialization.
    """
    token_cache = TokenCache(
        max_size=config.token_cache_max_size,
        ttl=config.token_cache_ttl,
    )
    permission_cache = PermissionCache(
        max_size=config.token_cache_max_size * 5,
        ttl=min(config.token_cache_ttl // 2, 30),
    )
    jwks_cache = JWKSCache(
        ttl=config.jwks_cache_ttl,
    )

    return token_cache, permission_cache, jwks_cache
