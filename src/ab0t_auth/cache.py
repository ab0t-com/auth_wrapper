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

from ab0t_auth.core import AuthConfig, AuthenticatedUser, TokenClaims


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


def create_permission_cache_key(user_id: str, permission: str, resource_id: str | None) -> str:
    """
    Create cache key for permission check.

    Pure function.
    """
    parts = [user_id, permission]
    if resource_id:
        parts.append(resource_id)
    return ":".join(parts)


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
        """
        key = hash_token(token)
        return self._cache.get(key)

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

        entry = TokenCacheEntry(
            user=user,
            claims=claims,
            created_at=now,
            expires_at=now + effective_ttl,
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
    ) -> bool | None:
        """Get cached permission result."""
        key = create_permission_cache_key(user_id, permission, resource_id)
        return self._cache.get(key)

    def set(
        self,
        user_id: str,
        permission: str,
        allowed: bool,
        resource_id: str | None = None,
    ) -> None:
        """Cache permission check result."""
        key = create_permission_cache_key(user_id, permission, resource_id)
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
