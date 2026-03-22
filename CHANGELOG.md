# Changelog

All notable changes to ab0t-auth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security Fixes

- **CRITICAL: API key validation no longer hardcodes `valid=True`** (`client.py`)
  - `validate_api_key()` previously ignored the `valid` field from the auth service response and hardcoded `True` for any HTTP 200 — meaning **any string** as `X-API-Key` was accepted
  - Now reads `data.get("valid", False)` — fail-closed
  - The `error` field from the auth service is now captured and propagated
  - Same fix applied to `validate_token()` default (`True` → `False`)
  - Affects both FastAPI and Flask adapters
  - Reported by: Runner backend team (red-team testing)

- **API key auth now rejects null/empty `user_id`** (`guard.py`, `flask.py`)
  - Previously, `valid=true` with `user_id=null` created a shared identity `"api_key_user"` — multiple API keys mapped to the same user with no audit trail
  - Now returns `AuthResult.fail("INVALID_API_KEY")` when `user_id` is missing

- **Server-side permission fallback narrowed from `Exception` to `AuthServiceError`** (`permissions.py`)
  - Previously caught all exceptions (including programming bugs like `TypeError`) and silently fell back to JWT claims
  - Now only catches `AuthServiceError` (network/service errors)
  - Behavior is configurable via new `permission_fallback` setting (see Added below)

- **String permissions no longer explode into characters** (`client.py`)
  - If the auth service returns `permissions: "admin,read"` (string instead of array), `tuple()` previously produced `('a','d','m','i','n',...)` — garbage permissions
  - Now handled by `_safe_permissions()` which splits comma-separated or space-separated strings correctly

- **Middleware path exclusion hardened** (`middleware.py`, `flask.py`)
  - Path matching is now case-insensitive (`/Health` matches `/health`)
  - Trailing slashes are normalized (`/health/` matches `/health`)
  - Wildcard prefix patterns are segment-boundary-aware (`/api/public*` no longer matches `/api/publicly_secret`, only `/api/public/...`)

### Added

- **Permission fallback configuration** (`permission_fallback`)
  - New `AuthConfig` option controlling behavior when server-side permission checks fail
  - `"deny"` (default): Reject the request — fail-closed, recommended for production
  - `"client"`: Fall back to JWT claims — fail-open, maintains availability during outages
  - Environment variable: `AB0T_AUTH_PERMISSION_FALLBACK=deny`
  - A WARNING is logged whenever the fallback triggers, regardless of mode

### Breaking Changes

- API keys with no `user_id` association are now rejected (previously silently authenticated as `"api_key_user"`)
- `permission_fallback` defaults to `"deny"` — services that relied on graceful degradation during auth service outages must explicitly set `permission_fallback="client"`
- Middleware path exclusion patterns like `/api/public*` now require a `/` segment boundary — `/api/publicly_secret` is no longer excluded

### Migration Guide

If you were relying on the old fail-open behavior for permission checks during auth service outages:

```python
# Explicit opt-in to fail-open (old behavior)
auth = AuthGuard(
    auth_url="https://auth.service.ab0t.com",
    permission_fallback="client",  # Fall back to JWT claims on error
)
```

- **Server-side permission checking mode** (`permission_check_mode`)
  - New configuration option to switch between client-side (JWT claims) and server-side (API call) permission verification
  - Environment variable: `AB0T_AUTH_PERMISSION_CHECK_MODE=server`
  - Programmatic: `AuthGuard(auth_url="...", permission_check_mode="server")`
  - Default is `"client"` for backward compatibility
  - Server mode calls `/permissions/check` endpoint for authoritative, real-time verification
  - Enables instant permission revocation without waiting for JWT expiration

### Why Server Mode?

The Ab0t auth service intentionally stores permissions in the database rather than JWT tokens. This design supports:

1. **Instant revocation** - Permissions can be removed immediately without waiting for token expiry
2. **Dynamic org scoping** - Permissions can vary by organization context
3. **Role-based inheritance** - Roles expand to permissions at check time
4. **Real-time updates** - Permission changes take effect immediately

**Recommendation:** Services using `auth.service.ab0t.com` should enable server mode:

```bash
AB0T_AUTH_PERMISSION_CHECK_MODE=server
```

This ensures permission checks are authoritative and reflect the latest state.

## [0.1.0] - 2026-01-15

### Added

- Initial release
- JWT validation with JWKS
- API key authentication
- Permission checking (client-side)
- FastAPI dependencies (`require_auth`, `require_permission`, etc.)
- FastAPI middleware (`AuthMiddleware`)
- FastAPI decorators (`@protected`, `@permission_required`, etc.)
- Token caching with TTL
- JWKS caching with auto-refresh
- Structured logging
- Flask support (`Ab0tAuth` extension)
- Multi-tenancy with nested organizations
- Auth bypass for testing/development
- Check callbacks for dynamic authorization
