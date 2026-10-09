# Changelog

All notable changes to ab0t-auth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3] - 2026-10-09

Additive feature release. No behaviour change to existing APIs; safe to upgrade.

### Added

- **`token_for(...)` — a token to call another mesh service for a signed-in person.**
  Performs an OAuth 2.0 Token Exchange (RFC 8693): the person's token is the `subject_token`, your app proves who it
  is with its OWN client credentials (HTTP Basic by default, or `client_secret_post`), exactly one `resource`
  (RFC 8707) is requested, and NO `actor_token` is sent — the authenticated client is the actor. It is the Python twin
  of the Go SDK's `TokenFor` (person-present pattern).

  ```python
  from ab0t_auth import token_for, MeshTokenCache

  tok = await token_for(
      client, config,
      "https://b.service.example", "b.documents.read", person_token,
      client_id=CLIENT_ID, client_secret=CLIENT_SECRET,
      cache=MeshTokenCache(),  # optional
  )
  headers = {"Authorization": tok.authorization_header}
  ```

  - **One resource per token.** Send `tok` only to the resource it was requested for; never forward a token you
    received on to another service — get your own with `token_for`.
  - **Caching** (pass a `MeshTokenCache`): a token is served from memory until 30 s before it expires and never past
    the person's own token expiry; keyed by the client, the resource, the sorted scope set and a hash of the person's
    token (never stored verbatim). Errors are never cached.
  - **No refresh tokens** — renewing is simply calling again.
  - **Only client credentials reach the token endpoint** — a configured service API key is never sent here.

- **Typed outcomes for `token_for`**, classified from the HTTP status and the OAuth `error` / `suberror` members only
  (never the free-text description): `ClientAuthError` (invalid_client), `ClientNotEnabledError` (unauthorized_client),
  `ScopeNotAllowedError` (invalid_scope), `NoConnectionError` (invalid_target), `ConsentRequiredError`
  (invalid_target + `consent_required`, with an `authorization_url(...)` helper and the `new_pkce()` PKCE generator),
  `ReauthenticateRequired` (invalid_request / invalid_grant); a dependency failure (5xx / 429 / network) raises the
  existing `AuthServiceError`. All share the base `MeshTokenError`.

- **`MeshToken`** result type (`access_token`, `token_type`, `resource`, `scope`, `expires_at`,
  `authorization_header`) and **`MeshTokenCache`**.

- **`User-Agent: ab0t-auth/<version>`** is sent on the `token_for` token-endpoint call so SDK adoption can be measured.

## [0.1.2] - 2026-09-26

Security release. Upgrade all server-mode services. Companion auth-service change: `/permissions/check` now answers
for the calling credential (API key or delegation) rather than its owner.

### Upgrade order (READ FIRST)

Upgrade to 0.1.2 **with or before** the auth-service `/permissions/check` change. A 0.1.1 service talking to the
updated auth service caches a narrow key's `allowed:false` under its OWNER's user id, so the owner's login and other
keys are refused on that service for up to 30 s. 0.1.2 works with both the old and the updated auth service.

### Security Fixes

- **HIGH: permission cache keyed by credential + org, not by user id** (`cache.py`, `permissions.py`)
  - The server-mode `PermissionCache` key was `user_id:permission`. An owner's cached `allowed` was served to the
    owner's narrow API key (e.g. a read-only key could perform writes its owner could, for 30 s), and answers were reused across orgs.
  - The key is now `user_id:cred=<sha256 prefix of the presented credential>:org=<org>:permission[:resource]`. The raw
    credential is never stored. With no credential there is no caching. `invalidate_user()` still clears every entry
    for the user.
- **HIGH: the server-mode permission check uses the credential that authenticated the request** (`permissions.py`)
  - When the bearer was rejected locally (wrong audience, another service's token) and the request authenticated with
    `X-API-Key`, `/permissions/check` was still called with the rejected bearer, naming the key's owner. So a narrow
    key plus any login token that auth accepts got the owner's authority. API-key users are now checked with the key,
    and JWT users with the JWT.
- **MEDIUM: JWKS refetch limited for unknown `kid`** (`jwt.py`)
  - With older PyJWT (confirmed on 2.8.0 and 2.11.0; 2.15 has its own cooldown), every token with an unknown `kid` forced a synchronous JWKS
    fetch on the event loop, which an unauthenticated caller could trigger at will. `CooldownPyJWKClient` now allows
    at most one forced refresh per 30 s, and key rotation still works.
- **MEDIUM: an expired JWT is no longer served from the token cache** (`cache.py`)
  - Cache entries are capped at the token's `exp`. Before, they could be served for up to `token_cache_ttl` after it.
- **MEDIUM: `TenantConfig.enforce_org_isolation` now defaults to `True`** (`tenant.py`)
  - With the old default `False`, `validate_org_access` / `check_org_permission` allowed ANY requested org.
- **MEDIUM (config): warning when JWT audience is not verified** (`guard.py`)
  - `AuthGuard.initialize` logs a WARNING when `audience` is unset or `verify_aud` is false. In that state, tokens
    minted for other services are accepted.
- **LOW: `require_auth_and_permission` honours `permission_check_mode="server"`** (`dependencies.py`)
- **LOW: no internal URLs or raw exception text in client-facing errors** (`client.py`, `guard.py`, `flask.py`)
- **LOW: auth-service decision fields must be JSON `true`** (`client.py`)
  - `allowed`, `valid` and `active` now reject truthy non-booleans such as `"false"` or `1`.

### Changed (added 2026-10-08, ships in 0.1.2)

- **Default JWT clock-skew leeway 10 s → 5 s** (`config.py`, `core.py`). A token more than
  5 s past its `exp` is refused locally with a clean 401 instead of being accepted and forwarded to the auth service (seen in production:
  auth answered 401 to an expired token a service had let through). `@authmesh/sdk` 0.4.1 refreshes 30 s early, so
  5 s covers clock skew. Pass `leeway_seconds` explicitly to keep the old value.

### Behaviour notes

- Permission-cache hit rate: repeat checks by the SAME credential in the SAME org still hit the cache. A user's login
  and each of their keys now have separate entries, and checks made without a credential are never cached.
- Code that read `PermissionCache.get(user_id, perm)` directly (user id only) now always misses. This is intentional:
  it falls through to a real check instead of reusing another credential's answer.
- A request that sends BOTH a locally rejected bearer and a valid `X-API-Key` is now authorised with the key's own
  scope.
- `TenantConfig()` with no arguments now enforces org isolation. To keep the old behaviour, pass
  `enforce_org_isolation=False` explicitly. Every ab0t service already sets `True`.
- Decorators (`permission_required`, `permissions_required`), the Flask adapter and `tenant.require_tenant_permission`
  remain client-side only: they use the token or key's own permission list, not `/permissions/check`.
- `__version__` now matches the package version (0.1.1 had shipped `__version__ = "0.1.0"`).

### Upgrade checklist (0.1.1 → 0.1.2)

No public API was renamed or removed. Check these before deploying:
1. **Pin the release commit SHA** in `requirements.txt` (don't track `main`).
2. **Set the JWT audience** (`AB0T_AUTH_AUDIENCE` / `AuthConfig.audience`). Without it the service now logs a WARNING
   at startup, and tokens minted for other services are accepted.
3. **Org isolation:** if you build `TenantConfig()` with no arguments and relied on cross-org access, pass
   `enforce_org_isolation=False` explicitly. Otherwise nothing to do.
4. **Server-mode permissions:** `require_auth_and_permission` now honours `permission_check_mode="server"`. A route
   that used it in server mode is now checked by the auth service (credential's own scope) rather than locally.
5. **Error text:** 401/403/503 response details no longer include internal URLs or exception text. Clients must not
   match on the old strings.
6. **Strict decisions:** the auth service's `allowed` / `valid` / `active` must be JSON `true`. The official auth
   service already sends booleans; a custom or mock auth endpoint that returns `"true"` or `1` will now be denied.

## [0.1.1] - 2026-04-01

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

- **Permissions parsing unified across all client functions** (`client.py`)
  - `login()`, `refresh_token()`, and `validate_token()` now all use `_parse_permissions()` with consistent order: `permissions` field first, `scope` as fallback
  - Previously `login()` checked `scope` first, `validate_token()` checked `permissions` first, and `refresh_token()` only checked `scope` — same response data could produce different results depending on the function

- **`introspect_token()` now returns typed `IntrospectionResponse`** (`client.py`)
  - Previously returned a raw `dict` with no validation of the RFC 7662 `active` field — callers could forget to check it and treat inactive tokens as valid
  - Now returns `IntrospectionResponse` dataclass with `active: bool` defaulting to `False` (fail-closed)

- **Non-bool check callback results logged at ERROR** (`dependencies.py`)
  - Previously logged at WARNING — easy to miss in production logs
  - Now logs at ERROR with the returned value for easier debugging

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
