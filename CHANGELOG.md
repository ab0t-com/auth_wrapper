# Changelog

All notable changes to ab0t-auth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.5] - 2026-10-16

Patch release: four fixes found by an adversarial test pass on 0.1.4. No public signature is removed or changed; the
two new parameters are optional and keyword-only. **Safe to upgrade; nothing in this release stops a service from
starting.** A decision-cache TTL **set in code** outside the documented 0–300 s range is no longer honoured: it is
clamped into range with a warning (see Fixed → TTL range). Read `migrations/v0.1.4-to-v0.1.5/MIGRATION.md`.

### Fixed

- **MEDIUM (security): `resource_type` is now part of the permission-cache key** (`cache.py`, `permissions.py`).
  `verify_permission(..., resource_id=, resource_type=)` sent `resource_type` to `/permissions/check` but cached the
  answer without it, so an `allowed` for `("x.read", resource_type="doc", resource_id="42")` was served for
  `("x.read", resource_type="invoice", resource_id="42")` for up to 15 s (and a denial across types for 5 s) without
  asking the auth service. Every input of the question sent to `/permissions/check` (credential, org, permission,
  resource type, resource id) is now in the key. Affected: direct callers of `verify_permission` that pass
  `resource_type`. The FastAPI dependencies never pass a resource and were not affected.
- **LOW: the permission-cache key is injective** (`cache.py`). The key was the parts joined with `":"`, so a
  permission containing `:` could collide with permission + resource: `("docs:read", resource_id="x")` and
  `("docs:read:x")` shared one entry. The key is now a fixed-length tuple, one slot per input. `invalidate_user(id)`
  now matches the user id exactly (before, a prefix match on `"<id>:"` also dropped the entries of a user whose id
  starts with `"<id>:"`; it never dropped too few).
- **LOW-MEDIUM: a lower-case `bearer` scheme is forwarded correctly** (`client.py`). Authentication accepts the scheme
  case-insensitively (RFC 7235 §2.1 / RFC 6750 §2.1), but `check_permission`, `validate_token` and
  `get_user_permissions` re-prefixed with a case-sensitive check, so `Authorization: bearer <t>` reached the auth
  service as `Bearer bearer <t>` and was refused: in `permission_check_mode="server"` a valid token got a 401/403
  (fail-closed, on a cold cache). The scheme is now removed case-insensitively and re-added as `Bearer <t>`, by the
  same rule that fingerprints the credential for the permission cache, so the cached answer and the forwarded
  credential always match. A whitespace-only bearer now falls back to the API key, like the cache fingerprint
  (before, an empty `Bearer ` was sent).
- **LOW: TTL range — a decision-cache TTL set in code is kept inside the documented range** (`cache.py`). The 0.1.4
  docs give `0–300` for the `AuthConfig` fields `permission_cache_ttl`, `permission_cache_negative_ttl`,
  `api_key_cache_ttl`, `api_key_cache_negative_ttl`, and an env value outside it already raised. A value set in code
  was not checked: `AuthConfig(api_key_cache_ttl=86_400)` let a revoked key keep working for a day. It is now
  **clamped** (above 300 → 300; below 0 → 0, i.e. that cache off — what a negative value already did) and logged once
  at WARNING on the `ab0t_auth.cache` logger, naming the field (`AuthConfig.api_key_cache_ttl=86400 is outside the
  documented 0-300 seconds; using 300. …`). It does not raise: a patch release must not stop a service from
  starting. A later minor release may refuse such values, as the env var does. A non-integer value raises as
  before. Values 0–300 and the env vars behave exactly as before.

### Added

- `resource_type=` (keyword-only, optional) on `verify_any_permission` and `verify_all_permissions` (it is sent with
  every check and keyed, as in `verify_permission`), and on `PermissionCache.get` / `PermissionCache.set`.
- `ab0t_auth.cache.bearer_credential(value)`: the credential inside an Authorization value (scheme removed,
  case-insensitive).

### Changed (internal)

- `ab0t_auth.cache.create_permission_cache_key(...)` returns a tuple (was a `":"`-joined string) and accepts an
  optional `resource_type`. It is not exported from `ab0t_auth` and not documented; code that inspected
  `PermissionCache._cache` keys as strings must treat them as tuples. The cache is in memory only, so no stored data
  changes on upgrade.

## [0.1.4] - 2026-10-16

Released 2026-10-16. Cache defaults aligned with the Go SDK (`auth-sdk-go`) so both SDKs behave the same. No public
signature is removed or changed; everything new is optional and keyword-only. **Defaults change a security
property (revocation latency) — read `migrations/v0.1.3-to-v0.1.4/MIGRATION.md`.** Every TTL is configurable and `0`
disables that cache.

### Changed

- **Permission decision cache (server mode): 30 s → 15 s for `allowed`, and a separate 5 s for `denied`.**
  Up to 0.1.3 both answers lived 30 s (derived as `min(token_cache_ttl // 2, 30)`); now
  `min(token_cache_ttl // 2, 15)` for allowed and 5 s (never above the positive TTL) for denied. A revoked grant now
  stops passing within 15 s (was 30 s); a new grant is seen within 5 s (was 30 s). `PermissionCache()` class default
  `ttl` is now 15, with a new `negative_ttl` field.
- **API-key validation is now cached: 60 s for a valid key, 10 s for a rejected key** (`AuthGuard` and the Flask
  extension). Up to 0.1.3 every request carrying `X-API-Key` called `POST /auth/validate-api-key`. A revoked key can
  now keep working on your service for up to 60 s. Keyed by SHA-256 of the key; errors are never cached.
- **Unknown-`kid` JWKS refetch cooldown: 30 s → 60 s** (`JWKS_UNKNOWN_KID_REFRESH_COOLDOWN_SECONDS`): at most one
  forced refetch per minute, matching the Go SDK. Key rotation still works (the first unknown `kid` after the window
  refetches once). The regular JWKS TTL is unchanged (300 s).

### Added

- Config (all optional; env prefix `AB0T_AUTH_`): `permission_cache_ttl`, `permission_cache_negative_ttl`,
  `api_key_cache_ttl`, `api_key_cache_negative_ttl` (seconds, `0` disables, `0..300`). Unset = derived from
  `token_cache_ttl`, so **`token_cache_ttl=0` still disables every cache**, as before. The four
  `AB0T_AUTH_*_CACHE_*` env vars are honoured however the guard is built (not only via `AuthSettings`); a value set in
  code wins; an invalid value (not 0–300) raises at start-up naming the variable.
- **Per-call `fresh=True` bypass** for sensitive operations: `verify_permission` / `verify_any_permission` /
  `verify_all_permissions`, `AuthGuard.authenticate` / `authenticate_or_raise`, the Flask `Ab0tAuth.authenticate`,
  and the FastAPI dependencies `require_auth`, `require_permission`, `require_any_permission`,
  `require_all_permissions`, `require_auth_and_permission`. Skips the cache read, asks the auth service, stores the
  new answer.
- `ApiKeyCache`, `create_api_key_cache(config)`, `resolve_cache_ttls(config)` and the `DEFAULT_*_CACHE_*TTL` constants
  in `ab0t_auth.cache`; `AuthGuard.invalidate_api_key(key)` / `Ab0tAuth.invalidate_api_key(key)`;
  `AuthGuard.cache_stats()` (hit/miss/size/effective TTLs for the permission and API-key caches).

### Unchanged (verified, now covered by tests)

- Token cache: 60 s default, **never served past the token's `exp`**, only successful validations are cached, an
  expired entry is never served after a failed re-validation (fail closed). `TokenCache(ttl=0)` stores nothing.
- Errors / `429` / `5xx` / network failures are never cached by any cache.
- JWKS TTL default stays 300 s (the design allows up to 10 min; kept shorter because it also bounds how long a
  signing key removed from the JWKS keeps verifying).

### Security note — revocation latency

Local JWT verification has no network call and **does not see a server-side logout or session revocation until the
token's `exp`** (access tokens are ~15 min). For routes that must refuse a logged-out session immediately use
`permission_check_mode="server"` with `fresh=True`, or `ab0t_auth.client.introspect_token()`. See the README section
"Caching and revocation latency".

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
