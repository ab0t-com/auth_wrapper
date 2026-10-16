# Migration: ab0t-auth 0.1.3 → 0.1.4

**No source-breaking change.** Every public function and class keeps its signature; new options are optional and
keyword-only. What changes are **cache defaults**. A cache TTL is a security property: it is the longest a revoked
grant / revoked key keeps working **on your service**. The new defaults are the same as the Go SDK (`auth-sdk-go`),
so Python and Go services behave the same.

Run the checker first. It is read-only, and it exits non-zero while ACTION findings remain:

```bash
./migrate-check.sh /path/to/your/service          # add --strict to also fail on advisory REVIEW findings
```

| Rule | Type | Scope | Before (0.1.3) | After (0.1.4) |
|---|---|---|---|---|
| B1 `perm-allowed-ttl` | BEHAVIOURAL | server permission mode (`/permissions/check`) | allowed answer cached **30 s** | **15 s** |
| B2 `perm-denied-ttl` | BEHAVIOURAL | same | denied answer cached **30 s** | **5 s** |
| B3 `apikey-cache` | BEHAVIOURAL | `X-API-Key` auth (`AuthGuard`, Flask `Ab0tAuth`) | **not cached**: one `/auth/validate-api-key` call per request | valid key **60 s**, rejected key **10 s** |
| B4 `kid-cooldown` | BEHAVIOURAL | local JWT verification, unknown `kid` | forced JWKS refetch at most once per **30 s** | once per **60 s** |
| A1 `fresh` | ADD (optional) | permission checks, `authenticate*`, FastAPI dependencies | — | `fresh=True` per-call cache bypass |
| A2 `config` | ADD (optional) | `AuthConfig` / `AB0T_AUTH_*` env | — | 4 new TTL settings, `invalidate_api_key`, `cache_stats` |

Unchanged (verified, now covered by tests): the token cache (60 s, **never past the token's `exp`**), JWKS TTL
(300 s), "errors are never cached", and `token_cache_ttl=0` turning every cache off.

---

## B1 + B2 — permission decision cache: 30 s → 15 s allowed, 5 s denied

Applies when `permission_check_mode="server"` (`AB0T_AUTH_PERMISSION_CHECK_MODE=server`). Client mode (JWT claims)
has no permission cache and does not change.

| | Before | After |
|---|---|---|
| Derived TTL (no explicit setting) | `min(token_cache_ttl // 2, 30)` for both answers | allowed: `min(token_cache_ttl // 2, 15)`; denied: `min(5, allowed)` |
| Default (`token_cache_ttl=60`) | 30 s / 30 s | **15 s / 5 s** |
| `PermissionCache()` class default | `ttl=30` | `ttl=15`, new `negative_ttl=None` (→ 5, never above `ttl`) |
| A grant revoked server-side stops passing | within 30 s | within **15 s** |
| A new grant is seen | within 30 s | within **5 s** |

*Why:* permissions are dynamic (grants, revokes, team moves). A short window removes almost all repeat calls on a
hot path, and it keeps a revoked grant usable for at most 15 s. Denials get a shorter TTL, so a fix is seen quickly.
*Cost:* on a hot path, up to ~2× more `/permissions/check` calls than at 30 s.

Keep the old behaviour (opt-out):

```bash
AB0T_AUTH_PERMISSION_CACHE_TTL=30
AB0T_AUTH_PERMISSION_CACHE_NEGATIVE_TTL=30
```
```python
AuthConfig(..., permission_cache_ttl=30, permission_cache_negative_ttl=30)
PermissionCache(ttl=30, negative_ttl=30)          # if you build the cache yourself
```

No permission cache at all (strict): `AB0T_AUTH_PERMISSION_CACHE_TTL=0`.

## B3 — API-key validation is now cached: valid 60 s, rejected 10 s

| | Before | After |
|---|---|---|
| Request with `X-API-Key` | `POST /auth/validate-api-key` **every request** | answered from memory for 60 s (valid) / 10 s (rejected) |
| Revoked key keeps working on your service | 0 s | up to **60 s** |
| Errors (`429`, `5xx`, timeout, network) | not cached, request refused | **unchanged**: never cached, request refused (fail closed) |
| Answer "valid but no user id" | refused | refused, not cached |
| Cache key | — | SHA-256 of the key (the raw key is never stored); bounded (10 000 entries, LRU) |

*Why:* an API key is opaque, so only the auth service can validate it. Without a cache, every request pays an auth
round trip, which adds latency on your side and load (and rate limiting) on the auth service. 60 s is the same bound
the Go SDK uses.

Keep the old behaviour (opt-out): `AB0T_AUTH_API_KEY_CACHE_TTL=0` (or `AuthConfig(..., api_key_cache_ttl=0)`).
Cache valid keys only: `AB0T_AUTH_API_KEY_CACHE_NEGATIVE_TTL=0`.
Need a revocation to take effect at once? Call `auth.invalidate_api_key(raw_key)` when your service revokes a key, or
use `fresh=True` on the sensitive route (A1).

**If you wrapped the guard to cache API keys yourself** (e.g. by replacing `guard._authenticate_api_key` and storing
answers in `guard._token_cache`): 0.1.4 does this itself, so remove the wrapper. A wrapper written to stand down when
upstream caches will detect 0.1.4 and stand down. If you keep it, two caches stack up: the wrapper re-fills from
0.1.4's cache, and invalidating only the wrapper's entry no longer revokes. Replace any
`_token_cache.invalidate(api_key)` with `auth.invalidate_api_key(api_key)`. If you override `_authenticate_api_key` /
`_authenticate_jwt` / `authenticate` and want to use `fresh=True`, accept a keyword-only `fresh: bool = False`. (The
library passes `fresh` only when it is `True`, so existing two-argument overrides keep working.)

**Tests that count auth-service calls** (respx/mocks asserting how many times `/auth/validate-api-key` was called,
or a `side_effect=[...]` sequence of answers for the same key) will now see fewer calls. In those tests set
`api_key_cache_ttl=0`, call `auth.clear_caches()` between steps, or pass `fresh=True`.

## B4 — unknown-`kid` JWKS refetch: once per 30 s → once per 60 s

A token whose `kid` is not in the cached JWKS forces at most **one** refetch per 60 s (was 30 s). That stops random-
`kid` tokens from driving JWKS fetches. Key rotation still works: the first unknown `kid` after the window refetches
once. The regular JWKS TTL (`AB0T_AUTH_JWKS_CACHE_TTL`, default 300 s) is unchanged.

Opt-out: set `ab0t_auth.jwt.JWKS_UNKNOWN_KID_REFRESH_COOLDOWN_SECONDS = 30` before the guard initializes, or pass
`refresh_cooldown=30` when you build `CooldownPyJWKClient` yourself.

## A1 — `fresh=True`: per-call bypass for sensitive operations (new, optional)

Use it for admin actions, money movement and ownership changes. It skips the cache read, asks the auth service, and
stores the new answer.

```python
# FastAPI dependency (require_auth / require_permission / require_any_permission /
# require_all_permissions / require_auth_and_permission)
@app.post("/payouts")
async def payout(user=Depends(require_permission(auth, "payouts.create", fresh=True))): ...

# Direct calls
await verify_permission(client, config, token, user, "payouts.create", cache=cache, fresh=True)
await auth.authenticate_or_raise(authorization, api_key, fresh=True)
flask_auth.authenticate(authorization, api_key, fresh=True)
```

**Local JWT verification does not see logout.** A JWT is verified locally (signature, `exp`, `aud`, `iss`), with no
network call. So a server-side logout or session revocation is not visible until the token's own `exp` (access tokens
are ~15 min). `fresh=True` on `authenticate` re-verifies locally, and that alone does not see a logout either. Where a
logged-out session must be refused at once, ask the auth service, which checks the session:
`permission_check_mode="server"` + `fresh=True` on that route, or `ab0t_auth.client.introspect_token(...)` and
require `active is True`.

## A2 — new configuration and helpers (optional)

| Setting (`AuthConfig` field / env var) | Default | Range |
|---|---|---|
| `permission_cache_ttl` / `AB0T_AUTH_PERMISSION_CACHE_TTL` | unset → `min(token_cache_ttl // 2, 15)` | 0–300, `0` disables |
| `permission_cache_negative_ttl` / `AB0T_AUTH_PERMISSION_CACHE_NEGATIVE_TTL` | unset → 5 (≤ positive) | 0–300 |
| `api_key_cache_ttl` / `AB0T_AUTH_API_KEY_CACHE_TTL` | unset → `min(token_cache_ttl, 60)` | 0–300, `0` disables |
| `api_key_cache_negative_ttl` / `AB0T_AUTH_API_KEY_CACHE_NEGATIVE_TTL` | unset → 10 (≤ positive) | 0–300 |

Precedence: a value passed in code (`AuthConfig` / `create_config(**kwargs)`) > the env var > the derived default. The
four env vars above are read on **every** construction path (`AuthGuard(auth_url=...)`, `create_config(...)`,
`AuthConfig(...)`, `AuthSettings()`); a value that is not an integer 0–300 raises `ValueError` naming the variable at
start-up (a typo in an opt-out must not silently leave the cache on).
`token_cache_ttl=0` still disables **every** cache, as in 0.1.3, because unset TTLs derive from it. Note the older
`AB0T_AUTH_TOKEN_CACHE_TTL` env var is read only when the guard is built from `AuthSettings()` (unchanged); with
`AuthGuard(auth_url=...)` / `create_config(...)` pass `token_cache_ttl=0` in code.
Helpers: `auth.invalidate_api_key(key)`, `auth.cache_stats()` (hits / misses / size / effective TTLs for the
permission and API-key caches), and `ab0t_auth.cache.resolve_cache_ttls(config)` (shows the effective TTLs).
`create_caches(config)` still returns the same 3-tuple; the API-key cache comes from `create_api_key_cache(config)`.

---

## Agent-applicable rule list

1. Run `migrate-check.sh <repo>`. Fix ACTION findings only where the matched object is the ab0t_auth one the rule
   names; otherwise append `# ab0t-auth-0.1.4: reviewed` to the line.
2. `perm-cache-default` / `perm-ttl-30-literal`: accept 15/5 s, or pin `ttl=30, negative_ttl=30` (config preferred).
3. `apikey-call-count`: in that test, set `api_key_cache_ttl=0` or clear the cache between steps. Never weaken the
   assertion just to make it pass.
4. `apikey-wrapper` / `apikey-token-cache-invalidate`: remove the API-key caching wrapper, and switch invalidation to
   `auth.invalidate_api_key(key)`.
5. REVIEW findings are BEHAVIOURAL: do not edit them automatically. A human decides the TTL / `fresh=True` per route.
6. Bump the dependency to 0.1.4 and run the service's test suite. Re-run the checker (expect exit 0).

## Verify

```bash
./migrate-check.sh .                     # exit 0
pip install "ab0t-auth @ git+https://github.com/ab0t-com/auth_wrapper.git@v0.1.4"   # not on PyPI; a PyPI "ab0t-auth" is not ours
pytest                                   # your suite
python -c "from ab0t_auth import AuthGuard; print(AuthGuard(auth_url='https://auth.example').cache_stats())"
```

## Rollback

All changes are defaults. To go back, **pin `ab0t-auth` to 0.1.3** and redeploy. If you already used the 0.1.4-only
options, remove them first: the `fresh=` keyword, the four new `AuthConfig(...)` fields, `invalidate_api_key`,
`cache_stats`. The new `AB0T_AUTH_*_CACHE_*` env vars are ignored by 0.1.3 and are harmless to leave set.

To stay on 0.1.4 with the 0.1.3 permission and API-key cache behaviour (assuming the default
`token_cache_ttl` of 60 s), set: `AB0T_AUTH_PERMISSION_CACHE_TTL=30`, `AB0T_AUTH_PERMISSION_CACHE_NEGATIVE_TTL=30`,
`AB0T_AUTH_API_KEY_CACHE_TTL=0`. If you use a custom `token_cache_ttl`, set the permission TTLs to
`min(token_cache_ttl // 2, 30)`. For the kid cooldown, see B4.
