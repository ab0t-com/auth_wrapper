# Client notice — ab0t-auth 0.1.4 (cache defaults aligned with the Go SDK)

*Copy/paste to any team whose service depends on `ab0t-auth` (Python, FastAPI or Flask).*

---

**Subject: ab0t-auth 0.1.4: shorter permission cache, API keys now cached. No code changes required, but revocation timing changes.**

Hi — **ab0t-auth 0.1.4** changes cache defaults so that Python and Go services (`auth-sdk-go`) behave the same. No
function or class signature changes, and your code keeps compiling and running. What changes is **how long a
revocation takes to reach your service**:

| What | 0.1.3 | 0.1.4 |
|---|---|---|
| Permission check, server mode — **allowed** answer reused for | 30 s | **15 s** |
| Permission check, server mode — **denied** answer reused for | 30 s | **5 s** |
| **API key** (`X-API-Key`) — valid answer reused for | not cached (auth call every request) | **60 s** |
| API key — rejected answer reused for | not cached | **10 s** |
| JWT (verified locally) | up to 60 s, never past the token's `exp` | unchanged |
| Unknown JWT `kid` → JWKS refetch | at most once per 30 s | at most once per 60 s |

**Revocation latency on your service, after upgrading:**
- A permission **revoked** in auth stops passing within **15 s** (was 30 s). A new grant is seen within **5 s**.
- An API key **revoked** in auth can keep working **for up to 60 s** (before, it was refused on the next request).
- A **logout / session revocation** is **not** seen by local JWT verification until the token expires (access tokens
  last ~15 min). This was already true in 0.1.3; it is now documented.

What you get: far fewer calls to the auth service (an API-key request no longer pays an auth round trip), so lower
latency and less exposure to auth rate limits. Errors, timeouts, `429`s and `5xx`s are **never** cached. A request
that hits one is refused (fail closed) and the next request asks again.

## What to do

```bash
pip install "ab0t-auth==0.1.4"     # or bump your pinned git ref
```

Then run the read-only migration checker from the kit in the ab0t-auth repository (`migrations/v0.1.3-to-v0.1.4/`):

```bash
./migrate-check.sh /path/to/your/service
```

It lists places that rely on the old behaviour: tests that count API-key validation calls, code that pins a 30 s
permission cache, and wrappers that cached API keys themselves. It prints the fix for each, and exits non-zero until
they are reviewed (gate CI on it). It never edits your code. `MIGRATION.md` in the same folder has the
before → after for every change.

## If 60 s / 15 s is too long for a route

- **Per route:** add `fresh=True` (e.g. `require_permission(auth, "payouts.create", fresh=True)`). That route skips
  every cache and asks the auth service on every request.
- **When you revoke a key yourself:** call `auth.invalidate_api_key(key)` to drop it from your cache immediately.
- **Must refuse a logged-out session immediately:** use `permission_check_mode="server"` with `fresh=True` on that
  route, or `ab0t_auth.client.introspect_token(...)`.
- **Service-wide opt-out** (env): `AB0T_AUTH_API_KEY_CACHE_TTL=0` (API keys uncached, as before);
  `AB0T_AUTH_PERMISSION_CACHE_TTL=30` + `AB0T_AUTH_PERMISSION_CACHE_NEGATIVE_TTL=30` (the old permission window);
  these four `AB0T_AUTH_*_CACHE_*` variables work however you build the guard (`AuthGuard(auth_url=...)`,
  `create_config(...)`, `AuthConfig(...)` or `AuthSettings()`); a value you pass in code wins over the variable, and an
  invalid value (not 0–300) stops start-up with an error naming the variable.
  To turn off ALL caching: `token_cache_ttl=0` in code, or `AB0T_AUTH_TOKEN_CACHE_TTL=0` if you build the guard from
  `AuthSettings()` (that older variable is only read there).

## Watch out for

- **Tests that count auth calls** for API keys will see fewer calls. Set `api_key_cache_ttl=0` in those tests, or
  call `auth.clear_caches()` between steps.
- **Your own API-key caching wrapper** (if you added one around the guard): remove it, because 0.1.4 does this. Use
  `auth.invalidate_api_key(key)` instead of invalidating through the token cache.

**Rollback:** pin `ab0t-auth` back to `0.1.3` and redeploy (remove any 0.1.4-only options you started using, such
as `fresh=` or the new config fields). Or stay on 0.1.4 and use the env opt-outs above.

Questions? Reply here. Full detail: the `[Unreleased]` / `[0.1.4]` section of `CHANGELOG.md`, the README section
"Caching and revocation latency", and `migrations/v0.1.3-to-v0.1.4/MIGRATION.md`.
