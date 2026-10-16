# Migration: ab0t-auth 0.1.4 → 0.1.5

**Patch release. No breaking change to the documented API.** Every public function and class keeps its signature;
the two new parameters are optional and keyword-only. 0.1.5 fixes four defects found by an adversarial test pass on
0.1.4. Three of them change only answers that were **wrong** (a cached permission answer served for a different
question, or a valid lower-case `bearer` token refused). The fourth keeps an **out-of-range TTL set in code** inside
the documented range: it is clamped (≤ 300 s; negative → off) with a WARNING log naming the field. **Nothing in
0.1.5 stops a service that ran on 0.1.4 from starting.**

Run the checker first. It is read-only, and it exits non-zero while ACTION findings remain:

```bash
./migrate-check.sh /path/to/your/service          # add --strict to also fail on advisory REVIEW findings
```

| Rule | Type | Scope | Before (0.1.4) | After (0.1.5) |
|---|---|---|---|---|
| F1 `resource-type-key` | FIX (security, Medium) | direct `verify_permission(..., resource_type=...)` in server mode | answer cached **without** `resource_type`: an allow for `(perm, "doc", "42")` answered `(perm, "invoice", "42")` for up to 15 s | `resource_type` is in the key; each type is asked separately |
| F2 `key-injective` | FIX (Low) | permission names containing `:` | `("docs:read", resource "x")` and `("docs:read:x")` shared one cache entry | distinct entries (tuple key) |
| F3 `lowercase-bearer` | FIX (Low-Medium) | `Authorization: bearer <t>` (any case) in server mode, `validate_token`, `get_user_permissions` | forwarded as `Bearer bearer <t>`: refused by auth (401/403 on a valid token) | forwarded as `Bearer <t>` |
| F4 `ttl-range-code` | FIX (Low) | the four decision-cache TTLs set **in code** | any value accepted (`86400` = a revoked key works for a day; negative = cache off) | outside `0–300` → clamped (> 300 → 300; < 0 → 0 = off) + one WARNING on `ab0t_auth.cache` naming the field; never raises |
| A1 `resource-type-param` | ADD (optional) | `verify_any_permission`, `verify_all_permissions`, `PermissionCache.get/set` | — | keyword-only `resource_type=` |
| C1 `cache-key-tuple` | CHANGED (internal) | `ab0t_auth.cache.create_permission_cache_key`, `PermissionCache._cache` keys | `":"`-joined `str` | `tuple` |

Unchanged: every TTL default (15 s / 5 s permission, 60 s / 10 s API key, token cache, JWKS), "errors are never
cached", `fresh=True`, `token_cache_ttl=0` turning every cache off, and the env-var handling (same values accepted,
same error text).

---

## F1 — `resource_type` is part of the permission-cache key (security fix)

Applies when you call `verify_permission` directly with `resource_type=` and a `cache` (server mode). The FastAPI
dependencies (`require_permission`, ...) never pass a resource and were never affected.

| | Before | After |
|---|---|---|
| Key | credential, org, permission, resource id | credential, org, permission, **resource type**, resource id |
| `(x.read, "doc", "42")` allowed, then `(x.read, "invoice", "42")` | answered `allowed` from the cache for ≤ 15 s, no auth call | asked of `/permissions/check` (correct answer) |
| Denial for one type, then the other type | served as `denied` for ≤ 5 s | asked |

*Exposure on 0.1.4:* real when two resource types can share an id (sequential ids, slugs such as `default`).
*Cost after upgrading:* one `/permissions/check` call per distinct `(type, id)` instead of one per id. Tests that count
calls for several types on the same id will see more calls; that is the fix.

`verify_any_permission` / `verify_all_permissions` now accept `resource_type=` too (before, they could not send it).

## F2 — the permission-cache key is injective

The key was `user:cred=…:org=…:permission[:resource]` joined with `:`. A permission containing `:` (the library's
own docs use `users:delete`) could collide with permission + resource. The key is now a fixed-length tuple. Names
registered with the ab0t auth service are `[a-z0-9_.]`, so this mainly matters for custom permission names.

`invalidate_user(user_id)` / `auth.invalidate_user_permissions(user_id)` now matches the user id exactly. Before, the
prefix match `"<id>:"` also dropped another user's entries when that user's id started with `"<id>:"`. The returned
count can therefore be lower for such ids. It never drops too few.

## F3 — lower-case `bearer` is forwarded as `Bearer`

RFC 7235 §2.1 / RFC 6750 §2.1: the auth scheme is case-insensitive. Authentication always accepted `bearer <t>`, but
the call to the auth service re-added the scheme with a case-sensitive check, so it sent `Bearer bearer <t>` and was
refused. On 0.1.4 a server-mode route therefore refused a valid token sent by a client that writes the scheme in
lower case (whenever the permission cache was cold). 0.1.5 sends `Bearer <t>` from `check_permission`,
`validate_token` and `get_user_permissions`.

If you added a workaround (normalising `bearer` to `Bearer` before calling the SDK), you can remove it; it is harmless
to keep.

Also aligned: a whitespace-only bearer with an API key is now checked with the API key (the permission cache already
attributed the answer to the key). Before, an empty `Bearer ` header was sent.

## F4 — a TTL set in code is kept inside 0–300 s (clamped, with a warning)

| Setting | 0.1.4 code value | 0.1.5 code value | env var (unchanged since 0.1.4) |
|---|---|---|---|
| `permission_cache_ttl`, `permission_cache_negative_ttl`, `api_key_cache_ttl`, `api_key_cache_negative_ttl` | any int; negative → 0 (off); > 300 used as-is | `0–300` used as-is; > 300 → **300**; < 0 → **0** (off), each with one WARNING on the `ab0t_auth.cache` logger: `AuthConfig.<field>=<v> is outside the documented 0-300 seconds; using <n>. …` | `0–300`, else `ValueError` naming the variable |

The clamp happens where `AuthGuard(...)` / Flask `Ab0tAuth(...).init_app(...)` builds its caches, and in
`ab0t_auth.cache.resolve_cache_ttls(config)`. As before, a negative-result TTL is also capped at its positive TTL. A
non-integer value raises `AuthConfig.<field> must be an integer number of seconds (0-300)`, as it would have failed
before too.

*Why:* a TTL is the revocation latency. `api_key_cache_ttl=86400` meant a revoked API key kept working on your
service for a day. The 0.1.4 docs (MIGRATION A2) gave `0–300` for these fields. *Why not refuse:* a patch release
must not stop a service that started on 0.1.4. A later **minor** release may refuse out-of-range code values, as the
env var already does, so fix them now.

*What to do:* if the checker reports `ttl-out-of-range-code`, or your logs show the warning, pick a value in range:
`0` to turn that cache off (what a negative value did), or ≤ `300`. If you need revocation to be seen sooner, keep the
TTL short and use `fresh=True` / `auth.invalidate_api_key(key)`.

## C1 — internal: the cache key is a tuple

`ab0t_auth.cache.create_permission_cache_key(...)` returns a `tuple` (was a `str`) and takes an optional
`resource_type`. It is not exported from `ab0t_auth` and is not documented. Only code that builds keys itself or
reads `PermissionCache._cache` keys as strings (e.g. `" ".join(cache._cache.keys())` in a test) is affected. The
public `PermissionCache.get/set` calls, including the positional `set(user_id, permission, allowed, resource_id,
credential=, org_id=)` used to seed a cache in tests, work unchanged. The cache is in memory only, so nothing stored
needs migrating.

---

## Agent-applicable rule list

1. Run `migrate-check.sh <repo>`. Fix ACTION findings only where the matched object is the ab0t_auth one the rule
   names; otherwise append `# ab0t-auth-0.1.5: reviewed` to the line.
2. `ttl-out-of-range-code`: change the value to `0` (off) or a value ≤ `300` (0.1.5 already clamps it and warns; a
   later minor release may refuse it). Never raise the range.
3. `cache-key-internal`: treat permission-cache keys as tuples
   `(user_id, credential, org, permission, resource_type, resource_id)`. In tests, use
   `" ".join(repr(k) for k in cache._cache.keys())`, or better, go through `PermissionCache.get`.
4. REVIEW findings are advisory. `resource-type-direct`: nothing to change; call counts may rise where several types
   share an id. `bearer-case-workaround`: optional cleanup. `ttl-code-expression`: make sure the value is 0–300.
5. Bump the dependency to 0.1.5 and run the service's test suite. Re-run the checker (expect exit 0).

## Verify

```bash
./migrate-check.sh .                     # exit 0
pip install "ab0t-auth @ git+https://github.com/ab0t-com/auth_wrapper.git@v0.1.5"   # not on PyPI; a PyPI "ab0t-auth" is not ours
pytest                                   # your suite
python -c "import ab0t_auth; from ab0t_auth import AuthGuard; print(ab0t_auth.__version__, AuthGuard(auth_url='https://auth.example').cache_stats())"
```

## Rollback

Pin `ab0t-auth` back to `0.1.4` and redeploy. If you started passing `resource_type=` to `verify_any_permission` /
`verify_all_permissions` or to `PermissionCache.get/set`, remove it first (0.1.4 does not accept it there). Rolling
back brings the four defects back, F1 (a cached answer served across resource types) included.
