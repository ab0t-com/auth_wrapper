# Client notice — ab0t-auth 0.1.5 (patch: four fixes, one security)

*Copy/paste to any team whose service depends on `ab0t-auth` (Python, FastAPI or Flask).*

---

**Subject: ab0t-auth 0.1.5: permission-cache fix (resource_type), lower-case `bearer` fix. No code changes required; nothing stops your service from starting.**

Hi. **ab0t-auth 0.1.5** is a patch release. No function or class signature changes; your code keeps running. It fixes:

| What | 0.1.4 | 0.1.5 |
|---|---|---|
| **Security (Medium):** `verify_permission(..., resource_id=, resource_type=)` in server mode | an `allowed` for `(perm, "doc", "42")` was reused for `(perm, "invoice", "42")` for up to 15 s, without asking auth | `resource_type` is part of the cache key; every type is asked |
| Permission names containing `:` | `("docs:read", resource "x")` and `("docs:read:x")` shared one cache entry | separate entries |
| `Authorization: bearer <token>` (lower-case scheme) in server mode | forwarded as `Bearer bearer <token>`: auth refused a **valid** token | forwarded as `Bearer <token>` |
| A permission/API-key cache TTL **set in code** outside 0–300 s | accepted (e.g. `api_key_cache_ttl=86400`: a revoked key kept working for a day) | **clamped** to the range (above 300 → 300; negative → off), with a warning in your logs naming the setting |

**Who is affected:**
- You call `verify_permission` yourself with `resource_type=`: 0.1.4 could return a wrong cached answer when two
  resource types share an id. **Upgrade.** Expect one `/permissions/check` call per `(type, id)` instead of one per id.
- Your clients send `bearer` in lower case and you use `permission_check_mode="server"`: those requests now pass.
- You set `permission_cache_ttl`, `permission_cache_negative_ttl`, `api_key_cache_ttl` or `api_key_cache_negative_ttl`
  **in code** to a negative number or above 300: 0.1.5 uses the nearest value in range and logs a warning naming the
  setting. Change it to a value in range (`0` turns that cache off; the maximum is `300`); a later minor release may
  refuse it. The FastAPI dependencies, the env vars, and values 0–300 are unaffected.

## What to do

```bash
pip install "ab0t-auth @ git+https://github.com/ab0t-com/auth_wrapper.git@v0.1.5"   # not on PyPI; a PyPI "ab0t-auth" is not ours
```

Then run the read-only migration checker from the kit in the ab0t-auth repository (`migrations/v0.1.4-to-v0.1.5/`):

```bash
./migrate-check.sh /path/to/your/service
```

It lists TTLs set in code outside 0–300 s and code that reads permission-cache keys as strings (they are tuples now).
Each finding comes with its fix, and the checker exits non-zero until they are dealt with, so you can gate CI on it.
It never edits your code. `MIGRATION.md` in the same folder has the before → after for every change.

## Watch out for

- **Tests that count `/permissions/check` calls** across several resource types with the same id will see more calls.
  That is the fix.
- **Tests that read `PermissionCache._cache` keys as strings** (e.g. `" ".join(cache._cache.keys())`): keys are tuples
  now. Use `" ".join(repr(k) for k in ...)` or go through `PermissionCache.get`.

**Rollback:** pin `ab0t-auth` back to `0.1.4` and redeploy. That brings the defects back, including the security one.

Questions? Reply here. Full detail: the `[0.1.5]` section of `CHANGELOG.md` and
`migrations/v0.1.4-to-v0.1.5/MIGRATION.md`.
