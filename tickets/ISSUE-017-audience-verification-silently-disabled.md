# ISSUE-017: JWT audience verification is silently disabled when no audience is configured

## Summary

When an `AuthGuard` is constructed without an `audience` (or with `verify_aud=False`), the library
**silently accepts a JWT minted for ANY service in the mesh** as this service's caller. The audience claim
(`aud`, e.g. `LOCAL:<org_uuid>`) is the boundary that stops a token issued for service X being replayed
against service Y. There is no guard against running this way — a single unset/forgotten audience runs the
service wide open, with no error and (before this fix) no warning.

## Severity

**High** — cross-service token confusion. Any mesh service that forgets to set its audience accepts tokens
minted for a *different* service/org. Because the wrapper is shared by every service, this is a fleet-wide
exposure, not a single-service bug.

## Affected Versions

- All versions. The wrapper defaults `audience=None`, and PyJWT is told not to verify the claim when the
  expected audience is absent.

## Root Cause Analysis

### The bug location

`src/ab0t_auth/jwt.py`, `validate_token_local()` builds the PyJWT decode options as:

```python
"verify_aud": config.verify_aud and config.audience is not None,
```

When `config.audience is None`, `verify_aud` collapses to `False` and PyJWT does **not** validate `aud`.
Nothing at construction time flags or refuses this configuration, unlike the auth-bypass path which is
gated behind a defense-in-depth flag (`load_bypass_config()` requires `AB0T_AUTH_BYPASS=true` **and**
`AB0T_AUTH_DEBUG=true`).

### Flow breakdown

```
1. Service constructs AuthGuard(auth_url=...) with no audience (or AB0T_AUTH_AUDIENCE unset).
2. config.audience is None → decode option verify_aud = (True and None is not None) = False.
3. A token minted for a DIFFERENT service (different aud) is signed by the same mesh JWKS.
4. jwt.decode() skips the aud check → token is accepted.
5. The request is authorized as this service's caller, using the foreign token's org_id/user_id.
```

### Why it went unnoticed

`verify_aud` defaults to `True`, which reads as "audience is verified" — but it is a no-op unless an
`audience` is also supplied. The two settings must agree, and nothing enforced that they do.

## Fix

`src/ab0t_auth/guard.py` — new `AuthGuard._enforce_audience_security()`, called at construction.
Deliberately **non-breaking on upgrade**, two tiers:

1. **Always** emit a loud `logger.warning("audience_verification_disabled", …)` whenever audience
   verification is off — so the exposure is visible in every environment.
2. **Fail closed** (`raise ConfigurationError`) **only** when the service declares a production/staging
   environment via `ENVIRONMENT` / `AB0T_AUTH_ENVIRONMENT` **and** `AB0T_AUTH_DEBUG` is not set. A
   dev/test/unset environment is warn-only, so upgrading the library does not break existing consumers —
   only a *production deployment that forgot its audience* is stopped at boot.

Mirrors the existing bypass defense-in-depth: the dangerous mode is only reachable behind an explicit
signal. Clearing it is one line — set the service's audience (`AB0T_AUTH_AUDIENCE` / `audience=`).

### Why not fail hard regardless of environment?

A first draft raised whenever `AB0T_AUTH_DEBUG` was absent. That broke **19** of the library's own tests,
which legitimately construct audience-less guards in unit tests. The shipped, env-gated form keeps the full
suite green.

## Testing

`tests/test_audience_security.py` (8 tests):

- Prod-like env (`ENVIRONMENT` ∈ {production, prod, staging}) + no audience → `ConfigurationError` (RED if
  the guard is reverted to a no-op: the 4 prod-refusal cases stop raising).
- Prod-like env + audience set (str or tuple) → constructs fine (no over-block).
- Prod-like env + `AB0T_AUTH_DEBUG=true` → allowed (escape hatch, matches bypass).
- Dev / unset env + no audience → allowed, warn-only (non-breaking).

Full suite: **466 passed** (with `flask` + `respx` installed so nothing is skipped) — the fix adds no
regressions.

## Rollout note (IMPORTANT — coordinated release)

Because prod services set `ENVIRONMENT`, a service running in production **with no audience configured will
now fail fast at boot**. That is the intended behavior, but it means each mesh consumer must set its
`AB0T_AUTH_AUDIENCE` **before** this release reaches its production environment. Recommend confirming
audience is set for every consumer, then releasing.

## Reported by

Resource-service security audit (R-M2, 2026-07-12/13). The per-service interim guard
(`resource/output/app/auth.py::_resolve_audience`) is deployed as defense-in-depth; this issue generalizes
that guarantee to every consumer of the shared wrapper.
