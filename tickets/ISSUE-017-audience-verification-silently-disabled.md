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

`src/ab0t_auth/guard.py` — new `AuthGuard._warn_or_require_audience()`, called at construction. Designed as
a **backward-compatible, additive** change (no contract break — a minor-version feature, not a breaking one):

1. **Always** emit a loud `logger.warning("audience_verification_disabled", …)` whenever audience
   verification is off. **Construction still succeeds by default** — the historical behaviour is preserved,
   so upgrading the library cannot break any existing consumer.
2. **Opt-in fail-closed** — a new constructor kwarg `require_audience: bool = False` **and** env var
   `AB0T_AUTH_REQUIRE_AUDIENCE=true`. When either is set, an audience-less configuration raises
   `ConfigurationError` at construction. Off by default.

This mirrors the auth-bypass philosophy correctly: the stricter/dangerous posture is **opt-in**, never
imposed. A security-conscious service (or a deployment's prod config) turns `AB0T_AUTH_REQUIRE_AUDIENCE=true`
on to get the fail-closed guarantee; everyone else gets the visibility of the warning with zero behaviour
change. Clearing the warning entirely is one line — set the service's audience (`AB0T_AUTH_AUDIENCE` /
`audience=`).

### Why additive rather than a stricter default?

The wrapper is used by many services; `AuthGuard(auth_url=...)` with no audience has always constructed
successfully (the library's own tests do so 19×). Making that raise — even gated on an ambient `ENVIRONMENT`
var the library did not previously read — is a silent contract change that would fail existing prod
deployments on a patch bump. Per best-practice engineering, a behaviour break must be a deliberate,
documented, version-gated contract change. This PR ships the safe, non-breaking layer (warn + opt-in);
if the team later wants `require_audience` to default `True`, that is a documented **major** release with a
migration note — the maintainers' call, not a side effect of a security patch.

### Public API surface added (backward compatible)

- `AuthGuard(..., require_audience: bool = False)` — new optional kwarg.
- `AB0T_AUTH_REQUIRE_AUDIENCE` — new env var (read directly in the guard; covers `settings=`/env-driven
  construction without touching the frozen `AuthConfig`/`AuthSettings`).
- A new `warning` log event `audience_verification_disabled`.

## Testing

`tests/test_audience_security.py` (7 tests):

- **Backward-compat:** no audience + no opt-in → constructs (warn-only); with audience → constructs. These
  pin the contract existing consumers rely on.
- **Opt-in strict:** `require_audience=True` (kwarg) or `AB0T_AUTH_REQUIRE_AUDIENCE=true` (env) + no audience
  → `ConfigurationError` (RED if the guard is reverted to a no-op); with audience (str or tuple) → constructs;
  `=false` env does not opt in.

Full suite: **465 passed** (with `flask` + `respx` installed so nothing is skipped) — no regressions; every
existing audience-less construction test still passes because the default is unchanged.

## Rollout note (non-breaking)

Nothing is forced. On upgrade, consumers that already set `AB0T_AUTH_AUDIENCE` see no change; consumers
without it get a new loud warning at startup. To adopt the guarantee, a service sets
`AB0T_AUTH_REQUIRE_AUDIENCE=true` (recommended for prod) **after** confirming its `AB0T_AUTH_AUDIENCE` is set.
A fleet audit of `production/.env.production` across the mesh (2026-07-13) found audience set for every
wrapper-consuming service (billing/banking/integration/payment/resource/sandbox-platform/schema/tool
explicitly; audit via its config default) — so enabling `AB0T_AUTH_REQUIRE_AUDIENCE` is currently safe
everywhere.

## Reported by

Resource-service security audit (R-M2, 2026-07-12/13). The per-service interim guard
(`resource/output/app/auth.py::_resolve_audience`) is deployed as defense-in-depth; this issue generalizes
that guarantee to every consumer of the shared wrapper.
