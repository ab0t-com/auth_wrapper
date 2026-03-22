# Security Audit Tasklist — 2026-03-22

**Triggered by:** Runner backend team bug report (API key `valid=True` hardcoding)
**Scope:** Full audit of ab0t-auth library for similar fail-open patterns
**Branch:** main

---

## Completed

- [x] **BUG-001: API key `valid=True` hardcoded** (`client.py:232`)
  - Auth service returns HTTP 200 with `{"valid": false}` for invalid keys
  - Library ignored the field and hardcoded `valid=True`
  - Any string as `X-API-Key` bypassed authentication
  - **Fixed:** `valid=data.get("valid", False)` — fail-closed
  - **Fixed:** capture `error` field from response
  - **Commit:** `98d8d1e`

- [x] **BUG-002: Token validation defaults to `True`** (`client.py:190`)
  - `valid=data.get("valid", True)` — if field missing, defaults to allow
  - **Fixed:** `valid=data.get("valid", False)` — fail-closed
  - **Commit:** `98d8d1e`

- [x] **TEST: 14 tests for BUG-001 and BUG-002** (`tests/test_api_key_validation.py`)
  - Client-level: valid/invalid/missing field/empty body/SQL injection/401/403
  - Guard-level: full flow reject/accept/null user_id fallback
  - Token validation: fail-closed default
  - **Commit:** `98d8d1e`

---

## To Do — Critical

- [x] **BUG-003: Server-side permission check fails open** (`permissions.py:228-230`)
  - `except Exception:` narrowed to `except AuthServiceError:`
  - Added configurable `permission_fallback` setting: `"deny"` (default) or `"client"`
  - WARNING logged whenever fallback triggers
  - **Tests:** deny default, client fallback, programming error propagation

- [x] **BUG-004: `"api_key_user"` fallback on null user_id** (`guard.py:449`, `flask.py:388`)
  - Now rejects with `AuthResult.fail("INVALID_API_KEY")` when user_id is null/empty
  - Fixed in both FastAPI guard and Flask adapter
  - **Tests:** null user_id, empty string user_id

- [x] **BUG-005: `tuple()` on string permissions** (`client.py:184, 236, 339`)
  - Added `_safe_permissions()` helper that handles list, string, None
  - Comma-separated and space-separated strings split correctly
  - **Tests:** string permissions in API key and token validation

---

## Completed — Medium

- [x] **BUG-006: Middleware path exclusion too loose** (`middleware.py:145`, `flask.py:292`)
  - Case-insensitive matching, trailing slash normalization, segment-boundary-aware wildcards
  - Fixed in both FastAPI middleware and Flask adapter
  - **Tests:** prefix overreach, case bypass, trailing slash bypass

- [ ] **BUG-007: Inconsistent permissions parsing** (`client.py:84-93` vs `135-137` vs `183-187`)
  - `login()` checks `scope` first, then `permissions`
  - `validate_token()` checks `permissions` first, then `scope`
  - `refresh_token()` only checks `scope`
  - **Fix:** Unify parsing order across all three functions. Extract to a helper.
  - **Test:** `test_security_failopen.py::test_permissions_parsing_consistency`

- [ ] **BUG-008: `introspect_token()` returns raw dict** (`client.py:437`)
  - No validation of RFC 7662 `active` field
  - Caller must manually check — easy to miss
  - **Fix:** Return a typed dataclass with `active: bool` defaulting to `False`.
  - **Test:** `test_security_failopen.py::test_introspect_missing_active_field`

---

## To Do — Low

- [ ] **BUG-009: `token_type` hardcoded to `"Bearer"`** (`client.py:98, 142`)
  - Minor — reasonable default but should read from response
  - **Fix:** Already uses `.get()` — acceptable as-is. Document.

- [ ] **BUG-010: Non-bool check callback results silent** (`dependencies.py:56-71`)
  - Returns `False` on non-bool — safe default but hard to debug
  - **Fix:** Log at ERROR level, not WARNING. Consider raising in debug mode.

---

## Test Plan

All red tests written FIRST (TDD) to prove vulnerabilities exist, then fixes applied.

### Mock tests (`respx`)
- Simulate auth service returning unexpected payloads
- No network dependency — runs in CI

### Live tests (`localhost:8001`)
- Hit real auth service to confirm behavior matches OpenAPI spec
- Skipped when auth service unavailable (`pytest.mark.skipif`)
- Validates that our mocks match reality

### Test file: `tests/test_security_failopen.py`

---

## Verification

After all fixes:
1. All red tests turn green
2. Full suite (`pytest tests/ -x`) passes
3. No regressions in existing 420 tests
4. Security fixes committed with descriptive messages
5. Push to main
