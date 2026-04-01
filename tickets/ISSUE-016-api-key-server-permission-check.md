# ISSUE-016: API Key Authentication Fails Server-Side Permission Checks

## Summary

When requests authenticate via `X-API-Key` header instead of JWT Bearer tokens, server-side permission validation consistently fails with 403 Forbidden. The API key successfully authenticates and creates a user object with correct permissions, but subsequent permission checks send an empty Bearer token to the auth service.

## Severity

**High** - Complete failure of server-side permission checks for API key authenticated requests.

## Affected Versions

- All versions with `permission_check_mode="server"` support

## Root Cause Analysis

### The Bug Location

In `src/ab0t_auth/dependencies.py`, three functions pass `authorization or ""` when the authorization header is `None`:

| Function | Line | Code |
|----------|------|------|
| `require_permission` | 243 | `authorization or ""` |
| `require_any_permission` | 306 | `authorization or ""` |
| `require_all_permissions` | 369 | `authorization or ""` |

### Flow Breakdown

```
1. Request: X-API-Key: <valid_key> (no Authorization header)
2. guard.authenticate_or_raise() → Success, returns AuthenticatedUser with permissions
3. permission_check_mode == "server" branch executes
4. authorization is None → authorization or "" → ""
5. verify_permission() called with token=""
6. client.check_permission() sends: Authorization: Bearer <empty>
7. Auth service returns 401 → mapped to 403 Forbidden
```

### Code Path

```python
# dependencies.py:require_any_permission
async def dependency(...):
    api_key = x_api_key if allow_api_key else None
    user = await guard.authenticate_or_raise(authorization, api_key)  # ✓ Works

    if guard._config.permission_check_mode == "server":
        result = await verify_any_permission(
            guard._http_client,
            guard._config,
            authorization or "",  # ✗ BUG: Empty string when API key auth
            user,
            *permissions,
            cache=guard._permission_cache,
        )
```

## Why This Was Not Caught

### Test Coverage Gap Analysis

1. **Isolated unit tests**: Existing tests for `require_*` dependencies mock `guard.authenticate_or_raise()` but don't test the full flow with `permission_check_mode="server"` + API key auth combination.

2. **Missing integration scenario**: No test combines:
   - `permission_check_mode="server"`
   - API key authentication (`X-API-Key` header)
   - Permission-protected routes

3. **Default configuration**: Most tests use `permission_check_mode="client"` (the default), which uses JWT claims and doesn't hit this code path.

4. **API key tests focus on auth, not authz**: Tests in `test_api_key_validation.py` verify authentication works but don't test downstream permission checking.

5. **Server-mode tests use JWT**: Tests for server-side permission checks use Bearer tokens, not API keys.

## Proposed Solution

### Option A: Pass API key via `X-API-Key` header to permission check (Recommended)

**Rationale:**
- Server-side permission checks are **authoritative** - this is a Zanzibar-based real-time permission system
- Permissions can change at any moment; local/cached permissions (from JWT claims or API key validation) may be stale
- The `/permissions/check` endpoint must perform the real-time check regardless of auth method
- **CONFIRMED:** The auth service `/permissions/check` endpoint accepts both `Authorization: Bearer <jwt>` AND `X-API-Key: <apikey>` headers for authentication (OpenAPI spec not fully updated but this is the actual behavior)

**Implementation:**

```python
# In client.py check_permission():
# Support both Bearer token and API key for authenticating the permission check request
# API key is sent as Bearer token since /permissions/check uses HTTPBearer security scheme
if token:
    auth_header = token if token.startswith("Bearer ") else f"Bearer {token}"
    headers = {"Authorization": auth_header}
elif api_key:
    headers = {"Authorization": f"Bearer {api_key}"}
else:
    raise AuthError("No credentials for permission check")
```

```python
# In dependencies.py require_permission (and similar):
if guard._config.permission_check_mode == "server":
    result = await verify_permission(
        guard._http_client,
        guard._config,
        authorization or "",  # JWT token (may be empty for API key auth)
        user,
        permission,
        cache=guard._permission_cache,
        api_key=x_api_key,  # NEW: pass API key for fallback auth
    )
```

### Why NOT Option B (Skip server-side checks for API key)

| Reason | Explanation |
|--------|-------------|
| Stale permissions | API key validation returns permissions at validation time; they may be revoked since |
| Zanzibar model | Real-time evaluation is the core value proposition of the permission system |
| Inconsistent behavior | Same route would have different permission semantics based on auth method |
| Security gap | Revoked permissions would not be enforced for API key authenticated requests |

### Alternative Options (Not Recommended)

| Option | Description | Trade-offs |
|--------|-------------|------------|
| B | Skip server-side checks for API key | **REJECTED**: Breaks Zanzibar real-time model, stale permissions |
| C | Auto-fallback on empty token | Silent degradation, masks the bug, stale permissions |

## Acceptance Criteria

- [ ] API key authenticated requests work with `permission_check_mode="server"`
- [ ] Permission checks use client-side validation for API key auth
- [ ] JWT Bearer token requests continue to use server-side validation when configured
- [ ] Comprehensive tests cover the matrix:
  - Auth method: JWT, API key
  - Permission mode: client, server
  - Permission result: allowed, denied
- [ ] No regression in existing functionality

## Test Requirements

### Red TDD Tests (must fail before fix)

1. `test_api_key_auth_with_server_permission_mode_succeeds`
2. `test_api_key_auth_server_mode_permission_denied_when_missing`
3. `test_api_key_auth_server_mode_uses_client_side_check`
4. `test_jwt_auth_server_mode_still_calls_server`

### Matrix Coverage

```
| Auth Method | Permission Mode | Has Permission | Expected Result |
|-------------|-----------------|----------------|-----------------|
| API Key     | server          | Yes            | 200 OK          |
| API Key     | server          | No             | 403 Forbidden   |
| API Key     | client          | Yes            | 200 OK          |
| API Key     | client          | No             | 403 Forbidden   |
| JWT         | server          | Yes            | 200 OK          |
| JWT         | server          | No             | 403 Forbidden   |
| JWT         | client          | Yes            | 200 OK          |
| JWT         | client          | No             | 403 Forbidden   |
```

## Files to Modify

- `src/ab0t_auth/dependencies.py` - Pass API key to verify_permission functions
- `src/ab0t_auth/permissions.py` - Accept and forward API key parameter
- `src/ab0t_auth/client.py` - Support X-API-Key header for permission check requests
- `tests/test_api_key_server_permission.py` - Comprehensive test file (already created)

## Related Issues

- GitHub Issue: https://github.com/ab0t-com/auth_wrapper/issues/16

## Timeline

- Investigation: Complete
- Test writing (red): This ticket
- Implementation (green): After tests
- Refactor & review: After green
