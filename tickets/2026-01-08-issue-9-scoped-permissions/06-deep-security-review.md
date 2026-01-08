# AB0T-AUTH Deep Security Review

**Date:** 2026-01-08
**Reviewer:** Security Audit
**Branch:** security/bypass-attack-tests
**Scope:** Complete codebase audit - authentication, authorization, bypass, API design

---

## Executive Summary

This deep security review examines the `ab0t_auth` library from the perspective of:
- A malicious attacker seeking to bypass authentication/authorization
- A system engineer looking for design flaws
- A permission expert analyzing logic chains
- A developer who might misuse the API

**Overall Assessment:** The library demonstrates strong security fundamentals but has several areas requiring attention, particularly around API confusion that could lead to security misconfigurations.

---

## Table of Contents

1. [Critical Findings](#1-critical-findings)
2. [High Severity Issues](#2-high-severity-issues)
3. [Medium Severity Issues](#3-medium-severity-issues)
4. [Low Severity Issues](#4-low-severity-issues)
5. [API Confusion Risks](#5-api-confusion-risks)
6. [Logic Chain Analysis](#6-logic-chain-analysis)
7. [Race Conditions & Concurrency](#7-race-conditions--concurrency)
8. [Test Coverage Gaps](#8-test-coverage-gaps)
9. [Recommendations](#9-recommendations)

---

## 1. Critical Findings

### NONE IDENTIFIED

No critical vulnerabilities were found that would allow immediate authentication bypass or remote code execution in a properly configured deployment.

---

## 2. High Severity Issues

### 2.1 JWKS Cache Not Thread-Safe (Potential Race Condition)

**Location:** `src/ab0t_auth/cache.py:241-303`

**Issue:** The `JWKSCache` class uses a plain `dict` for storage, unlike `TokenCache` and `PermissionCache` which use thread-safe `TTLCache`.

```python
@dataclass
class JWKSCache:
    ttl: int = 300
    _cache: dict[str, JWKSCacheEntry] = field(default_factory=dict)  # NOT THREAD-SAFE
```

**Attack Scenario:**
1. Two concurrent requests arrive when JWKS cache is expired
2. Both threads read `_cache.get(key)` returning `None`
3. Both threads fetch JWKS from remote server
4. Race condition during `_cache[key] = entry` could cause inconsistent state
5. Potential for one thread to use partially written entry

**Impact:** Could lead to authentication failures or, in worst case, accepting tokens validated against stale/corrupted keys.

**Recommendation:** Use `TTLCache` or add threading lock:
```python
from threading import Lock

@dataclass
class JWKSCache:
    _lock: Lock = field(default_factory=Lock, init=False)

    def get(self, ...):
        with self._lock:
            # ... existing logic
```

---

### 2.2 Bypass Config Can Be Replaced at Runtime

**Location:** `src/ab0t_auth/guard.py` - `_bypass_config` attribute

**Issue:** While `BypassConfig` itself is immutable (frozen dataclass), the `_bypass_config` attribute on `AuthGuard` can be replaced entirely:

```python
# Attacker with code execution can do:
guard._bypass_config = BypassConfig(
    enabled=True,
    user_id="hacker",
    permissions=("admin:*",),
)
```

**Test Evidence:** `test_bypass.py:1113-1133` explicitly documents this works.

**Impact:** If an attacker gains code execution (e.g., through dependency confusion, template injection, or SSRF leading to code eval), they can enable bypass mode programmatically.

**Mitigation:** This is somewhat expected - if attacker has code execution, they can do anything. However, consider:
1. Using `__slots__` to prevent attribute addition
2. Making `_bypass_config` a property with a setter that raises
3. Documenting this as accepted risk

---

### 2.3 Token Cache Accepts Any Token Hash

**Location:** `src/ab0t_auth/cache.py:70-77`

**Issue:** The `hash_token()` function truncates SHA256 to 32 characters:

```python
def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()[:32]
```

**Concern:** While SHA256 is collision-resistant, truncating to 128 bits (32 hex chars) increases collision probability. With birthday paradox, collision becomes likely after ~2^64 operations.

**Attack Scenario:** An attacker who can observe timing differences or has partial cache oracle might be able to craft a token whose hash collides with a cached valid token.

**Impact:** Low probability but theoretically possible cache poisoning.

**Recommendation:** Use full SHA256 hash (64 chars) or use a keyed hash (HMAC) with a server-side secret.

---

## 3. Medium Severity Issues

### 3.1 `optional_auth` Returns None on Error (Silent Failure)

**Location:** `src/ab0t_auth/dependencies.py:193-216`

**Issue:** The `optional_auth` dependency swallows ALL exceptions and returns `None`:

```python
async def dependency(...) -> AuthenticatedUser | None:
    try:
        # ... authentication logic
    except Exception:
        return None  # ALL errors become "not authenticated"
```

**Problem:** This masks:
- Configuration errors
- Network failures to auth service
- Invalid JWKS
- Malformed tokens that should be rejected

**Attack Scenario:** Attacker sends malformed token that crashes parsing. Instead of returning 401 (invalid token), the route treats request as "anonymous" and may expose different data.

**Example Vulnerable Code:**
```python
@app.get("/content")
async def get_content(user: AuthenticatedUser | None = Depends(optional_auth(auth))):
    if user:
        return {"secret_data": "..."}  # Should be shown only to VALID users
    return {"public_data": "..."}
```

If token parsing crashes, attacker sees public data instead of getting 401.

**Recommendation:** Only catch `AuthError` subclasses, not all `Exception`:
```python
except (TokenInvalidError, TokenExpiredError, TokenNotFoundError):
    return None
# Let other exceptions propagate as 500
```

---

### 3.2 Check Callback Can Raise Arbitrary Exceptions

**Location:** `src/ab0t_auth/dependencies.py:75-102` and `src/ab0t_auth/decorators.py:37-78`

**Issue:** User-provided check callbacks are called without exception handling:

```python
if asyncio.iscoroutinefunction(check_fn):
    result = await check_fn(user, request)
else:
    result = check_fn(user, request)
```

**Problem:** If a check callback raises an exception (e.g., database connection error), it will bubble up as a 500 error, potentially leaking stack traces.

**Worse:** If callback returns non-boolean (e.g., returns the user object, or a string), the truthiness check might pass unexpectedly:

```python
def bad_check(user, request):
    return user  # Returns AuthenticatedUser, which is truthy!

# This PASSES the check even though it's a bug
```

**Recommendation:**
1. Wrap callback in try/except
2. Validate return type is strictly `bool`
3. Log and convert non-bool returns to `False` with warning

---

### 3.3 Middleware Exclude Patterns Use Simple String Matching

**Location:** `src/ab0t_auth/middleware.py:60-70`

**Issue:** Path exclusion uses `startswith()`:

```python
def _should_exclude_path(self, path: str) -> bool:
    for pattern in self.config.exclude_paths:
        if path.startswith(pattern):
            return True
    return False
```

**Attack Scenario:** If admin configures `exclude_paths=["/health"]`, attacker can access:
- `/health` (intended)
- `/healthcheck` (unintended)
- `/health/../../admin` (path traversal - though frameworks usually normalize)

**Example:**
```python
app.config["AB0T_AUTH_EXCLUDE_PATHS"] = ["/api/public"]

# Attacker accesses:
# /api/public -> excluded (intended)
# /api/public-but-actually-private -> excluded (UNINTENDED!)
```

**Recommendation:**
1. Use exact matching by default
2. Support glob patterns with explicit `*` suffix
3. Document the startswith behavior clearly

---

### 3.4 API Key Sent in Request Body (Potential Logging Exposure)

**Location:** `src/ab0t_auth/client.py:221-225`

**Issue:** API key validation sends the key in JSON body:

```python
response = await client.post(
    f"{config.auth_url}/auth/validate-api-key",
    json={"api_key": api_key},  # API key in body
)
```

**Concern:** Request bodies are often logged by:
- WAF/reverse proxies
- APM tools
- Debug middleware
- Error tracking (Sentry, etc.)

**Impact:** API keys could be exposed in logs.

**Recommendation:** Send API key in header instead:
```python
response = await client.post(
    f"{config.auth_url}/auth/validate-api-key",
    headers={"X-API-Key": api_key},
)
```

---

### 3.5 Permission Pattern Uses fnmatch (Limited Security)

**Location:** `src/ab0t_auth/permissions.py` - uses `fnmatch.fnmatch()`

**Issue:** `fnmatch` supports `*`, `?`, `[seq]`, `[!seq]` patterns. This is more powerful than simple prefix matching.

**Concern:** Users might not realize `[` has special meaning:

```python
# User thinks this checks for literal "users[0]:read"
check_permission_pattern(user, "users[0]:read")

# Actually matches: "users0:read", "userso:read", "users:read" (any char in [0])
```

**Impact:** Could lead to overly permissive permission checks.

**Recommendation:**
1. Document fnmatch behavior explicitly
2. Consider escaping special chars by default
3. Or use simpler `*`-only matching

---

## 4. Low Severity Issues

### 4.1 Default Token Cache TTL is 60 Seconds

**Location:** `src/ab0t_auth/cache.py:118`

**Issue:** Cached tokens remain valid for 60 seconds after revocation.

**Impact:** If a token is revoked (user logout, password change, permission change), it remains usable for up to 60 seconds.

**Recommendation:**
1. Document this tradeoff clearly
2. Consider shorter default (30s)
3. Provide cache invalidation hook for critical operations

---

### 4.2 User ID from Bypass Not Sanitized

**Location:** `src/ab0t_auth/config.py:75`

**Issue:** `AB0T_AUTH_BYPASS_USER_ID` value is used as-is:

```python
user_id=os.getenv("AB0T_AUTH_BYPASS_USER_ID", "bypass_user"),
```

**Test Evidence:** `test_bypass.py:1201-1219` documents that injection strings are stored literally.

**Impact:** If bypass user ID is used in:
- SQL queries (SQL injection)
- Log aggregation (log injection)
- Template rendering (XSS)
- File paths (path traversal)

The downstream code is responsible for sanitization.

**Recommendation:** Document clearly that user_id must be sanitized by consuming code.

---

### 4.3 Empty Permissions Tuple from Bypass

**Location:** `src/ab0t_auth/config.py:52-53`

**Issue:** If `AB0T_AUTH_BYPASS_PERMISSIONS=""`, the result is empty tuple `()`.

**Concern:** Developer might expect bypass user to have "all permissions" but gets none.

**Impact:** Could lead to confusion during development, then different behavior in production.

**Recommendation:** Consider warning if bypass is enabled but permissions are empty.

---

### 4.4 Flask Extension Creates Event Loop Per Request

**Location:** `src/ab0t_auth/flask.py:260-280`

**Issue:** `_authenticate_api_key()` creates a new event loop for each API key validation:

```python
def _authenticate_api_key(self, api_key: str) -> AuthResult:
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(self.guard.authenticate_api_key(api_key))
    finally:
        loop.close()
```

**Impact:** Performance overhead, potential resource leak under high load.

**Recommendation:** Reuse event loop or use sync HTTP client for Flask.

---

### 4.5 Metrics Not Thread-Safe

**Location:** `src/ab0t_auth/guard.py` - `AuthMetrics` class

**Issue:** Metrics are incremented without locking:

```python
self._metrics.auth_attempts += 1  # Not atomic
```

**Impact:** Under high concurrency, counters may be inaccurate. This is cosmetic, not security-critical.

**Recommendation:** Use `threading.Lock` or `atomics` for accurate metrics.

---

## 5. API Confusion Risks

These are design issues where confused developers might create security vulnerabilities.

### 5.1 Multiple Ways to Do the Same Thing

**Issue:** There are 4+ ways to protect a route in FastAPI:

1. `Depends(require_auth(auth))`
2. `Depends(require_permission(auth, "..."))`
3. `@protected(auth)`
4. `@auth_decorator.protected()`
5. Manual check in route

**Risk:** Teams might mix patterns inconsistently, leading to:
- Some routes protected, some not
- Inconsistent error responses
- Difficulty auditing which routes are protected

**Recommendation:** Established in Section 18 of system prompt. Enforce via linting/code review.

---

### 5.2 `@protected` Decorator Requires `auth_user=None` Default

**Location:** `src/ab0t_auth/decorators.py:100-102`

**Issue:** FastAPI decorator pattern requires awkward signature:

```python
@app.get("/route")
@protected(auth)
async def my_route(request: Request, auth_user=None):  # Must have =None!
    ...
```

**Risk:** Developer forgets `=None`, FastAPI interprets `auth_user: AuthenticatedUser` as request body parameter, leading to 422 errors that seem like auth is working but isn't.

**Recommendation:**
1. Document prominently (done)
2. Consider runtime validation that raises clear error
3. Consider different injection mechanism

---

### 5.3 `check_mode="any"` vs `check_mode="all"` Confusion

**Issue:** Multiple checks can use "any" (OR) or "all" (AND) mode.

```python
# This requires EITHER check to pass
Depends(require_auth(auth, checks=[check_a, check_b], check_mode="any"))

# This requires BOTH checks to pass
Depends(require_auth(auth, checks=[check_a, check_b], check_mode="all"))
```

**Risk:** Developer might confuse modes:
- Uses "any" thinking "any user can access"
- Uses "all" thinking "all checks must run" (they do, but must all pass)

**Recommendation:** More explicit naming: `check_mode="require_all"` vs `check_mode="require_one"`

---

### 5.4 Flask `get_current_user()` Can Return None

**Location:** `src/ab0t_auth/flask.py:389-399`

**Issue:** `get_current_user()` returns `None` if not authenticated:

```python
@app.route("/private")
@login_required
def private():
    user = get_current_user()
    return f"Hello {user.email}"  # Could be None if decorator failed!
```

**Risk:** If `@login_required` is accidentally removed, `get_current_user()` returns `None`, causing AttributeError instead of 401.

**Recommendation:** Add `get_current_user_or_raise()` that raises if no user.

---

### 5.5 `permission_required` vs `permissions_required` Naming

**Issue:** Two similar function names:
- `permission_required("users:read")` - single permission
- `permissions_required("users:read", "admin:access")` - multiple

**Risk:** Developer might use wrong one:
```python
# Intended: require BOTH permissions
@permission_required("users:read", "admin:access")  # ERROR: takes 1 permission

# Correct:
@permissions_required("users:read", "admin:access")
```

**Recommendation:** Consider unified API: `@require_permissions("p1", "p2", mode="all")`

---

## 6. Logic Chain Analysis

### 6.1 Authentication Flow

```
Request arrives
    |
    v
Check bypass enabled? ----YES----> Return bypass user (logs WARNING)
    |
    NO
    v
Extract Authorization header
    |
    v
Token present? ----NO----> Check API key header
    |                           |
    YES                         v
    |                      API key present? --NO--> Return NO_CREDENTIALS error
    v                           |
Parse Bearer token              YES
    |                           |
    v                           v
Check token cache          Validate API key with auth service
    |                           |
    HIT                         v
    |                      Return API key user
    v
Return cached user
    |
    MISS
    v
Validate JWT locally (signature, exp, nbf, aud, iss)
    |
    v
Cache result
    |
    v
Return authenticated user
```

**Observations:**
1. Bypass is checked FIRST - this is correct (development convenience)
2. Token takes precedence over API key - documented behavior
3. Cache hit skips re-validation - potential staleness window

---

### 6.2 Authorization Flow (with check callbacks)

```
Route invoked
    |
    v
Authentication (see above)
    |
    v
User authenticated? ----NO----> Raise TokenNotFoundError (401)
    |
    YES
    v
Check static permissions (if require_permission used)
    |
    v
Permission granted? ----NO----> Raise PermissionDeniedError (403)
    |
    YES
    v
Run check callbacks (if provided)
    |
    v
check_mode = "all"?
    |
    YES: All callbacks must return True
    NO: Any callback returning True passes
    |
    v
All checks pass? ----NO----> Raise PermissionDeniedError (403)
    |
    YES
    v
Execute route handler
```

**Potential Issue:** Check callbacks run AFTER permission check. If permission check passes but callback fails, error message says "Authorization check failed" - might confuse debugging.

---

### 6.3 Bypass Decision Logic

```python
bypass_enabled = (
    os.getenv("AB0T_AUTH_BYPASS", "").lower() == "true" and
    os.getenv("AB0T_AUTH_DEBUG", "").lower() == "true"
)
```

**Analysis:**
- Uses `==` for exact match (not truthiness)
- Case-insensitive via `.lower()`
- Requires BOTH flags (defense in depth)
- Empty string from missing var != "true"

**Attack surface covered:**
- Whitespace padding: ` true ` != `true` after `.lower()` but no `.strip()` - PROTECTED
- Unicode tricks: Cyrillic chars != ASCII - PROTECTED
- Type confusion: All env vars are strings - N/A
- Null bytes: OS prevents in env vars - PROTECTED

**Gap identified:** Whitespace IS handled because `.lower()` doesn't strip, and " true" != "true".

---

## 7. Race Conditions & Concurrency

### 7.1 JWKS Cache Race (HIGH - see Section 2.1)

Multiple threads can simultaneously:
1. Read expired/missing JWKS
2. Fetch from remote
3. Write to dict

### 7.2 Token Cache Race (LOW)

`TTLCache` from `cachetools` is NOT thread-safe by default. However:
- Read-heavy workload
- Worst case: extra remote validation call
- `cachetools` operations are typically atomic in CPython due to GIL

### 7.3 Permission Cache Race (LOW)

Same as token cache - `TTLCache` used.

### 7.4 Metrics Counter Race (COSMETIC)

```python
self._metrics.auth_attempts += 1
```

Not atomic, but only affects accuracy of metrics, not security.

---

## 8. Test Coverage Gaps

### 8.1 Missing Tests

| Area | Gap | Risk |
|------|-----|------|
| JWKS Cache | No concurrency tests | HIGH - race condition |
| optional_auth | No test for exception handling | MEDIUM - silent failures |
| Check callbacks | No test for non-boolean return | MEDIUM - truthy confusion |
| Middleware exclude | No test for path traversal | MEDIUM - bypass via path tricks |
| Flask event loop | No load test | LOW - resource exhaustion |

### 8.2 Tests That Document (But Don't Fix) Issues

- `test_bypass.py:1113-1133` - Documents bypass config can be replaced
- `test_bypass.py:1189-1199` - Documents wildcard permissions stored as-is
- `test_bypass.py:1201-1219` - Documents user_id injection strings stored

These tests are good for documentation but represent accepted risks, not verified security.

### 8.3 Recommended Additional Tests

1. **Concurrent JWKS fetch** - Verify thread safety
2. **optional_auth with crashing token** - Verify correct behavior
3. **Check callback returning non-bool** - Verify rejection
4. **Path traversal on exclude patterns** - Verify normalization
5. **Token cache collision** - Verify behavior with colliding hashes
6. **API key in logs** - Verify not logged by default middleware

---

## 9. Recommendations

### Immediate Actions (Before Production)

1. **Add thread lock to JWKSCache** - Prevents race condition
2. **Fix optional_auth exception handling** - Catch specific errors only
3. **Validate check callback return type** - Must be bool
4. **Document path exclude behavior** - Clear that it's startswith

### Short-Term Improvements

1. **Use full SHA256 for token cache keys** - Reduce collision risk
2. **Add get_current_user_or_raise() for Flask** - Safer API
3. **Unify permission decorator naming** - Reduce confusion
4. **Add thread-safe metrics** - Accurate observability

### Long-Term Considerations

1. **Add cache invalidation webhook** - For immediate token revocation
2. **Consider signed cache keys** - HMAC instead of plain hash
3. **Add static analysis rules** - Catch missing auth decorators
4. **Rate limiting on auth endpoints** - Prevent brute force

---

## Appendix: Files Reviewed

| File | Lines | Security-Critical |
|------|-------|-------------------|
| guard.py | ~400 | YES - main auth logic |
| config.py | ~150 | YES - bypass config |
| jwt.py | ~200 | YES - token validation |
| dependencies.py | ~450 | YES - FastAPI auth |
| decorators.py | ~630 | YES - route protection |
| flask.py | ~550 | YES - Flask auth |
| permissions.py | ~300 | YES - authorization |
| middleware.py | ~200 | YES - auto-auth |
| cache.py | ~330 | YES - token caching |
| client.py | ~440 | MEDIUM - HTTP calls |
| core.py | ~400 | LOW - data structures |
| errors.py | ~200 | LOW - error types |
| test_bypass.py | ~1600 | N/A - tests |
| test_permissions.py | ~240 | N/A - tests |

---

## Conclusion

The `ab0t_auth` library demonstrates strong security awareness with defense-in-depth bypass protection, immutable data structures, and comprehensive attack vector testing. However, the following issues should be addressed:

**Must Fix:**
- JWKS cache thread safety
- optional_auth exception swallowing

**Should Fix:**
- Check callback validation
- Path exclude documentation
- API confusion reduction

**Monitor:**
- Token cache collision probability
- Bypass config replaceability (accepted risk)

The library is suitable for production use after addressing the "Must Fix" items.
