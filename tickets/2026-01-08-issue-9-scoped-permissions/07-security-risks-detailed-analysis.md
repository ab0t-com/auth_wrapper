# AB0T-AUTH Security Risks - Detailed Analysis for Planning

**Purpose:** Comprehensive breakdown of each security risk with full context for decision-making and implementation planning.

---

## Risk Summary Matrix

| ID | Risk | Severity | Likelihood | Impact | Fix Effort | Priority |
|----|------|----------|------------|--------|------------|----------|
| R1 | JWKS Cache Race Condition | HIGH | Medium | High | Low | **P0** |
| R2 | Bypass Config Replaceable | HIGH | Low | Critical | Medium | P2 |
| R3 | Token Hash Truncation | HIGH | Very Low | High | Low | P3 |
| R4 | optional_auth Silent Failures | MEDIUM | High | Medium | Low | **P0** |
| R5 | Check Callback No Validation | MEDIUM | Medium | Medium | Low | **P1** |
| R6 | Path Exclude startswith | MEDIUM | Medium | Medium | Low | **P1** |
| R7 | API Key in Request Body | MEDIUM | Medium | Low | Low | P2 |
| R8 | fnmatch Special Characters | MEDIUM | Low | Medium | Medium | P3 |
| R9 | Token Cache 60s TTL | LOW | High | Low | Trivial | P3 |
| R10 | Bypass User ID Unsanitized | LOW | Low | Medium | Doc only | P3 |
| R11 | Empty Bypass Permissions | LOW | Medium | Low | Low | P3 |
| R12 | Flask Event Loop Per Request | LOW | Low | Low | Medium | P4 |
| R13 | Metrics Not Thread-Safe | LOW | High | None | Low | P4 |
| A1 | Multiple Auth Patterns | API | N/A | Medium | Doc only | P2 |
| A2 | Decorator auth_user=None | API | Medium | Low | Medium | P2 |
| A3 | check_mode Naming | API | Low | Low | Medium | P4 |
| A4 | Flask get_current_user None | API | Medium | Medium | Low | **P1** |
| A5 | permission vs permissions | API | Medium | Low | Breaking | P4 |

**Priority Key:** P0 = Before any production use, P1 = Before wide adoption, P2 = Next release, P3 = Eventually, P4 = Nice to have

---

## R1: JWKS Cache Race Condition

### Classification
- **Severity:** HIGH
- **Type:** Concurrency / Thread Safety
- **CVSS-like Score:** 7.5 (High)

### Detailed Description

The `JWKSCache` class uses a plain Python `dict` for storage while `TokenCache` and `PermissionCache` use thread-safe `TTLCache`. This inconsistency creates a race condition vulnerability.

### Affected Code

```python
# src/ab0t_auth/cache.py:241-303

@dataclass
class JWKSCache:
    ttl: int = 300  # 5 minutes default
    _cache: dict[str, JWKSCacheEntry] = field(default_factory=dict)  # <-- PROBLEM

    def get(self, auth_url: str, org_id: str | None = None) -> dict[str, Any] | None:
        key = create_jwks_cache_key(auth_url, org_id)
        entry = self._cache.get(key)  # <-- Read without lock
        # ... expiration check ...
        return entry.keys

    def set(self, auth_url: str, keys: dict[str, Any], ...):
        key = create_jwks_cache_key(auth_url, org_id)
        # ... create entry ...
        self._cache[key] = entry  # <-- Write without lock
```

### Attack Scenario (Detailed)

```
Timeline:
=========

T0: JWKS cache is empty or expired

T1: Request A arrives
    - Thread A calls jwks_cache.get() -> returns None
    - Thread A starts HTTP request to fetch JWKS

T2: Request B arrives (before A completes)
    - Thread B calls jwks_cache.get() -> returns None
    - Thread B starts HTTP request to fetch JWKS

T3: Auth server rotates keys (unlikely but possible)
    - New key K2 replaces old key K1

T4: Thread A receives JWKS with key K1
    - Thread A calls jwks_cache.set(keys_with_K1)

T5: Thread B receives JWKS with key K2
    - Thread B calls jwks_cache.set(keys_with_K2)

T6: Thread A validates token signed with K1
    - Uses K1 from its local variable (fetched at T4)
    - Validation succeeds

T7: Thread C arrives
    - Gets cached K2 (set by Thread B)
    - Token signed with K1 now FAILS validation
    - User gets 401 despite valid token

Worse scenario:
T5': Thread B's set() partially completes
     - dict internal state corrupted
     - Thread A reads corrupted data
     - Unpredictable behavior / crash
```

### Likelihood Assessment

- **In Practice:** Medium
  - Requires concurrent requests during cache miss
  - More likely at application startup or after cache expiry
  - High-traffic applications more vulnerable

- **Key Rotation Scenario:** Low
  - Auth servers don't rotate keys mid-request typically
  - But Murphy's Law applies

- **Dict Corruption Scenario:** Very Low in CPython
  - GIL protects most dict operations
  - But not guaranteed by Python specification
  - Other interpreters (PyPy, etc.) may behave differently

### Impact Assessment

| Outcome | Probability | Impact |
|---------|-------------|--------|
| Duplicate JWKS fetches | High | Performance (minor) |
| Temporary validation failures | Medium | User experience |
| Dict corruption/crash | Very Low | Service outage |
| Wrong key used for validation | Very Low | Security bypass |

### Exploitation Difficulty

- **Skill Required:** Medium (understanding of race conditions)
- **Access Required:** Network access to send concurrent requests
- **Tooling:** Simple scripts or tools like `ab`, `wrk`, `locust`
- **Reproducibility:** Difficult to exploit reliably

### Detection Methods

1. **Monitoring:** Track JWKS fetch frequency - spikes indicate cache misses
2. **Logging:** Log when JWKS is fetched vs served from cache
3. **Testing:** Concurrent load tests during cache expiration
4. **Code Review:** Static analysis for thread-unsafe patterns

### Fix Options

**Option A: Use TTLCache (Recommended)**
```python
from cachetools import TTLCache

@dataclass
class JWKSCache:
    ttl: int = 300
    max_size: int = 100
    _cache: TTLCache[str, JWKSCacheEntry] = field(init=False)

    def __post_init__(self):
        self._cache = TTLCache(maxsize=self.max_size, ttl=self.ttl)
```
- Effort: ~30 minutes
- Risk: Low (same pattern as other caches)
- Breaking: No

**Option B: Add Threading Lock**
```python
from threading import Lock

@dataclass
class JWKSCache:
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def get(self, ...):
        with self._lock:
            # existing logic

    def set(self, ...):
        with self._lock:
            # existing logic
```
- Effort: ~30 minutes
- Risk: Low
- Breaking: No
- Note: Slightly more overhead than TTLCache

**Option C: Use asyncio.Lock for async context**
```python
import asyncio

class JWKSCache:
    def __init__(self):
        self._lock = asyncio.Lock()

    async def get(self, ...):
        async with self._lock:
            # existing logic
```
- Effort: ~1 hour (requires API changes)
- Risk: Medium (async lock not usable from sync code)
- Breaking: Yes (sync callers affected)

### Recommendation

**Go with Option A (TTLCache)** - matches existing pattern, low risk, no breaking changes.

### Dependencies

- None - can be fixed independently

### Test Coverage After Fix

- [x] `test_security_vulnerabilities.py::TestJWKSCacheRaceConditions` - 3 tests already added

---

## R4: optional_auth Silent Failures

### Classification
- **Severity:** MEDIUM
- **Type:** Error Handling / Information Disclosure
- **CVSS-like Score:** 5.5 (Medium)

### Detailed Description

The `optional_auth` dependency catches ALL exceptions and returns `None`, making it impossible to distinguish between:
1. No credentials provided (expected)
2. Invalid credentials (should maybe be 401)
3. Auth service down (should be 503)
4. Code bugs (should be 500)

### Affected Code

```python
# src/ab0t_auth/dependencies.py:193-216

def optional_auth(guard: AuthGuard) -> ...:
    async def dependency(request: Request) -> AuthenticatedUser | None:
        try:
            authorization = request.headers.get("Authorization")
            api_key = request.headers.get(guard.config.api_key_header)

            if not authorization and not api_key:
                return None

            result = await guard.authenticate(authorization, api_key)
            if result.success and result.user:
                return result.user
            return None

        except Exception:  # <-- CATCHES EVERYTHING
            return None

    return dependency
```

### Attack Scenario (Detailed)

**Scenario 1: Data Exposure via Crash**
```python
# Developer's code
@app.get("/content")
async def get_content(user: AuthenticatedUser | None = Depends(optional_auth(auth))):
    if user:
        return {"secret_data": "classified information", "user": user.user_id}
    return {"public_data": "welcome, guest"}

# Attacker sends malformed token that crashes JWT parsing
# curl -H "Authorization: Bearer not.valid.base64!!!" /content

# Expected: 401 Unauthorized
# Actual: 200 OK with {"public_data": "welcome, guest"}

# Attack works because:
# 1. Malformed token causes exception in JWT parsing
# 2. Exception is caught and returns None
# 3. Route treats request as unauthenticated
# 4. Attacker gets public response instead of error
```

**Scenario 2: Service Degradation Masking**
```python
# Auth service goes down
# All requests return None instead of 503
# Application continues serving "public" data
# Operators don't realize auth is broken
# Users can't log in but don't see errors
```

**Scenario 3: Security Bug Masking**
```python
# Bug in authentication code causes exception
# Instead of failing loudly (500), silently returns None
# Security bug goes undetected in production
# Attackers might find ways to trigger this
```

### Likelihood Assessment

- **Malformed Token Crash:** Medium
  - Depends on JWT library robustness
  - PyJWT is generally robust but edge cases exist

- **Auth Service Down:** High (over time)
  - Network issues happen
  - Service restarts happen
  - Should be visible, not hidden

- **Code Bugs:** Low-Medium
  - Depends on code quality
  - New features might introduce bugs

### Impact Assessment

| Outcome | Probability | Impact |
|---------|-------------|--------|
| User sees wrong content tier | Medium | Data exposure |
| Auth outage goes unnoticed | Medium | Extended downtime |
| Security bugs hidden | Low | Potential breach |
| Logging/monitoring gaps | High | Reduced visibility |

### Exploitation Difficulty

- **Skill Required:** Low (just send malformed requests)
- **Access Required:** Network access
- **Tooling:** curl, any HTTP client
- **Reproducibility:** Easy

### Fix Options

**Option A: Catch Specific Exceptions (Recommended)**
```python
def optional_auth(guard: AuthGuard) -> ...:
    async def dependency(request: Request) -> AuthenticatedUser | None:
        authorization = request.headers.get("Authorization")
        api_key = request.headers.get(guard.config.api_key_header)

        if not authorization and not api_key:
            return None

        try:
            result = await guard.authenticate(authorization, api_key)
            if result.success and result.user:
                return result.user
            return None
        except (TokenInvalidError, TokenExpiredError, TokenNotFoundError):
            # Expected auth failures - treat as unauthenticated
            return None
        # Let other exceptions propagate (500)

    return dependency
```
- Effort: ~30 minutes
- Risk: Low
- Breaking: Potentially (routes might now get 500 instead of treating as anonymous)

**Option B: Add Error Classification**
```python
def optional_auth(
    guard: AuthGuard,
    *,
    on_error: Literal["none", "raise", "log_and_none"] = "none",
) -> ...:
    async def dependency(request: Request) -> AuthenticatedUser | None:
        try:
            # ... auth logic ...
        except AuthError:
            return None  # Expected auth errors
        except Exception as e:
            if on_error == "raise":
                raise
            elif on_error == "log_and_none":
                logger.warning("Unexpected error in optional_auth", exc_info=True)
                return None
            else:
                return None
```
- Effort: ~1 hour
- Risk: Low
- Breaking: No (default behavior preserved)

**Option C: Separate Functions**
```python
def optional_auth_strict(guard):
    """Returns None only for missing credentials, raises for errors."""
    ...

def optional_auth_lenient(guard):
    """Returns None for any auth failure (current behavior)."""
    ...
```
- Effort: ~1 hour
- Risk: Low
- Breaking: No

### Recommendation

**Go with Option A** - it's the most correct behavior. Document that routes using `optional_auth` may now return 500 for unexpected errors, which is actually better for debugging.

### Dependencies

- None - can be fixed independently

### Test Coverage After Fix

- [x] `test_security_vulnerabilities.py::TestOptionalAuthSilentFailures` - 4 tests added
- [ ] Need to update tests to verify new behavior after fix

---

## R5: Check Callback No Validation

### Classification
- **Severity:** MEDIUM
- **Type:** Input Validation / Type Safety
- **CVSS-like Score:** 5.0 (Medium)

### Detailed Description

User-provided check callbacks are executed without:
1. Validating the return type is `bool`
2. Catching exceptions from the callback
3. Timeout protection

Python's truthiness rules mean many non-bool values will pass:
- Non-empty strings: `"yes"`, `"no"`, `"false"` all truthy
- Non-zero numbers: `1`, `-1`, `0.1` all truthy
- Objects: `user`, `request`, any object truthy
- Collections: `[False]`, `{"allowed": False}` truthy

### Affected Code

```python
# src/ab0t_auth/dependencies.py:75-102

async def _run_auth_checks(
    user: AuthenticatedUser,
    request: Request,
    check: AuthCheckCallable | None,
    checks: Sequence[AuthCheckCallable] | None,
    check_mode: Literal["all", "any"],
    check_error: str,
) -> None:
    # ... collect checks ...

    for check_fn in all_checks:
        if asyncio.iscoroutinefunction(check_fn):
            result = await check_fn(user, request)  # <-- No try/except
        else:
            result = check_fn(user, request)

        # Short-circuit for "any" mode on success
        if check_mode == "any" and result:  # <-- Truthiness, not bool check
            return

        # Short-circuit for "all" mode on failure
        if check_mode == "all" and not result:  # <-- Falsiness, not bool check
            raise PermissionDeniedError(check_error)
```

### Attack Scenario (Detailed)

**Scenario 1: Accidental Authorization Bypass**
```python
# Developer makes a mistake in check callback
def can_access_resource(user: AuthenticatedUser, request: Request):
    resource = get_resource(request.path_params["id"])
    # BUG: forgot to return bool, returns resource instead
    if resource.owner_id == user.user_id:
        return resource  # Returns Resource object, not True!
    # Falls through, returns None implicitly

# When owner_id matches:
#   Returns Resource object -> truthy -> PASSES
# When owner_id doesn't match:
#   Returns None -> falsy -> correctly fails

# But what if resource is an empty object?
#   Returns Resource() with no attributes -> still truthy -> PASSES

# What if checking wrong condition?
def bad_check(user, request):
    return user  # Always returns truthy user object!
    # This check ALWAYS passes
```

**Scenario 2: Exception Causes 500 Instead of 403**
```python
def check_ownership(user: AuthenticatedUser, request: Request) -> bool:
    # Database query might fail
    resource = db.get_resource(request.path_params["id"])  # Raises on connection error
    return resource.owner_id == user.user_id

# If DB is down:
#   Exception propagates as 500 Internal Server Error
#   Stack trace might leak in response
#   Should probably be 403 or 503

# If resource doesn't exist:
#   AttributeError on None.owner_id
#   500 error instead of 404 or 403
```

**Scenario 3: Slow Callback Causes Timeout**
```python
async def slow_check(user: AuthenticatedUser, request: Request) -> bool:
    # Makes external API call
    result = await external_api.check_permission(user.user_id)  # Takes 30 seconds
    return result

# No timeout protection
# Request hangs for 30 seconds
# Connection pool exhaustion possible
```

### Likelihood Assessment

- **Returning Wrong Type:** High
  - Easy mistake to make
  - Python doesn't enforce return types
  - No IDE warning without strict type checking

- **Exception in Callback:** Medium
  - Database calls, API calls common
  - Network issues happen

- **Slow Callback:** Medium
  - External dependencies can be slow
  - No timeout by default

### Impact Assessment

| Outcome | Probability | Impact |
|---------|-------------|--------|
| Accidental auth bypass | Medium | Unauthorized access |
| 500 errors for auth failures | Medium | Bad UX, info leak |
| Slow requests | Medium | Performance, DoS |
| Debugging confusion | High | Developer time |

### Fix Options

**Option A: Strict Bool Validation (Recommended)**
```python
async def _run_auth_checks(...) -> None:
    for check_fn in all_checks:
        try:
            if asyncio.iscoroutinefunction(check_fn):
                result = await check_fn(user, request)
            else:
                result = check_fn(user, request)
        except Exception as e:
            # Log the error for debugging
            logger.warning(
                "Check callback raised exception",
                callback=check_fn.__name__,
                error=str(e),
            )
            # Treat exception as check failure (safe default)
            result = False

        # Strict bool check
        if not isinstance(result, bool):
            logger.warning(
                "Check callback returned non-bool",
                callback=check_fn.__name__,
                result_type=type(result).__name__,
            )
            # Treat non-bool as failure (safe default)
            result = False

        # ... rest of logic ...
```
- Effort: ~1 hour
- Risk: Low (fails closed)
- Breaking: Potentially (callbacks returning non-bool will now fail)

**Option B: Add Timeout Protection**
```python
async def _run_auth_checks(..., timeout: float = 5.0) -> None:
    for check_fn in all_checks:
        try:
            if asyncio.iscoroutinefunction(check_fn):
                result = await asyncio.wait_for(
                    check_fn(user, request),
                    timeout=timeout,
                )
            else:
                # Sync functions can't easily be timed out
                result = check_fn(user, request)
        except asyncio.TimeoutError:
            logger.warning("Check callback timed out", callback=check_fn.__name__)
            result = False
```
- Effort: ~1 hour
- Risk: Medium (might break slow but valid checks)
- Breaking: Potentially

**Option C: Type Hints + Runtime Validation**
```python
from typing import TypeGuard

def _validate_check_result(result: Any, callback_name: str) -> TypeGuard[bool]:
    if isinstance(result, bool):
        return True
    logger.warning(f"Check callback {callback_name} returned {type(result)}, expected bool")
    return False
```
- Effort: ~30 minutes
- Risk: Low
- Breaking: No (just adds warnings)

### Recommendation

**Go with Option A + Option C combination:**
1. Add strict bool validation with warnings
2. Catch exceptions and treat as failure
3. Don't add timeout yet (breaking change, can add later)

### Dependencies

- None - can be fixed independently

### Test Coverage After Fix

- [x] `test_security_vulnerabilities.py::TestCheckCallbackValidation` - 9 tests added
- [ ] Tests will need updating to expect new behavior (warnings, failures)

---

## R6: Path Exclude startswith Behavior

### Classification
- **Severity:** MEDIUM
- **Type:** Input Validation / Authorization Bypass
- **CVSS-like Score:** 5.5 (Medium)

### Detailed Description

The middleware's path exclusion uses `startswith()` matching, which can lead to unintended paths being excluded from authentication.

### Affected Code

```python
# src/ab0t_auth/middleware.py:60-70

def _should_exclude_path(self, path: str) -> bool:
    """Check if path should be excluded from authentication."""
    for pattern in self.config.exclude_paths:
        if path.startswith(pattern):  # <-- Simple prefix match
            return True
    return False
```

### Attack Scenario (Detailed)

**Scenario 1: Suffix Extension Attack**
```python
# Configuration
app.config["AB0T_AUTH_EXCLUDE_PATHS"] = ["/health", "/api/public"]

# Developer's mental model:
#   /health -> excluded
#   /api/public -> excluded
#   /api/private -> protected

# Actual behavior:
#   /health -> excluded (intended)
#   /healthcheck -> excluded (UNINTENDED!)
#   /health/admin/delete-everything -> excluded (UNINTENDED!)
#   /api/public -> excluded (intended)
#   /api/public-secret-data -> excluded (UNINTENDED!)
#   /api/public/admin -> excluded (UNINTENDED!)

# Attacker discovers:
# 1. Find excluded path prefix
# 2. Append anything to it
# 3. Access protected resources without auth
```

**Scenario 2: Route Naming Collision**
```python
# API routes defined:
@app.get("/api/public")  # Public endpoint
@app.get("/api/public-internal-use-only")  # Should be protected!
@app.post("/api/publish")  # Should be protected!

# Exclude config:
exclude_paths = ["/api/public"]

# Result:
# /api/public -> excluded (intended)
# /api/public-internal-use-only -> excluded (UNINTENDED!)
# /api/publish -> protected (correct, "publish" != "public")
```

**Scenario 3: Root Path Disaster**
```python
# Someone adds root path to exclusions
exclude_paths = ["/"]

# EVERY path is now excluded!
# /admin -> excluded
# /api/private -> excluded
# /users/delete -> excluded
# Complete auth bypass
```

### Likelihood Assessment

- **Suffix Attack:** Medium
  - Requires attacker to know excluded paths
  - Common paths like `/health` are guessable
  - API documentation might reveal paths

- **Naming Collision:** Medium
  - Depends on route naming conventions
  - More likely in large codebases

- **Root Path Mistake:** Low
  - Obvious mistake, likely caught in review
  - But devastating if it happens

### Impact Assessment

| Outcome | Probability | Impact |
|---------|-------------|--------|
| Access to unintended paths | Medium | Unauthorized access |
| Complete auth bypass (root) | Low | Full compromise |
| Confusion in security audits | High | False sense of security |

### Fix Options

**Option A: Exact Matching by Default (Breaking)**
```python
def _should_exclude_path(self, path: str) -> bool:
    for pattern in self.config.exclude_paths:
        if path == pattern:  # Exact match
            return True
    return False
```
- Effort: ~15 minutes
- Risk: High (breaking change)
- Breaking: Yes - existing `/health` won't match `/health/`

**Option B: Explicit Prefix Patterns**
```python
def _should_exclude_path(self, path: str) -> bool:
    for pattern in self.config.exclude_paths:
        if pattern.endswith("*"):
            # Explicit prefix: "/api/public*"
            if path.startswith(pattern[:-1]):
                return True
        else:
            # Exact match only
            if path == pattern:
                return True
    return False

# Usage:
exclude_paths = [
    "/health",       # Exact: only /health
    "/api/public/*", # Prefix: /api/public/anything
]
```
- Effort: ~30 minutes
- Risk: Low
- Breaking: Partial (existing behavior changes but opt-in to prefix)

**Option C: Full Glob Pattern Support**
```python
import fnmatch

def _should_exclude_path(self, path: str) -> bool:
    for pattern in self.config.exclude_paths:
        if fnmatch.fnmatch(path, pattern):
            return True
    return False

# Usage:
exclude_paths = [
    "/health",           # Exact
    "/api/public",       # Exact
    "/api/public/*",     # One level below
    "/static/**",        # Recursive
]
```
- Effort: ~30 minutes
- Risk: Medium (fnmatch has its own quirks - see R8)
- Breaking: Partial

**Option D: Document Current Behavior Clearly**
```python
# In docstring and README:
"""
WARNING: exclude_paths uses prefix matching (startswith).
- "/health" matches: /health, /healthcheck, /health/anything
- Use trailing slash for directories: "/api/public/"
- Be specific to avoid unintended exclusions
"""
```
- Effort: ~15 minutes
- Risk: None
- Breaking: No

### Recommendation

**Go with Option B + Option D:**
1. Add explicit `*` suffix support for prefix matching
2. Change default to exact matching
3. Document clearly with examples
4. Add deprecation warning for implicit prefix matching

### Dependencies

- None - can be fixed independently

### Test Coverage After Fix

- [x] `test_security_vulnerabilities.py::TestPathExclusionBypass` - 5 tests added
- [ ] Tests document current behavior, need new tests for fixed behavior

---

## A4: Flask get_current_user() Returns None

### Classification
- **Severity:** API CONFUSION (Medium impact)
- **Type:** Developer Experience / Error Handling

### Detailed Description

`get_current_user()` returns `None` if no user is authenticated, which can cause crashes if the developer forgets to check.

### Affected Code

```python
# src/ab0t_auth/flask.py:389-399

def get_current_user() -> AuthenticatedUser | None:
    """Get current authenticated user from request context."""
    return getattr(g, "_ab0t_auth_user", None)
```

### Attack Scenario (Developer Mistake)

```python
# Developer writes:
@app.route("/profile")
@login_required
def profile():
    user = get_current_user()
    return f"Hello, {user.email}!"  # Safe - @login_required ensures user exists

# Later, during refactoring, decorator is accidentally removed:
@app.route("/profile")
def profile():
    user = get_current_user()
    return f"Hello, {user.email}!"  # CRASH: AttributeError: 'NoneType' has no attribute 'email'

# Or worse, partial check:
@app.route("/profile")
def profile():
    user = get_current_user()
    if user.is_admin:  # CRASH before the check even matters
        return "Admin view"
    return "User view"
```

### Impact Assessment

- **Frequency:** Medium (common pattern)
- **Detection:** Usually caught in testing
- **Production Impact:** 500 errors, poor UX
- **Security Impact:** Low (crashes are fail-closed)

### Fix Options

**Option A: Add get_current_user_or_raise() (Recommended)**
```python
def get_current_user() -> AuthenticatedUser | None:
    """Get current user or None if not authenticated."""
    return getattr(g, "_ab0t_auth_user", None)

def get_current_user_or_raise() -> AuthenticatedUser:
    """Get current user or raise 401 if not authenticated."""
    user = get_current_user()
    if user is None:
        raise TokenNotFoundError("Authentication required")
    return user
```
- Effort: ~15 minutes
- Risk: None
- Breaking: No

**Option B: Make get_current_user() Raise**
```python
def get_current_user() -> AuthenticatedUser:
    """Get current user or raise if not authenticated."""
    user = getattr(g, "_ab0t_auth_user", None)
    if user is None:
        raise TokenNotFoundError("Authentication required")
    return user
```
- Effort: ~15 minutes
- Risk: High
- Breaking: Yes - existing code checking `if user:` will break

### Recommendation

**Go with Option A** - add the safe variant without breaking existing code.

---

## Complete Risk Register

### Must Fix Before Production (P0)

| ID | Risk | Effort | Owner |
|----|------|--------|-------|
| R1 | JWKS Cache Race Condition | 30 min | - |
| R4 | optional_auth Silent Failures | 30 min | - |

### Should Fix Before Wide Adoption (P1)

| ID | Risk | Effort | Owner |
|----|------|--------|-------|
| R5 | Check Callback No Validation | 1 hour | - |
| R6 | Path Exclude startswith | 30 min | - |
| A4 | Flask get_current_user None | 15 min | - |

### Next Release (P2)

| ID | Risk | Effort | Owner |
|----|------|--------|-------|
| R2 | Bypass Config Replaceable | 1 hour | - |
| R7 | API Key in Request Body | 30 min | - |
| A1 | Multiple Auth Patterns | Doc only | - |
| A2 | Decorator auth_user=None | 2 hours | - |

### Eventually (P3)

| ID | Risk | Effort | Owner |
|----|------|--------|-------|
| R3 | Token Hash Truncation | 30 min | - |
| R8 | fnmatch Special Characters | 2 hours | - |
| R9 | Token Cache 60s TTL | Doc only | - |
| R10 | Bypass User ID Unsanitized | Doc only | - |
| R11 | Empty Bypass Permissions | 30 min | - |

### Nice to Have (P4)

| ID | Risk | Effort | Owner |
|----|------|--------|-------|
| R12 | Flask Event Loop Per Request | 4 hours | - |
| R13 | Metrics Not Thread-Safe | 1 hour | - |
| A3 | check_mode Naming | 2 hours | - |
| A5 | permission vs permissions | Breaking | - |

---

## Implementation Order Recommendation

```
Phase 1: Critical Fixes (P0) - Before any production use
├── R1: Add TTLCache to JWKSCache
└── R4: Fix optional_auth exception handling

Phase 2: Important Fixes (P1) - Before recommending to others
├── R5: Add check callback validation
├── R6: Fix path exclude patterns
└── A4: Add get_current_user_or_raise()

Phase 3: Quality Improvements (P2) - Next release
├── R7: Move API key to header
├── A2: Improve decorator auth_user handling
└── Documentation updates for A1

Phase 4: Hardening (P3+) - Ongoing
├── R3: Use full SHA256 hash
├── R8: Document fnmatch behavior
└── Other improvements
```

---

## Appendix: Test Matrix

| Risk | Test File | Tests | Status |
|------|-----------|-------|--------|
| R1 | test_security_vulnerabilities.py | 3 | Passing (documents issue) |
| R4 | test_security_vulnerabilities.py | 4 | Passing (documents issue) |
| R5 | test_security_vulnerabilities.py | 9 | Passing (documents issue) |
| R6 | test_security_vulnerabilities.py | 5 | Passing (documents issue) |
| R7 | - | 0 | Not tested |
| R8 | test_security_vulnerabilities.py | 2 | Passing (documents behavior) |
| R9 | - | 0 | Not tested |
| R10 | test_bypass.py | 1 | Passing (documents behavior) |
| R11 | - | 0 | Not tested |
| R12 | - | 0 | Not tested |
| R13 | - | 0 | Not tested |
| A1 | - | 0 | N/A (documentation) |
| A2 | test_check_callback.py | 1 | Passing |
| A3 | test_security_vulnerabilities.py | 1 | Passing |
| A4 | test_security_vulnerabilities.py | 1 | Passing |
| A5 | test_security_vulnerabilities.py | 1 | Passing |
