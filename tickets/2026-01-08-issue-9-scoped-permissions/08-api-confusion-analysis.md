# API Confusion Analysis & Improvement Ideas

**Date:** 2026-01-08
**Status:** Planning
**Priority:** P2

---

## Executive Summary

The `ab0t_auth` library has strong security fundamentals but suffers from API confusion that could lead developers to make mistakes. This document analyzes the confusing patterns and proposes improvements.

---

## Current API Confusion Issues

### A1: Multiple Ways to Protect a Route (FastAPI)

There are 4+ ways to protect a route, which creates inconsistency:

```python
# Way 1: Dependency with Depends()
user: AuthenticatedUser = Depends(require_auth(auth))

# Way 2: Annotated type alias (recommended)
user: CurrentUser  # where CurrentUser = Annotated[..., Depends(...)]

# Way 3: @protected decorator
@protected(auth)
async def route(request: Request, auth_user=None):  # quirky!

# Way 4: Manual check in route
user = await auth.authenticate_or_raise(...)
```

**Risk:** Teams mix patterns inconsistently, making it hard to audit which routes are protected.

---

### A2: Decorator `auth_user=None` Quirk

The `@protected` decorator requires an awkward function signature:

```python
# WRONG - FastAPI thinks auth_user is request body
@protected(auth)
async def route(request: Request, auth_user: AuthenticatedUser):
    ...  # 422 Unprocessable Entity!

# RIGHT - but confusing
@protected(auth)
async def route(request: Request, auth_user=None):
    ...  # Works, auth_user is injected at runtime
```

**Risk:** Developer forgets `=None`, gets 422 errors, thinks auth is broken.

---

### A3: `check_mode` Naming Confusion

The check mode parameter has ambiguous naming:

```python
# What does "any" mean? Any user? Any check passes?
check_mode="any"   # Actually: ANY check passing = success (OR logic)
check_mode="all"   # Actually: ALL checks must pass (AND logic)
```

**Risk:** Developer uses "any" thinking "any user can access" instead of "any check can pass".

---

### A4: Flask `get_current_user()` Can Return None

**STATUS: FIXED** - Added `get_current_user_or_raise()` in P1 fixes.

```python
# Old problem:
@login_required
def route():
    user = get_current_user()
    return user.email  # Could be None if decorator removed!

# New solution:
@login_required
def route():
    user = get_current_user_or_raise()  # Raises if no user
    return user.email
```

---

### A5: `permission_required` vs `permissions_required` Naming

Two similar function names with subtle differences:

```python
# Easy to use wrong one
@permission_required("admin:read", "admin:write")  # ERROR - only takes 1 arg!
@permissions_required("admin:read", "admin:write")  # Correct - takes multiple

# The 's' makes a big difference
permission_required   # Single permission
permissions_required  # Multiple permissions
```

**Risk:** Developer uses singular form with multiple args, gets unexpected behavior.

---

## Improvement Ideas

### Idea 1: Deprecate Decorators, Standardize on Dependencies

**Rationale:** The dependency pattern is FastAPI-native and doesn't have the `auth_user=None` quirk.

```python
# BEFORE: Multiple patterns exist
@protected(auth)                          # Decorator (quirky)
Depends(require_auth(auth))               # Dependency (clean)

# AFTER: One standard pattern
CurrentUser = Annotated[AuthenticatedUser, Depends(require_auth(auth))]

@app.get("/me")
async def get_me(user: CurrentUser):      # Clean, type-safe
    return {"user_id": user.user_id}
```

**Implementation:**
```python
import warnings

def protected(guard, ...):
    """
    .. deprecated:: 2.0
        Use `Depends(require_auth(guard))` instead.
    """
    warnings.warn(
        "protected() decorator is deprecated. Use Depends(require_auth(guard)) instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    # ... existing implementation
```

**Pros:**
- Simpler API surface
- No `auth_user=None` quirk
- Better IDE support
- Consistent with FastAPI patterns

**Cons:**
- Breaking change for existing users
- Decorators are familiar to Flask users

---

### Idea 2: Rename `check_mode` to Be Clearer

**Option A: More explicit strings**
```python
# Current (confusing)
check_mode="all"
check_mode="any"

# Proposed (clear)
check_mode="require_all"   # All checks must pass
check_mode="require_any"   # Any check passing is enough
```

**Option B: Boolean parameter**
```python
# Current
check_mode="all"

# Proposed
all_checks_required=True   # All must pass (default)
all_checks_required=False  # Any can pass
```

**Option C: Enum with documentation**
```python
from enum import Enum

class CheckMode(Enum):
    """How multiple checks are evaluated."""
    ALL_MUST_PASS = "all"   # Every check must return True
    ANY_CAN_PASS = "any"    # At least one check must return True

# Usage
require_auth(auth, checks=[...], check_mode=CheckMode.ALL_MUST_PASS)
```

**Recommendation:** Option A (explicit strings) - minimal change, clear meaning.

---

### Idea 3: Unify Permission Functions

**Current (confusing):**
```python
# Two functions with subtle name difference
@permission_required("admin:access")              # Single permission
@permissions_required("p1", "p2", require_all=True)  # Multiple permissions
```

**Proposed Option A: One function handles both**
```python
# Single function, varargs
@require_permission("admin:access")                    # Single
@require_permission("p1", "p2")                        # Multiple, all required (default)
@require_permission("p1", "p2", mode="any")            # Multiple, any sufficient
```

**Proposed Option B: Explicit naming**
```python
@require_permission("admin:access")          # Single permission
@require_all_permissions("p1", "p2")         # All required
@require_any_permission("p1", "p2")          # Any sufficient
```

**Proposed Option C: Keep current but add aliases**
```python
# Keep existing for backwards compatibility
permission_required = require_permission           # Alias
permissions_required = require_all_permissions    # Alias

# Add new explicit names
require_permission(...)
require_all_permissions(...)
require_any_permission(...)
```

**Recommendation:** Option C - backwards compatible, adds clarity.

---

### Idea 4: Fix Decorator Injection (if keeping decorators)

**Option A: Use request.state instead of kwarg injection**
```python
# Current (quirky)
@protected(auth)
async def route(request: Request, auth_user=None):
    return auth_user.user_id

# Proposed (clean)
@protected(auth)
async def route(request: Request):
    user = request.state.auth_user  # Always available after @protected
    return user.user_id
```

**Option B: Runtime validation with clear error**
```python
@protected(auth)
async def route(request: Request, auth_user: AuthenticatedUser):  # No default
    ...

# Decorator inspects signature, raises immediately:
# ConfigurationError: "auth_user parameter must have default value (auth_user=None)
# for FastAPI compatibility. Example: async def route(request: Request, auth_user=None)"
```

**Option C: Auto-inject via dependency override**
```python
# Decorator registers a dependency override
@protected(auth)
async def route(request: Request, auth_user: AuthenticatedUser = Depends()):
    ...  # Depends() is replaced at startup with actual auth
```

**Recommendation:** Option A if keeping decorators - cleanest solution.

---

### Idea 5: Consistent Naming Convention

**Proposed naming scheme:**

| Current | Proposed | Notes |
|---------|----------|-------|
| `require_auth` | `require_auth` | Keep as-is |
| `require_permission` | `require_permission` | Accept varargs |
| `require_any_permission` | Add new | Explicit OR logic |
| `require_all_permissions` | Add new | Explicit AND logic |
| `permissions_required` | Deprecate | Use `require_all_permissions` |
| `permission_required` | Keep | Alias to `require_permission` |
| `check_mode="all"` | `check_mode="require_all"` | Clearer meaning |
| `check_mode="any"` | `check_mode="require_any"` | Clearer meaning |
| `protected` | Deprecate | Use dependencies |

---

## Implementation Priority

### Phase 1: Non-Breaking Improvements
1. Add `check_mode="require_all"` / `"require_any"` as aliases (keep old values working)
2. Add `require_all_permissions()` / `require_any_permission()` functions
3. Add runtime validation for decorator `auth_user` parameter
4. Improve error messages

### Phase 2: Deprecation Warnings
1. Warn on `check_mode="all"` / `"any"` (suggest new names)
2. Warn on `permissions_required` (suggest `require_all_permissions`)
3. Warn on `@protected` decorator (suggest dependencies)

### Phase 3: Documentation
1. Update all examples to use recommended patterns
2. Add migration guide
3. Add linting rules (optional)

### Phase 4: Breaking Changes (Major Version)
1. Remove deprecated aliases
2. Remove decorator if adoption is low

---

## Questions to Resolve

1. **Should decorators be deprecated or improved?**
   - Deprecate: Simpler API, one way to do things
   - Improve: Familiar to Flask users, some prefer decorator style

2. **Should `check_mode` use strings or enum?**
   - Strings: Simpler, JSON-serializable
   - Enum: Type-safe, IDE autocomplete

3. **Backwards compatibility priority?**
   - High: Keep all old APIs, add deprecation warnings
   - Medium: Add aliases, deprecate over 2 versions
   - Low: Breaking changes in next major version

---

## Related Files

- `src/ab0t_auth/dependencies.py` - FastAPI dependencies
- `src/ab0t_auth/decorators.py` - Route decorators
- `src/ab0t_auth/flask.py` - Flask integration
- `src/ab0t_auth/permissions.py` - Permission checking

---

## References

- Section 18 of system prompt: AB0T Recommended Approach
- Deep Security Review: Section 5 (API Confusion Risks)
- PR #10: P0/P1 Security Fixes
