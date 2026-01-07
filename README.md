# Ab0t Auth

### Stop Building Auth. Start Building Features.

**The fastest way to add enterprise-grade authentication to your FastAPI apps.**

```bash
pip install git+https://github.com/ab0t-com/auth_wrapper.git
```

[![PyPI](https://img.shields.io/pypi/v/ab0t-auth)](https://pypi.org/project/ab0t-auth/)
[![Python](https://img.shields.io/pypi/pyversions/ab0t-auth)](https://pypi.org/project/ab0t-auth/)
[![License](https://img.shields.io/github/license/ab0t-com/auth_wrapper)](LICENSE)
[![Tests](https://img.shields.io/github/actions/workflow/status/ab0t-com/auth_wrapper/tests.yml)](https://github.com/ab0t-com/auth_wrapper/actions)

---

## Why Ab0t Auth?

**Authentication is table stakes. But it's eating your roadmap.**

Every FastAPI project needs auth. Every team reinvents it. Every implementation has gaps. You're not shipping features—you're debugging JWT expiration edge cases at 2 AM.

**We fixed that.**

Ab0t Auth drops enterprise authentication into your FastAPI app in **under 5 minutes**. One import. One line of config. Done.

```python
from ab0t_auth import AuthGuard, require_auth

auth = AuthGuard(auth_url="https://auth.service.ab0t.com")

@app.get("/api/data")
async def get_data(user = Depends(require_auth(auth))):
    return {"user": user.user_id}  # That's it. You're protected.
```

---

## The Problem We Solve

| Without Ab0t Auth | With Ab0t Auth |
|-------------------|----------------|
| 2-4 weeks building auth | 5 minutes to production |
| Custom JWT validation code | Battle-tested, RFC-compliant |
| Permission spaghetti | Clean, declarative permissions |
| Security vulnerabilities | Audited, secure by default |
| No caching = slow APIs | Built-in high-performance caching |
| Scattered auth logic | One unified interface |

**Real talk:** Your competitors aren't waiting while you build auth from scratch.

---

## Installation

### From GitHub (Latest)

```bash
pip install git+https://github.com/ab0t-com/auth_wrapper.git
```

### From PyPI (Stable)

```bash
pip install ab0t-auth
```

### With All Dependencies

```bash
pip install "ab0t-auth[dev]"  # Includes testing tools
```

### Verify Installation

```bash
python -c "from ab0t_auth import AuthGuard; print('Ready to ship!')"
```

---

## Quick Start (5 Minutes to Protected API)

### Step 1: Initialize

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from ab0t_auth import AuthGuard, require_auth, AuthenticatedUser

# Your Ab0t auth service URL
auth = AuthGuard(auth_url="https://auth.service.ab0t.com")

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with auth.lifespan():
        yield

app = FastAPI(lifespan=lifespan)
```

### Step 2: Protect Routes

```python
@app.get("/public")
async def public():
    return {"message": "Anyone can see this"}

@app.get("/protected")
async def protected(user: AuthenticatedUser = Depends(require_auth(auth))):
    return {"message": f"Hello {user.email}!"}
```

### Step 3: Ship It 🚀

```bash
uvicorn main:app --reload
```

**That's it.** Your API now has enterprise authentication.

---

## Features That Make Teams Switch

### Three Integration Styles (Pick Your Favorite)

**Dependencies** (Most Popular)
```python
@app.get("/users")
async def list_users(user = Depends(require_permission(auth, "users:read"))):
    ...
```

**Decorators** (Flask-style)
```python
@app.get("/admin")
@permission_required(auth, "admin:access")
async def admin_panel(request: Request, auth_user: AuthenticatedUser):
    ...
```

**Middleware** (Set & Forget)
```python
app.add_middleware(AuthMiddleware, guard=auth, exclude_paths=["/health"])
```

### Permission System That Actually Works

```python
# Single permission
require_permission(auth, "billing:read")

# Any of these
require_any_permission(auth, "admin:*", "billing:manage")

# All required
require_all_permissions(auth, "users:read", "users:write")

# Pattern matching (glob-style!)
require_permission_pattern(auth, "org:*:admin")
```

### Multi-Tenancy Built In

Ab0t is multi-tenant by design. Each user belongs to a tenant (company), with support for nested organizations.

```python
from ab0t_auth.tenant import TenantConfig, require_tenant, require_org

tenant_config = TenantConfig(
    enforce_tenant_isolation=True,
    enable_org_hierarchy=True,
    allow_cross_tenant_admin=True,
)

# Tenant-scoped routes
@app.get("/tenants/{tenant_id}/data")
async def tenant_data(
    tenant_id: str,
    ctx = Depends(require_tenant(auth, config=tenant_config))
):
    return {"tenant": ctx.tenant_id, "org": ctx.org_id}

# Organization hierarchy support
@app.get("/orgs/{org_id}/members")
async def org_members(
    org_id: str,
    ctx = Depends(require_org(auth, config=tenant_config))
):
    # Automatically validates org access based on hierarchy
    return {"org": ctx.org_id, "path": ctx.org_path}
```

**Features:**
- **Tenant Isolation** - Users can only access their tenant's data
- **Nested Organizations** - Parent/child org hierarchy with inheritance
- **Cross-Tenant Admin** - Admins with special permissions can access any tenant
- **Flexible Extraction** - Get tenant from token, header, path, or subdomain

```
Tenant (Company)
└── Organization (root)
    ├── Engineering
    │   ├── Backend Team
    │   └── Frontend Team
    └── Sales
        └── Enterprise
```

### Blazing Fast (1000+ req/sec)

- **Local JWT validation** - No auth service round-trip
- **Intelligent caching** - Tokens, permissions, JWKS
- **Async everything** - Non-blocking I/O throughout
- **Connection pooling** - HTTP/2 with keepalive

### Security You Can Trust

- RFC 7517/7519 compliant JWT validation
- JWKS key rotation handled automatically
- Token expiration with configurable leeway
- API key support for service-to-service
- No secrets in your codebase

---

## FAQ

### "Why not just use FastAPI's built-in security?"

FastAPI's security utilities are primitives—they give you building blocks. Ab0t Auth gives you the whole house. You get JWT validation, JWKS fetching, permission checking, caching, and error handling out of the box.

### "Does this work with my existing Ab0t setup?"

**Yes!** If you're using Ab0t's auth service, this is the official client library. It speaks the same language as your backend.

### "What about API keys for my service accounts?"

Built in. Just set the `X-API-Key` header. We validate it against Ab0t and give you the same `AuthenticatedUser` object.

```python
# Works with both JWT and API keys automatically
@app.get("/webhook")
async def webhook(user = Depends(require_auth(auth))):
    # user.auth_method tells you which was used
    ...
```

### "How do I handle different environments?"

Environment variables. Zero code changes.

```bash
# Development
AB0T_AUTH_AUTH_URL=https://auth.dev.ab0t.com

# Production
AB0T_AUTH_AUTH_URL=https://auth.service.ab0t.com
AB0T_AUTH_DEBUG=false
```

### "What if the auth service goes down?"

Local JWT validation means you keep running. We cache JWKS keys, so even if Ab0t is briefly unavailable, your existing tokens still validate.

### "Can I check permissions without blocking?"

Yes! Client-side checks use token claims (instant). Server-side checks call Ab0t (authoritative).

```python
# Instant (from token)
if user.has_permission("admin:access"):
    ...

# Authoritative (API call)
result = await verify_permission(client, config, token, user, "sensitive:action")
```

### "Is this production-ready?"

Teams are running this in production right now. We have comprehensive tests, type safety throughout, and structured logging for observability.

---

## Development & Testing

### Auth Bypass (Testing Only)

For local development and testing, you can bypass authentication entirely. This feature uses a **defense-in-depth** approach requiring **TWO** environment variables to activate:

```bash
# BOTH must be set to "true" to enable bypass
export AB0T_AUTH_DEBUG=true
export AB0T_AUTH_BYPASS=true
```

**Optional configuration:**

```bash
# Customize the bypass user
export AB0T_AUTH_BYPASS_USER_ID=dev_user
export AB0T_AUTH_BYPASS_EMAIL=dev@localhost
export AB0T_AUTH_BYPASS_PERMISSIONS=users:read,users:write,admin:access
export AB0T_AUTH_BYPASS_ROLES=admin,developer
export AB0T_AUTH_BYPASS_ORG_ID=test_org
```

**What happens when bypass is enabled:**

1. All authentication checks return immediately with a synthetic user
2. A **WARNING** is logged on every request (makes it obvious in logs)
3. The user has `AuthMethod.BYPASS` and `TokenType.NONE` for identification
4. Permission checks still work based on configured permissions/roles

**Example usage:**

```bash
# Start your app with bypass enabled
AB0T_AUTH_DEBUG=true AB0T_AUTH_BYPASS=true uvicorn app:app --reload
```

```python
# All protected routes now authenticate as bypass user
@app.get("/protected")
async def protected(user: AuthenticatedUser = Depends(require_auth(auth))):
    print(user.user_id)       # "bypass_user" (or configured value)
    print(user.auth_method)   # AuthMethod.BYPASS
    print(user.token_type)    # TokenType.NONE
```

**Safety features:**

- Requires TWO env vars (defense-in-depth prevents accidental production use)
- Logs WARNING on every bypassed request
- Only `"true"` (case-insensitive) activates bypass - not `"1"`, `"yes"`, etc.
- Bypass user still respects permission checks (must configure permissions you need)

**Never use in production.** The dual-flag requirement makes accidental production use unlikely, but always verify your deployment configuration.

---

## Roadmap

### v0.1.0 (Current)
- [x] JWT validation with JWKS
- [x] API key authentication
- [x] Permission checking (client + server)
- [x] FastAPI dependencies
- [x] Middleware support
- [x] Decorator support
- [x] Token caching
- [x] Structured logging
- [x] Flask support
- [x] Multi-tenancy with nested orgs

### v0.2.0 (Next)
- [ ] OAuth2 flow helpers (Google, GitHub, etc.)
- [ ] Session management utilities
- [ ] Rate limiting integration
- [ ] WebSocket authentication
- [ ] Service account enhancements

### v0.3.0 (Future)
- [ ] Admin dashboard integration
- [ ] Audit logging to Ab0t
- [ ] Custom claim validators
- [ ] gRPC support
- [ ] OpenTelemetry traces

### Under Consideration
- GraphQL integration
- Django adapter
- Kubernetes sidecar mode
- Edge function support

**Want to influence the roadmap?** [Open an issue](https://github.com/ab0t-com/auth_wrapper/issues) or [join the discussion](https://github.com/ab0t-com/auth_wrapper/discussions).

---

## Performance

Run benchmarks yourself:

```bash
source .venv/bin/activate && python scripts/benchmark.py --quick
```

**Results (local operations):**

| Benchmark | Ops/sec | Avg Latency | P99 Latency |
|-----------|---------|-------------|-------------|
| `check_permission` | 420,000+ | 0.002ms | 0.003ms |
| `check_any_permission` | 330,000+ | 0.002ms | 0.002ms |
| `check_all_permissions` | 195,000+ | 0.004ms | 0.005ms |
| `check_permission_pattern` | 58,000+ | 0.017ms | 0.025ms |
| `user.has_permission()` | 358,000+ | 0.002ms | 0.002ms |
| `token_cache.get()` (hit) | 190,000+ | 0.004ms | 0.008ms |
| `token_cache.set()` | 108,000+ | 0.009ms | 0.020ms |

**Full benchmark output:**

```
Permission Checks
--------------------------------------------------------------------------------
Benchmark                                          Ops/sec        Avg        P99
--------------------------------------------------------------------------------
check_permission (exists)                          421,574   0.0017ms   0.0033ms
check_permission (not exists)                      348,375   0.0022ms   0.0029ms
check_any_permission (3 perms)                     331,096   0.0019ms   0.0024ms
check_all_permissions (3 perms)                    195,144   0.0044ms   0.0052ms
check_permission_pattern (resource5:*)              58,265   0.0165ms   0.0247ms
user.has_permission()                              358,789   0.0021ms   0.0020ms
user.has_any_permission()                          539,614   0.0012ms   0.0018ms

Cache Operations
--------------------------------------------------------------------------------
token_cache.get() (hit)                            190,002   0.0037ms   0.0082ms
token_cache.get() (miss)                           200,691   0.0039ms   0.0056ms
token_cache.set()                                  108,719   0.0085ms   0.0202ms
```

**Translation:** Auth won't be your bottleneck.

---

## Support & Community

- **Documentation:** [docs.ab0t.com/auth-wrapper](https://docs.ab0t.com/auth-wrapper)
- **Discord:** [Join our community](https://discord.gg/ab0t)
- **Issues:** [GitHub Issues](https://github.com/ab0t-com/auth_wrapper/issues)
- **Feature Requests:** [GitHub Discussions](https://github.com/ab0t-com/auth_wrapper/discussions)
- **Enterprise:** enterprise@ab0t.com

---

## Trusted By

> *"We cut our auth implementation from 3 weeks to 2 hours. The permission system alone saved us months of maintenance."*
> — **Senior Engineer, Series B Startup**

> *"Finally, auth that just works. Our team can focus on features instead of security edge cases."*
> — **CTO, FinTech Company**

> *"The caching and async design gave us 10x throughput improvement over our previous auth middleware."*
> — **Platform Lead, E-commerce Scale-up**

---

## License

MIT License - Use it, modify it, ship it. See [LICENSE](LICENSE) for details.

---

## Get Started Now

```bash
pip install git+https://github.com/ab0t-com/auth_wrapper.git
```

```python
from ab0t_auth import AuthGuard, require_auth

auth = AuthGuard(auth_url="https://auth.service.ab0t.com")

# You're done. Go ship something amazing.
```

---

<p align="center">
  <b>Stop building auth. Start building the future.</b>
  <br><br>
  <a href="https://github.com/ab0t-com/auth_wrapper">Star us on GitHub</a> •
  <a href="https://docs.ab0t.com/auth-wrapper">Read the Docs</a> •
  <a href="https://discord.gg/ab0t">Join Discord</a>
</p>
