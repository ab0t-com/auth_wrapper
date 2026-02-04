# Changelog

All notable changes to ab0t-auth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Server-side permission checking mode** (`permission_check_mode`)
  - New configuration option to switch between client-side (JWT claims) and server-side (API call) permission verification
  - Environment variable: `AB0T_AUTH_PERMISSION_CHECK_MODE=server`
  - Programmatic: `AuthGuard(auth_url="...", permission_check_mode="server")`
  - Default is `"client"` for backward compatibility
  - Server mode calls `/permissions/check` endpoint for authoritative, real-time verification
  - Enables instant permission revocation without waiting for JWT expiration

### Why Server Mode?

The Ab0t auth service intentionally stores permissions in the database rather than JWT tokens. This design supports:

1. **Instant revocation** - Permissions can be removed immediately without waiting for token expiry
2. **Dynamic org scoping** - Permissions can vary by organization context
3. **Role-based inheritance** - Roles expand to permissions at check time
4. **Real-time updates** - Permission changes take effect immediately

**Recommendation:** Services using `auth.service.ab0t.com` should enable server mode:

```bash
AB0T_AUTH_PERMISSION_CHECK_MODE=server
```

This ensures permission checks are authoritative and reflect the latest state.

## [0.1.0] - 2026-01-15

### Added

- Initial release
- JWT validation with JWKS
- API key authentication
- Permission checking (client-side)
- FastAPI dependencies (`require_auth`, `require_permission`, etc.)
- FastAPI middleware (`AuthMiddleware`)
- FastAPI decorators (`@protected`, `@permission_required`, etc.)
- Token caching with TTL
- JWKS caching with auto-refresh
- Structured logging
- Flask support (`Ab0tAuth` extension)
- Multi-tenancy with nested organizations
- Auth bypass for testing/development
- Check callbacks for dynamic authorization
