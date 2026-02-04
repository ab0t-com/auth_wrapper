# Ab0t Auth Demo Servers

Example FastAPI and Flask servers demonstrating Ab0t Auth integration.

## Quick Start

### 1. Create Virtual Environment

```bash
# From the auth_wrapper directory
python -m venv .venv

# Activate it
source .venv/bin/activate  # Linux/Mac
# or
.venv\Scripts\activate     # Windows
```

### 2. Install Dependencies

```bash
# Install with all frameworks (recommended for demo)
pip install -e ".[all]"

# Or install individually
pip install -e ".[fastapi]"  # For FastAPI only
pip install -e ".[flask]"    # For Flask only
```

### 2. Configure Auth URL

Edit the `AUTH_URL` in either server file to point to your Ab0t auth service:

```python
AUTH_URL = "https://auth.service.ab0t.com"  # Your Ab0t auth URL
```

Or set via environment variables:

```bash
export AB0T_AUTH_URL="https://auth.service.ab0t.com"

# Recommended: Enable server-side permission checking
# This calls /permissions/check for authoritative verification
# Supports instant permission revocation without waiting for JWT expiry
export AB0T_AUTH_PERMISSION_CHECK_MODE="server"
```

---

## Running the Servers

### FastAPI Server

```bash
# Option 1: Using uvicorn directly
uvicorn fastapi_server:app --reload --port 8000

# Option 2: Run as Python script
python fastapi_server.py
```

**Access at:** http://localhost:8000

**API Docs:** http://localhost:8000/docs

### Flask Server

```bash
# Option 1: Using Flask CLI
flask --app flask_server run --port 5000 --reload

# Option 2: Run as Python script
python flask_server.py
```

**Access at:** http://localhost:5000

---

## Testing the Endpoints

### Public Endpoints (No Auth)

```bash
# Root
curl http://localhost:8000/

# Health check
curl http://localhost:8000/health
```

### Protected Endpoints (Require Auth)

```bash
# With JWT token
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  http://localhost:8000/me

# With API key
curl -H "X-API-Key: YOUR_API_KEY" \
  http://localhost:8000/protected
```

### Permission-Based Endpoints

```bash
# Requires 'users:read' permission
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8000/users

# Requires 'admin:access' permission
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8000/admin

# Requires 'users:delete' permission
curl -X DELETE -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8000/users/123
```

### Optional Auth Endpoints

```bash
# Anonymous access (basic content)
curl http://localhost:8000/content

# Authenticated access (premium content)
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8000/content
```

---

## Endpoint Summary

### Core Endpoints (Dependency Injection Pattern)

| Endpoint | Method | Auth Required | Permission/Role |
|----------|--------|---------------|-----------------|
| `/` | GET | No | - |
| `/health` | GET | No | - |
| `/me` | GET | Yes | - |
| `/protected` | GET | Yes | - |
| `/context` | GET | Yes | - |
| `/users` | GET | Yes | `users:read` |
| `/users` | POST | Yes | `users:write` |
| `/users/{id}` | DELETE | Yes | `users:delete` |
| `/admin` | GET | Yes | `admin:access` |
| `/admin/dashboard` | GET | Yes | Role: `admin` |
| `/reports` | GET | Yes | `reports:read` OR `admin:access` |
| `/content` | GET | Optional | - |

### Decorator Pattern Endpoints (FastAPI only)

| Endpoint | Method | Auth Required | Permission/Role |
|----------|--------|---------------|-----------------|
| `/decorator/protected` | GET | Yes | - |
| `/decorator/permission` | GET | Yes | `users:read` |
| `/decorator/multi-permission` | GET | Yes | `users:read` AND `reports:read` |
| `/decorator/any-permission` | GET | Yes | `admin:access` OR `super:user` |
| `/decorator/role` | GET | Yes | Role: `admin` |

### Class-Based Decorator Endpoints (FastAPI only)

| Endpoint | Method | Auth Required | Permission/Role |
|----------|--------|---------------|-----------------|
| `/class/protected` | GET | Yes | - |
| `/class/permission` | GET | Yes | `users:write` |
| `/class/role` | GET | Yes | Role: `editor` |
| `/class/pattern` | GET | Yes | Pattern: `users:*` |

---

## Getting Test Tokens

### From Ab0t Auth Service

```bash
# Login to get tokens
curl -X POST https://auth.service.ab0t.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password"}'
```

### For Development (Mock Token)

For local development without a real Ab0t service, you can create a mock JWT:

```python
import jwt
from datetime import datetime, timedelta

# Create a mock token (DO NOT use in production)
payload = {
    "sub": "user_123",
    "email": "test@example.com",
    "permissions": ["users:read", "users:write", "reports:read"],
    "roles": ["user"],
    "exp": datetime.utcnow() + timedelta(hours=1),
}

token = jwt.encode(payload, "secret", algorithm="HS256")
print(token)
```

---

## Project Structure

```
demo/
├── README.md           # This file
├── fastapi_server.py   # FastAPI example
└── flask_server.py     # Flask example
```

---

## Key Differences

| Feature | FastAPI | Flask |
|---------|---------|-------|
| Import | `from ab0t_auth import ...` | `from ab0t_auth.flask import ...` |
| Auth Guard | `AuthGuard` class | `Ab0tAuth` extension |
| Protection | `Depends(require_auth(auth))` | `@login_required` decorator |
| Permissions | `Depends(require_permission(auth, "x"))` | `@permission_required("x")` |
| Current User | Injected via `Depends` | `get_current_user()` function |
| Async | Native async/await | Sync (uses event loop internally) |

## FastAPI Integration Patterns

FastAPI supports **three different patterns** for authentication:

### 1. Dependency Injection (Recommended)
```python
@app.get("/users")
async def get_users(user: AuthenticatedUser = Depends(require_permission(auth, "users:read"))):
    return {"user": user.user_id}
```

### 2. Function Decorators
```python
@app.get("/users")
@permission_required(auth, "users:read")
async def get_users(request: Request, auth_user: AuthenticatedUser):
    return {"user": auth_user.user_id}
```

### 3. Class-Based Decorators (slowapi-style)
```python
auth_decorator = Auth(auth)

@app.get("/users")
@auth_decorator.permission("users:read")
async def get_users(request: Request, auth_user: AuthenticatedUser):
    return {"user": auth_user.user_id}
```

**Note:** Decorators require `request: Request` as the first parameter and receive `auth_user` injected into kwargs.
