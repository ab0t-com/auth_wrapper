# Auth Service API Reference

Auth service base URL: `https://auth.service.ab0t.com`

Full OpenAPI spec: `assets/auth-service-openapi-filtered.json` (42 endpoints)
Complete spec (137 endpoints): `https://auth.service.ab0t.com/openapi.json`

## Table of Contents

- [Authentication](#authentication)
- [API Keys](#api-keys)
- [Permissions](#permissions)
- [Organizations](#organizations)
- [Users](#users)
- [Health & Discovery](#health-discovery)
- [Quotas](#quotas)

## Authentication

### `POST /auth/login`

**Login**

**Request Body** (`LoginRequest`):

```json
{
  "email": "<Email>",
  "password": "<Password>",
  "org_id": "<Org Id>",
  "provider_type": "internal"
}
```

**Response** `200`: Successful Response

**Error codes:** `422`

---

### `POST /auth/register`

**Register**

**Request Body** (`RegisterRequest`):

```json
{
  "email": "<Email>",
  "password": "<Password must meet policy: min 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char. See GET /status for password_policy.>",
  "name": "<Name>",
  "org_id": "<Org Id>",
  "invitation_code": "<Invitation Code>"
}
```

**Response** `200`: Successful Response

**Error codes:** `422`

---

### `GET /auth/me`

**Get Current User Info**

**Response** `200`: Successful Response

---

### `POST /auth/refresh`

**Refresh Token**

**Request Body** (`RefreshTokenRequest`):

```json
{
  "refresh_token": "<Refresh Token>"
}
```

**Response** `200`: Successful Response

**Error codes:** `422`

---

### `POST /auth/validate-api-key`

**Validate Api Key**

**Request Body** (`ValidateApiKeyRequest`):

```json
{
  "api_key": "<The API key to validate>",
  "required_permissions": [],
  "expected_audience": "<Expected audience - API key's org must match (e.g., LOCAL:org-123)>"
}
```

**Response** `200`: Successful Response

**Error codes:** `422`

---

### `POST /auth/validate-token`

**Validate Token**

**Request Body** (`TokenValidationRequest`):

```json
{
  "token": "<Token>",
  "required_permissions": [],
  "resource_type": "<Resource Type>",
  "resource_id": "<Resource Id>",
  "expected_audience": "<Expected audience - token must include this in its aud claim to be valid>"
}
```

**Response** `200`: Successful Response

**Error codes:** `422`

---

### `POST /auth/check-permission`

**Check Permission**

**Request Body** (`PermissionCheckRequest`):

```json
{
  "user_id": "<User Id>",
  "org_id": "<Org Id>",
  "permission": "<Permission>",
  "resource_type": "<Resource Type>",
  "resource_id": "<Resource Id>"
}
```

**Response** `200`: Successful Response

**Error codes:** `422`

---

### `POST /auth/switch-organization`

**Switch Organization**

**Request Body** (`SwitchOrganizationRequest`):

```json
{
  "org_id": "<Org Id>"
}
```

**Response** `200`: Successful Response

**Error codes:** `422`

---

## API Keys

### `GET /api-keys/`

**Get Api Keys**

**Response** `200`: Successful Response

---

### `POST /api-keys/`

**Create Api Key**

**Request Body** (`APIKeyCreate`):

```json
{
  "name": "<Name>",
  "permissions": [],
  "rate_limit": 0,
  "expires_at": "<Expires At>",
  "metadata": "<object>"
}
```

**Response** `200`: Successful Response

**Error codes:** `422`

---

### `GET /api-keys/{key_id}`

**Get Api Key**

**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `key_id` | path | string | Yes |  |

**Response** `200`: Successful Response

**Error codes:** `422`

---

### `PUT /api-keys/{key_id}`

**Update Api Key**

**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `key_id` | path | string | Yes |  |

**Request Body** (`APIKeyUpdate`):

```json
{
  "name": "<Name>",
  "permissions": [],
  "rate_limit": 0,
  "is_active": false,
  "metadata": "<object>"
}
```

**Response** `200`: Successful Response

**Error codes:** `422`

---

### `DELETE /api-keys/{key_id}`

**Delete Api Key**

**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `key_id` | path | string | Yes |  |

**Response** `200`: Successful Response

**Error codes:** `422`

---

## Permissions

### `POST /permissions/grant`

**Grant Permission**

**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `user_id` | query | string | Yes |  |
| `org_id` | query | string | Yes |  |
| `permission` | query | string | Yes |  |

**Response** `200`: Successful Response

**Error codes:** `422`

---

### `POST /permissions/revoke`

**Revoke Permission**

**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `user_id` | query | string | Yes |  |
| `org_id` | query | string | Yes |  |
| `permission` | query | string | Yes |  |

**Response** `200`: Successful Response

**Error codes:** `422`

---

### `POST /permissions/check`

**Check User Permission**

**Request Body** (`PermissionCheckRequest`):

```json
{
  "user_id": "<User Id>",
  "org_id": "<Org Id>",
  "permission": "<Permission>",
  "resource_type": "<Resource Type>",
  "resource_id": "<Resource Id>"
}
```

**Response** `200`: Successful Response

**Error codes:** `422`

---

### `GET /permissions/user/{user_id}`

**Get User Permissions**

**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `user_id` | path | string | Yes |  |
| `org_id` | query | string | No |  |

**Response** `200`: Successful Response

**Error codes:** `422`

---

### `GET /permissions/roles`

**Get Available Roles**

**Response** `200`: Successful Response

---

### `POST /permissions/registry/register`

**Register Service Permissions**

**Request Body** (`ServicePermissionRegister`):

```json
{
  "service": "<Service name (lowercase, alphanumeric + underscore)>",
  "description": "<Human-readable service description>",
  "actions": [],
  "resources": [],
  "metadata": "<object>"
}
```

**Response** `200`: Successful Response

**Error codes:** `422`

---

### `GET /permissions/registry/services`

**Get Registered Services**

**Response** `200`: Successful Response

---

### `GET /permissions/registry/valid-permissions`

**Get Valid Permissions**

**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `service` | query | string | No |  |

**Response** `200`: Successful Response

**Error codes:** `422`

---

### `POST /permissions/registry/validate`

**Validate Permission**

**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `permission` | query | string | Yes |  |

**Response** `200`: Successful Response

**Error codes:** `422`

---

### `GET /permissions/registry/stats`

**Get Registry Stats**

**Response** `200`: Successful Response

---

## Organizations

### `POST /organizations/`

**Create Organization**

**Request Body** (`OrganizationCreate`):

```json
{
  "name": "<Name>",
  "slug": "<Slug>",
  "domain": "<Domain>",
  "parent_id": "<Parent Id>",
  "billing_type": "prepaid",
  "logo_url": "<Logo Url>",
  "website": "<Website>",
  "industry": "<Industry>",
  "size": "<Size>",
  "timezone": "UTC",
  "settings": "<object>",
  "metadata": "<object>"
}
```

**Response** `200`: Successful Response

**Error codes:** `422`

---

### `GET /organizations/{org_id}`

**Get Organization**

**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `org_id` | path | string | Yes |  |

**Response** `200`: Successful Response

**Error codes:** `422`

---

### `PUT /organizations/{org_id}`

**Update Organization**

**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `org_id` | path | string | Yes |  |

**Request Body** (`OrganizationUpdate`):

```json
{
  "name": "<Name>",
  "slug": "<Slug>",
  "domain": "<Domain>",
  "parent_id": "<Parent Id>",
  "logo_url": "<Logo Url>",
  "website": "<Website>",
  "industry": "<Industry>",
  "size": "<Size>",
  "timezone": "<Timezone>",
  "settings": "<object>",
  "metadata": "<object>"
}
```

**Response** `200`: Successful Response

**Error codes:** `422`

---

### `POST /organizations/{org_id}/invite`

**Invite User To Organization**

**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `org_id` | path | string | Yes |  |

**Request Body** (`OrganizationInvite`):

```json
{
  "email": "<Email>",
  "role": "<Role>",
  "team_id": "<Team Id>",
  "permissions": [],
  "message": "<Message>",
  "expires_at": "<Expires At>"
}
```

**Response** `200`: Successful Response

**Error codes:** `422`

---

### `GET /organizations/{org_id}/users`

**Get Organization Users**

**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `org_id` | path | string | Yes |  |
| `role` | query | ? | No |  |
| `limit` | query | ? | No |  |
| `offset` | query | integer | No |  |
| `next_token` | query | ? | No |  |

**Response** `200`: Successful Response

**Error codes:** `422`

---

### `GET /organizations/{org_id}/invitations`

**List Organization Invitations**

**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `org_id` | path | string | Yes |  |
| `status` | query | ? | No |  |
| `limit` | query | integer | No |  |
| `offset` | query | integer | No |  |

**Response** `200`: Successful Response

**Error codes:** `422`

---

## Users

### `GET /users/me`

**Get Current User Profile**

**Response** `200`: Successful Response

---

### `PUT /users/me`

**Update Current User Profile**

**Request Body** (`UserUpdate`):

```json
{
  "name": "<Name>",
  "phone": "<Phone>",
  "avatar_url": "<Avatar Url>",
  "timezone": "<Timezone>",
  "language": "<Language>",
  "status": "<?>",
  "metadata": "<object>"
}
```

**Response** `200`: Successful Response

**Error codes:** `422`

---

## Health & Discovery

### `GET /health`

**Health Check**

**Response** `200`: Successful Response

---

### `GET /.well-known/jwks.json`

**Get Jwks**

**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `provider` | query | ? | No | Filter by provider (internal, google, microsoft, all) |
| `org_id` | query | ? | No | Organization ID for org-specific JWKS |
| `refresh` | query | boolean | No | Force refresh of cached keys |

**Response** `200`: Successful Response

**Error codes:** `422`

---

## Quotas

### `GET /quotas/check/{resource_type}`

**Check Quota**

**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `resource_type` | path | string | Yes |  |
| `org_id` | query | string | No |  |

**Response** `200`: Successful Response

**Error codes:** `422`

---

### `GET /quotas/my-usage`

**Get My Quota Usage**

**Response** `200`: Successful Response

---

### `GET /quotas/tiers`

**Get Quota Tiers**

**Response** `200`: Successful Response

---
