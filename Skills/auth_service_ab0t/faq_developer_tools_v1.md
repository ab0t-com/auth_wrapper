# Developer Tools / API Economy — Complete Auth Guide
## Flowbase: A Workflow Automation Platform with a Public API

**Scenario:** Sam Chen and Aiko Tanaka are co-founders of Flowbase — a workflow automation
platform (think Zapier + n8n). Companies connect Flowbase to their tools (Slack, GitHub, Notion,
Postgres) and build automated pipelines. Flowbase has a public REST API and wants third-party
developers to build integrations and publish them to a marketplace.

**What they need:**
- Developers authenticate with API keys for CLI/scripting/CI-CD
- Third-party apps (a VS Code extension, a Notion plugin, a Zapier-style integration builder)
  can request access to a user's Flowbase workspace via OAuth 2.1
- A self-serve **developer portal** where third-party devs register, create OAuth apps, and
  manage their listings without emailing Sam
- Enterprise customers can create **org-scoped OAuth clients** for internal integrations
- Users can see and revoke connected apps from a "Connected Apps" dashboard
- Webhook delivery and workflow execution run as service accounts

**Characters:**
- **Sam Chen** — CTO, sets up the platform org and auth config
- **Aiko Tanaka** — co-founder, builds the API gateway and token validation
- **Marcus Webb** — developer advocate, configures the developer portal
- **Priya Kapoor** — third-party developer, building a Notion plugin for Flowbase
- **Tom Reyes** — third-party developer, building a Flowbase CLI
- **Elena Rodriguez** — enterprise customer (AcmeCorp), wants internal OAuth integration

```
AUTH_URL="https://auth.service.ab0t.com"
FLOWBASE_SLUG="flowbase"
DEVPORTAL_SLUG="flowbase-developers"
```

---

## Step 1: Sam bootstraps Flowbase

**Situation:** Day one. Sam registers Flowbase as an org on the auth platform.

```bash
# Register Sam
SAM_TOKEN=$(curl -s -X POST "$AUTH_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "sam@flowbase.io",
    "password": "...",
    "name": "Sam Chen"
  }' | jq -r '.access_token')

# Create the Flowbase platform org
PLATFORM_ORG=$(curl -s -X POST "$AUTH_URL/organizations" \
  -H "Authorization: Bearer $SAM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Flowbase",
    "slug": "flowbase",
    "billing_type": "enterprise"
  }')

PLATFORM_ORG_ID=$(echo $PLATFORM_ORG | jq -r '.id')
echo "Platform org: $PLATFORM_ORG_ID"
```

**What just happened:** Flowbase is now the top-level platform org. All customer orgs,
developer portal orgs, and the integration marketplace will live under this.

---

## Step 2: Service accounts for platform operations

**Situation:** Flowbase runs several internal services. The webhook delivery service fires
HTTP requests on behalf of users. The execution engine runs workflow steps. These are machines,
not people.

```bash
# Webhook delivery service account
WEBHOOK_SA=$(curl -s -X POST "$AUTH_URL/admin/users/create-service-account" \
  -H "Authorization: Bearer $SAM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "webhook-delivery@svc.flowbase.internal",
    "name": "webhook-delivery",
    "description": "Delivers webhook payloads to customer endpoints",
    "permissions": [
      "flowbase.read.workflows",
      "flowbase.read.executions",
      "flowbase.write.delivery_logs"
    ],
    "org_id": "'"$PLATFORM_ORG_ID"'"
  }')

WEBHOOK_API_KEY=$(echo $WEBHOOK_SA | jq -r '.api_key')

# Execution engine — needs to act on behalf of users (delegation)
EXEC_SA=$(curl -s -X POST "$AUTH_URL/admin/users/create-service-account" \
  -H "Authorization: Bearer $SAM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "execution-engine@svc.flowbase.internal",
    "name": "execution-engine",
    "description": "Runs workflow steps on behalf of users",
    "permissions": [
      "flowbase.read.workflows",
      "flowbase.write.executions",
      "flowbase.delegate"
    ],
    "org_id": "'"$PLATFORM_ORG_ID"'"
  }')

EXEC_API_KEY=$(echo $EXEC_SA | jq -r '.api_key')
```

> **Concept: Service accounts vs users**
>
> A service account is a machine identity. It authenticates with a static API key
> (`X-API-Key` header), never a password or OAuth token. Service accounts:
> - Have no email/password login
> - Hold only the permissions they need (least privilege)
> - Are audited separately from human activity
> - Can hold the `flowbase.delegate` permission, which lets them request
>   delegation tokens to act on behalf of real users

---

## Step 3: Customer workspaces (sub-orgs)

**Situation:** AcmeCorp signs up for Flowbase. Their workspace should be isolated — their
workflows, API keys, and connected apps are invisible to other customers.

```bash
# AcmeCorp signs up (via Flowbase's own onboarding flow)
# Flowbase backend calls auth service to create customer workspace
ACME_ORG=$(curl -s -X POST "$AUTH_URL/organizations" \
  -H "Authorization: Bearer $SAM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "AcmeCorp Flowbase Workspace",
    "slug": "acmecorp-flowbase",
    "parent_id": "'"$PLATFORM_ORG_ID"'",
    "billing_type": "prepaid"
  }')

ACME_ORG_ID=$(echo $ACME_ORG | jq -r '.id')

# Invite Elena as org owner
curl -s -X POST "$AUTH_URL/organizations/$ACME_ORG_ID/invite" \
  -H "Authorization: Bearer $SAM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "elena@acmecorp.io",
    "role": "owner"
  }'
```

> **Concept: Customer workspace isolation**
>
> Each customer org is a fully isolated Zanzibar namespace boundary. When Elena creates an
> API key inside AcmeCorp's workspace, it is scoped to `org_id=ACME_ORG_ID`. When her
> developers call the Flowbase API, every request carries that org boundary. Flowbase's API
> gateway validates: does this token's `org_id` match the resource being requested?
>
> Elena cannot see Flowbase's other customers. Flowbase staff with `cross_tenant` permission
> can see all workspaces for support purposes.

---

## Step 4: API keys for direct access

**Situation:** Tom Reyes is building a Flowbase CLI. He wants developers to authenticate with
a personal API key — no OAuth dance, just copy-paste and ship.

### 4a. Tom creates a personal API key

Tom logs into Flowbase, navigates to Settings → API Keys, clicks "Create Key":

```bash
# Tom is logged in as a Flowbase user (in AcmeCorp workspace for this example,
# or in his own personal workspace)

# Behind the scenes, Flowbase's frontend calls:
TOM_KEY=$(curl -s -X POST "$AUTH_URL/api-keys/" \
  -H "Authorization: Bearer $TOM_USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Tom CLI — laptop",
    "permissions": [
      "flowbase.read.workflows",
      "flowbase.write.workflows",
      "flowbase.read.executions",
      "flowbase.trigger.workflows"
    ],
    "expires_at": "2027-01-01T00:00:00Z"
  }')

TOM_API_KEY=$(echo $TOM_KEY | jq -r '.key')
KEY_ID=$(echo $TOM_KEY | jq -r '.id')

echo "Key ID: $KEY_ID"
echo "Key (save this, shown once): $TOM_API_KEY"
```

> **Concept: API key scoping**
>
> An API key is NOT a credential to log in as Tom with all his permissions. It is a
> *capability token* scoped to exactly what Tom specifies at creation time. If Tom's
> account has `flowbase.admin.platform` but he doesn't include it in the key permissions,
> the key cannot use it. The key can never escalate beyond the user's own permissions.
>
> This is the principle of least privilege applied to developer tooling.

### 4b. Tom uses the key in his CLI

```bash
# flowbase CLI — authenticate once
flowbase auth login --api-key fb_live_abc123xyz

# Under the hood, the CLI stores the key and sends:
curl -s "$FLOWBASE_API/workflows" \
  -H "X-API-Key: fb_live_abc123xyz"
```

### 4c. Flowbase API gateway validates the key

```python
# In Flowbase's FastAPI backend (appv2 pattern)
from ab0t_auth import AuthGuard, AuthenticatedUser
from fastapi import Depends

@router.get("/workflows")
async def list_workflows(
    user: AuthenticatedUser = Depends(AuthGuard(
        required_permissions=["flowbase.read.workflows"]
    ))
):
    # user.org_id is the workspace this key belongs to
    # user.user_id is the human who created the key
    # Phase 2: only return workflows in user.org_id
    return await db.get_workflows(org_id=user.org_id)
```

> **Concept: API key vs Bearer token — what's different?**
>
> | | API Key | Bearer Token (OAuth) |
> |---|---|---|
> | Auth method | `X-API-Key` header | `Authorization: Bearer` header |
> | Issued by | User (self-serve) | Auth server (OAuth flow) |
> | Lifespan | Long-lived (months/years) | Short-lived (15–60 min) + refresh |
> | Refresh | No — rotate manually | Yes — refresh token |
> | Revocation | Immediate (delete key) | Next expiry or active revocation |
> | Use case | CLI, scripts, CI/CD | Web apps, mobile apps, third-party integrations |
> | Carries identity | Yes (created_by user) | Yes (authorized user) |

### 4d. Key rotation without downtime

Tom's key is about to expire. He needs to rotate without breaking CI/CD:

```bash
# Step 1: Create the new key FIRST (both keys work simultaneously)
NEW_KEY=$(curl -s -X POST "$AUTH_URL/api-keys/" \
  -H "Authorization: Bearer $TOM_USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Tom CLI — laptop (rotated 2026-03)",
    "permissions": [
      "flowbase.read.workflows",
      "flowbase.write.workflows",
      "flowbase.read.executions",
      "flowbase.trigger.workflows"
    ]
  }')

NEW_API_KEY=$(echo $NEW_KEY | jq -r '.key')

# Step 2: Update CI/CD secrets with the new key
# Step 3: Verify the new key works in all systems
# Step 4: Delete the old key (immediate revocation)
curl -s -X DELETE "$AUTH_URL/api-keys/$OLD_KEY_ID" \
  -H "Authorization: Bearer $TOM_USER_TOKEN"
```

> **What just happened:** The old key is immediately revoked. Any CI/CD job still using it
> will start getting 401 responses. There is no grace period — this is intentional. Rotate
> first, delete second.

### 4e. List and audit all keys

```bash
# Elena (org admin) audits all keys in the workspace
curl -s "$AUTH_URL/api-keys/" \
  -H "Authorization: Bearer $ELENA_TOKEN" | jq '.[] | {
    id, name,
    created_by: .created_by_user.email,
    last_used: .last_used_at,
    expires_at,
    permissions
  }'

# Output:
# {
#   "id": "key_abc",
#   "name": "Tom CLI — laptop",
#   "created_by": "tom@acmecorp.io",
#   "last_used": "2026-02-24T18:32:11Z",
#   "expires_at": "2027-01-01T00:00:00Z",
#   "permissions": ["flowbase.read.workflows", ...]
# }
```

---

## Step 5: OAuth 2.1 — third-party app integrations

**Situation:** Priya is building a Notion plugin. When a Notion user clicks "Connect Flowbase",
Priya's plugin needs to access that user's Flowbase workflows — but Priya should never see
their password. This is exactly what OAuth 2.1 solves.

> **Concept: OAuth 2.1 — the three-party handshake**
>
> Three parties are involved:
> - **Resource Owner** — the Flowbase user (e.g., Elena at AcmeCorp)
> - **Client** — Priya's Notion plugin
> - **Authorization Server** — the auth service
>
> The flow:
> 1. Priya's plugin redirects Elena to Flowbase's login/consent page
> 2. Elena logs in and approves: "Yes, Notion plugin can read my workflows"
> 3. Auth server issues a short-lived `authorization_code` to Priya's plugin
> 4. Priya's plugin exchanges the code for `access_token` + `refresh_token`
> 5. Priya's plugin calls Flowbase API using the `access_token`
> 6. Flowbase's API validates the token — it knows this is Elena's token, issued to Priya's app
>
> Elena can revoke access at any time. Priya never sees Elena's password.

---

## Step 6: Developer portal — self-serve OAuth app registration

**Situation:** Priya needs to register her Notion plugin as an OAuth client. Sam doesn't
want to approve every registration manually. Marcus sets up a self-serve developer portal.

### 6a. Create the developer portal org

```bash
# Developer portal is a sub-org of Flowbase platform
DEVPORTAL_ORG=$(curl -s -X POST "$AUTH_URL/organizations" \
  -H "Authorization: Bearer $SAM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Flowbase Developer Portal",
    "slug": "flowbase-developers",
    "parent_id": "'"$PLATFORM_ORG_ID"'",
    "billing_type": "enterprise"
  }')

DEVPORTAL_ORG_ID=$(echo $DEVPORTAL_ORG | jq -r '.id')
```

### 6b. Configure self-serve registration

```bash
# Anyone can sign up as a developer — open registration
curl -s -X PUT "$AUTH_URL/organizations/$DEVPORTAL_ORG_ID/login-config" \
  -H "Authorization: Bearer $SAM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "auth_methods": {
      "email_password": true,
      "signup_enabled": true,
      "invitation_only": false
    },
    "providers": [
      {"type": "google"},
      {"type": "github"}
    ],
    "registration": {
      "default_role": "developer",
      "welcome_redirect": "https://developers.flowbase.io/dashboard"
    },
    "branding": {
      "company_name": "Flowbase Developers",
      "logo_url": "https://flowbase.io/dev-logo.png",
      "primary_color": "#6C47FF",
      "tagline": "Build with Flowbase"
    }
  }'
```

> **Concept: The `developer` role**
>
> The developer portal uses a custom `developer` role (not the built-in `end_user` role).
> This role grants:
> - `flowbase.register.oauth_apps` — can register OAuth clients
> - `flowbase.read.oauth_apps` — can list their own apps
> - `flowbase.write.oauth_apps` — can update their app settings
> - `flowbase.read.devportal_docs` — access to API docs and sandbox
>
> A regular Flowbase `end_user` does NOT get these permissions. Developer portal users
> are a distinct audience.

### 6c. Hosted developer portal login page

```
https://auth.service.ab0t.com/login/flowbase-developers
```

Flowbase embeds this at `https://developers.flowbase.io/login` using the hosted iframe or
redirects there directly. Priya lands here, clicks "Continue with GitHub", and gets a
developer account instantly.

---

## Step 7: Registering an OAuth application

**Situation:** Priya has a developer account. She registers her Notion plugin.

```bash
# Priya is logged in — developer portal token
PRIYA_DEV_TOKEN="..."  # Priya's token in the developer portal org

# Register the Notion plugin as an OAuth client
NOTION_APP=$(curl -s -X POST "$AUTH_URL/organizations/$DEVPORTAL_ORG_ID/auth/oauth/clients" \
  -H "Authorization: Bearer $PRIYA_DEV_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Notion Flowbase Plugin",
    "description": "Connect Flowbase workflows directly from Notion pages",
    "client_type": "confidential",
    "redirect_uris": [
      "https://notion-flowbase.priya.dev/oauth/callback",
      "https://notion-flowbase.priya.dev/oauth/callback-dev"
    ],
    "allowed_scopes": [
      "flowbase.read.workflows",
      "flowbase.trigger.workflows",
      "flowbase.read.executions"
    ],
    "logo_url": "https://notion-flowbase.priya.dev/logo.png",
    "homepage_url": "https://notion-flowbase.priya.dev",
    "privacy_policy_url": "https://notion-flowbase.priya.dev/privacy"
  }')

CLIENT_ID=$(echo $NOTION_APP | jq -r '.client_id')
CLIENT_SECRET=$(echo $NOTION_APP | jq -r '.client_secret')

echo "Client ID: $CLIENT_ID"
echo "Client Secret (store securely): $CLIENT_SECRET"
```

> **Concept: OAuth client types**
>
> `confidential` — the app has a server backend that can keep a secret. Uses
> `client_id` + `client_secret` + PKCE to exchange codes for tokens. Best for
> web apps with a backend (like Priya's Notion plugin backend server).
>
> `public` — the app cannot keep a secret (e.g., a CLI tool, mobile app, browser
> extension). Uses PKCE only — no client secret. The auth server validates the
> PKCE challenge instead of a secret.
>
> Both require PKCE in OAuth 2.1. The implicit flow is removed entirely.

---

## Step 8: The full OAuth 2.1 authorization code flow

**Situation:** Elena (AcmeCorp, Flowbase customer) installs Priya's Notion plugin and clicks
"Connect Flowbase". Here's every step in detail.

### Step 8a: Priya's plugin initiates the flow

```javascript
// In Priya's Notion plugin backend (Node.js)
import crypto from 'crypto'

function initiateOAuth(req, res) {
  // PKCE: generate code_verifier and code_challenge
  const code_verifier = crypto.randomBytes(32).toString('base64url')
  const code_challenge = crypto
    .createHash('sha256')
    .update(code_verifier)
    .digest('base64url')

  // Store verifier in session (needed at callback)
  req.session.pkce_verifier = code_verifier
  req.session.oauth_state = crypto.randomBytes(16).toString('hex')

  // Build the authorization URL
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: 'https://notion-flowbase.priya.dev/oauth/callback',
    scope: 'flowbase.read.workflows flowbase.trigger.workflows flowbase.read.executions',
    state: req.session.oauth_state,
    code_challenge: code_challenge,
    code_challenge_method: 'S256'
  })

  // Redirect Elena to Flowbase's authorization endpoint
  // The org slug scopes this to Flowbase's hosted login
  res.redirect(
    `https://auth.service.ab0t.com/organizations/flowbase/auth/authorize?${params}`
  )
}
```

> **Concept: PKCE — Proof Key for Code Exchange**
>
> PKCE prevents authorization code interception attacks. The flow:
>
> 1. Priya's app generates a random `code_verifier` (43-128 chars)
> 2. Computes `code_challenge = BASE64URL(SHA256(code_verifier))`
> 3. Sends `code_challenge` with the authorization request
> 4. Auth server stores it alongside the issued authorization code
> 5. When Priya's app exchanges the code for tokens, it sends the original `code_verifier`
> 6. Auth server recomputes the hash — if it matches, the code is genuine
>
> Even if someone intercepts the authorization code in the redirect URL, they cannot
> exchange it without the `code_verifier` (which never leaves Priya's server).

### Step 8b: Elena sees the consent screen

The auth service renders a hosted consent page:

```
╔══════════════════════════════════════════════════════╗
║                    Flowbase                          ║
║                                                      ║
║  Notion Flowbase Plugin                              ║
║  wants access to your Flowbase account               ║
║                                                      ║
║  This app will be able to:                           ║
║  ✓ Read your workflows                               ║
║  ✓ Trigger workflow runs                             ║
║  ✓ Read execution history                            ║
║                                                      ║
║  This app will NOT be able to:                       ║
║  ✗ Create or delete workflows                        ║
║  ✗ Manage team members                               ║
║  ✗ Access billing information                        ║
║                                                      ║
║  Authorizing as: elena@acmecorp.io                   ║
║  Workspace: AcmeCorp                                 ║
║                                                      ║
║  [Allow]              [Cancel]                       ║
╚══════════════════════════════════════════════════════╝
```

Elena clicks **Allow**.

### Step 8c: Auth server redirects back with code

```
https://notion-flowbase.priya.dev/oauth/callback
  ?code=auth_code_abc123_60s_expiry
  &state=csrf_state_xyz
```

> The authorization code expires in **60 seconds** and is single-use. If Priya's app
> doesn't exchange it immediately, it becomes invalid.

### Step 8d: Priya's app exchanges the code for tokens

```javascript
async function handleCallback(req, res) {
  const { code, state } = req.query

  // Verify state (CSRF protection)
  if (state !== req.session.oauth_state) {
    return res.status(400).send('State mismatch — possible CSRF')
  }

  // Exchange authorization code for tokens
  const tokenResponse = await fetch(
    'https://auth.service.ab0t.com/organizations/flowbase/auth/token',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: 'https://notion-flowbase.priya.dev/oauth/callback',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,  // confidential client
        code_verifier: req.session.pkce_verifier  // PKCE verifier
      })
    }
  )

  const tokens = await tokenResponse.json()
  // {
  //   "access_token": "eyJ...",       expires in 15 minutes
  //   "refresh_token": "rt_xyz...",   expires in 30 days
  //   "token_type": "Bearer",
  //   "expires_in": 900,
  //   "scope": "flowbase.read.workflows flowbase.trigger.workflows ...",
  //   "user_id": "usr_elena",
  //   "org_id": "org_acmecorp"
  // }

  // Store tokens securely (server-side, never in cookies or localStorage)
  await db.saveTokens(req.user.id, tokens)

  res.redirect('/dashboard?connected=flowbase')
}
```

### Step 8e: Priya's app calls the Flowbase API

```javascript
async function listUserWorkflows(userId) {
  const tokens = await db.getTokens(userId)

  const response = await fetch('https://api.flowbase.io/workflows', {
    headers: {
      'Authorization': `Bearer ${tokens.access_token}`
    }
  })

  if (response.status === 401) {
    // Token expired — refresh it
    const refreshed = await refreshTokens(tokens.refresh_token)
    return listUserWorkflows(userId)  // retry
  }

  return response.json()
}

async function refreshTokens(refresh_token) {
  const response = await fetch(
    'https://auth.service.ab0t.com/organizations/flowbase/auth/token',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refresh_token,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET
      })
    }
  )

  const tokens = await response.json()
  // IMPORTANT: refresh token rotation — old refresh token is now invalid.
  // Save the NEW refresh token immediately.
  await db.saveTokens(userId, tokens)
  return tokens
}
```

> **Concept: Refresh token rotation**
>
> Every time you use a refresh token, you get a NEW refresh token back. The old one is
> immediately invalidated. This means:
>
> - If an attacker steals a refresh token and uses it, Priya's app's next refresh attempt
>   will fail (old token rejected) — alerting to a possible compromise
> - Priya's app must always save the latest refresh token — never re-use the old one
> - Refresh tokens expire after 30 days of non-use (sliding window)

---

## Step 9: Token validation on the Flowbase API

**Situation:** Aiko builds the Flowbase API gateway. When a request arrives with a Bearer
token — whether from a user's own session, an API key, or a third-party OAuth client —
the gateway needs to validate it and extract the identity.

### 9a. Using the ab0t_auth client library

```python
# Flowbase API backend (FastAPI)
from ab0t_auth import AuthGuard, AuthenticatedUser
from fastapi import APIRouter, Depends

router = APIRouter()

@router.get("/workflows")
async def list_workflows(
    user: AuthenticatedUser = Depends(AuthGuard(
        required_permissions=["flowbase.read.workflows"]
    ))
):
    """
    Works for ALL three token types:
    - Session token (user logged into Flowbase directly)
    - API key (X-API-Key header)
    - OAuth access token (third-party app acting for user)
    """
    # Phase 2: only return this user's org's workflows
    return await workflow_db.list(org_id=user.org_id)

@router.post("/workflows/{workflow_id}/trigger")
async def trigger_workflow(
    workflow_id: str,
    user: AuthenticatedUser = Depends(AuthGuard(
        required_permissions=["flowbase.trigger.workflows"]
    ))
):
    # If this is an OAuth token, user.authorized_scopes will contain the
    # scopes Elena approved — cannot exceed that set
    workflow = await workflow_db.get(workflow_id, org_id=user.org_id)
    if not workflow:
        raise HTTPException(404, "Workflow not found")
    return await execution_engine.trigger(workflow, triggered_by=user.user_id)
```

### 9b. Token introspection — inspecting a token directly

```bash
# Aiko's debugging tool — inspect any token (RFC 7662, form-encoded)
curl -s -X POST "$AUTH_URL/token/introspect" \
  -H "Authorization: Bearer $FLOWBASE_PLATFORM_TOKEN" \
  --data-urlencode "token=$SUSPECT_TOKEN" | jq .
# Note: always returns 200 — check the "active" boolean field

# Output for an OAuth access token:
# {
#   "active": true,
#   "sub": "usr_elena",
#   "email": "elena@acmecorp.io",
#   "org_id": "org_acmecorp",
#   "token_type": "access_token",
#   "issued_to_client": {
#     "client_id": "fb_client_notion_xyz",
#     "name": "Notion Flowbase Plugin",
#     "developer": "priya@priya.dev"
#   },
#   "scope": "flowbase.read.workflows flowbase.trigger.workflows flowbase.read.executions",
#   "permissions": ["flowbase.read.workflows", "flowbase.trigger.workflows", "flowbase.read.executions"],
#   "issued_at": "2026-02-25T10:00:00Z",
#   "expires_at": "2026-02-25T10:15:00Z",
#   "iat": 1740477600,
#   "exp": 1740478500
# }
```

> **Concept: scope vs permissions on OAuth tokens**
>
> An OAuth access token is *doubly scoped*:
>
> 1. **Elena's permissions** — what Elena is allowed to do in her workspace
> 2. **Priya's approved scopes** — what Elena authorized the Notion plugin to do
>
> The effective permissions are the **intersection**. If Elena has
> `flowbase.admin.workflows` but only approved `flowbase.read.workflows` for the plugin,
> the token only grants `flowbase.read.workflows`. The plugin cannot escalate.
>
> Flowbase's API gateway enforces both layers automatically via `ab0t_auth`.

---

## Step 10: Tom's CLI — public OAuth client with device flow

**Situation:** Tom is building a CLI tool. A CLI can't keep a client secret (it ships
to users' machines). Tom uses a **public** OAuth client with PKCE only.

```bash
# Tom registers a public client (no client_secret)
CLI_APP=$(curl -s -X POST "$AUTH_URL/organizations/$DEVPORTAL_ORG_ID/auth/oauth/clients" \
  -H "Authorization: Bearer $TOM_DEV_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Flowbase CLI",
    "client_type": "public",
    "redirect_uris": [
      "http://localhost:9999/callback",
      "urn:ietf:wg:oauth:2.0:oob"
    ],
    "allowed_scopes": [
      "flowbase.read.workflows",
      "flowbase.write.workflows",
      "flowbase.trigger.workflows",
      "flowbase.read.executions"
    ]
  }')

CLI_CLIENT_ID=$(echo $CLI_APP | jq -r '.client_id')
# Note: no client_secret returned — this is a public client
```

### CLI login flow

```bash
# The CLI opens the browser and starts a local server to catch the redirect
flowbase login

# Behind the scenes (Go/Python CLI):
# 1. Generate PKCE
# 2. Start local HTTP server on :9999
# 3. Open browser to:
#    https://auth.service.ab0t.com/login/flowbase
#    ?response_type=code
#    &client_id=fb_client_cli
#    &redirect_uri=http://localhost:9999/callback
#    &scope=flowbase.read.workflows flowbase.write.workflows ...
#    &code_challenge=xxx
#    &code_challenge_method=S256
#
# 4. User logs in and approves in browser
# 5. Browser redirects to http://localhost:9999/callback?code=xxx
# 6. CLI catches the code, exchanges it (PKCE only, no secret):
#    POST /organizations/flowbase/auth/token
#    grant_type=authorization_code
#    code=xxx
#    code_verifier=yyy
#    client_id=fb_client_cli
#    redirect_uri=http://localhost:9999/callback
#
# 7. Store access_token + refresh_token in ~/.flowbase/credentials
```

> **What just happened:** The CLI never handled a password. The user authenticated
> in their browser (where they may already have SSO or a saved session). The CLI only
> received an authorization code via localhost redirect, which it exchanged for tokens
> using PKCE. If someone intercepts the code, they cannot use it without the verifier.

---

## Step 11: "Connected Apps" dashboard — user revocation

**Situation:** Elena wants to audit and revoke third-party access to her Flowbase workspace.
Flowbase builds a "Connected Apps" page in their dashboard.

> **Note:** A dedicated list-authorizations endpoint (`GET /organizations/{org_id}/auth/oauth/authorizations`)
> is not yet in the current API. Flowbase tracks granted authorizations in its own application
> database (stored when tokens are issued) and uses that to power the Connected Apps UI.
> The auth service is used to validate and revoke the individual tokens.

```bash
# Flowbase's own DB stores: {user_id, client_id, client_name, scopes, granted_at, last_used}
# when tokens are issued. The Connected Apps page queries this, not the auth service directly.

# Elena's Connected Apps page (Flowbase application data):
# ┌──────────────────────────┬───────────────────────────┬──────────────┐
# │ App                      │ Granted                   │ Last used    │
# ├──────────────────────────┼───────────────────────────┼──────────────┤
# │ Notion Flowbase Plugin   │ 2026-02-10 (priya@...)    │ 2026-02-24   │
# │ Flowbase CLI             │ 2026-01-15 (tom@...)      │ 2026-02-25   │
# └──────────────────────────┴───────────────────────────┴──────────────┘
```

### Elena revokes the Notion plugin

```bash
# Elena clicks "Revoke" — Flowbase backend revokes the token and clears its DB record

# Revoke Elena's current access token for the Notion plugin
curl -s -X POST "$AUTH_URL/token/revoke" \
  -H "Authorization: Bearer $ELENA_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$NOTION_ACCESS_TOKEN_FOR_ELENA"

# Also revoke the refresh token so Priya's app cannot silently re-authenticate
curl -s -X POST "$AUTH_URL/token/revoke" \
  -H "Authorization: Bearer $ELENA_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$NOTION_REFRESH_TOKEN_FOR_ELENA&token_type_hint=refresh_token"
```

> **What just happened:** Immediately:
> - Priya's current access token for Elena is invalidated
> - Elena's refresh token issued to Priya's app is revoked
> - The next API call from Priya's Notion plugin (on Elena's behalf) returns 401
> - Priya's app must redirect Elena through the OAuth flow again if she wants to reconnect
>
> Elena's own Flowbase session is unaffected. Only the third-party tokens are revoked.
> Flowbase stores the token references at issuance time so they can be looked up and
> revoked when Elena clicks the button.

---

## Step 12: Org-scoped OAuth clients — enterprise integrations

**Situation:** Elena's team at AcmeCorp wants to build an internal Zapier-style integration
between Flowbase and their internal tools. They don't want to publish it to the developer
portal — it should only work within AcmeCorp's workspace and only AcmeCorp users should
be able to authorize it.

```bash
# Elena creates an org-scoped OAuth client via RFC 7591 dynamic registration
INTERNAL_APP=$(curl -s -X POST "$AUTH_URL/auth/oauth/register" \
  -H "Authorization: Bearer $ELENA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "AcmeCorp Internal Integration",
    "client_type": "confidential",
    "redirect_uris": ["https://internal.acmecorp.io/flowbase/callback"],
    "allowed_scopes": [
      "flowbase.read.workflows",
      "flowbase.trigger.workflows"
    ],
    "visibility": "private",
    "org_restricted": true
  }')
```

> **Concept: Org-restricted OAuth clients**
>
> `org_restricted: true` means:
> - Only users within AcmeCorp's Flowbase workspace can authorize this client
> - The authorization URL will fail if a user from a different org tries to use it
> - This prevents phishing: a malicious actor cannot register a client that pretends
>   to be AcmeCorp's integration and trick other users into authorizing it
>
> Flowbase-published apps (Priya's Notion plugin) are platform-level clients registered
> in the developer portal — they can be authorized by any Flowbase customer. Enterprise
> clients are workspace-level — scoped to one org only.

---

## Step 13: Delegation tokens — execution engine acting for users

**Situation:** When a Flowbase workflow runs on a schedule, the execution-engine service
account needs to call integrations (GitHub, Slack) on behalf of Elena. The execution engine
holds tokens Elena authorized when she connected those integrations, but Flowbase's audit
log should show "workflow triggered by execution-engine on behalf of elena@acmecorp.io",
not just "execution-engine".

**Option A — execution engine acts as Elena** (`/auth/delegate`):

```bash
# Execution engine gets a token that acts AS Elena
# /auth/delegate takes only target_user_id — the caller gets Elena's full token context
DELEGATION=$(curl -s -X POST "$AUTH_URL/auth/delegate" \
  -H "X-API-Key: $EXEC_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target_user_id": "'"$ELENA_USER_ID"'"}')

DELEGATION_TOKEN=$(echo $DELEGATION | jq -r '.access_token')
# This token acts as Elena — Flowbase's API sees it as Elena's request
```

**Option B — Elena pre-authorises the execution engine** (`/delegation/grant`):

```bash
# Elena grants the execution engine to act on her behalf (she does this once, e.g. at OAuth consent)
curl -s -X POST "$AUTH_URL/delegation/grant" \
  -H "Authorization: Bearer $ELENA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "actor_id": "'"$EXEC_SERVICE_ACCOUNT_ID"'",
    "scope": [
      "flowbase.read.workflows",
      "flowbase.write.executions",
      "flowbase.trigger.workflows"
    ],
    "expires_in_hours": 720
  }'

# The execution engine then uses X-Acting-As: $ELENA_USER_ID with its own API key
# The auth service validates the delegation record exists before allowing the request
```

> **Concept: Delegation and audit trails**
>
> `/auth/delegate` creates a JWT where the execution engine carries Elena's full identity.
> Flowbase's own API layer records both identities — who made the call (execution-engine)
> and whose context it ran in (Elena) — in its application audit log.
>
> `/delegation/grant` is the user-consent model: Elena explicitly authorises the engine
> with a specific scope. The engine uses `X-Acting-As` with its own credentials. The
> auth service validates the delegation grant exists before permitting the request.
>
> **Permission scoping, expiry beyond these options, and audit reason fields** are
> application-layer concerns — enforce them in Flowbase's own middleware, not in
> the auth token itself. This matches the same model used in cloud provider audit logs
> (AWS CloudTrail `assumedRoleUser`, GCP `serviceAccountDelegationInfo`).

---

## Step 14: Scopes and permission design for a public API

**Situation:** Sam and Aiko are designing the official Flowbase permission scopes that
appear on the OAuth consent screen. Good scope design is part of the developer experience.

> **Best practices for API scope design:**

```
# Too broad — never do this
flowbase.all                    ← "access everything" is a red flag

# Too granular — confusing for developers and users
flowbase.read.workflow_metadata
flowbase.read.workflow_steps
flowbase.read.workflow_triggers
flowbase.read.workflow_history  ← 4 scopes where 1 would do

# Just right — meaningful, user-readable boundaries
flowbase.workflows:read         ← read workflows and their steps
flowbase.workflows:write        ← create, update, delete workflows
flowbase.executions:read        ← read execution history and logs
flowbase.executions:write       ← trigger and cancel runs
flowbase.connections:read       ← read connected integrations (GitHub, Slack)
flowbase.connections:write      ← manage connections (add, remove)
flowbase.team:read              ← read team members (org admin scoped)
flowbase.billing:read           ← read subscription and usage data
```

> **Concept: Scope naming conventions**
>
> The consent screen shows scope names to end users. Design them to be:
> - **Readable by non-developers** — "Read your workflows" not "flowbase.wf.r"
> - **Grouped by resource** — `resource:action` pattern is cleaner than `action.resource`
> - **Incrementally requestable** — apps can request only what they need; users trust
>   apps that ask for less
> - **Separate read/write** — never require write permission to get read access
>
> Flowbase publishes a public scope registry at `https://developers.flowbase.io/scopes`
> so third-party developers know exactly what each scope grants before registering.

---

## Step 15: Webhook signature validation — inbound webhooks

**Situation:** Flowbase sends webhooks to customer endpoints when workflows complete.
How does the customer know the webhook really came from Flowbase?

```python
# Flowbase signs every webhook with HMAC-SHA256
# Sam's webhook service generates a signing secret per customer

import hmac
import hashlib

def send_webhook(customer_endpoint: str, payload: dict, signing_secret: str):
    body = json.dumps(payload).encode()
    timestamp = str(int(time.time()))

    # Signature covers timestamp + body (prevents replay attacks)
    signature_input = f"{timestamp}.{body.decode()}".encode()
    signature = hmac.new(
        signing_secret.encode(),
        signature_input,
        hashlib.sha256
    ).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-Flowbase-Timestamp": timestamp,
        "X-Flowbase-Signature": f"sha256={signature}"
    }
    requests.post(customer_endpoint, data=body, headers=headers)
```

```python
# Elena's backend validates incoming webhooks
def validate_flowbase_webhook(request: Request, signing_secret: str) -> bool:
    timestamp = request.headers.get("X-Flowbase-Timestamp")
    signature = request.headers.get("X-Flowbase-Signature")
    body = request.body()

    # Reject webhooks older than 5 minutes (replay protection)
    if abs(time.time() - int(timestamp)) > 300:
        return False

    expected = "sha256=" + hmac.new(
        signing_secret.encode(),
        f"{timestamp}.{body.decode()}".encode(),
        hashlib.sha256
    ).hexdigest()

    # Constant-time comparison (prevents timing attacks)
    return hmac.compare_digest(expected, signature)
```

> **Where does the signing secret come from?**
>
> The webhook-delivery service account calls the auth service to generate a per-customer
> signing secret. It's stored in the customer's org settings. Elena can rotate it from
> her Flowbase dashboard — old secret immediately invalidated, new webhooks use new secret.

---

## Step 16: Putting it all together — the developer identity graph

```
Flowbase Platform Org (org_flowbase)
├── Service Accounts
│   ├── webhook-delivery       [flowbase.read.workflows, flowbase.write.delivery_logs]
│   └── execution-engine       [flowbase.read.workflows, flowbase.write.executions, flowbase.delegate]
│
├── Developer Portal (org_flowbase-developers)
│   ├── Login config: open signup, GitHub + Google
│   ├── Default role: developer
│   ├── Priya Kapoor (developer role)
│   │   └── OAuth Client: Notion Flowbase Plugin
│   │       ├── client_type: confidential
│   │       └── scopes: read.workflows, trigger.workflows, read.executions
│   └── Tom Reyes (developer role)
│       └── OAuth Client: Flowbase CLI
│           ├── client_type: public
│           └── scopes: read.workflows, write.workflows, trigger.workflows
│
└── Customer Workspaces
    └── AcmeCorp (org_acmecorp)
        ├── Elena Rodriguez (owner)
        ├── OAuth Authorizations
        │   ├── Notion Flowbase Plugin → Elena [authorized 2026-02-10, active]
        │   └── Flowbase CLI → Elena [authorized 2026-01-15, active]
        ├── API Keys
        │   └── Tom CLI — laptop [read.workflows, write.workflows, trigger, executions]
        └── Internal OAuth Client
            └── AcmeCorp Internal Integration [org_restricted: true]
```

---

## Decision matrix: which token type for which use case?

| Use case | Token type | Why |
|----------|-----------|-----|
| CI/CD pipeline | API key | Long-lived, scripted, no user interaction |
| Server-to-server | Service account + API key | Machine identity, audit trail |
| CLI tool (user) | OAuth 2.1 public client | No secret in binary, PKCE |
| Web app (your own) | Session token | First-party, full permissions |
| Third-party web app | OAuth 2.1 confidential client | User consent, scope limited |
| Mobile app | OAuth 2.1 public client | No secret in app binary |
| Zapier / automation | OAuth 2.1 confidential client | Same as third-party web app |
| Service acting for user | Delegation token | Dual identity in audit log |
| Webhook verification | HMAC signing secret | Inbound authenticity, not identity |

---

## Quick reference

```bash
# Register OAuth app (RFC 7591 dynamic client registration)
POST /auth/oauth/register

# Create API key (org from bearer token context)
POST /api-keys/

# Delete API key
DELETE /api-keys/{key_id}

# Authorize endpoint (start OAuth flow)
GET  /auth/authorize

# Token exchange (form-encoded)
POST /auth/oauth/token
# Org-scoped variant (validates client_id against the org)
POST /organizations/{org-slug}/auth/token

# Token introspection (form-encoded, RFC 7662 — always 200, check "active")
POST /token/introspect

# List user's authorized apps
# NOTE: no list-authorizations endpoint currently — use token introspect to inspect
# individual tokens, or POST /token/revoke to revoke a specific token directly

# Revoke a specific token
POST /token/revoke

# Request delegation token (caller acts AS target user)
POST /auth/delegate
     {"target_user_id": "..."}

# User-initiated delegation (grant actor to act on your behalf)
POST /delegation/grant
     {"actor_id": "...", "scope": [...], "expires_in_hours": 24}
```
