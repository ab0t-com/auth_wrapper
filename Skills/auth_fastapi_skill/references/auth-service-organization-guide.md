# Auth Service Enterprise Features Guide (Part 2)

**Version:** 2.0
**Last Updated:** 2026-02-04
**Prerequisite:** Read AUTH_SERVICE_ORGANIZATION_GUIDE.md first

---

## How to Use This Guide

Part 1 covered the fundamentals: organizations, teams, users, permissions, and basic setup patterns. This guide covers **enterprise features** - the advanced capabilities you'll need as your organization grows, faces security incidents, or requires compliance with regulations.

**This guide is organized by intent:**
- "I need to integrate with existing identity providers" → OAuth 2.1 section
- "I need to handle a security incident" → Super-Admin and JWKS sections
- "I need my assistant to act on my behalf" → Delegation section
- "I need real-time alerts when things happen" → Events section
- "I need to audit who has access to what" → Advanced Zanzibar section

**Each section includes:**
- **Why this exists** - The problem it solves
- **When to use it** - Real scenarios
- **How to think about it** - Mental models
- **Step-by-step examples** - Working code
- **Common mistakes** - What to avoid

---

## Table of Contents

**Part V: OAuth 2.1 Compliance**
19. [OAuth 2.1 Authorization](#19-oauth-21-authorization)
20. [Pushed Authorization Requests (PAR)](#20-pushed-authorization-requests-par)
21. [Dynamic Client Registration](#21-dynamic-client-registration)
22. [Token Management](#22-token-management)
23. [Discovery Endpoints](#23-discovery-endpoints)

**Part VI: Enterprise Administration**
24. [Super-Admin Operations](#24-super-admin-operations)
25. [Delegation (Act-As)](#25-delegation-act-as)
26. [Quota Management](#26-quota-management)
27. [Password Policies](#27-password-policies)

**Part VII: Security Operations**
28. [JWKS Key Management](#28-jwks-key-management)
29. [Circuit Breakers](#29-circuit-breakers)
30. [Leak & Security Reports](#30-leak--security-reports)

**Part VIII: Events & Webhooks**
31. [Event Subscriptions](#31-event-subscriptions)
32. [Event Types & Patterns](#32-event-types--patterns)

**Part IX: Advanced Zanzibar**
33. [Namespaces (Custom Schemas)](#33-namespaces-custom-schemas)
34. [Visualization APIs](#34-visualization-apis)
35. [Migration Tools](#35-migration-tools)

**Part X: Monitoring & Operations**
36. [Metrics & Observability](#36-metrics--observability)
37. [Health Endpoints](#37-health-endpoints)

---

# Part V: OAuth 2.1 Compliance

## 19. OAuth 2.1 Authorization

### Why This Exists

OAuth 2.1 is the modern standard for authorization. If you're building:
- A mobile app that needs to authenticate users
- A web app that uses "Sign in with Google/Microsoft"
- A third-party integration that needs access to user data
- An API that other developers will integrate with

...you need to understand OAuth 2.1.

### The Key Concept: PKCE

**PKCE (Proof Key for Code Exchange)** is no longer optional - it's required for all clients. Here's why:

Imagine you're building a mobile app. The old OAuth flow went like this:
1. User clicks "Login"
2. App opens browser to auth server
3. User authenticates
4. Auth server redirects back with a `code`
5. App exchanges `code` for tokens using a `client_secret`

**The problem:** Mobile apps can't keep secrets. Anyone can decompile your app and extract the `client_secret`. A malicious app could intercept the redirect and steal the code.

**PKCE fixes this:**
1. App generates a random `code_verifier` (kept secret, never sent over network)
2. App creates `code_challenge` = SHA256(code_verifier)
3. App sends `code_challenge` with authorization request
4. Auth server remembers the challenge
5. When exchanging the code, app sends `code_verifier`
6. Auth server verifies: SHA256(code_verifier) == stored challenge

Even if an attacker intercepts the code, they can't exchange it without the `code_verifier`.

### Step-by-Step: Implementing OAuth with PKCE

**Step 1: Generate PKCE Values (Do this in your app, not on server)**

```bash
# Generate a cryptographically random code_verifier
# Must be 43-128 characters, URL-safe
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=' | tr '/+' '_-')
echo "Code Verifier (KEEP SECRET): $CODE_VERIFIER"

# Generate code_challenge from verifier
# This is what you send to the auth server
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl sha256 -binary | base64 | tr -d '=' | tr '/+' '_-')
echo "Code Challenge (SAFE TO SEND): $CODE_CHALLENGE"
```

**Step 2: Build the Authorization URL**

The user will visit this URL in their browser:

```bash
# Your configuration
AUTH_BASE="https://auth.service.ab0t.com"
CLIENT_ID="your_client_id"
REDIRECT_URI="https://yourapp.com/callback"  # Must be registered!
STATE=$(openssl rand -hex 16)  # Random, for CSRF protection

# Build the URL
AUTH_URL="${AUTH_BASE}/auth/authorize"
AUTH_URL+="?client_id=${CLIENT_ID}"
AUTH_URL+="&response_type=code"
AUTH_URL+="&redirect_uri=${REDIRECT_URI}"
AUTH_URL+="&scope=openid%20profile%20email"
AUTH_URL+="&state=${STATE}"
AUTH_URL+="&code_challenge=${CODE_CHALLENGE}"
AUTH_URL+="&code_challenge_method=S256"

echo "Redirect user to: $AUTH_URL"
```

**Important:** Save `STATE` and `CODE_VERIFIER` in your session. You'll need them when the user returns.

**Step 3: Handle the Callback**

After the user authenticates, they're redirected to your `redirect_uri` with:
- `code` - The authorization code (short-lived, one-time use)
- `state` - Must match what you sent (verify this!)

```bash
# User returns to: https://yourapp.com/callback?code=abc123&state=xyz789

# CRITICAL: Verify state matches what you stored
# If it doesn't match, this might be a CSRF attack - reject it!

# Extract the code
AUTH_CODE="abc123"  # From the URL
```

**Step 4: Exchange Code for Tokens**

```bash
curl -X POST "${AUTH_BASE}/auth/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "client_id=${CLIENT_ID}" \
  -d "code=${AUTH_CODE}" \
  -d "redirect_uri=${REDIRECT_URI}" \
  -d "code_verifier=${CODE_VERIFIER}"

# Response:
# {
#   "access_token": "eyJhbG...",
#   "token_type": "Bearer",
#   "expires_in": 900,
#   "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4...",
#   "scope": "openid profile email"
# }
```

### When to Use OAuth Providers vs Internal Auth

| Scenario | Recommendation |
|----------|----------------|
| Users already have Google/Microsoft accounts | Use OAuth provider |
| Enterprise customers with Okta/Azure AD | Use SAML or OAuth provider |
| You want to manage user credentials yourself | Use internal auth (`/auth/register`, `/auth/login`) |
| B2B SaaS with many enterprise customers | Support both - let them choose |

### Authenticating via External Providers (Google, Microsoft, etc.)

If your users should "Sign in with Google":

```bash
# Step 1: Start the OAuth flow with the provider
# The provider can be a type ("google") or a specific provider ID
curl -s "${AUTH_BASE}/auth/oauth/google/authorize" \
  -G \
  -d "org_id=${ORG_ID}" \
  -d "redirect_uri=https://yourapp.com/callback" \
  -d "state=${STATE}" \
  -d "code_challenge=${CODE_CHALLENGE}" \
  -d "code_challenge_method=S256"

# Response:
# { "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?..." }
```

The response contains a Google URL. Redirect your user there. After they sign in with Google, they'll be sent back to your `redirect_uri`. Then:

```bash
# Step 2: Complete the OAuth flow
curl -X POST "${AUTH_BASE}/auth/oauth/google/callback" \
  -G \
  -d "code=${GOOGLE_AUTH_CODE}" \
  -d "state=${STATE}" \
  -d "redirect_uri=https://yourapp.com/callback" \
  -d "org_id=${ORG_ID}" \
  -d "code_verifier=${CODE_VERIFIER}"

# Returns your auth service tokens (not Google's)
# {
#   "access_token": "eyJhbG...",
#   "refresh_token": "...",
#   "user": { "id": "user_123", "email": "user@gmail.com", ... }
# }
```

**What just happened:** The user authenticated with Google, and the auth service:
1. Verified the Google token
2. Created (or found) a user in your system
3. Issued your own JWT tokens for that user

---

## 20. Pushed Authorization Requests (PAR)

### Why This Exists

Standard OAuth authorization URLs can get very long. They include:
- Client ID, redirect URI, scope
- PKCE challenge
- State
- Custom parameters

**Problems with long URLs:**
1. **Browser limits:** Some browsers truncate URLs over 2,000 characters
2. **Logging exposure:** The full URL might be logged in server access logs
3. **Tampering:** Someone could modify parameters in the URL

**PAR solves this:** Instead of putting everything in the URL, you POST the parameters to the auth server first. It gives you back a short `request_uri` that references your stored parameters.

### When to Use PAR

- You have many custom parameters in your auth request
- You're passing sensitive data (like `login_hint` with an email)
- You want to ensure parameters can't be tampered with
- Your URLs are exceeding browser limits

### How PAR Works

**Without PAR (traditional):**
```
User clicks login
    ↓
App builds long URL with all parameters
    ↓
User redirected to: https://auth.../authorize?client_id=...&scope=...&state=...&...
```

**With PAR:**
```
User clicks login
    ↓
App POSTs parameters to /auth/oauth/par
    ↓
Server returns: { "request_uri": "urn:ietf:params:oauth:request_uri:abc123" }
    ↓
User redirected to: https://auth.../authorize?client_id=...&request_uri=urn:...
                    (much shorter!)
```

### Step-by-Step Example

```bash
# Step 1: Push your authorization request
PAR_RESPONSE=$(curl -X POST "${AUTH_BASE}/auth/oauth/par" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${CLIENT_ID}" \
  -d "response_type=code" \
  -d "redirect_uri=${REDIRECT_URI}" \
  -d "scope=openid profile email custom_scope" \
  -d "state=${STATE}" \
  -d "code_challenge=${CODE_CHALLENGE}" \
  -d "code_challenge_method=S256" \
  -d "login_hint=user@example.com" \
  -d "acr_values=urn:mace:incommon:iap:silver")

echo "$PAR_RESPONSE"
# {
#   "request_uri": "urn:ietf:params:oauth:request_uri:abc123def456",
#   "expires_in": 60
# }

REQUEST_URI=$(echo "$PAR_RESPONSE" | jq -r '.request_uri')

# Step 2: Build a short authorization URL
# Notice: only client_id and request_uri needed!
AUTH_URL="${AUTH_BASE}/auth/authorize?client_id=${CLIENT_ID}&request_uri=${REQUEST_URI}"

echo "Redirect user to: $AUTH_URL"
# Much shorter than including all parameters!
```

**Note:** The `request_uri` expires (typically 60 seconds). The user must be redirected quickly.

---

## 21. Dynamic Client Registration

### Why This Exists

Traditional OAuth requires you to manually register each client application:
1. Go to admin dashboard
2. Create a new client
3. Copy the client_id and client_secret
4. Configure them in your application

This works fine for a few applications, but what if:
- You're building a platform where developers create their own apps
- You have automated deployment that spins up new services
- You want to programmatically manage client applications

**Dynamic Client Registration** lets applications register themselves via API.

### When to Use This

| Scenario | Use Dynamic Registration? |
|----------|--------------------------|
| You have a few known applications | No, manual registration is fine |
| Building a developer platform | Yes, let developers register their apps |
| Microservices that need OAuth clients | Yes, automate client creation in CI/CD |
| Multi-tenant platform | Yes, create clients per tenant automatically |

### The Registration Flow

**Step 1: Register a New Client**

```bash
# Any application can register (no auth needed for basic registration)
REGISTRATION=$(curl -X POST "${AUTH_BASE}/auth/oauth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My Developer App",
    "redirect_uris": [
      "https://myapp.com/callback",
      "https://localhost:3000/callback"
    ],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
    "application_type": "web"
  }')

echo "$REGISTRATION" | jq

# Response:
# {
#   "client_id": "client_abc123xyz",
#   "client_id_issued_at": 1707012345,
#   "registration_access_token": "rat_secret_token_for_management",
#   "registration_client_uri": "https://auth.../auth/oauth/register/client_abc123xyz"
# }
```

**Understanding the response:**
- `client_id` - Use this in your OAuth flows
- `client_secret` - Only returned for confidential clients (not shown above because `token_endpoint_auth_method` is "none")
- `registration_access_token` - **Save this securely!** It's the only way to manage this client later
- `registration_client_uri` - The URL to GET/PUT/DELETE this client

**Step 2: Managing Your Client**

```bash
# Save these from registration
CLIENT_ID="client_abc123xyz"
RAT="rat_secret_token_for_management"  # Registration Access Token

# View current configuration
curl -s "${AUTH_BASE}/auth/oauth/register/${CLIENT_ID}" \
  -H "Authorization: Bearer ${RAT}" | jq

# Update configuration (e.g., add a new redirect URI)
curl -X PUT "${AUTH_BASE}/auth/oauth/register/${CLIENT_ID}" \
  -H "Authorization: Bearer ${RAT}" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My Developer App v2",
    "redirect_uris": [
      "https://myapp.com/callback",
      "https://myapp.com/v2/callback",
      "https://localhost:3000/callback"
    ],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"]
  }'

# Delete client (permanent!)
curl -X DELETE "${AUTH_BASE}/auth/oauth/register/${CLIENT_ID}" \
  -H "Authorization: Bearer ${RAT}"
```

### Client Types Explained

| Field | Options | When to Use |
|-------|---------|-------------|
| `application_type` | `web`, `native` | `web` for server-side apps, `native` for mobile/desktop |
| `token_endpoint_auth_method` | `none`, `client_secret_basic`, `client_secret_post` | `none` for public clients (mobile, SPA), others for confidential clients |
| `grant_types` | `authorization_code`, `refresh_token`, `client_credentials` | Most apps need `authorization_code` + `refresh_token` |

---

## 22. Token Management

### The Token Lifecycle

Understanding how tokens work is essential for building secure applications:

```
User authenticates
       ↓
Auth server issues:
  - access_token (short-lived, ~15 minutes)
  - refresh_token (long-lived, ~7 days)
       ↓
App uses access_token for API calls
       ↓
access_token expires
       ↓
App uses refresh_token to get new access_token
       ↓
Eventually refresh_token expires → user must re-authenticate
```

### Token Introspection: "Is this token valid?"

**When to use:** You're building a resource server (API) that receives tokens from clients. Before processing a request, you need to verify the token is valid.

**Two ways to validate:**
1. **Local validation** - Verify JWT signature yourself using JWKS (faster, but can't check if token was revoked)
2. **Introspection** - Ask the auth server (slower, but always accurate)

Use introspection when:
- You need to check if a token was revoked
- You don't want to manage JWKS key rotation
- You need additional token metadata

```bash
# Ask the auth server: "Is this token valid?"
curl -X POST "${AUTH_BASE}/token/introspect" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=${ACCESS_TOKEN}" \
  -d "token_type_hint=access_token"

# If valid:
# {
#   "active": true,
#   "sub": "user_123",
#   "client_id": "client_abc",
#   "scope": "openid profile",
#   "exp": 1707100000,
#   "iat": 1707099100,
#   "iss": "https://auth.service.ab0t.com",
#   "org_id": "org_xyz",
#   "permissions": ["resource.read", "resource.write"]
# }

# If invalid/expired/revoked:
# { "active": false }
```

**Important:** A response of `{ "active": false }` doesn't tell you *why* it's invalid (expired? revoked? malformed?). This is intentional - it prevents information leakage.

### Token Revocation: "Invalidate this token now"

**When to use:**
- User logs out (revoke both tokens)
- User changes password (revoke all their tokens)
- Security incident (revoke compromised tokens)
- User removes app access (revoke that app's tokens)

```bash
# Revoke an access token
curl -X POST "${AUTH_BASE}/token/revoke" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=${ACCESS_TOKEN}" \
  -d "token_type_hint=access_token"

# Revoke a refresh token (also invalidates any access tokens it issued)
curl -X POST "${AUTH_BASE}/token/revoke" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=${REFRESH_TOKEN}" \
  -d "token_type_hint=refresh_token"

# Response is always 200 OK, even if token was already invalid
# This prevents attackers from learning whether a token existed
```

### Token Refresh: Getting new tokens

```bash
# Your access_token expired, use refresh_token to get a new one
curl -X POST "${AUTH_BASE}/token/refresh" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "refresh_token=${REFRESH_TOKEN}" \
  -d "client_id=${CLIENT_ID}"

# Response:
# {
#   "access_token": "new_eyJhbG...",
#   "token_type": "Bearer",
#   "expires_in": 900,
#   "refresh_token": "new_refresh_token..."  # May be rotated!
# }
```

**Watch out for refresh token rotation:** The response may include a new `refresh_token`. If it does, you **must** save and use the new one. The old refresh token may no longer work. This is a security feature that limits the damage if a refresh token is stolen.

---

## 23. Discovery Endpoints

### Why Discovery Matters

Hard-coding URLs is fragile. What if the auth server moves? What if endpoints change?

**Discovery endpoints** let your application automatically find all the URLs it needs. Just configure the base URL, and your app discovers everything else.

### OpenID Connect Discovery

This is the standard way to discover an OpenID Connect provider:

```bash
curl -s "${AUTH_BASE}/.well-known/openid-configuration" | jq

# Response includes everything your app needs:
# {
#   "issuer": "https://auth.service.ab0t.com",
#   "authorization_endpoint": "https://auth.../auth/authorize",
#   "token_endpoint": "https://auth.../auth/oauth/token",
#   "userinfo_endpoint": "https://auth.../users/me",
#   "jwks_uri": "https://auth.../.well-known/jwks.json",
#   "registration_endpoint": "https://auth.../auth/oauth/register",
#   "scopes_supported": ["openid", "profile", "email", "offline_access"],
#   "response_types_supported": ["code"],
#   "grant_types_supported": ["authorization_code", "refresh_token"],
#   "token_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
#   "code_challenge_methods_supported": ["S256"]
# }
```

**Best practice:** At startup, your application should:
1. Fetch the discovery document
2. Cache the endpoints (refresh periodically)
3. Use the discovered URLs for all operations

### JWKS: Getting Public Keys for Token Validation

If you're validating JWT tokens locally (recommended for performance), you need the public keys:

```bash
# Get all public keys
curl -s "${AUTH_BASE}/.well-known/jwks.json" | jq

# Response:
# {
#   "keys": [
#     {
#       "kty": "RSA",
#       "kid": "key_abc123",      # Key ID - tokens reference this
#       "use": "sig",              # This key is for signatures
#       "alg": "RS256",
#       "n": "0vx7agoebG...",     # RSA modulus
#       "e": "AQAB"                # RSA exponent
#     }
#   ]
# }
```

**How to use these keys:**
1. When you receive a JWT, look at its `kid` (key ID) in the header
2. Find the matching key in the JWKS
3. Use that key to verify the token's signature

**Important:** Keys rotate! Your application should:
- Cache JWKS for performance (e.g., 1 hour)
- Re-fetch if you encounter an unknown `kid`
- Handle key rotation gracefully

```bash
# Force refresh (bypass cache) - useful after key rotation
curl -s "${AUTH_BASE}/.well-known/jwks.json?refresh=true" | jq

# Get keys for a specific organization (multi-tenant)
curl -s "${AUTH_BASE}/organizations/${ORG_ID}/.well-known/jwks.json" | jq
```

---

# Part VI: Enterprise Administration

## 24. Super-Admin Operations

### Why This Exists

Normal admin permissions handle day-to-day operations. But sometimes you need **extraordinary access**:

- A critical production issue requires immediate access to all systems
- A security incident requires investigating across all organizations
- An emergency deployment needs permissions that no one normally has

**Super-admin** provides time-limited, audited, approval-required elevated access.

### The Philosophy: Minimal Privilege with Emergency Escape Hatches

The principle of least privilege says: "Give people only the access they need."

But what happens at 3 AM when production is down and the one person with access is unreachable?

Super-admin is the answer: **Anyone can request elevated access, but it requires:**
1. **Justification** - Why do you need this?
2. **Time limit** - Access automatically expires (max 24 hours)
3. **Dual approval** - Another admin must approve (except emergencies)
4. **Complete audit trail** - Every action is logged
5. **MFA verification** - Prove you are who you say you are

### When to Use Super-Admin

| Scenario | Use Super-Admin? |
|----------|-----------------|
| Daily admin tasks | No, use regular admin role |
| Debugging a customer issue | Maybe, if you need cross-org access |
| Security incident response | Yes |
| Emergency production access | Yes |
| One-time data migration | Yes |
| "I want more access" | No, request permanent role change |

### The Super-Admin Flow

**Step 1: Request Elevated Access**

```bash
# I'm an admin, but I need super-admin for an incident
curl -X POST "${AUTH_BASE}/super-admin/grant" \
  -H "Authorization: Bearer ${MY_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "target_user_id": "user_me",
    "duration_hours": 4,
    "reason": "Security incident INC-2345: Investigating unauthorized access patterns across multiple orgs",
    "mfa_code": "123456",
    "require_approval": true
  }'

# Response:
# {
#   "request_id": "req_abc123",
#   "status": "pending_approval",
#   "expires_at": "2026-02-04T18:00:00Z",
#   "message": "Request submitted. Awaiting approval from another admin."
# }
```

**Step 2: Another Admin Approves**

```bash
# A different admin receives the request and approves
curl -X POST "${AUTH_BASE}/super-admin/approve" \
  -H "Authorization: Bearer ${OTHER_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "request_id": "req_abc123",
    "mfa_code": "654321"
  }'

# Now the original requester has super-admin access for 4 hours
```

**Important rules:**
- You cannot approve your own request
- The approver must have `system.admin` permission
- MFA is required for both requester and approver

**Step 3: Monitor and Manage Active Grants**

```bash
# Who currently has super-admin access?
curl -s "${AUTH_BASE}/super-admin/active-grants" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq

# Response:
# {
#   "grants": [
#     {
#       "user_id": "user_me",
#       "granted_at": "2026-02-04T14:00:00Z",
#       "expires_at": "2026-02-04T18:00:00Z",
#       "reason": "Security incident INC-2345...",
#       "approved_by": "user_other_admin",
#       "remaining_minutes": 180
#     }
#   ]
# }
```

**Step 4: Extend or Revoke**

```bash
# Incident is taking longer than expected, need more time
# (Can only extend up to 24 hours total)
curl -X POST "${AUTH_BASE}/super-admin/extend" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "additional_hours": 2,
    "reason": "Incident still ongoing, need to complete forensic analysis"
  }' \
  -G -d "user_id=user_me"

# Incident resolved, revoke access immediately
curl -X POST "${AUTH_BASE}/super-admin/revoke" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user_me",
    "reason": "Incident INC-2345 resolved, access no longer needed"
  }'
```

### Auditing Super-Admin Usage

Every super-admin action is logged and queryable:

```bash
curl -s "${AUTH_BASE}/super-admin/audit-log?days=30" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq

# Response shows:
# - When access was requested, by whom, why
# - When it was approved/denied, by whom
# - When it expired or was revoked
# - What actions were taken with elevated access
```

---

## 25. Delegation (Act-As)

### Why This Exists

Real organizations have complex workflows:
- An executive assistant manages calendars for multiple executives
- A support agent needs to see what a customer sees to debug their issue
- A manager approves expense reports on behalf of their team
- An automated system needs to perform actions as a specific user

**Delegation** lets User A act on behalf of User B, with:
- Explicit permission from User B
- Scoped access (only specific permissions, not everything)
- Time limits
- Full audit trail (the system knows it was A acting as B)

### How Delegation Differs from Other Approaches

| Approach | Pros | Cons |
|----------|------|------|
| **Share password** | Simple | Insecure, no audit trail, can't revoke |
| **Give A all of B's permissions** | Works | A has too much power, persists after need is gone |
| **Admin access** | Powerful | Overkill for specific tasks |
| **Delegation** | Scoped, audited, time-limited | Requires setup |

### Setting Up Delegation

**Scenario:** Alice is the CEO. Bob is her executive assistant. Bob needs to manage Alice's calendar and send emails on her behalf.

**Step 1: Alice grants delegation to Bob**

```bash
# Alice (the target) grants specific permissions to Bob (the actor)
curl -X POST "${AUTH_BASE}/delegation/grant" \
  -H "Authorization: Bearer ${ALICE_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "actor_id": "user_bob",
    "target_id": "user_alice",
    "permissions": [
      "calendar.read",
      "calendar.write",
      "email.send"
    ],
    "expires_at": "2026-12-31T23:59:59Z",
    "reason": "Executive assistant access"
  }'

# Response:
# {
#   "delegation_id": "del_abc123",
#   "actor": "user_bob",
#   "target": "user_alice",
#   "permissions": ["calendar.read", "calendar.write", "email.send"],
#   "expires_at": "2026-12-31T23:59:59Z",
#   "created_at": "2026-02-04T10:00:00Z"
# }
```

**Step 2: Bob creates a delegated token to act as Alice**

```bash
# Bob wants to perform actions as Alice
curl -X POST "${AUTH_BASE}/auth/delegate" \
  -H "Authorization: Bearer ${BOB_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "target_user_id": "user_alice",
    "scope": "calendar.read calendar.write"
  }'

# Response:
# {
#   "access_token": "eyJhbG...",
#   "token_type": "delegated",
#   "expires_in": 900,
#   "actor": "user_bob",
#   "subject": "user_alice"
# }
```

**Step 3: Bob uses the delegated token**

```bash
# This request appears to come from Alice, but the system knows Bob is acting
curl -X POST "https://calendar.api/meetings" \
  -H "Authorization: Bearer ${DELEGATED_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"title": "Board Meeting", ...}'

# The calendar service sees:
# - sub (subject): user_alice
# - act (actor): user_bob
# - The meeting is created as Alice
# - Audit log shows: "Bob acting as Alice created meeting"
```

### Managing Delegations

```bash
# Check if Bob can act as Alice
curl -s "${AUTH_BASE}/delegation/check/user_alice" \
  -H "Authorization: Bearer ${BOB_TOKEN}" \
  -G -d "acting_as=user_bob"

# Response:
# {
#   "allowed": true,
#   "permissions": ["calendar.read", "calendar.write", "email.send"],
#   "expires_at": "2026-12-31T23:59:59Z"
# }

# List all delegations for a user (as target or actor)
curl -s "${AUTH_BASE}/delegation/list/user_alice" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq

# Response shows delegations where Alice is the target (gave access to others)
# and delegations where Alice is the actor (received access from others)

# Revoke delegation
curl -X DELETE "${AUTH_BASE}/delegation/revoke/user_bob" \
  -H "Authorization: Bearer ${ALICE_TOKEN}"
```

### Common Mistakes with Delegation

1. **Granting too many permissions** - Only grant what's needed
2. **Forgetting expiration** - Always set an `expires_at`
3. **Not checking delegation exists** - Verify before creating delegated tokens
4. **Ignoring audit trail** - The point is accountability

---

## 26. Quota Management

### Why Quotas Exist

Without limits:
- One customer could consume all your resources
- A bug could create millions of entities
- Pricing tiers would be meaningless
- You couldn't plan capacity

**Quotas** enforce limits per organization based on their plan tier.

### Understanding Your Quotas

```bash
# What are my current limits and usage?
curl -s "${AUTH_BASE}/quotas/my-usage" \
  -H "Authorization: Bearer ${TOKEN}" | jq

# Response:
# {
#   "tier": "professional",
#   "quotas": {
#     "users": { "limit": 100, "used": 45, "remaining": 55 },
#     "teams": { "limit": 20, "used": 8, "remaining": 12 },
#     "api_keys": { "limit": 50, "used": 12, "remaining": 38 },
#     "organizations": { "limit": 5, "used": 2, "remaining": 3 },
#     "api_calls_per_month": { "limit": 1000000, "used": 234567, "remaining": 765433 }
#   }
# }
```

### Pre-Checking Before Operations

Before creating a resource, check if you have quota:

```bash
# Will this user creation succeed?
curl -s "${AUTH_BASE}/quotas/check/users" \
  -H "Authorization: Bearer ${TOKEN}" \
  -G -d "org_id=${ORG_ID}" | jq

# Response if OK:
# {
#   "allowed": true,
#   "resource_type": "users",
#   "current": 45,
#   "limit": 100,
#   "remaining": 55
# }

# Response if at limit:
# {
#   "allowed": false,
#   "resource_type": "users",
#   "current": 100,
#   "limit": 100,
#   "remaining": 0,
#   "message": "User quota exceeded. Upgrade to enterprise for unlimited users."
# }
```

### Available Quota Tiers

```bash
curl -s "${AUTH_BASE}/quotas/tiers" | jq

# Response:
# {
#   "tiers": {
#     "free": {
#       "users": 10,
#       "teams": 3,
#       "api_keys": 5,
#       "organizations": 1,
#       "api_calls_per_month": 10000
#     },
#     "professional": {
#       "users": 100,
#       "teams": 20,
#       "api_keys": 50,
#       "organizations": 5,
#       "api_calls_per_month": 1000000
#     },
#     "enterprise": {
#       "users": -1,         // -1 means unlimited
#       "teams": -1,
#       "api_keys": -1,
#       "organizations": -1,
#       "api_calls_per_month": -1
#     }
#   }
# }
```

---

## 27. Password Policies

### Why Password Policies Matter

Weak passwords are the #1 cause of account compromise. But users resist strong password requirements because they're inconvenient.

**Password policies** let you balance security with usability for your organization's needs.

### Setting a Password Policy

```bash
curl -X POST "${AUTH_BASE}/admin/password-policy" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "org_id": "'"${ORG_ID}"'",

    "min_length": 12,
    "max_length": 128,
    "require_uppercase": true,
    "require_lowercase": true,
    "require_numbers": true,
    "require_special": true,

    "max_age_days": 90,
    "history_count": 5,

    "lockout_threshold": 5,
    "lockout_duration_minutes": 30,

    "require_mfa_for_admins": true,
    "allow_common_passwords": false
  }'
```

**What these settings mean:**

| Setting | Purpose | Recommendation |
|---------|---------|----------------|
| `min_length` | Minimum password length | 12+ for modern security |
| `require_*` | Character requirements | Enable all for sensitive systems |
| `max_age_days` | Force password change after N days | 90 days is common; some argue against rotation |
| `history_count` | Remember last N passwords, prevent reuse | 5-10 |
| `lockout_threshold` | Lock account after N failed attempts | 5-10 |
| `lockout_duration_minutes` | How long lockout lasts | 30 minutes |
| `require_mfa_for_admins` | Admins must have MFA enabled | Always true |
| `allow_common_passwords` | Allow "password123", etc. | Always false |

### Responding to Security Incidents

If you suspect passwords may have been compromised:

```bash
# Force everyone in the org to reset their password
curl -X POST "${AUTH_BASE}/admin/password-policy/force-reset" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "org_id": "'"${ORG_ID}"'",
    "reason": "Security incident - potential credential exposure",
    "exclude_service_accounts": true,
    "notify_users": true
  }'

# Response:
# {
#   "affected_users": 145,
#   "excluded_service_accounts": 12,
#   "notifications_sent": 145,
#   "message": "All users must reset password on next login"
# }
```

### Monitoring Compliance

```bash
# Are users following the password policy?
curl -s "${AUTH_BASE}/admin/reports/password-compliance?org_id=${ORG_ID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq

# Response:
# {
#   "org_id": "org_123",
#   "policy": { ... current policy ... },
#   "compliance": {
#     "total_users": 150,
#     "compliant": 142,
#     "non_compliant": 8,
#     "compliance_rate": 94.67
#   },
#   "password_age": {
#     "expired": 3,
#     "expiring_within_7_days": 12,
#     "expiring_within_30_days": 28
#   },
#   "mfa_status": {
#     "enabled": 145,
#     "disabled": 5,
#     "required_but_missing": 2  // Admins without MFA!
#   },
#   "non_compliant_users": [
#     { "user_id": "user_123", "issues": ["password_expired", "mfa_missing"] }
#   ]
# }
```

---

# Part VII: Security Operations

## 28. JWKS Key Management

### Understanding JWT Signing Keys

When the auth service issues a JWT token, it signs the token with a private key. Anyone can verify the signature using the corresponding public key (served via JWKS).

**Why key management matters:**
- If a private key is compromised, attackers can forge tokens
- Old keys must be rotated to limit exposure window
- You need to be able to emergency-revoke keys if compromised
- Keys must be rotated without breaking existing tokens

### The Key Lifecycle

```
Generate → Activate → Active (signing tokens) → Rotate → Grace Period → Cleanup
                          ↓
                   (If compromised)
                          ↓
                       Revoke
```

**Key states:**
- **Pending** - Generated but not yet used
- **Active** - Currently used to sign new tokens
- **Rotated** - No longer signs new tokens, but still validates old tokens (grace period)
- **Revoked** - Immediately invalid, tokens signed with it are rejected
- **Expired** - Past grace period, can be cleaned up

### Routine Key Rotation

You should rotate keys regularly (e.g., every 90 days) even without incidents:

```bash
# Check current status
curl -s "${AUTH_BASE}/admin/jwks/rotation-status" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq

# Response:
# {
#   "current_key": {
#     "kid": "key_abc123",
#     "created_at": "2025-11-01T00:00:00Z",
#     "age_days": 95
#   },
#   "rotation_policy": {
#     "max_age_days": 90,
#     "grace_period_hours": 24
#   },
#   "status": "rotation_recommended"
# }

# When is the next scheduled rotation?
curl -s "${AUTH_BASE}/admin/jwks/next-rotation" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq

# Perform rotation
curl -X POST "${AUTH_BASE}/admin/jwks/rotate" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "Scheduled quarterly rotation",
    "key_size": 2048,
    "algorithm": "RS256"
  }'

# Response:
# {
#   "new_key": { "kid": "key_def456", "status": "active" },
#   "old_key": { "kid": "key_abc123", "status": "rotated", "valid_until": "..." },
#   "message": "Rotation complete. Old key valid for 24 hour grace period."
# }
```

### Emergency Key Revocation

If a key is compromised, revoke it immediately:

```bash
# EMERGENCY: Revoke compromised key
curl -X POST "${AUTH_BASE}/admin/jwks/revoke/key_abc123" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "Key possibly compromised - security incident SEC-1234"
  }'

# Response:
# {
#   "revoked_key": "key_abc123",
#   "revoked_at": "2026-02-04T10:30:00Z",
#   "impact": "All tokens signed with this key are now invalid",
#   "affected_tokens_estimate": 15234
# }
```

**Warning:** Revoking a key immediately invalidates ALL tokens signed with it. Users will be logged out and must re-authenticate. Only do this for actual security incidents.

### Manual Key Management

For more control, you can manage keys step by step:

```bash
# Step 1: Generate a new key (not yet active)
NEW_KEY=$(curl -X POST "${AUTH_BASE}/admin/jwks/generate" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "key_size": 2048,
    "algorithm": "RS256",
    "purpose": "signing"
  }')

NEW_KID=$(echo "$NEW_KEY" | jq -r '.kid')
echo "Generated key: $NEW_KID (status: pending)"

# Step 2: When ready, activate the key
curl -X POST "${AUTH_BASE}/admin/jwks/activate/${NEW_KID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# Step 3: Clean up old keys after grace period
curl -X POST "${AUTH_BASE}/admin/jwks/cleanup" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "dry_run": true  // Preview what would be deleted
  }'

# If preview looks good, actually delete:
curl -X POST "${AUTH_BASE}/admin/jwks/cleanup" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "dry_run": false
  }'
```

### JWKS Recovery

If JWT signing is completely broken (e.g., database corruption):

```bash
# Emergency recovery - activates any available keys
curl -X POST "${AUTH_BASE}/health/jwks/recover" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### Auditing Key Operations

```bash
# See all key revocations
curl -s "${AUTH_BASE}/admin/audit/revocations?limit=100" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq

# See revocations for a specific key
curl -s "${AUTH_BASE}/admin/audit/revocations?kid=key_abc123" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq
```

---

## 29. Circuit Breakers

### What Are Circuit Breakers?

Circuit breakers prevent cascading failures. If a downstream service (database, external OAuth provider, etc.) starts failing, the circuit breaker "opens" and fails fast instead of waiting for timeouts.

**States:**
- **Closed** - Normal operation, requests pass through
- **Open** - Service is failing, requests fail immediately (don't wait for timeout)
- **Half-Open** - Testing if service recovered, allowing limited requests

### Monitoring Circuit Breakers

```bash
curl -s "${AUTH_BASE}/admin/circuit-breakers/status" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq

# Response:
# {
#   "breakers": {
#     "database": {
#       "state": "closed",
#       "failure_rate": 0.001,
#       "last_failure": null
#     },
#     "redis": {
#       "state": "closed",
#       "failure_rate": 0.0
#     },
#     "external_oauth_google": {
#       "state": "half_open",     // <-- Recovering
#       "failure_rate": 0.15,
#       "failures_in_window": 23,
#       "last_failure": "2026-02-04T10:25:00Z"
#     },
#     "external_oauth_microsoft": {
#       "state": "open",          // <-- Down!
#       "failure_rate": 0.85,
#       "opens_at": "2026-02-04T10:20:00Z",
#       "estimated_recovery": "2026-02-04T10:35:00Z"
#     }
#   }
# }
```

### Resetting Circuit Breakers

Sometimes a circuit breaker gets stuck open even after the downstream service recovers:

```bash
# Reset a specific breaker
curl -X POST "${AUTH_BASE}/admin/circuit-breakers/external_oauth_microsoft/reset" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# Nuclear option: reset ALL breakers
# Use with caution - may cause cascade of failures if services aren't ready
curl -X POST "${AUTH_BASE}/admin/circuit-breakers/reset-all" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

---

## 30. Leak & Security Reports

### Why This Exists

Credentials get leaked:
- Developer accidentally commits API key to public GitHub repo
- Configuration file with secrets uploaded to public S3 bucket
- Employee shares credentials in public Slack channel

**The auth service accepts leak reports** so that:
- Good actors can report leaked credentials they find
- The organization can be notified quickly
- Leaked credentials can be rotated before abuse

### Reporting a Leaked Credential

Anyone can submit a report, even anonymously:

```bash
# Report a leaked API key found on GitHub
curl -X POST "${AUTH_BASE}/reports" \
  -H "Content-Type: application/json" \
  -d '{
    "reports": [
      {
        "category": "leak",
        "credential_type": "api_key",
        "credential_value": "ab0t_sk_live_EXPOSED_KEY_DO_NOT_USE",
        "source": "GitHub public repository",
        "url": "https://github.com/someuser/project/blob/main/config.py#L42",
        "discovered_at": "2026-02-04T09:00:00Z"
      }
    ]
  }'

# Response (same whether credential exists or not - prevents confirmation attacks):
# {
#   "accepted": 1,
#   "message": "Thank you for your report. If valid, the affected organization will be notified."
# }
```

**Security note:** The response intentionally doesn't confirm whether the credential is valid. This prevents attackers from using the report endpoint to verify stolen credentials.

### Managing Reports as an Admin

```bash
# List reports matched to my organization
curl -s "${AUTH_BASE}/reports" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -G \
  -d "category_filter=leak" \
  -d "status_filter=pending" | jq

# Response:
# {
#   "reports": [
#     {
#       "id": "report_abc123",
#       "category": "leak",
#       "credential_type": "api_key",
#       "credential_hint": "ab0t_sk_live_EXP...USE",  // Partial, for identification
#       "source": "GitHub public repository",
#       "url": "https://github.com/...",
#       "status": "pending",
#       "reported_at": "2026-02-04T09:00:00Z"
#     }
#   ]
# }

# It's a false positive (test credential, not real)
curl -X POST "${AUTH_BASE}/reports/report_abc123/dismiss" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# It's real, and I've rotated the credential
curl -X POST "${AUTH_BASE}/reports/report_abc123/resolve" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "resolution_notes": "Credential rotated, source removed from public repo"
  }'
```

### Other Report Types

```bash
# Bug report
curl -X POST "${AUTH_BASE}/reports" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "reports": [{
      "category": "bug",
      "description": "Login fails intermittently on Safari",
      "steps_to_reproduce": "1. Use Safari 17\n2. Click login\n3. Sometimes fails with 500"
    }]
  }'

# Security vulnerability report
curl -X POST "${AUTH_BASE}/reports" \
  -H "Content-Type: application/json" \
  -d '{
    "reports": [{
      "category": "security",
      "severity": "high",
      "description": "Potential CSRF in password reset flow",
      "contact_email": "security_researcher@example.com"
    }]
  }'
```

---

# Part VIII: Events & Webhooks

## 31. Event Subscriptions

### Why Events Matter

Your auth service knows when important things happen:
- User logged in from a new device
- Admin granted elevated permissions
- API key was created or revoked
- Multiple failed login attempts (possible attack)

**Event subscriptions** let you react to these in real-time:
- Send alerts to Slack/PagerDuty
- Update external systems
- Trigger security workflows
- Build audit dashboards

### Designing Your Event Strategy

Before creating subscriptions, think about:

1. **What do you need to know?** (Security events? All logins? Permission changes?)
2. **How quickly?** (Real-time webhook? Or is batch OK?)
3. **What will you do with it?** (Alert humans? Update another system?)

**Example strategies:**

| Goal | Events to Subscribe | Endpoint |
|------|---------------------|----------|
| Security monitoring | `user.login.failed`, `suspicious_activity`, `api_key.revoked` | Security SIEM |
| User analytics | `user.login.success`, `user.created` | Analytics service |
| Compliance audit | All events | Audit log system |
| Real-time notifications | `permission.granted`, `user.invited` | Slack webhook |

### Creating a Subscription

```bash
# First, see what events are available
curl -s "${AUTH_BASE}/events/types" | jq

# Response is organized by category:
# {
#   "authentication": [
#     { "type": "user.login.success", "description": "User successfully logged in" },
#     { "type": "user.login.failed", "description": "Login attempt failed" },
#     ...
#   ],
#   "security": [
#     { "type": "suspicious_activity", "description": "Suspicious activity detected" },
#     ...
#   ],
#   ...
# }

# Create a subscription for security events
curl -X POST "${AUTH_BASE}/events/subscriptions" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Security Alerts to Slack",
    "description": "Send critical security events to the #security-alerts channel",

    "event_types": [
      "user.login.failed",
      "suspicious_activity",
      "api_key.created",
      "api_key.revoked",
      "super_admin.granted"
    ],

    "endpoint": "https://hooks.slack.com/services/T.../B.../xxx",
    "headers": {
      "Content-Type": "application/json"
    },

    "filters": {
      "org_id": "'"${ORG_ID}"'"
    },

    "retry_policy": {
      "max_retries": 3,
      "initial_delay_ms": 1000,
      "backoff_multiplier": 2
    },

    "is_active": true
  }'

# Response:
# {
#   "id": "sub_abc123",
#   "name": "Security Alerts to Slack",
#   "status": "active",
#   "created_at": "2026-02-04T11:00:00Z"
# }
```

### Testing Your Subscription

Before relying on a subscription, test it:

```bash
# Send a test event
curl -X POST "${AUTH_BASE}/events/subscriptions/sub_abc123/test" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# Response:
# {
#   "test_event_sent": true,
#   "delivery_status": "success",
#   "response_code": 200,
#   "response_time_ms": 234
# }
```

### Monitoring Delivery

```bash
# How reliable is delivery?
curl -s "${AUTH_BASE}/events/subscriptions/sub_abc123/stats?days=7" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq

# Response:
# {
#   "subscription_id": "sub_abc123",
#   "period_days": 7,
#   "total_events": 1547,
#   "successful_deliveries": 1532,
#   "failed_deliveries": 15,
#   "success_rate": 99.03,
#   "average_latency_ms": 187,
#   "p99_latency_ms": 523
# }
```

### Managing Subscriptions

```bash
# List all subscriptions
curl -s "${AUTH_BASE}/events/subscriptions" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq

# Pause a subscription (keep config, stop delivery)
curl -X POST "${AUTH_BASE}/events/subscriptions/sub_abc123/toggle?is_active=false" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# Resume it
curl -X POST "${AUTH_BASE}/events/subscriptions/sub_abc123/toggle?is_active=true" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# Update subscription
curl -X PATCH "${AUTH_BASE}/events/subscriptions/sub_abc123" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "event_types": ["user.login.failed", "suspicious_activity"],
    "retry_policy": { "max_retries": 5 }
  }'

# Delete subscription
curl -X DELETE "${AUTH_BASE}/events/subscriptions/sub_abc123" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

---

## 32. Event Types & Patterns

### Event Categories Reference

| Category | Events | Use Cases |
|----------|--------|-----------|
| **Authentication** | `user.login.success`, `user.login.failed`, `user.logout`, `token.refresh`, `token.revoked` | Security monitoring, session analytics |
| **User Management** | `user.created`, `user.updated`, `user.deleted`, `user.invited`, `user.activated`, `user.deactivated` | User lifecycle tracking, provisioning |
| **Permission** | `permission.granted`, `permission.revoked`, `role.assigned`, `role.removed` | Access control audit, compliance |
| **Organization** | `org.created`, `org.updated`, `team.created`, `team.deleted`, `member.added`, `member.removed` | Organization structure tracking |
| **Security** | `api_key.created`, `api_key.revoked`, `suspicious_activity`, `mfa.enabled`, `mfa.disabled`, `password.changed` | Security alerting |
| **Admin** | `super_admin.granted`, `super_admin.revoked`, `password_policy.updated`, `force_password_reset` | Privileged action monitoring |

### Event Payload Format

All events follow a consistent format:

```json
{
  "event_id": "evt_abc123",
  "event_type": "user.login.success",
  "timestamp": "2026-02-04T11:30:00.123Z",
  "org_id": "org_xyz",
  "actor": {
    "id": "user_123",
    "email": "user@example.com",
    "type": "user"
  },
  "target": {
    "id": "user_123",
    "type": "user"
  },
  "data": {
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0...",
    "method": "password"
  },
  "metadata": {
    "request_id": "req_xyz789"
  }
}
```

### Common Integration Patterns

**Pattern 1: Security Alerting**
```
Events: login.failed, suspicious_activity
→ Slack/PagerDuty webhook
→ Human investigates
```

**Pattern 2: Audit Logging**
```
Events: All events
→ Your audit log service / SIEM
→ Compliance reports
```

**Pattern 3: User Provisioning**
```
Events: user.created, user.deleted
→ Your provisioning service
→ Create/remove accounts in other systems
```

**Pattern 4: Analytics**
```
Events: login.success, user.created
→ Analytics warehouse
→ Dashboards
```

---

# Part IX: Advanced Zanzibar

## 33. Namespaces (Custom Schemas)

### Why Custom Namespaces?

Part 1 covered basic Zanzibar relationships like `document:123#viewer@user:alice`. But what relations and permissions are valid?

**Namespaces** define the schema:
- What object types exist (document, folder, team)
- What relations are valid (owner, editor, viewer)
- What permissions each relation grants
- How permissions inherit

### Real-World Example: Document Sharing

Let's model Google Docs-style sharing:

```bash
curl -X POST "${AUTH_BASE}/zanzibar/namespaces" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "document",
    "description": "Documents with owner/editor/viewer/commenter sharing",

    "relations": {
      "owner": {
        "description": "Full control over the document",
        "direct_users": true,
        "direct_teams": false,
        "permissions": ["read", "write", "delete", "share", "change_owner"]
      },

      "editor": {
        "description": "Can edit but not delete or share",
        "direct_users": true,
        "direct_teams": true,
        "permissions": ["read", "write"]
      },

      "commenter": {
        "description": "Can read and add comments",
        "direct_users": true,
        "direct_teams": true,
        "permissions": ["read", "comment"]
      },

      "viewer": {
        "description": "Read-only access",
        "direct_users": true,
        "direct_teams": true,
        "inherits_from": ["owner", "editor", "commenter"],
        "permissions": ["read"]
      }
    }
  }'
```

**What this defines:**
- `document:X#owner@user:Y` means Y is the owner of document X
- Owners can read, write, delete, share, and change owner
- Editors can read and write
- Anyone with viewer relation can read
- Viewers inherit from owner/editor/commenter, so checking `viewer` returns true for all of them

### Using Custom Namespaces

```bash
# Alice creates a document
curl -X POST "${AUTH_BASE}/zanzibar/relationships" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "object": "document:doc_123",
    "relation": "owner",
    "subject": "user:alice"
  }'

# Alice shares with Bob as editor
curl -X POST "${AUTH_BASE}/zanzibar/relationships" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "object": "document:doc_123",
    "relation": "editor",
    "subject": "user:bob"
  }'

# Alice shares with the design team as viewers
curl -X POST "${AUTH_BASE}/zanzibar/relationships" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "object": "document:doc_123",
    "relation": "viewer",
    "subject": "team:design"
  }'

# Check: Can Bob write?
curl -X POST "${AUTH_BASE}/zanzibar/check" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "object": "document:doc_123",
    "permission": "write",
    "subject": "user:bob"
  }'
# { "allowed": true }  -- Bob is an editor

# Check: Can Carol (on design team) write?
curl -X POST "${AUTH_BASE}/zanzibar/check" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "object": "document:doc_123",
    "permission": "write",
    "subject": "user:carol"
  }'
# { "allowed": false }  -- Design team only has viewer access
```

---

## 34. Visualization APIs

### Understanding Permission Graphs

Real permission models are complex. The visualization APIs help you:
- Debug why someone has (or doesn't have) access
- Generate org charts for documentation
- Build admin UIs that show permission inheritance

### Visualize Organization Hierarchy

```bash
curl -X POST "${AUTH_BASE}/zanzibar/visualize/hierarchy" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "org_id": "'"${ORG_ID}"'",
    "include_users": true,
    "include_teams": true,
    "max_depth": 5
  }'

# Returns D3.js-compatible tree structure:
# {
#   "name": "Acme Corp",
#   "type": "organization",
#   "id": "org_123",
#   "children": [
#     {
#       "name": "Engineering",
#       "type": "team",
#       "id": "team_eng",
#       "children": [
#         { "name": "Backend", "type": "team", "children": [...] },
#         { "name": "Frontend", "type": "team", "children": [...] }
#       ]
#     },
#     {
#       "name": "Sales",
#       "type": "team",
#       "children": [...]
#     }
#   ]
# }
```

### Visualize User's Permissions

"Why does Alice have this permission?"

```bash
curl -X POST "${AUTH_BASE}/zanzibar/visualize/permissions?user_id=user_alice" \
  -H "Authorization: Bearer ${TOKEN}"

# Returns graph showing:
# - Direct permissions granted to Alice
# - Permissions inherited from teams
# - Permissions inherited from org roles
# - The path through which each permission was granted
```

### Expand a Permission

"Who has access to this document, and how?"

```bash
curl -X POST "${AUTH_BASE}/zanzibar/expand" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "object": "document:doc_123",
    "permission": "write"
  }'

# Response shows the "userset tree":
# {
#   "permission": "write",
#   "object": "document:doc_123",
#   "subjects": [
#     {
#       "subject": "user:alice",
#       "path": "document:doc_123#owner → user:alice",
#       "direct": true
#     },
#     {
#       "subject": "user:bob",
#       "path": "document:doc_123#editor → user:bob",
#       "direct": true
#     }
#   ]
# }
```

---

## 35. Migration Tools

### Migrating to Zanzibar

If you have existing flat permissions, migrate them to Zanzibar relationships:

```bash
# Setup default namespaces first
curl -X POST "${AUTH_BASE}/zanzibar/migrate/setup-defaults" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# Migrate a user's permissions
curl -X POST "${AUTH_BASE}/zanzibar/migrate/permissions" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -G \
  -d "user_id=user_123" \
  -d "permissions=document.read" \
  -d "permissions=document.write" \
  -d "permissions=billing.admin"

# The service translates flat permissions to relationships:
# document.read → relationships in document namespace
# billing.admin → relationships in billing namespace
```

---

# Part X: Monitoring & Operations

## 36. Metrics & Observability

### Prometheus Metrics

The auth service exports Prometheus-format metrics:

```bash
curl -s "${AUTH_BASE}/metrics" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# Returns Prometheus text format, e.g.:
# auth_requests_total{method="POST",endpoint="/auth/login",status="200"} 123456
# auth_requests_total{method="POST",endpoint="/auth/login",status="401"} 789
# auth_request_duration_seconds_bucket{...} ...
# auth_active_sessions{org_id="org_123"} 456
# auth_token_generation_total{type="access"} 567890
```

### Key Metrics to Monitor

| Metric | What It Tells You | Alert Threshold |
|--------|-------------------|-----------------|
| `auth_requests_total{status="401"}` | Failed auth attempts | Spike > 100/minute |
| `auth_request_duration_seconds` | Latency | P99 > 1 second |
| `auth_active_sessions` | Concurrent users | Trending toward capacity |
| `auth_token_generation_total` | Token issuance rate | Unusual patterns |
| `auth_circuit_breaker_state` | Service health | Any "open" state |

### JWKS-Specific Metrics

```bash
curl -s "${AUTH_BASE}/metrics/jwks" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq

# {
#   "active_keys": 2,
#   "rotations_last_30_days": 4,
#   "last_rotation": "2026-01-15T00:00:00Z",
#   "key_ages_days": { "key_abc": 20, "key_def": 50 },
#   "upcoming_rotation": "2026-02-15T00:00:00Z"
# }
```

### Security Alerts

```bash
curl -s "${AUTH_BASE}/metrics/alerts/recent" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq

# {
#   "alerts": [
#     {
#       "level": "warning",
#       "type": "high_failure_rate",
#       "message": "Login failure rate above 10% threshold",
#       "value": 12.5,
#       "threshold": 10,
#       "timestamp": "2026-02-04T10:15:00Z"
#     },
#     {
#       "level": "critical",
#       "type": "key_rotation_overdue",
#       "message": "Key key_abc is 95 days old, rotation recommended at 90 days",
#       "timestamp": "2026-02-04T00:00:00Z"
#     }
#   ]
# }
```

---

## 37. Health Endpoints

### Basic Health Check

```bash
curl -s "${AUTH_BASE}/health" | jq

# { "status": "healthy", "timestamp": "2026-02-04T11:00:00Z" }
```

Use this for:
- Load balancer health checks
- Kubernetes liveness probes
- Simple monitoring

### Detailed Status

```bash
curl -s "${AUTH_BASE}/status" | jq

# {
#   "service": "auth-service",
#   "version": "1.2.3",
#   "status": "healthy",
#   "uptime_seconds": 864000,
#   "config": {
#     "access_token_expire_minutes": 15,
#     "refresh_token_expire_days": 7,
#     "session_timeout_minutes": 60,
#     "rate_limit_requests_per_minute": 100
#   },
#   "components": {
#     "database": { "status": "healthy", "latency_ms": 5 },
#     "redis": { "status": "healthy", "latency_ms": 2 },
#     "jwks": { "status": "healthy", "active_keys": 2 }
#   }
# }
```

### Help Endpoint

Quick reference for integration:

```bash
curl -s "${AUTH_BASE}/help"

# Returns condensed integration instructions
```

---

## Summary

This guide covered enterprise features for:

| Area | What You Learned |
|------|------------------|
| **OAuth 2.1** | PKCE, PAR, Dynamic Client Registration, Token Introspection/Revocation |
| **Super-Admin** | Time-limited elevation, dual approval, audit trails |
| **Delegation** | Act-as-user tokens for assistants and automation |
| **Quotas** | Resource limits per organization tier |
| **Password Policy** | Requirements, forced resets, compliance monitoring |
| **JWKS Management** | Key rotation, revocation, recovery |
| **Circuit Breakers** | Resilience monitoring and recovery |
| **Security Reports** | Leak reporting and management |
| **Events** | Webhook subscriptions for real-time alerts |
| **Advanced Zanzibar** | Custom namespaces, visualization, migration |
| **Monitoring** | Metrics, alerts, health checks |

### Quick Decision Guide

| "I need to..." | Use This |
|----------------|----------|
| Add "Sign in with Google" | OAuth 2.1 + Providers |
| Debug a customer's access issue | Delegation or Zanzibar Expand |
| Respond to a security incident | Super-Admin + JWKS Revocation |
| Get real-time security alerts | Event Subscriptions |
| Ensure compliance | Password Policies + Audit APIs |
| Understand who can access what | Zanzibar Visualization |

---

*Guide Version: 2.0*
*Last Updated: 2026-02-04*
*Companion to: AUTH_SERVICE_ORGANIZATION_GUIDE.md (Part 1)*
