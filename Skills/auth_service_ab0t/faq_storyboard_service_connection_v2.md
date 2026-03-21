question: We built an AI screenplay writing app called "Screenplay." We don't handle billing or payments ourselves — we use a separate Billing Company and a separate Payment Company
  that both run on the same auth mesh. Our users log into Screenplay. When they view invoices, that data lives in Billing Company. When they pay, that goes through Payment Company.
  But here's the thing: some of our customers are individual writers, and some are production studios with 50+ writers. Both need to work. The studios need their own billing
  relationship, their own admin, their own branded login portal. Individual writers just need a simple account. How do we model this? And how do we wire up OAuth so our frontend
  doesn't have to be a dumb proxy? We tried building per-user sub-orgs for every service (v3) and it was a nightmare. What's the right approach?

● This is the "service mesh consumer" pattern — your app is a customer of multiple service providers on the same auth infrastructure. The real complexity isn't connecting to
  the services (that's 4 API calls). It's modeling your customers correctly when they range from individual writers to multi-user production studios.

  This guide uses Screenplay as a real case study. v3 of their setup created a sub-org per user per service — 2,000 extra orgs for 1,000 users. We'll show what they should
  have done, covering both individual and organizational customers, with hosted login and OAuth 2.1.

  By the end you'll have:

  - Screenplay's root org (employees, platform config)
  - Customer orgs under Screenplay (one per production studio, or Screenplay itself for individuals)
  - ONE billing sub-org under Billing Company (shared by all Screenplay customers)
  - ONE payment sub-org under Payment Company (same)
  - Backend API keys for batch operations
  - OAuth 2.1 client for Screenplay's frontend (PKCE, no client secret in browser)
  - Hosted login portals per customer org (branded per studio)
  - Org-scoped auth endpoints for studio-specific registration and SSO
  - Decision guide for when v3's per-customer-org-per-service approach IS correct

  ---
  Concept: The Three Customer Tiers

  Screenplay has three types of customers. Each maps to a different org structure:

  ┌────────────┬────────────────────────────┬─────────────────────────────────────────────────────┐
  │ Tier       │ Who they are               │ How they map to orgs                                │
  ├────────────┼────────────────────────────┼─────────────────────────────────────────────────────┤
  │ Individual │ Jane Doe, freelance writer  │ Member of the Screenplay root org directly.         │
  │            │                            │ No child org. customer_ref = screenplay:{user_id}.  │
  ├────────────┼────────────────────────────┼─────────────────────────────────────────────────────┤
  │ Studio     │ Pinnacle Pictures, 50      │ Child org under Screenplay. Studio admin manages    │
  │            │ writers, own billing admin  │ their users. customer_ref = screenplay:{studio_id}. │
  │            │                            │ Own hosted login: /login/pinnacle-pictures           │
  ├────────────┼────────────────────────────┼─────────────────────────────────────────────────────┤
  │ Enterprise │ NetStream Inc, 500 writers, │ Child org under Screenplay + ALSO gets its own      │
  │            │ own billing relationship,  │ sub-org under Billing Company and Payment Company.  │
  │            │ own payment processing,    │ This is where v3's approach is correct.              │
  │            │ custom SSO via SAML        │ Own API keys. Own billing admin. Own SSO.            │
  └────────────┴────────────────────────────┴─────────────────────────────────────────────────────┘

  v3 treated every individual user as Enterprise tier. That's the over-engineering. Most customers are Tier 1 or Tier 2.

  ---
  Concept: Org Tree for All Three Tiers

  Auth Service
  │
  ├── Billing Company (root org, independent service provider)
  │   ├── Screenplay Billing Account (child org)                    ← Shared by Tier 1 + Tier 2
  │   │   └── ONE API key, customer_ref per user/studio
  │   │
  │   └── NetStream Billing Account (child org)                     ← Tier 3 only: own relationship
  │       └── Own API key, own billing admin
  │
  ├── Payment Company (root org, independent service provider)
  │   ├── Screenplay Merchant Account (child org)                   ← Shared by Tier 1 + Tier 2
  │   │   └── ONE API key, customer_ref per user/studio
  │   │
  │   └── NetStream Merchant Account (child org)                    ← Tier 3 only
  │       └── Own API key, own payment admin
  │
  └── Screenplay (root org)
      ├── Yuki Tanaka (founder, owner)
      ├── Marcus Webb (backend engineer, member)
      ├── Engineering Team
      │
      ├── Jane Doe (Tier 1 — individual, member of root org)
      ├── Bob Chen (Tier 1 — individual, member of root org)
      │
      ├── [CHILD ORG] Pinnacle Pictures (Tier 2 — studio)
      │   ├── Sarah Lin (studio admin, owner)
      │   ├── 50 writers (members)
      │   └── Hosted Login: /login/pinnacle-pictures
      │
      └── [CHILD ORG] NetStream Inc (Tier 3 — enterprise)
          ├── David Park (enterprise admin, owner)
          ├── 500 writers (members)
          ├── Hosted Login: /login/netstream
          ├── SSO via SAML (federated login)
          └── Own billing/payment sub-orgs under service providers

  Key insight: Tier 1 and Tier 2 share the same billing/payment sub-orgs. Only Tier 3 gets their own.
  Tier 2 studios are child orgs of Screenplay — they get their own user management and branded login,
  but billing goes through Screenplay's shared account (Screenplay invoices the studios, not Billing Company).

  ---
  Characters

  - Yuki Tanaka       — Screenplay founder/CTO
  - Marcus Webb       — Screenplay backend engineer
  - Jane Doe          — Tier 1: Individual writer
  - Sarah Lin         — Tier 2: Pinnacle Pictures studio admin
  - David Park        — Tier 3: NetStream Inc enterprise admin
  - Billing Company   — Independent service provider on the mesh
  - Payment Company   — Independent service provider on the mesh

  ---

## Step 1: Yuki Creates the Screenplay Platform Org

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /auth/register                                                           │
  └────────────────────────────────────────────────────────────────────────────────┘

  AUTH_URL="https://auth.service.ab0t.com"

  curl -X POST "$AUTH_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "yuki@screenplay.dev",
      "password": "YukiSecure2026!",
      "name": "Yuki Tanaka"
    }'

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /auth/login                                                              │
  └────────────────────────────────────────────────────────────────────────────────┘

  TOKEN=$(curl -s -X POST "$AUTH_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email": "yuki@screenplay.dev", "password": "YukiSecure2026!"}' \
    | jq -r '.access_token')

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /organizations/                                                          │
  └────────────────────────────────────────────────────────────────────────────────┘

  SCREENPLAY_ORG=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Screenplay",
      "slug": "screenplay",
      "domain": "screenplay.dev",
      "billing_type": "prepaid",
      "settings": {
        "type": "platform",
        "hierarchical": true,
        "allow_child_orgs": true,
        "integrations": ["billing", "payment"]
      },
      "metadata": {
        "product": "ai_screenplay_writer",
        "tiers": ["individual", "studio", "enterprise"]
      }
    }')

  SCREENPLAY_ORG_ID=$(echo "$SCREENPLAY_ORG" | jq -r '.id')

  What just happened: Screenplay's root org is created with `hierarchical: true` and `allow_child_orgs: true`. This means studio and enterprise customers can be modeled
  as child orgs — each with their own users, admins, and login pages — while sharing the parent platform's infrastructure.

  ---

## Step 2: Configure Hosted Login for Individual Writers (Tier 1)

  Individual writers sign up directly on Screenplay. No invitation needed — they self-register through a branded login portal.

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  PUT /organizations/{org_id}/login-config                                      │
  │  Authorization: Bearer $TOKEN                                                  │
  └────────────────────────────────────────────────────────────────────────────────┘

  curl -X PUT "$AUTH_URL/organizations/$SCREENPLAY_ORG_ID/login-config" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "allow_registration": true,
      "default_role": "member",
      "require_email_verification": true,
      "allowed_domains": [],
      "branding": {
        "company_name": "Screenplay",
        "logo_url": "https://screenplay.dev/logo.png",
        "primary_color": "#6366f1",
        "tagline": "AI-powered screenplay writing"
      },
      "auth_methods": {
        "password": true,
        "magic_link": true,
        "webauthn": false,
        "oauth_providers": ["google", "github"]
      },
      "redirect_urls": {
        "after_login": "https://app.screenplay.dev/dashboard",
        "after_register": "https://app.screenplay.dev/welcome",
        "after_logout": "https://screenplay.dev"
      }
    }'

  The hosted login page is now live at:

  https://auth.service.ab0t.com/login/screenplay

  Writers can also register through org-scoped endpoints directly:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /organizations/screenplay/auth/register                                  │
  │  (No auth token needed — this is a public registration endpoint)               │
  └────────────────────────────────────────────────────────────────────────────────┘

  curl -X POST "$AUTH_URL/organizations/screenplay/auth/register" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "jane@gmail.com",
      "password": "JaneSecure2026!",
      "name": "Jane Doe"
    }'

  Response:
  {
    "access_token": "eyJ...",
    "refresh_token": "eyJ...",
    "user": {
      "id": "usr_jane_001",
      "email": "jane@gmail.com",
      "name": "Jane Doe"
    }
  }

  What just happened: Jane registered directly into the Screenplay org. She's a member. No invitation required because `allow_registration: true` is set on the login config.
  The org-scoped endpoint `/organizations/screenplay/auth/register` automatically assigns her to the Screenplay org — she doesn't need to know the org_id.

  Jane can also log in through the org-scoped login endpoint:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /organizations/screenplay/auth/login                                     │
  └────────────────────────────────────────────────────────────────────────────────┘

  curl -X POST "$AUTH_URL/organizations/screenplay/auth/login" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "jane@gmail.com",
      "password": "JaneSecure2026!"
    }'

  The token she gets back already has the Screenplay org context baked in. No need for a separate switch-organization call.

  To check what the hosted login page looks like (useful for embedding in your frontend):

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  GET /organizations/screenplay/login-config/public                             │
  │  (No auth required — this is what your frontend fetches to render the form)    │
  └────────────────────────────────────────────────────────────────────────────────┘

  curl -s "$AUTH_URL/organizations/screenplay/login-config/public"

  Returns: branding, allowed auth methods, whether registration is open — everything your frontend needs to render a login/register form without hardcoding.

  ---

## Step 3: Register an OAuth 2.1 Client for Screenplay's Frontend

  Instead of storing tokens in sessionStorage and managing refresh manually, register an OAuth client. This gives you standard PKCE authorization code flow — same as "Login with Google" but it's "Login with Screenplay."

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /auth/oauth/register                                                     │
  │  (Dynamic Client Registration — RFC 7591)                                      │
  └────────────────────────────────────────────────────────────────────────────────┘

  OAUTH_CLIENT=$(curl -s -X POST "$AUTH_URL/auth/oauth/register" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "client_name": "Screenplay Web App",
      "redirect_uris": [
        "https://app.screenplay.dev/callback",
        "http://localhost:3000/callback"
      ],
      "grant_types": ["authorization_code", "refresh_token"],
      "response_types": ["code"],
      "token_endpoint_auth_method": "none",
      "scope": "openid profile email organizations",
      "application_type": "web"
    }')

  CLIENT_ID=$(echo "$OAUTH_CLIENT" | jq -r '.client_id')

  What just happened: You registered a public OAuth 2.1 client. Key choices:

  - `token_endpoint_auth_method: "none"` — This is a public client (SPA). No client_secret. Security comes from PKCE.
  - `grant_types: ["authorization_code", "refresh_token"]` — Standard OAuth 2.1. No implicit flow (deprecated).
  - `scope: "openid profile email organizations"` — The token will include user identity + their org memberships.

  The OAuth discovery endpoint tells your frontend everything it needs:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  GET /.well-known/oauth-authorization-server                                   │
  └────────────────────────────────────────────────────────────────────────────────┘

  curl -s "$AUTH_URL/.well-known/oauth-authorization-server"

  Returns: authorization_endpoint, token_endpoint, supported scopes, PKCE methods — standard RFC 8414 metadata.

  ---
  Concept: OAuth 2.1 PKCE Flow for the Frontend

  Here's how Screenplay's frontend authenticates users without ever touching a client secret:

  ┌──────────────────┐                    ┌──────────────────┐
  │  Screenplay SPA  │                    │   Auth Service   │
  │  (Browser)       │                    │                  │
  └────────┬─────────┘                    └────────┬─────────┘
           │                                        │
           │  1. Generate code_verifier (random)    │
           │  2. Hash it → code_challenge           │
           │                                        │
           ├──[3. GET /authorize]──────────────────►│
           │   client_id=...                        │
           │   redirect_uri=.../callback            │
           │   code_challenge=sha256(verifier)      │
           │   code_challenge_method=S256           │
           │   scope=openid profile email           │
           │                                        │
           │  (User sees login page, enters creds)  │
           │                                        │
           │◄──[4. Redirect to callback]────────────┤
           │   ?code=AUTH_CODE                      │
           │                                        │
           ├──[5. POST /auth/oauth/token]──────────►│
           │   grant_type=authorization_code        │
           │   code=AUTH_CODE                       │
           │   code_verifier=original_verifier      │
           │   client_id=...                        │
           │                                        │
           │◄──[6. Token Response]──────────────────┤
           │   access_token, refresh_token, id_token│
           │                                        │

  Pushed Authorization Requests (PAR) add extra security for Tier 3 enterprise clients:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /auth/oauth/par                                                          │
  │  (Pushed Authorization Request — RFC 9126)                                     │
  └────────────────────────────────────────────────────────────────────────────────┘

  PAR pushes the authorization parameters to the server first, then the browser redirect only carries a request_uri reference. Prevents parameter tampering. Required for
  Financial-grade API (FAPI) compliance.

  Frontend JavaScript (using standard OAuth 2.1 with PKCE):

  // 1. Generate PKCE values
  function generatePKCE() {
      const verifier = crypto.randomUUID() + crypto.randomUUID();
      const encoder = new TextEncoder();
      const data = encoder.encode(verifier);
      return crypto.subtle.digest('SHA-256', data).then(hash => {
          const challenge = btoa(String.fromCharCode(...new Uint8Array(hash)))
              .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
          return { verifier, challenge };
      });
  }

  // 2. Redirect to authorize
  async function login() {
      const { verifier, challenge } = await generatePKCE();
      sessionStorage.setItem('pkce_verifier', verifier);

      const params = new URLSearchParams({
          client_id: 'screenplay_web_app',
          redirect_uri: 'https://app.screenplay.dev/callback',
          response_type: 'code',
          scope: 'openid profile email organizations',
          code_challenge: challenge,
          code_challenge_method: 'S256',
          state: crypto.randomUUID()  // CSRF protection
      });

      window.location.href = `${AUTH_URL}/authorize?${params}`;
  }

  // 3. Handle callback
  async function handleCallback() {
      const params = new URLSearchParams(window.location.search);
      const code = params.get('code');
      const verifier = sessionStorage.getItem('pkce_verifier');

      const response = await fetch(`${AUTH_URL}/auth/oauth/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
              grant_type: 'authorization_code',
              code: code,
              redirect_uri: 'https://app.screenplay.dev/callback',
              client_id: 'screenplay_web_app',
              code_verifier: verifier
          })
      });

      const tokens = await response.json();
      // tokens.access_token, tokens.refresh_token, tokens.id_token
      sessionStorage.setItem('access_token', tokens.access_token);
      sessionStorage.setItem('refresh_token', tokens.refresh_token);
  }

  // 4. Refresh tokens (silent, no redirect needed)
  async function refreshTokens() {
      const response = await fetch(`${AUTH_URL}/auth/oauth/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
              grant_type: 'refresh_token',
              refresh_token: sessionStorage.getItem('refresh_token'),
              client_id: 'screenplay_web_app'
          })
      });

      const tokens = await response.json();
      sessionStorage.setItem('access_token', tokens.access_token);
      sessionStorage.setItem('refresh_token', tokens.refresh_token);
  }

  What just happened: Screenplay's frontend uses standard OAuth 2.1 with PKCE. No client secret lives in the browser. The auth service handles the login UI (hosted login page),
  token issuance, and refresh. Your frontend never sees the user's password.

  ---

## Step 4: Connect to Billing and Payment Companies

  Same as v1 — ONE sub-org per service, ONE API key per service. This doesn't change based on customer tier.

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /organizations/                                                          │
  │  Authorization: Bearer $BILLING_ADMIN_TOKEN                                    │
  └────────────────────────────────────────────────────────────────────────────────┘

  # Billing Company creates a customer account for Screenplay
  BILLING_SUB_ORG=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $BILLING_ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Screenplay - Billing Account",
      "slug": "screenplay-billing",
      "parent_id": "'$BILLING_COMPANY_ORG_ID'",
      "settings": {
        "type": "customer_account",
        "customer_org_id": "'$SCREENPLAY_ORG_ID'"
      }
    }')
  BILLING_SUB_ORG_ID=$(echo "$BILLING_SUB_ORG" | jq -r '.id')

  # Service account + API key
  curl -s -X POST "$AUTH_URL/admin/users/create-service-account" \
    -H "Authorization: Bearer $BILLING_ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "screenplay@billing.customers",
      "name": "Screenplay Billing Service Account",
      "org_id": "'$BILLING_SUB_ORG_ID'",
      "permissions": [
        "billing.read.accounts", "billing.write.accounts",
        "billing.write.usage", "billing.read.invoices",
        "billing.generate.reports"
      ]
    }'

  BILLING_API_KEY=$(curl -s -X POST "$AUTH_URL/api-keys/" \
    -H "Authorization: Bearer $BILLING_SERVICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Screenplay Billing Key",
      "permissions": [
        "billing.read.accounts", "billing.write.accounts",
        "billing.write.usage", "billing.read.invoices",
        "billing.generate.reports"
      ]
    }' | jq -r '.key')

  # Same for Payment Company
  PAYMENT_SUB_ORG=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $PAYMENT_ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Screenplay - Merchant Account",
      "slug": "screenplay-merchant",
      "parent_id": "'$PAYMENT_COMPANY_ORG_ID'",
      "settings": {
        "type": "merchant_account",
        "customer_org_id": "'$SCREENPLAY_ORG_ID'"
      }
    }')
  PAYMENT_SUB_ORG_ID=$(echo "$PAYMENT_SUB_ORG" | jq -r '.id')

  PAYMENT_API_KEY=$(curl -s -X POST "$AUTH_URL/api-keys/" \
    -H "Authorization: Bearer $PAYMENT_SERVICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Screenplay Payment Key",
      "permissions": [
        "payment.create.intents", "payment.read.intents",
        "payment.read.methods", "payment.create.methods",
        "payment.verify.webhooks", "payment.create.refunds"
      ]
    }' | jq -r '.key')

  Register permissions if not already done by the service providers:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /permissions/registry/register                                           │
  └────────────────────────────────────────────────────────────────────────────────┘

  curl -X POST "$AUTH_URL/permissions/registry/register" \
    -H "Content-Type: application/json" \
    -d '{
      "service": "billing",
      "description": "Billing, accounting, and subscription management",
      "actions": ["read", "write", "create", "update", "delete", "generate", "admin"],
      "resources": ["accounts", "usage", "invoices", "reports", "subscriptions", "payments", "credits"]
    }'

  curl -X POST "$AUTH_URL/permissions/registry/register" \
    -H "Content-Type: application/json" \
    -d '{
      "service": "payment",
      "description": "Payment processing and merchant services",
      "actions": ["create", "read", "update", "delete", "verify", "capture", "cancel", "refund"],
      "resources": ["intents", "methods", "charges", "refunds", "disputes", "webhooks", "subscriptions", "plans"]
    }'

  What just happened: Screenplay now has ONE billing account and ONE payment account. These serve ALL tiers of customers. The customer_ref pattern handles per-user and
  per-studio isolation within the shared account.

  ---

## Step 5: Onboard a Studio (Tier 2 — Pinnacle Pictures)

  Sarah Lin from Pinnacle Pictures wants to sign up her whole studio. Yuki creates a child org under Screenplay for them.

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /organizations/                                                          │
  │  Authorization: Bearer $TOKEN  (Yuki's token, Screenplay owner)                │
  └────────────────────────────────────────────────────────────────────────────────┘

  PINNACLE_ORG=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Pinnacle Pictures",
      "slug": "pinnacle-pictures",
      "parent_id": "'$SCREENPLAY_ORG_ID'",
      "domain": "pinnaclepictures.com",
      "settings": {
        "type": "studio",
        "tier": "studio",
        "max_users": 100
      },
      "metadata": {
        "contact": "sarah@pinnaclepictures.com",
        "plan": "studio_pro"
      }
    }')
  PINNACLE_ORG_ID=$(echo "$PINNACLE_ORG" | jq -r '.id')

  Invite Sarah as the studio admin:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /organizations/{org_id}/invite                                           │
  └────────────────────────────────────────────────────────────────────────────────┘

  curl -X POST "$AUTH_URL/organizations/$PINNACLE_ORG_ID/invite" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "sarah@pinnaclepictures.com",
      "role": "admin"
    }'

  Set up Pinnacle's branded login portal:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  PUT /organizations/{org_id}/login-config                                      │
  └────────────────────────────────────────────────────────────────────────────────┘

  curl -X PUT "$AUTH_URL/organizations/$PINNACLE_ORG_ID/login-config" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "allow_registration": true,
      "default_role": "member",
      "require_email_verification": true,
      "allowed_domains": ["pinnaclepictures.com"],
      "branding": {
        "company_name": "Pinnacle Pictures",
        "logo_url": "https://pinnaclepictures.com/logo.png",
        "primary_color": "#1a1a2e",
        "tagline": "Pinnacle Pictures Writing Room"
      },
      "auth_methods": {
        "password": true,
        "magic_link": true
      },
      "redirect_urls": {
        "after_login": "https://app.screenplay.dev/dashboard",
        "after_register": "https://app.screenplay.dev/welcome"
      }
    }'

  Pinnacle's writers now sign up at:

  https://auth.service.ab0t.com/login/pinnacle-pictures

  They see Pinnacle's branding, not Screenplay's. Registration is limited to @pinnaclepictures.com emails (`allowed_domains`). Sarah (as admin) can also invite writers manually:

  curl -X POST "$AUTH_URL/organizations/$PINNACLE_ORG_ID/invite" \
    -H "Authorization: Bearer $SARAH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "writer47@pinnaclepictures.com",
      "role": "member"
    }'

  What just happened: Pinnacle Pictures is a child org of Screenplay with its own branded login, its own admin, and its own user base. But NO separate billing/payment sub-orgs
  were created. When a Pinnacle writer views their invoices, the backend uses customer_ref: "screenplay:{pinnacle_org_id}" to pull Pinnacle's billing data from Screenplay's
  shared billing account.

  Sarah manages her writers. Yuki can see all studios (parent org visibility). Pinnacle can't see other studios (sibling isolation).

  Pinnacle writers can also use the org-scoped auth endpoints directly:

  # Register into Pinnacle's org (public, no token needed)
  POST /organizations/pinnacle-pictures/auth/register
  { "email": "newwriter@pinnaclepictures.com", "password": "...", "name": "New Writer" }

  # Login with Pinnacle context (token comes back with Pinnacle org context)
  POST /organizations/pinnacle-pictures/auth/login
  { "email": "writer@pinnaclepictures.com", "password": "..." }

  # Refresh token
  POST /organizations/pinnacle-pictures/auth/refresh
  { "refresh_token": "eyJ..." }

  ---

## Step 6: Onboard an Enterprise (Tier 3 — NetStream Inc)

  David Park from NetStream Inc has 500 writers, needs their own billing relationship with Billing Company, their own payment processing, and SAML SSO with their corporate IdP.

  This is the ONLY tier where v3's approach is correct: NetStream gets sub-orgs under the service providers.

  Step 6a: Create NetStream's org under Screenplay

  NETSTREAM_ORG=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "NetStream Inc",
      "slug": "netstream",
      "parent_id": "'$SCREENPLAY_ORG_ID'",
      "domain": "netstream.com",
      "settings": {
        "type": "enterprise",
        "tier": "enterprise",
        "sso_enabled": true,
        "own_billing": true,
        "own_payment": true
      }
    }')
  NETSTREAM_ORG_ID=$(echo "$NETSTREAM_ORG" | jq -r '.id')

  Step 6b: Create NetStream's OWN billing sub-org under Billing Company

  This is where v3's pattern is appropriate — but note it's per customer ORGANIZATION, not per individual user.

  NETSTREAM_BILLING_ORG=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $BILLING_ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "NetStream - Billing Account",
      "slug": "netstream-billing",
      "parent_id": "'$BILLING_COMPANY_ORG_ID'",
      "settings": {
        "type": "customer_account",
        "customer_org_id": "'$NETSTREAM_ORG_ID'",
        "billing_type": "postpaid"
      }
    }')
  NETSTREAM_BILLING_ORG_ID=$(echo "$NETSTREAM_BILLING_ORG" | jq -r '.id')

  # NetStream gets their OWN API key
  NETSTREAM_BILLING_KEY=$(curl -s -X POST "$AUTH_URL/api-keys/" \
    -H "Authorization: Bearer $NETSTREAM_BILLING_SERVICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "NetStream Billing Key",
      "permissions": ["billing.read.accounts", "billing.write.accounts", "billing.read.invoices"]
    }' | jq -r '.key')

  Step 6c: Same for Payment Company

  NETSTREAM_PAYMENT_ORG=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $PAYMENT_ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "NetStream - Merchant Account",
      "slug": "netstream-merchant",
      "parent_id": "'$PAYMENT_COMPANY_ORG_ID'",
      "settings": {
        "type": "merchant_account",
        "customer_org_id": "'$NETSTREAM_ORG_ID'"
      }
    }')

  Step 6d: Configure SAML SSO for NetStream

  NetStream uses Okta as their corporate IdP. Their employees sign in once to Okta and get access to Screenplay automatically.

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /federation/sso/config                                                   │
  │  Authorization: Bearer $TOKEN                                                  │
  └────────────────────────────────────────────────────────────────────────────────┘

  curl -X POST "$AUTH_URL/federation/sso/config" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "org_id": "'$NETSTREAM_ORG_ID'",
      "provider": "saml",
      "saml_config": {
        "idp_entity_id": "https://netstream.okta.com/app/exk123",
        "idp_sso_url": "https://netstream.okta.com/app/exk123/sso/saml",
        "idp_certificate": "MIIDpDCCAoygAwIBAgIGAX...",
        "attribute_mapping": {
          "email": "user.email",
          "name": "user.displayName",
          "department": "user.department"
        }
      },
      "auto_create_users": true,
      "default_role": "member"
    }'

  Register NetStream's domain for SSO auto-detection:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /federation/sso/domains                                                  │
  └────────────────────────────────────────────────────────────────────────────────┘

  curl -X POST "$AUTH_URL/federation/sso/domains" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "domain": "netstream.com",
      "org_id": "'$NETSTREAM_ORG_ID'",
      "verified": true
    }'

  Now when anyone with a @netstream.com email hits the login page, they're automatically redirected to Okta:

  # SSO initiation (frontend redirects here)
  GET /organizations/netstream/auth/sso/initiate

  # After Okta login, callback returns to:
  GET /organizations/netstream/auth/sso/callback?SAMLResponse=...

  Set up NetStream's branded login portal:

  curl -X PUT "$AUTH_URL/organizations/$NETSTREAM_ORG_ID/login-config" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "allow_registration": false,
      "require_sso": true,
      "allowed_domains": ["netstream.com"],
      "branding": {
        "company_name": "NetStream",
        "logo_url": "https://netstream.com/logo.png",
        "primary_color": "#0f766e",
        "tagline": "NetStream Writer Studio"
      },
      "auth_methods": {
        "password": false,
        "sso": true
      }
    }'

  What just happened: NetStream is the full enterprise package:
  - Own child org under Screenplay (user management, admin)
  - Own sub-orgs under Billing and Payment companies (separate billing relationship)
  - SAML SSO with their corporate Okta (no passwords managed by Screenplay)
  - Domain-based auto-detection (any @netstream.com email → Okta login)
  - Registration disabled (users come through SSO JIT provisioning)

  THIS is when v3's pattern of per-customer service sub-orgs is correct. NetStream is a company with its own billing admin, its own payment processing, and compliance
  requirements that demand org-level isolation from other Screenplay customers.

  But note: even here, NetStream does NOT create per-user sub-orgs under Billing Company. NetStream's 500 writers share ONE NetStream billing sub-org, with
  customer_ref: "netstream:{user_id}" for per-writer breakdown.

  ---

## Step 7: The Backend — Handling All Three Tiers

  Marcus wires up the backend to handle Tier 1, 2, and 3 customers with the same code path.

  .env.production:

  AUTH_SERVICE_URL=https://auth.service.ab0t.com
  SCREENPLAY_ORG_ID=33c03cc0-...

  BILLING_SERVICE_URL=https://billing.service.ab0t.com
  BILLING_SUB_ORG_ID=8d7e82c9-...
  BILLING_API_KEY=ab0t_sk_live_...

  PAYMENT_SERVICE_URL=https://payment.service.ab0t.com
  PAYMENT_SUB_ORG_ID=f76e008e-...
  PAYMENT_API_KEY=ab0t_sk_live_...

  Backend code (Python):

  import httpx, os
  from typing import Optional

  # Default billing/payment credentials (Tier 1 + Tier 2)
  DEFAULT_BILLING_KEY = os.environ["BILLING_API_KEY"]
  DEFAULT_BILLING_ORG = os.environ["BILLING_SUB_ORG_ID"]
  DEFAULT_PAYMENT_KEY = os.environ["PAYMENT_API_KEY"]
  DEFAULT_PAYMENT_ORG = os.environ["PAYMENT_SUB_ORG_ID"]

  # Tier 3 enterprise overrides (loaded from DB or config)
  ENTERPRISE_CONFIGS = {
      # org_id → { billing_key, billing_org, payment_key, payment_org }
      # Populated when enterprise customers onboard
  }

  def get_billing_credentials(user_org_id: str):
      """Route to the right billing account based on customer tier."""
      if user_org_id in ENTERPRISE_CONFIGS:
          config = ENTERPRISE_CONFIGS[user_org_id]
          return config["billing_key"], config["billing_org"]
      return DEFAULT_BILLING_KEY, DEFAULT_BILLING_ORG

  def get_customer_ref(user_id: str, user_org_id: str) -> str:
      """Build the customer_ref for filtering."""
      # Tier 1: individual user → screenplay:{user_id}
      # Tier 2: studio member  → screenplay:{studio_org_id}
      # Tier 3: enterprise     → netstream:{user_id}  (their own billing org)
      if user_org_id in ENTERPRISE_CONFIGS:
          return f"{user_org_id}:{user_id}"
      elif user_org_id != SCREENPLAY_ORG_ID:
          # Tier 2: studio — use studio org as the customer ref
          return f"screenplay:{user_org_id}"
      else:
          # Tier 1: individual
          return f"screenplay:{user_id}"

  async def get_user_invoices(user_id: str, user_org_id: str):
      """Works for all three tiers."""
      billing_key, billing_org = get_billing_credentials(user_org_id)
      customer_ref = get_customer_ref(user_id, user_org_id)

      async with httpx.AsyncClient() as client:
          response = await client.get(
              f"{BILLING_SERVICE_URL}/invoices",
              headers={
                  "X-API-Key": billing_key,
                  "X-Org-Context": billing_org
              },
              params={"customer_ref": customer_ref}
          )
          return response.json()

  What just happened: One code path handles all three tiers. The only difference is which API key and customer_ref are used. Tier 1 and Tier 2 use Screenplay's shared
  billing key. Tier 3 uses the enterprise customer's own billing key. The backend figures out which tier a user belongs to from their org_id.

  ---

## Step 8: Delegation for Support

  Same as v1. Delegation is for support/admin scenarios, not regular access.

  # Jane grants support agent temporary access
  curl -X POST "$AUTH_URL/delegation/grant" \
    -H "Authorization: Bearer $JANE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "actor_id": "'$SUPPORT_AGENT_USER_ID'",
      "scope": ["users.read", "billing.read"],
      "expires_in_hours": 1
    }'

  # Support agent gets delegated token
  curl -X POST "$AUTH_URL/auth/delegate" \
    -H "Authorization: Bearer $SUPPORT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"target_user_id": "'$JANE_USER_ID'"}'

  ---
  Case Study: When v3's Approach IS the Right Answer

  v3 created per-user sub-orgs under every service provider. That's wrong for individual users and studios. But the PATTERN
  (create a sub-org under a service provider for a specific customer) is correct in these scenarios:

  ┌──────────────────────────────────────────────────────────────────────────────────────┐
  │  Scenario 1: Enterprise customer with own billing relationship (Tier 3)              │
  │                                                                                      │
  │  NetStream Inc has a direct contract with Billing Company. NetStream's finance team   │
  │  needs their own billing admin portal, their own invoices, their own payment methods. │
  │  Screenplay is just the software — NetStream pays Billing Company directly.           │
  │                                                                                      │
  │  v3 pattern: ✓ Correct. Sub-org per enterprise customer under service providers.     │
  └──────────────────────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────────────────────────┐
  │  Scenario 2: Developer platform where users build integrations                       │
  │                                                                                      │
  │  If Screenplay offered an API that writers could script against (like Figma plugins), │
  │  each writer-developer would need their own API key with their own rate limits.       │
  │  Per-user sub-orgs give each developer an isolated key + permission set.              │
  │                                                                                      │
  │  v3 pattern: ✓ Correct. But only for the developer API, not billing/payment.         │
  └──────────────────────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────────────────────────┐
  │  Scenario 3: Marketplace with sellers (CraftMarket pattern)                          │
  │                                                                                      │
  │  Each seller IS a business. They need their own payment processing (payouts),         │
  │  their own tax reporting, their own storefront settings. A seller org under Payment   │
  │  Company is how you model "this seller receives money independently."                 │
  │                                                                                      │
  │  v3 pattern: ✓ Correct. See the marketplace guide.                                   │
  └──────────────────────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────────────────────────┐
  │  Scenario 4: Regulated data where audit boundaries must be per-entity                │
  │                                                                                      │
  │  Healthcare (HIPAA): each clinic's patient data in a separate org for audit.          │
  │  Finance (SOX): each fund's transaction data isolated at the org level.               │
  │  Government (FedRAMP): each agency's data in its own authorization boundary.          │
  │                                                                                      │
  │  v3 pattern: ✓ Correct. Compliance requires org-level isolation, not just filtering. │
  └──────────────────────────────────────────────────────────────────────────────────────┘

  The rule: create sub-orgs under service providers when the CUSTOMER (not the user) needs an independent business
  relationship with the service provider. If Screenplay mediates the relationship (Tier 1, 2), use customer_ref. If
  the customer deals directly with the service provider (Tier 3), create a sub-org.

  ---
  Updated Decision Matrix

  ┌────────────────────────────────┬─────────────────┬──────────────────┬─────────────────────────┐
  │  Question                      │ Tier 1          │ Tier 2           │ Tier 3                  │
  │                                │ (Individual)    │ (Studio/Team)    │ (Enterprise)            │
  ├────────────────────────────────┼─────────────────┼──────────────────┼─────────────────────────┤
  │  Org structure                 │ Member of root  │ Child org of     │ Child org of root +     │
  │                                │ org             │ root org         │ sub-orgs under services │
  ├────────────────────────────────┼─────────────────┼──────────────────┼─────────────────────────┤
  │  User management               │ Platform admin  │ Studio admin     │ Enterprise admin + SSO  │
  ├────────────────────────────────┼─────────────────┼──────────────────┼─────────────────────────┤
  │  Branded login portal          │ /login/screenplay│ /login/{studio} │ /login/{enterprise}     │
  │                                │ (shared)        │ (own branding)   │ (own branding + SSO)    │
  ├────────────────────────────────┼─────────────────┼──────────────────┼─────────────────────────┤
  │  Billing relationship          │ Through         │ Through          │ DIRECT with Billing Co  │
  │                                │ Screenplay      │ Screenplay       │ Own sub-org + API key   │
  ├────────────────────────────────┼─────────────────┼──────────────────┼─────────────────────────┤
  │  customer_ref                  │ screenplay:     │ screenplay:      │ {enterprise_org}:       │
  │                                │ {user_id}       │ {studio_org_id}  │ {user_id}               │
  ├────────────────────────────────┼─────────────────┼──────────────────┼─────────────────────────┤
  │  Billing API key used          │ Screenplay's    │ Screenplay's     │ Enterprise's own        │
  ├────────────────────────────────┼─────────────────┼──────────────────┼─────────────────────────┤
  │  Service provider sub-orgs     │ None            │ None             │ Yes — one per service   │
  ├────────────────────────────────┼─────────────────┼──────────────────┼─────────────────────────┤
  │  v3 approach needed?           │ No              │ No               │ Yes (per customer org)  │
  └────────────────────────────────┴─────────────────┴──────────────────┴─────────────────────────┘

  ---
  Complete Architecture — All Three Tiers

  Auth Service
  │
  ├── Billing Company (root org)
  │   ├── Screenplay Billing Account (child)     ← Tier 1 + Tier 2 (shared)
  │   │   └── API key: ab0t_sk_live_screenplay_billing_...
  │   └── NetStream Billing Account (child)      ← Tier 3 (own relationship)
  │       └── API key: ab0t_sk_live_netstream_billing_...
  │
  ├── Payment Company (root org)
  │   ├── Screenplay Merchant Account (child)    ← Tier 1 + Tier 2 (shared)
  │   │   └── API key: ab0t_sk_live_screenplay_payment_...
  │   └── NetStream Merchant Account (child)     ← Tier 3 (own relationship)
  │       └── API key: ab0t_sk_live_netstream_payment_...
  │
  └── Screenplay (root org)
      ├── Yuki (owner), Marcus (engineer)
      ├── OAuth Client: screenplay_web_app (PKCE, public)
      ├── Hosted Login: /login/screenplay
      │
      ├── Jane Doe (Tier 1, individual, member)
      ├── Bob Chen (Tier 1, individual, member)
      │
      ├── [CHILD] Pinnacle Pictures (Tier 2, studio)
      │   ├── Sarah Lin (admin), 50 writers (members)
      │   └── Hosted Login: /login/pinnacle-pictures
      │
      └── [CHILD] NetStream Inc (Tier 3, enterprise)
          ├── David Park (admin), 500 writers (via SAML SSO)
          ├── Hosted Login: /login/netstream (SSO required)
          ├── SAML IdP: netstream.okta.com
          └── Own billing/payment sub-orgs under service providers

  ---
  Endpoint Reference

  Hosted Login & Org-Scoped Auth:
    GET  /login/{org_slug}                              Hosted login page (renders branded UI)
    GET  /organizations/{org_slug}/login-config/public   Public login config (branding, auth methods)
    PUT  /organizations/{org_id}/login-config             Update login config (admin only)
    POST /organizations/{org_slug}/auth/register          Org-scoped registration (public if allowed)
    POST /organizations/{org_slug}/auth/login             Org-scoped login (token has org context)
    POST /organizations/{org_slug}/auth/refresh           Org-scoped token refresh
    POST /organizations/{org_slug}/auth/logout            Org-scoped logout
    POST /organizations/{org_slug}/auth/reset-password    Org-scoped password reset
    GET  /organizations/{org_slug}/auth/providers          List available auth methods for this org
    POST /organizations/{org_slug}/auth/token             Org-scoped token exchange

  OAuth 2.1:
    GET  /.well-known/oauth-authorization-server          OAuth server metadata (RFC 8414)
    POST /auth/oauth/register                             Dynamic client registration (RFC 7591)
    POST /auth/oauth/par                                  Pushed Authorization Request (RFC 9126)
    POST /auth/oauth/token                                Token endpoint (auth code, refresh)
    GET  /auth/oauth/{provider}/authorize                 OAuth provider authorization
    GET  /auth/oauth/{provider}/callback                  OAuth provider callback

  Federation/SSO:
    POST /federation/sso/config                           Configure SAML/SSO for an org
    POST /federation/sso/domains                          Register domain for SSO auto-detection
    GET  /organizations/{org_slug}/auth/sso/initiate      Start SSO flow
    GET  /organizations/{org_slug}/auth/sso/callback      SSO callback
    POST /federation/sso/create-token                     Create SSO session token
    GET  /federation/sso/sessions                         List SSO sessions
    POST /federation/sso/propagate                        Propagate SSO login across services
    POST /federation/sso/propagate-logout                 Propagate SSO logout across services
    POST /federation/jit/config                           Configure JIT (Just-In-Time) provisioning
    POST /federation/attribute-mappings                   Configure SAML attribute mappings

  Passwordless:
    POST /auth/passwordless/magic-link/send               Send magic link email
    POST /auth/passwordless/magic-link/verify             Verify magic link token
    POST /auth/passwordless/webauthn/register/start       Start WebAuthn registration
    POST /auth/passwordless/webauthn/register/finish      Finish WebAuthn registration
    POST /auth/passwordless/webauthn/authenticate/start   Start WebAuthn authentication
    POST /auth/passwordless/webauthn/authenticate/finish  Finish WebAuthn authentication

  ---
  References

  - Screenplay v3 setup scripts: ~/random/storyboard/setup/v3/
  - v3 architecture review: ~/random/storyboard/setup/v3/CRITICAL_ARCHITECTURE_REVIEW_V2.md
  - v3 hybrid auth architecture: ~/random/storyboard/setup/v3/OUR_HYBRID_AUTH_ARCHITECTURE.md
  - Simple company guide: ~/Skills/auth_service_ab0t/faq_simple_company_v2.md
  - SaaS reseller guide: ~/Skills/auth_service_ab0t/faq_saas_reseller_whitelabel_v2.md
  - Marketplace guide: ~/Skills/auth_service_ab0t/faq_marketplace_twosided_v1.md
  - v1 of this guide: ~/Skills/auth_service_ab0t/faq_storyboard_service_connection_v1.md
