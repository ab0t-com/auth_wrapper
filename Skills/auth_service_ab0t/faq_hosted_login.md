question: Following on from the SaaS company guide — I've got my company, my service (TaskFlow), and I can invite employees. But now I want my CUSTOMERS to sign themselves up. How do I open up registration? And what are these org-scoped auth endpoints I keep hearing about?

● Great question. This picks up right where Step 5 of the SaaS guide left off.

  Right now your system looks like this:

  Auth Service
  ├── YourCompany org (your employees)
  ├── TaskFlow Service org (permissions, API keys)
  ├── Acme Corp org (customer — Alice invited Bob and Carol manually)
  └── Widgets Inc org (customer — Dave invited Eve manually)

  The problem: every user in every customer org was put there by an admin calling `POST /organizations/{id}/invite`. That's fine for employees. But if TaskFlow is a product with thousands of end users, you can't manually invite each one. You need self-registration.

  ---
  The Two Registration Models (They Coexist)

  Your auth service now supports two paths into an org:

  ┌─────────────────────┬────────────────────────┬─────────────────────────────────────────┬───────────────────────────────────┐
  │        Path         │      Who uses it       │             How it works                │         Role comes from           │
  ├─────────────────────┼────────────────────────┼─────────────────────────────────────────┼───────────────────────────────────┤
  │ Invite flow         │ Employees, team members │ Admin calls POST /organizations/{id}/   │ The invitation (role field)       │
  │                     │                        │ invite, user gets email                 │                                   │
  ├─────────────────────┼────────────────────────┼─────────────────────────────────────────┼───────────────────────────────────┤
  │ Self-registration   │ End users, customers   │ User visits hosted login page or calls  │ Login config registration.        │
  │                     │ of your product        │ org-scoped register API                 │ default_role (default: end_user)  │
  └─────────────────────┴────────────────────────┴─────────────────────────────────────────┴───────────────────────────────────┘

  Both work in the same org at the same time. Invited users always get their invitation role. Self-registered users get the `default_role`. An invitation always wins when a code is provided.

  ---
  Step 1: Configure Self-Registration for Your Org

  You're Alice, the admin of Acme Corp. You want Acme's customers to sign up on their own.

  # Login as Alice, switch to Acme context
  TOKEN=$(curl -s -X POST "$AUTH_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email": "alice@acme.com", "password": "AliceSecure123!"}' \
    | jq -r '.access_token')

  ORG_ID="acme-corp-uuid"

  # Configure the login page — branding, self-registration, default role
  curl -X PUT "$AUTH_URL/organizations/$ORG_ID/login-config" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "branding": {
        "primary_color": "#2563EB",
        "page_title": "Acme — Sign In",
        "logo_url": "https://acme.com/logo.png",
        "login_template": "dark"
      },
      "content": {
        "welcome_message": "Welcome to Acme",
        "signup_message": "Create your account to get started",
        "terms_url": "https://acme.com/terms",
        "privacy_url": "https://acme.com/privacy"
      },
      "auth_methods": {
        "email_password": true,
        "signup_enabled": true,
        "invitation_only": false
      },
      "registration": {
        "default_role": "end_user"
      }
    }'

  What just happened: You told the auth service three things about Acme's login page:
  1. What it looks like (branding — colors, logo, title, dark template)
  2. What users see (content — welcome message, legal links)
  3. Who can join (auth_methods — self-registration is on, invitation_only is off)
  4. What role new users get (registration — `end_user`)

  The `login_config` is stored per-org. Every org can have different settings. Widgets Inc might use a light template with `invitation_only: true`. Acme uses dark with open registration.

  ---
  Step 2: Register an OAuth Client for Your App

  Your app needs a client_id to do the OAuth redirect flow. This is how the auth service knows "this login attempt is for Acme's TaskFlow instance, redirect back to their app."

  # Creates a client scoped to Acme's org
  CLIENT=$(curl -s -X POST "$AUTH_URL/auth/oauth/register" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "client_name": "Acme TaskFlow App",
      "redirect_uris": ["https://acme.taskflow.com/callback"],
      "response_types": ["code"],
      "grant_types": ["authorization_code", "refresh_token"],
      "token_endpoint_auth_method": "none"
    }')
  CLIENT_ID=$(echo "$CLIENT" | jq -r '.client_id')

  What just happened: You registered an OAuth client while authenticated as an Acme admin. Because you had a Bearer token, the client got automatically scoped to Acme's org. This is a security boundary — this client_id can only be used on Acme's login page. If someone tries to use it on Widgets Inc's login page, they get a 400 error.

  Clients registered without authentication (RFC 7591 dynamic registration) are "global" — no org restriction. But for hosted login, you always want org-scoped clients.

  ---
  Step 3: Choose How Your Users Log In

  You now have three options. Pick one (or use all three for different scenarios).

  Option A: Hosted Login Page (zero frontend work)

  Point users to the auth service's hosted page. It renders your branding, handles everything.

  https://auth.service.ab0t.com/login/acme-corp?client_id=CLIENT_ID&redirect_uri=https://acme.taskflow.com/callback&response_type=code&state=RANDOM_CSRF_TOKEN

  That's a URL. Put it behind your "Sign In" button. Users see Acme's branded page with your colors, logo, welcome message, and any configured providers (Google, Microsoft, SSO). They sign up or log in, and get redirected back to your app with an auth code.

  Templates available: `default` (light) and `dark` (Stytch-style). Set via `branding.login_template` in login config.

  The flow:
  User clicks "Sign In" on your app
    → Redirected to /login/acme-corp?client_id=...&redirect_uri=...
    → Sees branded login page
    → Signs up or logs in
    → Page calls POST /organizations/acme-corp/auth/login (or /register)
    → Gets access_token → calls GET /auth/authorize with OAuth params
    → Redirected to https://acme.taskflow.com/callback?code=abc&state=xyz
    → Your app exchanges code for tokens via POST /organizations/acme-corp/auth/token


  Option B: Embeddable Widget (minimal frontend work)

  Drop a script tag in your page. The widget creates an iframe with the hosted login page inside it.

  <script src="https://auth.service.ab0t.com/login/_static/auth-widget.js"></script>
  <script>
    AuthMesh.init({
      container: '#login',
      org: 'acme-corp',
      clientId: 'xxx',
      onSuccess: (result) => {
        // result.code — exchange this for tokens
        // result.state — your CSRF token
      },
      onError: (err) => { console.error(err); }
    });
  </script>

  Or popup mode:
  AuthMesh.popup({org: 'acme-corp', clientId: 'xxx'}).then(result => {
    // result.code, result.state
  });

  The widget handles PKCE, postMessage security, and token exchange. Your page never sees the user's password.


  Option C: Build Your Own UI (full control)

  Use the org-scoped API endpoints directly. You build the form, you control the UX, the auth service handles the identity.

  These are the new org-scoped endpoints — they resolve the org from the slug, respect the org's login config, and handle self-registration automatically:

  # Register a new user in Acme's org
  curl -X POST "$AUTH_URL/organizations/acme-corp/auth/register" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "newuser@gmail.com",
      "password": "SecurePass123!",
      "name": "New User"
    }'

  # Login
  curl -X POST "$AUTH_URL/organizations/acme-corp/auth/login" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "newuser@gmail.com",
      "password": "SecurePass123!"
    }'

  # Exchange code for tokens (after /auth/authorize)
  curl -X POST "$AUTH_URL/organizations/acme-corp/auth/token" \
    -H "Content-Type: application/json" \
    -d '{
      "grant_type": "authorization_code",
      "code": "AUTH_CODE",
      "client_id": "CLIENT_ID",
      "code_verifier": "PKCE_VERIFIER",
      "redirect_uri": "https://acme.taskflow.com/callback"
    }'

  # Refresh tokens
  curl -X POST "$AUTH_URL/organizations/acme-corp/auth/refresh" \
    -H "Content-Type: application/json" \
    -d '{"refresh_token": "REFRESH_TOKEN"}'

  # Logout
  curl -X POST "$AUTH_URL/organizations/acme-corp/auth/logout" \
    -H "Authorization: Bearer $USER_TOKEN"

  # Get available providers (public, no auth needed)
  curl "$AUTH_URL/organizations/acme-corp/auth/providers"

  Or use the npm SDK:
  import { AuthMeshClient } from '@authmesh/sdk';

  const auth = new AuthMeshClient({
    domain: 'auth.service.ab0t.com',
    org: 'acme-corp',
    clientId: 'xxx',
    redirectUri: 'https://acme.taskflow.com/callback'
  });

  auth.loginWithRedirect();                    // Redirect to hosted login
  const result = await auth.loginWithPopup();   // Popup
  const tokens = await auth.handleCallback();   // Handle callback
  auth.loginWithSSO();                          // SSO/SAML redirect

  ---
  Step 4: What Happens When a User Self-Registers

  Situation: Dave visits Acme's hosted login page and creates an account.

  Dave goes to:
  https://auth.service.ab0t.com/login/acme-corp?client_id=xxx&redirect_uri=https://acme.taskflow.com/callback&response_type=code&state=abc

  He clicks "Sign Up", enters his email, password, and name. Behind the scenes:

  1. The page calls `POST /organizations/acme-corp/auth/register` with Dave's info
  2. The endpoint resolves `acme-corp` slug → Acme's org_id
  3. Checks the login config: `signup_enabled: true`, `invitation_only: false` → registration allowed
  4. Creates Dave's account
  5. Adds Dave to Acme's org with role `end_user` (from `registration.default_role`)
  6. Returns an access token
  7. The page uses the token to call `GET /auth/authorize` → gets an auth code
  8. Redirects Dave to `https://acme.taskflow.com/callback?code=xyz&state=abc`
  9. Your app exchanges the code for tokens

  Dave is now an `end_user` in Acme Corp. He can do `api.read` — that's it. He can't manage users, create teams, or change the org config.

  What just happened: Dave signed himself up. No admin had to invite him. He got the minimum permissions automatically. This is the self-registration path.

  ---
  Step 5: Your Employees vs Your Customers (Same Org, Different Paths)

  This is the key insight: both models work in the same org at the same time.

  Acme Corp (org)
  ├── Alice (owner)     — created the org
  ├── Bob (admin)       — invited by Alice with role=admin
  ├── Carol (member)    — invited by Bob with role=member
  ├── Dave (end_user)   — self-registered via hosted login
  └── Eve (end_user)    — self-registered via hosted login

  How each person got there:
  - Alice: created the org → automatic `owner`
  - Bob: Alice called `POST /organizations/{id}/invite` with `role: admin` → Bob got `admin`
  - Carol: Bob called `POST /organizations/{id}/invite` with `role: member` → Carol got `member`
  - Dave: visited the hosted login page, clicked "Sign Up" → got `end_user` (the default_role)
  - Eve: same as Dave

  The role table:

  ┌───────────┬───────────────────────────────────┬─────────────────────────┬───────────────────────────────────────────┐
  │   Role    │          Who gets it              │  Default permissions    │             How to change                 │
  ├───────────┼───────────────────────────────────┼─────────────────────────┼───────────────────────────────────────────┤
  │ owner     │ Org creator                       │ Full control            │ N/A                                       │
  ├───────────┼───────────────────────────────────┼─────────────────────────┼───────────────────────────────────────────┤
  │ admin     │ Invited as admin                  │ Manage users, teams,    │ Via invitation                            │
  │           │                                   │ config                  │                                           │
  ├───────────┼───────────────────────────────────┼─────────────────────────┼───────────────────────────────────────────┤
  │ member    │ Invited as member                 │ Read org, read/write    │ Via invitation                            │
  │           │                                   │ API                     │                                           │
  ├───────────┼───────────────────────────────────┼─────────────────────────┼───────────────────────────────────────────┤
  │ end_user  │ Self-registered via hosted login  │ api.read only           │ PUT /login-config                         │
  │           │ or org-scoped register API        │                         │ {registration.default_role}               │
  ├───────────┼───────────────────────────────────┼─────────────────────────┼───────────────────────────────────────────┤
  │ personal  │ Individual signup (no org)        │ Own workspace only      │ N/A                                       │
  └───────────┴───────────────────────────────────┴─────────────────────────┴───────────────────────────────────────────┘

  Situation: Alice wants to upgrade Dave from end_user to member.

  Alice invites Dave with `role: member`:

  curl -X POST "$AUTH_URL/organizations/$ORG_ID/invite" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -d '{"email": "dave@gmail.com", "role": "member"}'

  Dave's role upgrades. He now has `member` permissions. The invitation always wins.

  Situation: Alice wants to stop new self-registrations but keep existing users.

  curl -X PUT "$AUTH_URL/organizations/$ORG_ID/login-config" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -d '{"auth_methods": {"invitation_only": true}}'

  Now new users who visit the login page can't sign up. Dave and Eve (already registered) are unaffected. Alice can still invite people via the admin API.

  ---
  Step 6: Multi-Org Users and Login-as-Join

  Situation: Dave is a consultant. He already has an account in Acme Corp. Now he visits Widgets Inc's hosted login page.

  Dave goes to:
  https://auth.service.ab0t.com/login/widgets-inc?client_id=yyy&redirect_uri=https://widgets.taskflow.com/callback&response_type=code&state=def

  Dave tries to log in (not register — he already has an account). What happens:

  1. The org-scoped login endpoint authenticates Dave (email + password)
  2. Dave's credentials are valid — he exists on the platform
  3. But Dave isn't a member of Widgets Inc
  4. The endpoint checks Widgets Inc's login config: `signup_enabled: true`, `invitation_only: false`
  5. Dave is automatically added to Widgets Inc with `default_role` (end_user)
  6. Dave gets his tokens scoped to Widgets Inc

  This is called login-as-join. It matches Auth0's "Membership on Authentication" pattern. Each org membership is independent:

  Dave's memberships:
  ├── Acme Corp     → member (upgraded from end_user by Alice)
  └── Widgets Inc   → end_user (auto-joined via login-as-join)

  Dave logs into Acme → member permissions (read/write). Dave logs into Widgets → end_user permissions (read only). The orgs are completely isolated — Acme data never leaks to Widgets, even though it's the same person.

  What if Dave tries to register on Widgets Inc instead of logging in? Same thing — the org-scoped register endpoint detects "user with this email already exists," validates the password, and auto-joins instead of returning an error.

  What if Widgets Inc has `invitation_only: true`? Dave gets 403. He can only join if a Widgets admin invites him.

  ---
  Step 7: Add Social Login Providers

  Situation: Alice wants her customers to log in with Google too, not just email/password.

  # Add Google login to Acme's org
  curl -X POST "$AUTH_URL/providers/" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "org_id": "'$ORG_ID'",
      "provider_type": "google",
      "name": "Continue with Google",
      "config": {
        "client_id": "YOUR_GOOGLE_CLIENT_ID",
        "client_secret": "YOUR_GOOGLE_SECRET"
      },
      "priority": 1
    }'

  What just happened: A "Continue with Google" button now appears on Acme's hosted login page automatically. No template changes, no frontend work. The hosted login endpoint fetches active providers server-side and injects them into the page config.

  You can add multiple providers:

  # Microsoft
  curl -X POST "$AUTH_URL/providers/" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -d '{
      "org_id": "'$ORG_ID'",
      "provider_type": "microsoft",
      "name": "Continue with Microsoft",
      "config": {"client_id": "MS_CLIENT_ID", "client_secret": "MS_SECRET"},
      "priority": 2
    }'

  # GitHub
  curl -X POST "$AUTH_URL/providers/" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -d '{
      "org_id": "'$ORG_ID'",
      "provider_type": "github",
      "name": "Continue with GitHub",
      "config": {"client_id": "GH_CLIENT_ID", "client_secret": "GH_SECRET"},
      "priority": 3
    }'

  Supported providers: `google`, `microsoft`, `github`, `saml`, `okta`, `auth0`, `keycloak`.

  The providers are org-specific. Acme might have Google + Microsoft. Widgets Inc might have only GitHub. Each org's login page shows only its configured providers.

  The public providers endpoint (no auth required) lets BYOUI integrations discover what's available:

  curl "$AUTH_URL/organizations/acme-corp/auth/providers"
  # Returns: [{type: "google", name: "Continue with Google"}, ...]

  ---
  Step 8: Add Enterprise SSO (SAML)

  Situation: Acme Corp has an enterprise IdP (Okta, Azure AD). Their security team requires SSO for all employees.

  # Add SAML SSO to Acme
  curl -X POST "$AUTH_URL/providers/" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "org_id": "'$ORG_ID'",
      "provider_type": "saml",
      "name": "Continue with SSO",
      "config": {
        "entity_id": "https://acme.com/saml",
        "assertion_consumer_service_url": "https://auth.service.ab0t.com/organizations/acme-corp/auth/sso/callback",
        "idp_entity_id": "https://acme.okta.com",
        "idp_sso_url": "https://acme.okta.com/app/xxx/sso/saml",
        "idp_cert": "MIID..."
      },
      "priority": 0
    }'

  A "Continue with SSO" button now appears on the hosted login page (priority 0 = first button). When clicked:

  User clicks "Continue with SSO"
    → Page redirects to /organizations/acme-corp/auth/sso/initiate?client_id=...&redirect_uri=...
    → Auth service generates SAML AuthnRequest, encodes OAuth params in RelayState
    → User redirected to IdP (Okta/Azure AD) for authentication
    → IdP sends SAML assertion back to /organizations/acme-corp/auth/sso/callback
    → Auth service validates assertion, JIT provisions user (creates account if new)
    → Adds user to org with default_role
    → If OAuth params in RelayState: generates auth code, redirects to tenant callback
    → If standalone: creates session, redirects to dashboard

  JIT provisioning means the auth service auto-creates accounts for SSO users. First time Alice's employee logs in via Okta, their account is created with the email from the SAML assertion and they're added to Acme's org. No manual invitation needed for SSO users.

  ---
  Why Two Sets of Endpoints?

  You might notice there are two register and two login endpoints:

  ┌──────────────────────────────────────────────────┬─────────────────────────────────────┬────────────────────────────────────────────┐
  │                    Endpoint                      │              Purpose                │               Who calls it                 │
  ├──────────────────────────────────────────────────┼─────────────────────────────────────┼────────────────────────────────────────────┤
  │ POST /auth/register                              │ Platform-level account creation     │ The auth mesh itself, internal tooling     │
  ├──────────────────────────────────────────────────┼─────────────────────────────────────┼────────────────────────────────────────────┤
  │ POST /auth/login                                 │ Platform-level login                │ Internal apps, admin dashboards            │
  ├──────────────────────────────────────────────────┼─────────────────────────────────────┼────────────────────────────────────────────┤
  │ POST /organizations/{slug}/auth/register         │ Tenant-scoped self-registration     │ Hosted login page, BYOUI integrations      │
  ├──────────────────────────────────────────────────┼─────────────────────────────────────┼────────────────────────────────────────────┤
  │ POST /organizations/{slug}/auth/login            │ Tenant-scoped login                 │ Hosted login page, BYOUI integrations      │
  ├──────────────────────────────────────────────────┼─────────────────────────────────────┼────────────────────────────────────────────┤
  │ POST /organizations/{id}/invite                  │ Admin-controlled member addition    │ Org admins adding employees                │
  └──────────────────────────────────────────────────┴─────────────────────────────────────┴────────────────────────────────────────────┘

  The org-scoped endpoints (`/organizations/{slug}/auth/*`) are the new ones. They:
  - Resolve the org from the URL slug (not from a JWT — the user isn't logged in yet)
  - Respect the org's login config (signup_enabled, invitation_only, default_role)
  - Handle login-as-join automatically (existing user + new org = auto-join)
  - Validate OAuth client_id belongs to the org

  The platform endpoints (`/auth/*`) are the originals from the SaaS guide. They:
  - Create accounts on the platform itself
  - Don't have org-specific self-registration logic
  - Used by the auth system's own operations and admin dashboards

  Think of it this way: `/auth/*` is your back door (admin use). `/organizations/{slug}/auth/*` is your front door (customer-facing, branded, self-service).

  ---
  Putting It All Together

  Here's what Acme Corp looks like after setting up self-registration with providers:

  Acme Corp (org)
  │
  │  Login Config:
  │    branding: dark template, blue primary, Acme logo
  │    auth_methods: email/password + signup enabled
  │    registration: default_role = end_user
  │
  │  OAuth Client: "Acme TaskFlow App"
  │    client_id: acme_client_xxx
  │    redirect_uris: [https://acme.taskflow.com/callback]
  │
  │  Providers:
  │    ├── SAML SSO (priority 0) — "Continue with SSO"
  │    ├── Google (priority 1)   — "Continue with Google"
  │    ├── Microsoft (priority 2) — "Continue with Microsoft"
  │    └── GitHub (priority 3)   — "Continue with GitHub"
  │
  │  Members:
  │    ├── Alice (owner)     — created the org
  │    ├── Bob (admin)       — invited by Alice
  │    ├── Carol (member)    — invited by Bob
  │    ├── Dave (member)     — self-registered as end_user, later upgraded via invite
  │    ├── Eve (end_user)    — self-registered via hosted login
  │    ├── Frank (end_user)  — self-registered via Google provider
  │    └── Grace (end_user)  — JIT provisioned via SSO
  │
  │  Hosted Login Page: /login/acme-corp
  │    Shows: SSO button, Google button, Microsoft button, GitHub button,
  │           email/password form, sign-up tab

  And the security model:

  - Eve (end_user in Acme) tries to access Widgets Inc's config → 403. Cross-org boundaries enforced.
  - Someone creates a client_id on their own org, tries to use it on Acme's login page → 400. Client is org-scoped.
  - Eve tries to call `PUT /organizations/{id}/login-config` → 403. She's end_user, not admin.
  - Eve tries to invite people → 403. Only admins can invite.
  - Self-registered users get `api.read` only. Minimal permissions by default.
  - All OAuth flows enforce PKCE (S256). No token leakage.
  - Template XSS prevention: `__AUTH_CONFIG__` is JSON-escaped before injection.
  - Invitation codes are validated server-side and single-use.

  ---
  Common Situations

  Situation: You want to change what self-registered users can do.

  Option 1 — change the default role for new registrations:
  curl -X PUT "$AUTH_URL/organizations/$ORG_ID/login-config" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -d '{"registration": {"default_role": "member"}}'

  Now new self-registrations get `member` instead of `end_user`. Existing users keep their current role.

  Option 2 — upgrade a specific user:
  curl -X POST "$AUTH_URL/organizations/$ORG_ID/invite" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -d '{"email": "eve@gmail.com", "role": "member"}'

  Eve's role upgrades from `end_user` to `member`. Invitation always wins.

  Situation: Your app has multiple customer orgs. Each customer wants their own branding.

  That's the point. Each org has its own login config. Acme gets blue with their logo. Widgets gets green with theirs. The hosted login page at `/login/acme-corp` looks different from `/login/widgets-inc`.

  Situation: You want to pre-fill the email on the login page.

  Add `login_hint` to the URL:
  /login/acme-corp?client_id=xxx&redirect_uri=...&login_hint=dave@gmail.com

  Situation: You want the login page to open on the signup tab.

  Add `screen_hint`:
  /login/acme-corp?client_id=xxx&redirect_uri=...&screen_hint=signup

  Situation: An invited employee registers through the hosted login page instead of the invite link.

  That works. If Bob was invited with `role: admin` and he registers through the hosted login page WITH his invitation code, he gets `admin` (from the invitation), not `end_user` (from the default_role). The invitation code takes priority over the default role.

  # Employee registers through the org-scoped endpoint with invitation_code
  curl -X POST "$AUTH_URL/organizations/acme-corp/auth/register" \
    -d '{
      "email": "bob@acme.com",
      "password": "BobSecure123!",
      "name": "Bob",
      "invitation_code": "inv_abc123"
    }'
  # Bob gets admin (from invitation), not end_user

  ---
  The Full Picture (Updated from the SaaS Guide)

  Auth Service (the brain)
  │
  ├── YourCompany org (your employees)
  │   ├── You (owner/admin)
  │   ├── Support team (cross_tenant)
  │   └── Engineering team
  │
  ├── TaskFlow Service org (your app's identity)
  │   ├── Registered permissions: taskflow.read, taskflow.write, ...
  │   ├── Roles: taskflow-viewer, taskflow-member, taskflow-admin
  │   └── API Keys
  │
  ├── Acme Corp org (customer — mixed invite + self-registration)
  │   ├── Login page: /login/acme-corp (dark template, branded)
  │   ├── OAuth client: acme_client_xxx
  │   ├── Providers: SSO, Google, Microsoft, GitHub
  │   ├── Invited: Alice (owner), Bob (admin), Carol (member)
  │   ├── Self-registered: Dave (end_user), Eve (end_user)
  │   └── SSO provisioned: Grace (end_user)
  │
  ├── Widgets Inc org (customer — invitation-only)
  │   ├── Login page: /login/widgets-inc (light template, branded)
  │   ├── OAuth client: widgets_client_yyy
  │   ├── Invited only: Dave (admin), Eve (member)
  │   └── Self-registration: disabled (invitation_only: true)
  │
  └── NightOwl Startup org (customer — open self-registration)
      ├── Login page: /login/nightowl (dark template)
      ├── OAuth client: nightowl_client_zzz
      ├── No social providers (email/password only)
      ├── Dave (end_user) — same Dave, joined via login-as-join
      └── Self-registered: 500+ end users

  Dave is in three orgs: member in Acme, admin in Widgets, end_user in NightOwl. Same person, different workspaces, different permissions. He switches between them by logging into different org-scoped endpoints. The auth service keeps everything isolated.
