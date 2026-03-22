question: I am a owner of a company its a saas company, I want to use this service as my identity provider for my users and things, and sign them up and manage everything through this
  platform, I also want some things for my employees. whats the step by step process for me to do this, and integrate fully with this service, also explain it to in very simple clear
  and concise terms, and explain concepts and meanings and give examples with situations. How do I make use of this batteries included auth/authz mesh?

● Great question. Let me walk you through this end-to-end.

  ---
  The Big Picture (30 seconds)

  Think of the auth service as Slack meets AWS IAM. Every company, team, service, and even individual user gets their own workspace (called an "org"). Inside each workspace: users,
  permissions, API keys. Workspaces are isolated — Company A can't see Company B's stuff.

  You'll set up:
  1. Your company's workspace (for your employees)
  2. Your service's workspace (for your app's permissions and API keys)
  3. Customer workspaces (one per customer, auto-created on signup)
  4. A hosted login page (so customers can sign themselves up — no invitation needed)

  ---
  Step 1: Register Yourself as Admin

  You're the founder. First, you exist on the platform.

  AUTH_URL="https://auth.service.ab0t.com"

  # Create your account
  curl -X POST "$AUTH_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "you@yourcompany.com",
      "password": "YourSecurePassword123!",
      "name": "Your Name"
    }'

  What just happened: You now have an identity on the platform. Think of it like creating a Google account — you exist, but you don't have a company yet.

  ---
  Step 2: Create Your Company Org

  This is your company's home. Your employees will live here.

  # Login first (gets you a token — like a temporary badge)
  TOKEN=$(curl -s -X POST "$AUTH_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email": "you@yourcompany.com", "password": "YourSecurePassword123!"}' \
    | jq -r '.access_token')

  # Create your company
  curl -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "YourCompany",
      "slug": "yourcompany",
      "domain": "yourcompany.com",
      "billing_type": "postpaid",
      "settings": {"type": "customer", "hierarchical": true},
      "metadata": {"plan": "business"}
    }'

  What just happened: You now have a workspace called "YourCompany." You're the owner. Nobody else can see inside it. Think of it like creating a Slack workspace — it's empty, just you.

  Save the id from the response — that's your ORG_ID. You'll need it everywhere.

  ---
  Step 3: Create Your Service (The App Your Customers Use)

  Your SaaS product needs its own identity too. Why? Because your app needs to know "what can users do?" — that's permissions. And permissions live in a service org.

  Example: You run a project management SaaS called "TaskFlow."

  3a: Define your permissions

  Create a .permissions.json file. This is where you declare what users CAN do in your app:

  {
    "service": "taskflow",
    "description": "Project management platform",
    "actions": ["read", "write", "create", "delete", "admin"],
    "resources": ["projects", "tasks", "comments", "reports"],
    "roles": {
      "taskflow-viewer": {
        "description": "Can view projects and tasks",
        "default_permissions": ["taskflow.read.projects", "taskflow.read.tasks", "taskflow.read.comments"]
      },
      "taskflow-member": {
        "description": "Can create and edit tasks",
        "default_permissions": [
          "taskflow.read.projects", "taskflow.read.tasks",
          "taskflow.create.tasks", "taskflow.write.tasks",
          "taskflow.create.comments", "taskflow.read.comments"
        ]
      },
      "taskflow-admin": {
        "description": "Full access",
        "implies": ["taskflow-member"],
        "default_permissions": [
          "taskflow.create.projects", "taskflow.write.projects",
          "taskflow.delete.projects", "taskflow.delete.tasks",
          "taskflow.admin"
        ]
      }
    }
  }

  What this means in plain English:
  - A viewer can look at projects, tasks, comments — but not touch anything
  - A member can create/edit tasks and comments — the day-to-day worker
  - An admin can do everything — create/delete projects, manage the workspace

  3b: Run the registration script

  The registration script (register-service-permissions.sh) does 6 things automatically:
  1. Creates a service admin account (you+taskflow@yourcompany.com)
  2. Creates a service org for TaskFlow (separate from your company org)
  3. Logs in with that org context
  4. Registers the permissions from .permissions.json
  5. Creates an API key for your service
  6. (Optional) registers with the proxy

  Why a separate org for the service? Imagine someone hacks your customer support dashboard. If your service permissions lived in the same org as customer data, the attacker could escalate.
  Separate org = separate blast radius. Your service org holds the "rulebook" (permissions, API keys). Customer orgs hold the actual data.

  ---
  Step 4: Integrate Your App

  4a: Install the library

  # requirements.txt
  git+https://github.com/ab0t-com/auth_wrapper.git

  4b: Configure (app/config.py)

  class Settings(BaseSettings):
      AB0T_AUTH_URL: str = "https://auth.service.ab0t.com"
      AB0T_AUTH_AUDIENCE: str = "taskflow"  # Matches service_audience from registration
      AB0T_AUTH_PERMISSION_CHECK_MODE: str = "server"  # Revocations take effect immediately

  4c: Create your auth module (app/auth.py)

  from ab0t_auth import AuthGuard, AuthenticatedUser, require_permission, require_any_permission
  from ab0t_auth.middleware import register_auth_exception_handlers
  from ab0t_auth.errors import PermissionDeniedError

  auth = AuthGuard(
      auth_url=settings.AB0T_AUTH_URL,
      audience=settings.AB0T_AUTH_AUDIENCE,
      permission_check_mode=settings.AB0T_AUTH_PERMISSION_CHECK_MODE,
  )

  # Type aliases — put these in your route signatures
  # "Who is this user and what can they do?"

  # Can view stuff
  TaskViewer = Annotated[AuthenticatedUser, Depends(
      require_permission(auth, "taskflow.read", check=belongs_to_org)
  )]

  # Can create/edit tasks
  TaskWorker = Annotated[AuthenticatedUser, Depends(
      require_any_permission(auth, "taskflow.create.tasks", "taskflow.write.tasks",
          checks=[belongs_to_org, is_not_suspended], check_mode="all")
  )]

  # Can manage projects
  ProjectAdmin = Annotated[AuthenticatedUser, Depends(
      require_permission(auth, "taskflow.admin", check=belongs_to_org)
  )]

  What are these? Think of them as security badges. When someone walks into a route, the badge checks:
  - Are you who you say you are? (authentication)
  - Are you allowed to do this? (permission)
  - Are you in the right workspace? (org check)
  - Are you suspended? (status check)

  4d: Protect your routes

  # Anyone in the org can see the project list
  @router.get("/projects")
  async def list_projects(user: TaskViewer):
      # user.org_id tells you which company this person belongs to
      # Only show THEIR company's projects
      return await db.list_projects(org_id=user.org_id)

  # Members can create tasks
  @router.post("/projects/{project_id}/tasks")
  async def create_task(project_id: str, data: TaskCreate, user: TaskWorker):
      project = await db.get_project(project_id)
      if not project:
          raise HTTPException(404)
      # Phase 2: Is this project in the user's org?
      if project.org_id != user.org_id:
          raise PermissionDeniedError("Access denied")
      return await db.create_task(project_id, data, user_id=user.user_id, org_id=user.org_id)

  # Only admins can delete projects
  @router.delete("/projects/{project_id}")
  async def delete_project(project_id: str, user: ProjectAdmin):
      project = await db.get_project(project_id)
      if not project:
          raise HTTPException(404)
      if project.org_id != user.org_id:
          raise PermissionDeniedError("Access denied")
      return await db.delete_project(project_id)

  The key insight: Every resource you store (project, task, comment) should have an org_id field. That's how you know "this project belongs to Acme Corp, not Widgets Inc." The auth library
  handles who-are-you. Your database handles what-belongs-where.

  ---
  Step 5: Onboard Your First Customer (The Admin-Invite Way)

  Situation: Acme Corp wants to use TaskFlow. Alice is their admin.

  5a: Acme signs up — gets their own org

  When Alice signs up on your platform, your backend creates an org for them:

  # Your backend does this when Alice registers
  curl -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $SERVICE_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Acme Corporation",
      "slug": "acme-corp",
      "domain": "acme.com",
      "billing_type": "postpaid",
      "settings": {"type": "customer"}
    }'

  Alice is now the owner of the Acme org. She can see Acme's stuff. She can't see Widgets Inc's stuff. Nobody at Widgets can see Acme's stuff. The walls are automatic.

  5b: Alice invites her employees

  # Alice (logged into Acme context) invites Bob
  curl -X POST "$AUTH_URL/organizations/$ACME_ORG_ID/invite" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "bob@acme.com",
      "role": "taskflow-member",
      "permissions": ["taskflow.read.projects", "taskflow.create.tasks", "taskflow.write.tasks"],
      "message": "Welcome to TaskFlow!"
    }'

  Bob gets an email, signs up, and lands in the Acme workspace. He can create tasks but can't delete projects.

  5c: Alice creates teams

  # Engineering team — can do everything with tasks
  curl -X POST "$AUTH_URL/organizations/$ACME_ORG_ID/teams" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Engineering",
      "permissions": ["taskflow.create.tasks", "taskflow.write.tasks", "taskflow.read.projects"]
    }'

  # Marketing team — read-only
  curl -X POST "$AUTH_URL/organizations/$ACME_ORG_ID/teams" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Marketing",
      "permissions": ["taskflow.read.projects", "taskflow.read.tasks"]
    }'

  Now when Bob joins the Engineering team, he inherits those permissions. New hires joining Engineering automatically get the right access.

  What just happened: This is the invite model. Every user was placed in the org by an admin. Alice invited Bob. Bob didn't sign himself up. This is perfect for employees — you control who gets in and what role they get.

  But what about Acme's customers? If TaskFlow is a product, Acme might have thousands of end users. Alice can't invite each one. That's Step 7.

  ---
  Step 6: Set Up Your Employees

  Your employees (support, engineering) need access too, but differently.

  Your internal team

  Support staff — need to see customer data to help them:

  # Grant cross_tenant to support (lets them see ANY org's data)
  curl -X POST "$AUTH_URL/permissions/grant?user_id=$SUPPORT_USER_ID&org_id=$YOUR_ORG_ID&permission=taskflow.cross_tenant"

  Your engineers — they work on the product, they're users of your company org:

  curl -X POST "$AUTH_URL/organizations/$YOUR_ORG_ID/invite" \
    -d '{"email": "dev@yourcompany.com", "role": "taskflow-admin", "permissions": ["taskflow.admin"]}'

  The difference
  ┌────────────────────┬─────────────┬─────────────────────────────────┬────────────────────────────────────────────┐
  │       Person       │     Org     │          What they see          │                    Why                     │
  ├────────────────────┼─────────────┼─────────────────────────────────┼────────────────────────────────────────────┤
  │ Alice (Acme admin) │ Acme Corp   │ All of Acme's projects          │ taskflow.admin in Acme org                 │
  ├────────────────────┼─────────────┼─────────────────────────────────┼────────────────────────────────────────────┤
  │ Bob (Acme member)  │ Acme Corp   │ His own tasks                   │ taskflow.read + taskflow.write in Acme org │
  ├────────────────────┼─────────────┼─────────────────────────────────┼────────────────────────────────────────────┤
  │ Your support agent │ YourCompany │ ALL customers' projects         │ taskflow.cross_tenant                      │
  ├────────────────────┼─────────────┼─────────────────────────────────┼────────────────────────────────────────────┤
  │ Your engineer      │ YourCompany │ YourCompany's internal projects │ taskflow.admin in YourCompany org          │
  └────────────────────┴─────────────┴─────────────────────────────────┴────────────────────────────────────────────┘

  ---
  Step 7: Open Self-Registration for Your Customers

  This is the big one. Up to now, every user was placed in an org by an admin calling POST /organizations/{id}/invite. That's fine for employees. But if TaskFlow has thousands of end users, you need self-registration.

  The auth service supports two registration models. They coexist in the same org:

  ┌─────────────────────┬────────────────────────┬─────────────────────────────────────────┬───────────────────────────────────┐
  │        Path         │      Who uses it       │             How it works                │         Role comes from           │
  ├─────────────────────┼────────────────────────┼─────────────────────────────────────────┼───────────────────────────────────┤
  │ Invite flow         │ Employees, team members │ Admin calls POST /organizations/{id}/   │ The invitation (role field)       │
  │                     │                        │ invite, user gets email                 │                                   │
  ├─────────────────────┼────────────────────────┼─────────────────────────────────────────┼───────────────────────────────────┤
  │ Self-registration   │ End users, customers   │ User visits hosted login page or calls  │ Login config registration.        │
  │                     │ of your product        │ org-scoped register API                 │ default_role (default: end_user)  │
  └─────────────────────┴────────────────────────┴─────────────────────────────────────────┴───────────────────────────────────┘

  7a: Configure the login page for Acme

  Alice (Acme's admin) configures self-registration:

  curl -X PUT "$AUTH_URL/organizations/$ACME_ORG_ID/login-config" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
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

  What just happened: Alice told the auth service three things:
  1. What the login page looks like (branding — colors, logo, dark template)
  2. What users see (content — welcome message, legal links)
  3. Who can join (auth_methods — self-registration is on, invitation_only is off)
  4. What role new users get (registration — end_user)

  7b: Register an OAuth client for Acme's app

  # Creates a client scoped to Acme's org (for the redirect flow)
  CLIENT=$(curl -s -X POST "$AUTH_URL/auth/oauth/register" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "client_name": "Acme TaskFlow App",
      "redirect_uris": ["https://acme.taskflow.com/callback"],
      "response_types": ["code"],
      "grant_types": ["authorization_code", "refresh_token"],
      "token_endpoint_auth_method": "none"
    }')
  CLIENT_ID=$(echo "$CLIENT" | jq -r '.client_id')

  What just happened: The OAuth client was registered while Alice had a Bearer token. So it's automatically scoped to Acme's org. This is a security boundary — this client_id can only be used on Acme's login page. If someone tries to use it on Widgets Inc's login page, they get 400.

  7c: Point end users to the hosted login page

  https://auth.service.ab0t.com/login/acme-corp?client_id=CLIENT_ID&redirect_uri=https://acme.taskflow.com/callback&response_type=code&state=RANDOM

  That's it. Put this URL behind your "Sign In" button. Users see Acme's branded page — dark template, blue primary color, Acme logo, welcome message. They sign up or log in, and get redirected back to your app with an auth code.

  Templates: default (light) and dark (Stytch-style). Set via branding.login_template.

  The flow:
  User clicks "Sign In" on your app
    -> Redirected to /login/acme-corp?client_id=...&redirect_uri=...
    -> Sees branded login page
    -> Signs up (or logs in)
    -> Page calls POST /organizations/acme-corp/auth/register (or /login)
    -> Gets access_token -> calls GET /auth/authorize with OAuth params
    -> Redirected to https://acme.taskflow.com/callback?code=abc&state=xyz
    -> Your app exchanges code for tokens via POST /organizations/acme-corp/auth/token

  7d: What the end_user role means

  Dave visits the hosted login page, creates an account. He gets end_user automatically.

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
  └───────────┴───────────────────────────────────┴─────────────────────────┴───────────────────────────────────────────┘

  Situation: Alice wants to upgrade Dave from end_user to member.

  curl -X POST "$AUTH_URL/organizations/$ACME_ORG_ID/invite" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -d '{"email": "dave@gmail.com", "role": "member"}'

  Dave's role upgrades. The invitation always wins over the default_role.

  7e: What Acme looks like now

  Acme Corp (org)
  ├── Alice (owner)     — created the org
  ├── Bob (admin)       — invited by Alice with role=admin
  ├── Carol (member)    — invited by Bob with role=member
  ├── Dave (end_user)   — self-registered via hosted login
  └── Eve (end_user)    — self-registered via hosted login

  Both models in the same org. Invited users get their invitation role. Self-registered users get end_user. If Alice later invites Dave with role=member, he upgrades.

  ---
  Step 8: Add Social Login Providers

  Situation: Alice wants her customers to log in with Google, not just email/password.

  # Add Google login to Acme's org
  curl -X POST "$AUTH_URL/providers/" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "org_id": "'$ACME_ORG_ID'",
      "provider_type": "google",
      "name": "Continue with Google",
      "config": {"client_id": "YOUR_GOOGLE_CLIENT_ID", "client_secret": "YOUR_SECRET"},
      "priority": 1
    }'

  What just happened: A "Continue with Google" button now appears on Acme's hosted login page. No template changes, no frontend work. The hosted login endpoint fetches active providers server-side and injects them into the page.

  Add more:

  # Microsoft
  curl -X POST "$AUTH_URL/providers/" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -d '{
      "org_id": "'$ACME_ORG_ID'",
      "provider_type": "microsoft",
      "name": "Continue with Microsoft",
      "config": {"client_id": "MS_ID", "client_secret": "MS_SECRET"},
      "priority": 2
    }'

  # GitHub
  curl -X POST "$AUTH_URL/providers/" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -d '{
      "org_id": "'$ACME_ORG_ID'",
      "provider_type": "github",
      "name": "Continue with GitHub",
      "config": {"client_id": "GH_ID", "client_secret": "GH_SECRET"},
      "priority": 3
    }'

  # SAML SSO (for enterprise customers)
  curl -X POST "$AUTH_URL/providers/" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -d '{
      "org_id": "'$ACME_ORG_ID'",
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

  Supported providers: google, microsoft, github, saml, okta, auth0, keycloak.

  Providers are org-specific. Acme has Google + Microsoft + SSO. Widgets Inc might have only GitHub. Each org's login page shows only its configured providers.

  The public providers endpoint (no auth required) lets BYOUI integrations discover what's available:

  curl "$AUTH_URL/organizations/acme-corp/auth/providers"
  # Returns: [{type: "saml", name: "Continue with SSO"}, {type: "google", name: "Continue with Google"}, ...]

  SSO flow: user clicks "Continue with SSO" -> redirected to IdP (Okta/Azure AD) -> IdP authenticates -> SAML assertion back to auth service -> JIT provisions user (auto-creates account if new) -> adds to org with default_role -> redirects back with auth code.

  ---
  Step 9: Wire Up Your Frontend

  There are now two families of auth endpoints. Which you use depends on who's logging in.

  The two doors

  ┌──────────────────────────────────────────────────┬─────────────────────────────────────┬────────────────────────────────────────────┐
  │                    Endpoint                      │              Purpose                │               Who calls it                 │
  ├──────────────────────────────────────────────────┼─────────────────────────────────────┼────────────────────────────────────────────┤
  │ POST /auth/login                                 │ Platform-level login                │ Your admin dashboard, internal tools       │
  ├──────────────────────────────────────────────────┼─────────────────────────────────────┼────────────────────────────────────────────┤
  │ POST /auth/register                              │ Platform-level registration         │ Your backend when creating customer orgs   │
  ├──────────────────────────────────────────────────┼─────────────────────────────────────┼────────────────────────────────────────────┤
  │ POST /organizations/{slug}/auth/login            │ Tenant-scoped login                 │ Hosted login page, customer-facing apps    │
  ├──────────────────────────────────────────────────┼─────────────────────────────────────┼────────────────────────────────────────────┤
  │ POST /organizations/{slug}/auth/register         │ Tenant-scoped self-registration     │ Hosted login page, customer-facing apps    │
  ├──────────────────────────────────────────────────┼─────────────────────────────────────┼────────────────────────────────────────────┤
  │ POST /organizations/{slug}/auth/token            │ Exchange auth code for tokens       │ Your app's callback handler                │
  ├──────────────────────────────────────────────────┼─────────────────────────────────────┼────────────────────────────────────────────┤
  │ POST /organizations/{slug}/auth/refresh          │ Refresh tokens                      │ Your app when token expires                │
  ├──────────────────────────────────────────────────┼─────────────────────────────────────┼────────────────────────────────────────────┤
  │ POST /organizations/{slug}/auth/logout           │ Revoke tokens                       │ Your app's logout button                   │
  ├──────────────────────────────────────────────────┼─────────────────────────────────────┼────────────────────────────────────────────┤
  │ GET  /organizations/{slug}/auth/providers        │ List configured providers (public)  │ Your custom login UI, SDKs                 │
  └──────────────────────────────────────────────────┴─────────────────────────────────────┴────────────────────────────────────────────┘

  Think of it this way: /auth/* is your back door (admin use). /organizations/{slug}/auth/* is your front door (customer-facing, branded, self-service).

  The org-scoped endpoints:
  - Resolve the org from the URL slug (the user isn't logged in yet)
  - Respect the org's login config (signup_enabled, invitation_only, default_role)
  - Handle login-as-join automatically (see below)
  - Validate OAuth client_id belongs to the org

  Three integration options for customer-facing login

  Option A: Hosted Login Page (zero frontend work)

  Point users to /login/{org_slug}. The auth service renders a branded page. After auth, redirects back with an OAuth code.

  https://auth.service.ab0t.com/login/acme-corp?client_id=xxx&redirect_uri=https://acme.taskflow.com/callback&response_type=code&state=abc

  Option B: Embeddable Widget (minimal frontend work)

  <script src="https://auth.service.ab0t.com/login/_static/auth-widget.js"></script>
  <script>
    AuthMesh.init({
      container: '#login',
      org: 'acme-corp',
      clientId: 'xxx',
      onSuccess: (result) => { /* result.code, result.state */ },
      onError: (err) => { /* handle error */ }
    });
  </script>

  Or popup mode: AuthMesh.popup({org: 'acme-corp', clientId: 'xxx'}).then(result => ...)

  Option C: Build Your Own UI (full control)

  Call the org-scoped endpoints directly:

  # Register
  curl -X POST "$AUTH_URL/organizations/acme-corp/auth/register" \
    -d '{"email": "newuser@gmail.com", "password": "Secure123!", "name": "New User"}'

  # Login
  curl -X POST "$AUTH_URL/organizations/acme-corp/auth/login" \
    -d '{"email": "newuser@gmail.com", "password": "Secure123!"}'

  # Exchange code for tokens
  curl -X POST "$AUTH_URL/organizations/acme-corp/auth/token" \
    -d '{"grant_type": "authorization_code", "code": "AUTH_CODE", "client_id": "xxx", "code_verifier": "PKCE_VERIFIER", "redirect_uri": "https://acme.taskflow.com/callback"}'

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

  Login-as-join (multi-org users)

  Situation: Dave already has an account in Acme Corp. He visits Widgets Inc's hosted login page and logs in.

  What happens:
  1. Dave's credentials are valid — he exists on the platform
  2. But he's not a member of Widgets Inc
  3. Widgets Inc has signup_enabled: true, invitation_only: false
  4. Dave is automatically added to Widgets Inc with default_role (end_user)
  5. Dave gets tokens scoped to Widgets Inc

  This is called login-as-join. Each org membership is independent:

  Dave's memberships:
  ├── Acme Corp     -> member (upgraded from end_user by Alice)
  └── Widgets Inc   -> end_user (auto-joined via login-as-join)

  Dave logs into Acme -> member permissions. Dave logs into Widgets -> end_user permissions. Completely isolated.

  If Widgets Inc has invitation_only: true, Dave gets 403 instead.

  Your admin dashboard flow (unchanged from v1)

  User clicks "Login" on your admin dashboard
    -> POST /auth/login { email, password }
    -> Gets back: { access_token (JWT, 15min), refresh_token }
    -> Store access_token, send as: Authorization: Bearer <token>
    -> Token expires? POST /auth/refresh { refresh_token }
    -> User belongs to multiple orgs? POST /auth/switch-organization { org_id }

  ---
  Step 10: (If Needed) Service-to-Service

  If TaskFlow calls other services (billing, notifications):

  TaskFlow needs to call Billing Service to charge customers
    -> Billing Service admin creates an API key in Billing's org
    -> Gives it to you: "ab0t_sk_live_xyz..."
    -> You store it in your .env: BILLING_API_KEY=ab0t_sk_live_xyz...
    -> Your app sends: X-API-Key: ab0t_sk_live_xyz...

  The key was created in Billing's org with only billing.create.charges and billing.read.invoices — so even if someone steals it, they can only create charges and read invoices. They can't
  delete billing records or access other services.

  ---
  Summary: What You End Up With

  Auth Service (the brain)
  │
  ├── YourCompany org (your employees)
  │   ├── You (owner/admin)
  │   ├── Support team (cross_tenant — can help any customer)
  │   ├── Engineering team (admin — builds the product)
  │   └── API Key: "yourcompany-ci" (for CI/CD)
  │
  ├── TaskFlow Service org (your app's identity)
  │   ├── Registered permissions: taskflow.read, taskflow.write, ...
  │   ├── Roles: taskflow-viewer, taskflow-member, taskflow-admin
  │   └── API Keys: "taskflow-internal", "taskflow-to-billing"
  │
  ├── Acme Corp org (customer — mixed invite + self-registration)
  │   ├── Login page: /login/acme-corp (dark, branded)
  │   ├── OAuth client: acme_client_xxx (scoped to this org)
  │   ├── Providers: SSO, Google, Microsoft, GitHub
  │   ├── Invited: Alice (owner), Bob (admin), Carol (member)
  │   ├── Self-registered: Dave (end_user), Eve (end_user)
  │   ├── SSO provisioned: Frank (end_user, via Okta JIT)
  │   └── Teams: Engineering, Marketing
  │
  ├── Widgets Inc org (customer — invitation-only)
  │   ├── Login page: /login/widgets-inc (light, branded)
  │   ├── OAuth client: widgets_client_yyy
  │   ├── Invited: Dave (admin), Eve (member)
  │   └── Self-registration: disabled (invitation_only: true)
  │
  └── NightOwl Startup org (customer — open self-registration)
      ├── Login page: /login/nightowl (dark)
      ├── No social providers (email/password only)
      └── Self-registered: 500+ end users

  Acme can't see Widgets. Widgets can't see Acme. Your support can see both. Dave is in three orgs with different roles in each. Your app enforces this automatically through the auth library.

  The security model:
  - Cross-org boundaries enforced: admin in OrgA cannot access OrgB's resources (403)
  - OAuth client_id is org-scoped: a client from OrgA can't be used on OrgB's login page
  - Self-registered users get minimal permissions (end_user = api.read only)
  - Invitation codes are validated server-side and single-use
  - PKCE (S256) enforced for all OAuth flows
  - Template XSS prevention: __AUTH_CONFIG__ is JSON-escaped before injection
