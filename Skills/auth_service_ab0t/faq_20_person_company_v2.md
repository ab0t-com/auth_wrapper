question: I run a 20-person company. We make a B2B invoicing app called "BillFlow." I want to use this auth service for everything — my employees, my customers, their employees,
  the whole thing. Walk me through it step by step, explain every concept, don't skip anything. I'm technical but I've never used this platform before.

● Perfect. Let's build the whole thing from scratch. By the end you'll have:
  - Your company set up with employees in the right roles
  - Your app integrated with protected routes
  - Customer companies that can manage their own people
  - A branded login page where your customers' users sign themselves up
  - Social login (Google, Microsoft) on that page
  - Everything isolated so Customer A can never see Customer B's data

  I'll explain every concept as we go.

  ---
  Concept: What Is an "Org"?

  An org is a workspace. Think of it like a Slack workspace or a Google Workspace domain. Inside an org: users, teams, permissions, API keys. Outside: nothing visible.

  You'll create several orgs:

  ┌──────────────────────────────┬────────────────────────────────────────────────────────┐
  │            Org               │                      What it's for                     │
  ├──────────────────────────────┼────────────────────────────────────────────────────────┤
  │ BillFlow Inc                 │ Your 20 employees. Internal stuff.                     │
  ├──────────────────────────────┼────────────────────────────────────────────────────────┤
  │ BillFlow Service             │ Your app's permission definitions and API keys.        │
  │                              │ The "rulebook" — what actions exist in your app.       │
  ├──────────────────────────────┼────────────────────────────────────────────────────────┤
  │ Martinez Plumbing            │ One of your customers. Their employees use BillFlow.   │
  ├──────────────────────────────┼────────────────────────────────────────────────────────┤
  │ Coastal Accounting           │ Another customer. Completely isolated from Martinez.    │
  ├──────────────────────────────┼────────────────────────────────────────────────────────┤
  │ ... more customers           │ Each gets their own org. Walls are automatic.           │
  └──────────────────────────────┴────────────────────────────────────────────────────────┘

  Why separate orgs for the company and the service? Blast radius. If someone compromises your customer support dashboard, they get access to BillFlow Inc (employee data). But the service org — where permissions and API keys live — is a separate vault. Attacker can't escalate from "I see employee names" to "I have the master API key."

  ---
  Step 1: Create Your Account

  You're Maya, the founder. First, you exist on the platform.

  AUTH_URL="https://auth.service.ab0t.com"

  curl -X POST "$AUTH_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "maya@billflow.com",
      "password": "MayaSecure2026!",
      "name": "Maya Chen"
    }'

  What just happened: You now have an identity. That's it — an email, a password hash, a user_id. You don't belong to any org yet. Think of it like creating a Gmail account before joining any Google Workspace.

  Concept: Authentication vs Authorization
  - Authentication = "who are you?" (the login, the password, the token)
  - Authorization = "what can you do?" (permissions, roles, org membership)

  Right now you have authentication (you can log in). You don't have authorization yet (there's nowhere to do anything).

  ---
  Step 2: Log In and Get a Token

  # Login — returns a JWT (JSON Web Token)
  TOKEN=$(curl -s -X POST "$AUTH_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email": "maya@billflow.com", "password": "MayaSecure2026!"}' \
    | jq -r '.access_token')

  echo $TOKEN

  What just happened: The auth service verified your password and gave you a token. This token is a JWT — a signed string that contains your user_id, email, and expiration time. It lasts 15 minutes. You'll send it with every request as proof of identity.

  Concept: Tokens
  - access_token: Short-lived (15 min). Send it as "Authorization: Bearer $TOKEN" on every request. Contains your identity.
  - refresh_token: Long-lived (days). Use it to get a new access_token when the old one expires. Never send it to your app's API — only to the auth service's /auth/refresh endpoint.

  Think of the access_token as a visitor badge that expires at the end of the day. The refresh_token is the key card that lets you get a new badge each morning.

  ---
  Step 3: Create Your Company Org

  curl -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "BillFlow Inc",
      "slug": "billflow",
      "domain": "billflow.com",
      "billing_type": "postpaid",
      "settings": {"type": "company", "hierarchical": true},
      "metadata": {"plan": "business", "employee_count": 20}
    }'

  Save the id from the response:

  BILLFLOW_ORG_ID="the-uuid-from-response"

  What just happened: You created a workspace called "BillFlow Inc." You're automatically the owner — the highest role, full control over everything inside. The slug "billflow" is a URL-safe identifier used in hosted login URLs later.

  Concept: Slug
  A slug is a human-readable URL identifier. "billflow" instead of "a3f7c2d1-..." You'll see it in URLs like /login/billflow. Must be unique across the platform. Use lowercase, hyphens, no spaces.

  Concept: Owner vs Admin vs Member
  - owner: Created the org. Can do everything including deleting the org. Can't be removed.
  - admin: Can manage users, teams, config. Can be granted by invitation.
  - member: Can use the app. Can't manage the org.
  - end_user: Self-registered user. Minimal permissions. More on this in Step 9.

  ---
  Step 4: Switch to Your Company Context

  Right now your token doesn't know about BillFlow Inc. You need to "enter" the org.

  MAYA_TOKEN=$(curl -s -X POST "$AUTH_URL/auth/switch-organization" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"org_id": "'"$BILLFLOW_ORG_ID"'"}' \
    | jq -r '.access_token')

  What just happened: You got a NEW token. This token contains your user_id AND org_id. Every API call you make with this token is now "Maya, acting within BillFlow Inc." The auth service knows where you are.

  Concept: Org-Scoped Tokens
  A token without an org_id is "homeless" — you can create orgs and manage your profile, but you can't do anything inside an org. A token with an org_id is "in a workspace" — now you can manage users, teams, permissions within that workspace.

  If you belong to multiple orgs, you switch between them. Each switch gives you a new token scoped to that org, with that org's permissions.

  ---
  Step 5: Define Your App's Permissions

  BillFlow is an invoicing app. You need to define what actions exist in your app. This is the "rulebook."

  Create a file called billflow.permissions.json:

  {
    "service": "billflow",
    "description": "B2B invoicing application",
    "actions": ["read", "write", "create", "delete", "send", "approve", "admin"],
    "resources": ["invoices", "clients", "payments", "reports", "settings"],
    "roles": {
      "billflow-viewer": {
        "description": "Can view invoices and reports but not modify anything",
        "default_permissions": [
          "billflow.read.invoices",
          "billflow.read.clients",
          "billflow.read.payments",
          "billflow.read.reports"
        ]
      },
      "billflow-member": {
        "description": "Can create and edit invoices, manage clients",
        "default_permissions": [
          "billflow.read.invoices", "billflow.create.invoices", "billflow.write.invoices",
          "billflow.read.clients", "billflow.create.clients", "billflow.write.clients",
          "billflow.read.payments", "billflow.read.reports",
          "billflow.send.invoices"
        ]
      },
      "billflow-approver": {
        "description": "Can approve invoices for sending, view reports",
        "implies": ["billflow-viewer"],
        "default_permissions": [
          "billflow.approve.invoices",
          "billflow.send.invoices"
        ]
      },
      "billflow-admin": {
        "description": "Full access — manage settings, users, everything",
        "implies": ["billflow-member", "billflow-approver"],
        "default_permissions": [
          "billflow.admin",
          "billflow.delete.invoices",
          "billflow.delete.clients",
          "billflow.write.settings",
          "billflow.read.settings"
        ]
      }
    }
  }

  What this means in plain English:
  - A viewer can see invoices, clients, payments, reports — but can't change anything. Your accountant's client who just needs to see their bill.
  - A member can create invoices, add clients, send invoices — the day-to-day bookkeeper.
  - An approver can approve invoices before they go out — the manager who signs off.
  - An admin can do everything — delete invoices, change settings, manage the workspace.

  Concept: Permission Format
  Permissions follow the pattern: service.action.resource

  billflow.create.invoices
  ^^^^^^^^ ^^^^^^ ^^^^^^^^
  service  action resource

  This is the same pattern as AWS IAM (s3:GetObject) or Google Cloud (storage.objects.get). The service name is a namespace — it prevents collisions if your platform runs multiple services.

  Concept: Role Inheritance ("implies")
  billflow-admin implies billflow-member and billflow-approver. That means an admin automatically has all permissions from both those roles, plus their own. You don't need to list read.invoices on admin — it's inherited from member.

  Now register these permissions with the auth service. The registration script does this:

  # This creates a service org, registers permissions, and gives you an API key
  ./register-service-permissions.sh \
    --auth-url "$AUTH_URL" \
    --service-name "billflow" \
    --admin-email "maya+billflow-svc@billflow.com" \
    --permissions-file billflow.permissions.json

  It outputs a SERVICE_API_KEY. Save this — your app uses it to talk to the auth service.

  SERVICE_API_KEY="ab0t_sk_live_..."

  ---
  Step 6: Integrate BillFlow with the Auth Library

  6a: Install

  # requirements.txt
  git+https://github.com/ab0t-com/auth_wrapper.git

  6b: Configure (app/config.py)

  from pydantic_settings import BaseSettings

  class Settings(BaseSettings):
      AB0T_AUTH_URL: str = "https://auth.service.ab0t.com"
      AB0T_AUTH_AUDIENCE: str = "LOCAL:your-billflow-service-org-uuid"
      AB0T_AUTH_PERMISSION_CHECK_MODE: str = "server"

  Concept: Audience
  The audience tells the auth library "which service's permissions are we checking?" Your service org has a UUID. When a token comes in, the library asks the auth service: "Does this user have billflow.read.invoices in the context of the BillFlow service?" The audience scopes the permission check.

  Concept: Permission Check Mode
  - "server": Every request checks permissions with the auth service in real-time. Slower (network call) but revocations take effect immediately.
  - "token": Permissions are read from the JWT itself. Faster (no network call) but revocations don't take effect until the token expires (15 min).

  For a 20-person company, "server" is fine. For 10,000 concurrent users, you'd use "token" with short expiry.

  6c: Create your auth module (app/auth.py)

  from typing import Annotated
  from fastapi import Depends
  from ab0t_auth import AuthGuard, AuthenticatedUser, require_permission, require_any_permission
  from ab0t_auth.middleware import register_auth_exception_handlers
  from ab0t_auth.errors import PermissionDeniedError

  auth = AuthGuard(
      auth_url=settings.AB0T_AUTH_URL,
      audience=settings.AB0T_AUTH_AUDIENCE,
      permission_check_mode=settings.AB0T_AUTH_PERMISSION_CHECK_MODE,
  )

  def belongs_to_org(user: AuthenticatedUser, **kwargs) -> bool:
      """Check that the user is accessing resources in their own org."""
      resource_org_id = kwargs.get("org_id")
      return resource_org_id is None or user.org_id == resource_org_id

  # Type aliases — these go in your route signatures
  InvoiceViewer = Annotated[AuthenticatedUser, Depends(
      require_permission(auth, "billflow.read.invoices", check=belongs_to_org)
  )]

  InvoiceCreator = Annotated[AuthenticatedUser, Depends(
      require_any_permission(auth, "billflow.create.invoices", "billflow.write.invoices",
          checks=[belongs_to_org], check_mode="all")
  )]

  InvoiceApprover = Annotated[AuthenticatedUser, Depends(
      require_permission(auth, "billflow.approve.invoices", check=belongs_to_org)
  )]

  BillFlowAdmin = Annotated[AuthenticatedUser, Depends(
      require_permission(auth, "billflow.admin", check=belongs_to_org)
  )]

  Concept: Type Aliases as Security Badges
  InvoiceViewer, InvoiceCreator, InvoiceApprover, BillFlowAdmin — these are like security badges you hand to your routes. When someone calls your API, the badge checks:
  1. Is this a valid token? (authentication)
  2. Does this user have billflow.read.invoices? (authorization)
  3. Is this user in the right org? (isolation)

  If any check fails, the request is rejected before your route code ever runs. You don't write if/else permission checks in your routes — the badge handles it.

  6d: Protect your routes (app/routes/invoices.py)

  from app.auth import InvoiceViewer, InvoiceCreator, InvoiceApprover, BillFlowAdmin

  @router.get("/invoices")
  async def list_invoices(user: InvoiceViewer):
      # user.org_id tells you which company this person belongs to
      return await db.list_invoices(org_id=user.org_id)

  @router.post("/invoices")
  async def create_invoice(data: InvoiceCreate, user: InvoiceCreator):
      return await db.create_invoice(
          data,
          created_by=user.user_id,
          org_id=user.org_id  # Invoice belongs to this company
      )

  @router.post("/invoices/{invoice_id}/approve")
  async def approve_invoice(invoice_id: str, user: InvoiceApprover):
      invoice = await db.get_invoice(invoice_id)
      if not invoice:
          raise HTTPException(404)
      # CRITICAL: Check that this invoice belongs to the user's org
      if invoice.org_id != user.org_id:
          raise PermissionDeniedError("Access denied")
      return await db.approve_invoice(invoice_id, approved_by=user.user_id)

  @router.delete("/invoices/{invoice_id}")
  async def delete_invoice(invoice_id: str, user: BillFlowAdmin):
      invoice = await db.get_invoice(invoice_id)
      if not invoice:
          raise HTTPException(404)
      if invoice.org_id != user.org_id:
          raise PermissionDeniedError("Access denied")
      return await db.delete_invoice(invoice_id)

  Concept: The org_id on Every Resource
  Every invoice, client, payment you store MUST have an org_id field. This is how you know "this invoice belongs to Martinez Plumbing, not Coastal Accounting." The auth library tells you WHO the user is and WHICH org they're in. Your database tells you WHICH resources belong to that org. Together, they enforce isolation.

  Concept: Phase 2 Check
  The line `if invoice.org_id != user.org_id` is called a "Phase 2 check." Phase 1 is the badge (does the user have the right permission?). Phase 2 is the resource check (does this specific invoice belong to the user's org?). Both are required. Phase 1 without Phase 2 means "user has billflow.delete.invoices permission... and can delete ANY org's invoices." That's a security hole.

  6e: Register exception handlers (app/main.py)

  from fastapi import FastAPI
  from ab0t_auth.middleware import register_auth_exception_handlers

  app = FastAPI()
  register_auth_exception_handlers(app)

  This makes auth errors return clean JSON responses:
  - 401: {"detail": "Token expired"} or {"detail": "Invalid token"}
  - 403: {"detail": "Permission denied: billflow.admin required"}

  ---
  Step 7: Invite Your 20 Employees

  Time to populate BillFlow Inc with your team.

  7a: Invite your co-founder as admin

  curl -X POST "$AUTH_URL/organizations/$BILLFLOW_ORG_ID/invite" \
    -H "Authorization: Bearer $MAYA_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "james@billflow.com",
      "role": "admin",
      "permissions": ["billflow.admin"],
      "message": "Welcome to BillFlow, co-founder!"
    }'

  What just happened: James gets an email with a link. He clicks it, creates his account (or logs in if he already has one), and lands in the BillFlow Inc org as an admin. He can now manage users, settings, and do everything in the app.

  7b: Invite the team in bulk

  # Engineering team (5 people) — they build the product, need admin for testing
  for dev in dev1 dev2 dev3 dev4 dev5; do
    curl -s -X POST "$AUTH_URL/organizations/$BILLFLOW_ORG_ID/invite" \
      -H "Authorization: Bearer $MAYA_TOKEN" \
      -d "{\"email\": \"${dev}@billflow.com\", \"role\": \"admin\", \"permissions\": [\"billflow.admin\"]}"
  done

  # Customer success (3 people) — they help customers, need to see everything
  for cs in sarah tom lisa; do
    curl -s -X POST "$AUTH_URL/organizations/$BILLFLOW_ORG_ID/invite" \
      -H "Authorization: Bearer $MAYA_TOKEN" \
      -d "{\"email\": \"${cs}@billflow.com\", \"role\": \"member\", \"permissions\": [\"billflow.read.invoices\", \"billflow.read.clients\", \"billflow.read.payments\", \"billflow.read.reports\"]}"
  done

  # Sales (4 people) — they demo the product, need basic access
  for rep in mike jenny alex pat; do
    curl -s -X POST "$AUTH_URL/organizations/$BILLFLOW_ORG_ID/invite" \
      -H "Authorization: Bearer $MAYA_TOKEN" \
      -d "{\"email\": \"${rep}@billflow.com\", \"role\": \"member\"}"
  done

  7c: Create teams

  # Engineering team
  curl -X POST "$AUTH_URL/organizations/$BILLFLOW_ORG_ID/teams" \
    -H "Authorization: Bearer $MAYA_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Engineering",
      "description": "Builds and maintains BillFlow",
      "permissions": ["billflow.admin"]
    }'

  # Customer Success team
  curl -X POST "$AUTH_URL/organizations/$BILLFLOW_ORG_ID/teams" \
    -H "Authorization: Bearer $MAYA_TOKEN" \
    -d '{
      "name": "Customer Success",
      "description": "Helps customers get the most from BillFlow",
      "permissions": ["billflow.read.invoices", "billflow.read.clients", "billflow.read.payments", "billflow.read.reports"]
    }'

  # Sales team
  curl -X POST "$AUTH_URL/organizations/$BILLFLOW_ORG_ID/teams" \
    -H "Authorization: Bearer $MAYA_TOKEN" \
    -d '{
      "name": "Sales",
      "description": "Demos and sells BillFlow",
      "permissions": ["billflow.read.invoices", "billflow.read.reports"]
    }'

  Concept: Teams
  Teams are groups of people with shared permissions. When Sarah joins the Customer Success team, she automatically gets all the team's permissions. When you add billflow.write.clients to the Customer Success team later, everyone on the team gets it immediately. No need to update each person.

  Teams are "soft walls" — grouping, not isolation. Everyone in BillFlow Inc can still see each other. If you needed hard walls (e.g., Finance data isolated from Engineering), you'd use child orgs instead (see the enterprise guide).

  7d: Grant cross-tenant access to Customer Success

  Your CS team needs to see inside customer orgs to help them. That requires a special permission:

  # Sarah can see any customer's data (for support)
  curl -X POST "$AUTH_URL/permissions/grant?user_id=$SARAH_USER_ID&org_id=$BILLFLOW_ORG_ID&permission=billflow.cross_tenant"

  Concept: cross_tenant
  Normal users can only see data in their own org. cross_tenant breaks that wall — it lets Sarah see invoices in Martinez Plumbing's org, Coastal Accounting's org, any org. Use it sparingly. Only support staff and platform admins should have it.

  What BillFlow Inc looks like now:

  BillFlow Inc (org, 20 people)
  ├── Maya (owner, founder)
  ├── James (admin, co-founder)
  │
  ├── [TEAM] Engineering (5 people)
  │   └── dev1, dev2, dev3, dev4, dev5 — billflow.admin
  │
  ├── [TEAM] Customer Success (3 people)
  │   ├── Sarah (cross_tenant — can help any customer)
  │   ├── Tom
  │   └── Lisa
  │
  ├── [TEAM] Sales (4 people)
  │   └── Mike, Jenny, Alex, Pat — billflow.read.*
  │
  └── Remaining: finance, marketing, ops (5 people, various roles)

  ---
  Step 8: Onboard Your First Customer

  Situation: Martinez Plumbing (8 employees) wants to use BillFlow.

  8a: Create their org

  Your backend does this when Martinez signs up on your marketing site:

  # Your signup flow calls this
  MARTINEZ=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "X-API-Key: $SERVICE_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Martinez Plumbing",
      "slug": "martinez-plumbing",
      "domain": "martinezplumbing.com",
      "billing_type": "postpaid",
      "settings": {"type": "customer"},
      "metadata": {"plan": "starter", "signup_source": "website"}
    }')
  MARTINEZ_ORG_ID=$(echo "$MARTINEZ" | jq -r '.id')

  What just happened: Martinez Plumbing now has their own isolated workspace. Nobody at Coastal Accounting can see inside. Nobody at BillFlow Inc can see inside (except Sarah with cross_tenant). The walls are automatic.

  8b: Rosa (Martinez owner) invites her team

  Rosa signed up and became the owner. She invites her people:

  # Rosa invites her office manager as admin
  curl -X POST "$AUTH_URL/organizations/$MARTINEZ_ORG_ID/invite" \
    -H "Authorization: Bearer $ROSA_TOKEN" \
    -d '{
      "email": "carlos@martinezplumbing.com",
      "role": "billflow-admin",
      "permissions": ["billflow.admin"],
      "message": "You manage our BillFlow account"
    }'

  # Rosa invites bookkeepers as members
  curl -X POST "$AUTH_URL/organizations/$MARTINEZ_ORG_ID/invite" \
    -H "Authorization: Bearer $ROSA_TOKEN" \
    -d '{
      "email": "maria@martinezplumbing.com",
      "role": "billflow-member",
      "permissions": ["billflow.create.invoices", "billflow.write.invoices", "billflow.send.invoices", "billflow.read.clients"]
    }'

  # Rosa invites the plumbers as viewers (they check their job invoices)
  curl -X POST "$AUTH_URL/organizations/$MARTINEZ_ORG_ID/invite" \
    -H "Authorization: Bearer $ROSA_TOKEN" \
    -d '{
      "email": "plumber1@martinezplumbing.com",
      "role": "billflow-viewer"
    }'

  What Martinez Plumbing looks like:

  Martinez Plumbing (org)
  ├── Rosa (owner) — full control
  ├── Carlos (admin) — manages the BillFlow account
  ├── Maria (member) — creates and sends invoices
  ├── Plumber 1 (viewer) — checks job invoices
  ├── Plumber 2 (viewer)
  └── ... 3 more employees

  Who can see what:

  ┌─────────────────────┬────────────────────┬────────────────────────────────────────────────┐
  │       Person        │        Org         │                   What they see                │
  ├─────────────────────┼────────────────────┼────────────────────────────────────────────────┤
  │ Rosa (owner)        │ Martinez Plumbing  │ All Martinez invoices, clients, reports         │
  ├─────────────────────┼────────────────────┼────────────────────────────────────────────────┤
  │ Maria (member)      │ Martinez Plumbing  │ Martinez invoices she can create/edit/send      │
  ├─────────────────────┼────────────────────┼────────────────────────────────────────────────┤
  │ Plumber 1 (viewer)  │ Martinez Plumbing  │ Martinez invoices (read-only)                   │
  ├─────────────────────┼────────────────────┼────────────────────────────────────────────────┤
  │ Sarah (CS, BillFlow)│ BillFlow Inc       │ ALL customers' invoices (cross_tenant)          │
  ├─────────────────────┼────────────────────┼────────────────────────────────────────────────┤
  │ Mike (Sales)        │ BillFlow Inc       │ Only BillFlow internal data. NOT Martinez.      │
  └─────────────────────┴────────────────────┴────────────────────────────────────────────────┘

  ---
  Step 9: Open Self-Registration (The Hosted Login Page)

  Martinez has 8 employees, so Rosa can invite them one by one. But Coastal Accounting has 200 people. And your next customer might have 2,000. You can't invite them all manually.

  This is where self-registration comes in. You create a branded login page for each customer org. Their users sign themselves up.

  Concept: Two Registration Models
  Your auth service supports two paths into an org, and they work simultaneously:

  ┌───────────────────┬─────────────────────────┬─────────────────────────────────────────┬──────────────────────────────────┐
  │       Path        │      Who uses it        │             How it works                │        Role comes from           │
  ├───────────────────┼─────────────────────────┼─────────────────────────────────────────┼──────────────────────────────────┤
  │ Invite            │ Employees you trust     │ Admin calls POST /organizations/{id}/   │ The invitation (role field)      │
  │                   │                         │ invite — user gets email with link      │                                  │
  ├───────────────────┼─────────────────────────┼─────────────────────────────────────────┼──────────────────────────────────┤
  │ Self-registration │ End users, external     │ User visits hosted login page or calls  │ Login config default_role        │
  │                   │ people                  │ org-scoped register API                 │ (default: end_user)              │
  └───────────────────┴─────────────────────────┴─────────────────────────────────────────┴──────────────────────────────────┘

  Invited users get whatever role the admin specified. Self-registered users get end_user (minimal permissions). If someone is invited AND self-registers with an invitation code, the invitation wins.

  Concept: The end_user Role
  end_user is a built-in role for self-registered users. It has minimal permissions — just api.read. The idea: anyone can walk in the front door, but they can only look around. An admin has to upgrade them if they need to do more.

  ┌───────────┬───────────────────────────────────┬─────────────────────────┐
  │   Role    │          Who gets it              │  Default permissions    │
  ├───────────┼───────────────────────────────────┼─────────────────────────┤
  │ owner     │ Org creator                       │ Full control            │
  ├───────────┼───────────────────────────────────┼─────────────────────────┤
  │ admin     │ Invited as admin                  │ Manage users, teams     │
  ├───────────┼───────────────────────────────────┼─────────────────────────┤
  │ member    │ Invited as member                 │ Read/write in the app   │
  ├───────────┼───────────────────────────────────┼─────────────────────────┤
  │ end_user  │ Self-registered                   │ api.read only           │
  └───────────┴───────────────────────────────────┴─────────────────────────┘

  9a: Configure self-registration for Coastal Accounting

  Coastal's admin (Diane) wants her 200 employees to sign themselves up, no invitations.

  curl -X PUT "$AUTH_URL/organizations/$COASTAL_ORG_ID/login-config" \
    -H "Authorization: Bearer $DIANE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "branding": {
        "primary_color": "#0891B2",
        "page_title": "Coastal Accounting — BillFlow",
        "logo_url": "https://coastalaccounting.com/logo.png",
        "login_template": "dark"
      },
      "content": {
        "welcome_message": "Welcome to Coastal Accounting",
        "signup_message": "Create your BillFlow account",
        "terms_url": "https://coastalaccounting.com/terms",
        "privacy_url": "https://coastalaccounting.com/privacy",
        "footer_message": "Contact IT at support@coastalaccounting.com for help"
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

  Concept: Login Config
  Every org can have its own login config. It controls:
  - branding: Colors, logo, page title, template (light or dark). Each customer's login page looks like THEIR brand, not yours.
  - content: Welcome message, signup prompt, legal links, footer.
  - auth_methods: Can users sign up? Is it invitation-only? Is email/password enabled?
  - registration: What role do self-registered users get?

  The config is stored per-org. Martinez Plumbing might use invitation_only: true (Rosa invites everyone). Coastal Accounting uses signup_enabled: true (anyone with the link can join).

  9b: Register an OAuth client

  Concept: OAuth Client
  An OAuth client represents your app in the redirect flow. When a user logs in on the hosted login page, they don't get tokens directly — they get redirected back to YOUR app with a one-time code. Your app exchanges that code for tokens. This is the OAuth 2.0 Authorization Code flow, and it's the standard for web apps.

  Why? Security. If the login page returned tokens directly, they'd be in the URL (visible in browser history, server logs, referrer headers). The code flow keeps tokens server-side.

  # Creates an OAuth client scoped to Coastal's org
  CLIENT=$(curl -s -X POST "$AUTH_URL/auth/oauth/register" \
    -H "Authorization: Bearer $DIANE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "client_name": "Coastal BillFlow App",
      "redirect_uris": ["https://app.billflow.com/callback"],
      "response_types": ["code"],
      "grant_types": ["authorization_code", "refresh_token"],
      "token_endpoint_auth_method": "none"
    }')
  CLIENT_ID=$(echo "$CLIENT" | jq -r '.client_id')

  What just happened: The client was registered with Diane's token, so it's automatically scoped to Coastal's org. This client_id can ONLY be used on Coastal's login page. If someone tries to use it on Martinez's login page, they get 400. This prevents phishing — an attacker can't redirect Coastal's users through their own client.

  Concept: PKCE (Proof Key for Code Exchange)
  When your app starts the login flow, it generates a random code_verifier and sends a code_challenge (hash of the verifier) to the login page. When exchanging the code for tokens, your app sends the original code_verifier. The auth service verifies it matches the challenge. This prevents code interception attacks — even if someone steals the authorization code, they can't exchange it without the verifier. PKCE is enforced on all flows. S256 hashing is required.

  9c: Point users to the hosted login page

  https://auth.service.ab0t.com/login/coastal-accounting?client_id=CLIENT_ID&redirect_uri=https://app.billflow.com/callback&response_type=code&state=RANDOM_CSRF_TOKEN&code_challenge=HASH&code_challenge_method=S256

  That URL goes behind the "Sign In" button in your app. When a Coastal employee clicks it:

  1. They see Coastal's branded login page (teal color, Coastal logo, dark template)
  2. They click "Sign Up" and enter their email, password, name
  3. The page calls POST /organizations/coastal-accounting/auth/register
  4. They get end_user role automatically
  5. The page exchanges the login token for an OAuth authorization code
  6. They're redirected to https://app.billflow.com/callback?code=abc&state=xyz
  7. Your app exchanges the code for tokens via POST /organizations/coastal-accounting/auth/token
  8. They're logged in

  Concept: Org-Scoped Auth Endpoints
  The hosted login page uses a new family of endpoints:

  POST /organizations/{slug}/auth/register   — self-registration
  POST /organizations/{slug}/auth/login      — login
  POST /organizations/{slug}/auth/token      — exchange code for tokens
  POST /organizations/{slug}/auth/refresh    — refresh tokens
  POST /organizations/{slug}/auth/logout     — revoke tokens
  GET  /organizations/{slug}/auth/providers  — list configured providers (public)

  These endpoints resolve the org from the URL slug. The user isn't logged in yet (that's the whole point — they're trying to log in), so the org comes from the URL, not a token.

  There's also the original set:

  POST /auth/register   — platform-level registration
  POST /auth/login      — platform-level login

  Think of /organizations/{slug}/auth/* as the front door (customer-facing). /auth/* as the back door (your admin dashboard).

  ---
  Step 10: Add Social Login Providers

  Diane wants her employees to use Google login instead of typing passwords.

  # Add Google to Coastal's org
  curl -X POST "$AUTH_URL/providers/" \
    -H "Authorization: Bearer $DIANE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "org_id": "'$COASTAL_ORG_ID'",
      "provider_type": "google",
      "name": "Continue with Google",
      "config": {
        "client_id": "YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com",
        "client_secret": "YOUR_GOOGLE_CLIENT_SECRET"
      },
      "priority": 1
    }'

  # Add Microsoft (many accountants use Office 365)
  curl -X POST "$AUTH_URL/providers/" \
    -H "Authorization: Bearer $DIANE_TOKEN" \
    -d '{
      "org_id": "'$COASTAL_ORG_ID'",
      "provider_type": "microsoft",
      "name": "Continue with Microsoft",
      "config": {"client_id": "MS_CLIENT_ID", "client_secret": "MS_SECRET"},
      "priority": 2
    }'

  What just happened: The hosted login page at /login/coastal-accounting now shows two buttons — "Continue with Google" and "Continue with Microsoft" — above the email/password form. No template changes needed. The auth service fetches active providers for the org and injects them into the page automatically.

  Concept: Provider Priority
  Priority controls the order of buttons. Lower number = higher on the page. Priority 0 would be first. Coastal has Google at 1, Microsoft at 2, so Google appears first.

  Concept: Providers Are Org-Scoped
  Coastal has Google + Microsoft. Martinez might have nothing (email/password only). Each org configures its own providers. The hosted login page shows only that org's providers.

  The public endpoint lets custom UIs discover providers:

  curl "https://auth.service.ab0t.com/organizations/coastal-accounting/auth/providers"
  # Returns: [
  #   {"provider_type": "google", "name": "Continue with Google", "id": "prov_123", "priority": 1},
  #   {"provider_type": "microsoft", "name": "Continue with Microsoft", "id": "prov_456", "priority": 2}
  # ]

  No auth required — it's a public endpoint. No secrets are exposed — just the provider type, name, and ID.

  ---
  Step 11: Alternative Integration Options

  The hosted login page (Step 9c) is Option A — zero frontend work. But you have two more options.

  Option B: Embeddable Widget

  Drop a script tag in your page. It creates an iframe with the hosted login inside your app.

  <div id="billflow-login"></div>
  <script src="https://auth.service.ab0t.com/login/_static/auth-widget.js"></script>
  <script>
    AuthMesh.init({
      container: '#billflow-login',
      org: 'coastal-accounting',
      clientId: 'CLIENT_ID',
      onSuccess: function(result) {
        // result.code — send to your backend to exchange for tokens
        // result.state — verify it matches what you sent
        fetch('/api/auth/callback?code=' + result.code + '&state=' + result.state)
          .then(function(resp) { window.location = '/dashboard'; });
      },
      onError: function(err) {
        console.error('Login failed:', err);
      }
    });
  </script>

  Or popup mode (user stays on your page, login opens in a popup):

  AuthMesh.popup({
    org: 'coastal-accounting',
    clientId: 'CLIENT_ID'
  }).then(function(result) {
    // Exchange result.code for tokens
  });

  The widget handles PKCE, postMessage security, and iframe sandboxing. Your page never sees the user's password.

  Option C: Build Your Own UI

  Call the org-scoped endpoints directly from your own login form:

  # Your frontend calls your backend, which calls these:

  # Register
  curl -X POST "$AUTH_URL/organizations/coastal-accounting/auth/register" \
    -H "Content-Type: application/json" \
    -d '{"email": "newuser@gmail.com", "password": "Secure123!", "name": "New User"}'

  # Login
  curl -X POST "$AUTH_URL/organizations/coastal-accounting/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email": "newuser@gmail.com", "password": "Secure123!"}'

  # Exchange code for tokens (after /auth/authorize)
  curl -X POST "$AUTH_URL/organizations/coastal-accounting/auth/token" \
    -H "Content-Type: application/json" \
    -d '{
      "grant_type": "authorization_code",
      "code": "AUTH_CODE_FROM_AUTHORIZE",
      "client_id": "CLIENT_ID",
      "code_verifier": "ORIGINAL_PKCE_VERIFIER",
      "redirect_uri": "https://app.billflow.com/callback"
    }'

  Or use the npm SDK:

  import { AuthMeshClient } from '@authmesh/sdk';

  const auth = new AuthMeshClient({
    domain: 'auth.service.ab0t.com',
    org: 'coastal-accounting',
    clientId: 'CLIENT_ID',
    redirectUri: 'https://app.billflow.com/callback'
  });

  // Redirect to hosted login
  auth.loginWithRedirect();

  // Handle callback (in your /callback route)
  const tokens = await auth.handleCallback();

  // Get current user
  const user = auth.getUser();

  // Refresh token when needed (automatic)
  const freshToken = await auth.getAccessToken();

  ---
  Step 12: Login-as-Join (Multi-Org Users)

  Situation: Maria works at Martinez Plumbing as a bookkeeper. She also does freelance work for Coastal Accounting. She has ONE account on the platform.

  Maria was invited to Martinez (she's a member there). Now she visits Coastal's login page:

  https://auth.service.ab0t.com/login/coastal-accounting?client_id=...

  She logs in with her email and password. What happens:

  1. Her credentials are valid — she exists on the platform
  2. But she's not a member of Coastal Accounting
  3. Coastal has signup_enabled: true, invitation_only: false
  4. She's automatically added to Coastal with end_user role
  5. She gets tokens scoped to Coastal

  Concept: Login-as-Join
  When an existing user logs into an org they don't belong to, and that org allows self-registration, they're automatically joined. This is called login-as-join (Auth0 calls it "Membership on Authentication"). Each membership is independent:

  Maria's memberships:
  ├── Martinez Plumbing  -> member (invited by Rosa, can create invoices)
  └── Coastal Accounting -> end_user (auto-joined, can only read)

  Maria logs into Martinez -> member permissions (create, edit, send invoices). Maria logs into Coastal -> end_user permissions (read only). The orgs are completely isolated. Martinez data never leaks to Coastal, even though it's the same person.

  What if Martinez has invitation_only: true? Maria can't login-as-join. She gets 403. A Martinez admin has to invite her.

  What if Maria tries to register on Coastal instead of logging in? Same result — the org-scoped register endpoint detects "user already exists," validates her password, and auto-joins instead of erroring.

  ---
  Step 13: Service-to-Service Communication

  If BillFlow calls other services (payment processing, email):

  BillFlow needs to call Stripe Proxy to process payments
    -> Stripe Proxy admin creates an API key in its org
    -> Gives it to you: "ab0t_sk_live_xyz..."
    -> You store it in your .env: STRIPE_PROXY_KEY=ab0t_sk_live_xyz...
    -> Your app sends: X-API-Key: ab0t_sk_live_xyz...

  Concept: Least-Privilege API Keys
  The API key was created with only payments.create.charges and payments.read.status — so even if someone steals it, they can only create charges and check status. They can't refund, delete records, or access other services. Each key has exactly the permissions it needs, nothing more.

  ---
  Summary: What You End Up With

  Auth Service
  │
  ├── BillFlow Inc (your 20 employees)
  │   ├── Maya (owner/founder)
  │   ├── James (admin/co-founder)
  │   ├── [TEAM] Engineering (5 devs, billflow.admin)
  │   ├── [TEAM] Customer Success (3 people, read-only + cross_tenant)
  │   ├── [TEAM] Sales (4 people, read-only)
  │   └── Finance, Marketing, Ops (5 people, various)
  │
  ├── BillFlow Service (your app's identity)
  │   ├── Permissions: billflow.read, billflow.create, billflow.send, ...
  │   ├── Roles: billflow-viewer, billflow-member, billflow-approver, billflow-admin
  │   └── API Keys: "billflow-internal", "billflow-to-stripe"
  │
  ├── Martinez Plumbing (customer, 8 people, invitation-only)
  │   ├── Rosa (owner), Carlos (admin), Maria (member)
  │   ├── 5 plumbers (viewers)
  │   └── No hosted login (Rosa invites everyone manually)
  │
  ├── Coastal Accounting (customer, 200 people, self-registration)
  │   ├── Login page: /login/coastal-accounting (dark, teal, branded)
  │   ├── OAuth client: coastal_billflow_app
  │   ├── Providers: Google, Microsoft
  │   ├── Diane (owner), 10 managers (admins, invited)
  │   ├── 40 accountants (members, invited)
  │   └── 150 staff (end_users, self-registered via hosted login)
  │
  └── ... more customers, each with their own config
      ├── Small shops: invitation-only, no providers
      ├── Mid-size firms: self-registration + Google
      └── Enterprises: self-registration + SSO/SAML + custom branding

  The security model:
  - Martinez can't see Coastal. Coastal can't see Martinez. Walls are automatic.
  - Sarah (CS, cross_tenant) can see both — for customer support.
  - Mike (Sales) can't see either — he's in BillFlow Inc, not a customer org.
  - Self-registered users get end_user (api.read only) until upgraded.
  - OAuth client_id is org-scoped — Coastal's client can't be used on Martinez's login page.
  - PKCE (S256) enforced on all OAuth flows.
  - Login-as-join auto-adds existing users to new orgs (if the org allows it).
  - Each org controls its own login experience: branding, providers, self-registration rules.

  Every customer gets exactly the setup that fits them. Small shops get manual invitations. Big firms get branded portals with Google login. Enterprises get SSO. Your code handles all of them the same way — the auth library abstracts the differences.
