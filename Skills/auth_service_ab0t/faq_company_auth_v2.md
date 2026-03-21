question: following on from that, lets say they are a multi department 100 person company with departments teams and deeply nested orgs, and they also have external customers
  who need to self-register and log in through branded portals, with SSO for employees (same question and response style)

● Continuing from Step 5: Acme Corp Goes Enterprise

  Acme Corp just raised their Series B. They're now 100 people across 4 departments. Alice (CEO) calls you and says: "We need Engineering isolated from Finance. Our VP of Engineering needs
  to manage her own people. And our security team requires that Finance data is firewalled. Oh — and Sales wants a customer portal where their clients can log in and see reports."

  Here's what you build for them.

  ---
  The Problem

  Right now Acme is one flat org. Everyone can see everything. That was fine at 10 people. At 100, it's a mess:

  - The intern in Marketing can see Finance's revenue reports
  - The contractor in Engineering can see HR's hiring pipeline
  - The VP of Sales can accidentally delete Engineering's projects
  - Sales clients have no way to self-register and see their own reports

  You need walls inside the company, and doors for external customers.

  ---
  The Decision: Teams vs Child Orgs

  First question for each department: do they need a hard wall or a soft wall?
  ┌─────────────┬────────┬───────────────────────────┬────────────────────────────────────┬───────────────────────┐
  │ Department  │ People │  Need separate billing?   │        Need data isolation?        │        Verdict        │
  ├─────────────┼────────┼───────────────────────────┼────────────────────────────────────┼───────────────────────┤
  │ Engineering │ 40     │ No (one budget)           │ No (they share code)               │ Teams within Acme org │
  ├─────────────┼────────┼───────────────────────────┼────────────────────────────────────┼───────────────────────┤
  │ Finance     │ 15     │ Yes (own budget tracking) │ Yes (SOX compliance, salary data)  │ Child org             │
  ├─────────────┼────────┼───────────────────────────┼────────────────────────────────────┼───────────────────────┤
  │ Sales       │ 25     │ Yes (commission tracking) │ Kinda (deal pipeline is sensitive) │ Child org             │
  ├─────────────┼────────┼───────────────────────────┼────────────────────────────────────┼───────────────────────┤
  │ Operations  │ 20     │ No                        │ No                                 │ Teams within Acme org │
  └─────────────┴────────┴───────────────────────────┴────────────────────────────────────┴───────────────────────┘
  Rule of thumb: If someone says "compliance" or "separate budget" — child org. If they just say "group these people" — team.

  ---
  Step 1: Create the Department Orgs

  Alice (Acme CEO, owner of the parent org) creates child orgs for Finance and Sales:

  # Alice is logged into Acme Corp context
  ACME_ORG_ID="acme-corp-uuid"

  # Finance — hard wall, separate budget
  FINANCE=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Acme Finance",
      "slug": "acme-finance",
      "parent_id": "'"$ACME_ORG_ID"'",
      "billing_type": "enterprise",
      "settings": {"type": "department", "hierarchical": false},
      "metadata": {"compliance": ["SOX"], "department_head": "CFO"}
    }')
  FINANCE_ORG_ID=$(echo "$FINANCE" | jq -r '.id')

  # Sales — hard wall, deal data is sensitive
  SALES=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Acme Sales",
      "slug": "acme-sales",
      "parent_id": "'"$ACME_ORG_ID"'",
      "billing_type": "enterprise",
      "settings": {"type": "department"},
      "metadata": {"department_head": "VP Sales"}
    }')
  SALES_ORG_ID=$(echo "$SALES" | jq -r '.id')

  What this looks like now:

  Acme Corporation (parent org) <- Alice is owner here
  ├── [CHILD ORG] Acme Finance   <- Hard wall. Isolated.
  ├── [CHILD ORG] Acme Sales     <- Hard wall. Isolated.
  ├── Engineering people          <- Still in the parent org (no wall needed)
  └── Operations people           <- Still in the parent org (no wall needed)

  The key insight: Engineering and Operations stay in the parent Acme org. They don't need walls — they collaborate daily. Finance and Sales get their own child orgs because their data is
  sensitive.

  ---
  Step 2: Set Up Your TenantConfig

  In your TaskFlow app, tell the auth library about the hierarchy:

  from ab0t_auth.tenant import TenantConfig

  tenant_config = TenantConfig(
      enforce_tenant_isolation=True,      # Acme can't see Widgets (different customers)
      enforce_org_isolation=True,         # Finance can't see Sales (different departments)
      enable_org_hierarchy=True,          # Parent/child orgs exist
      allow_ancestor_access=True,         # Alice (CEO, parent org) can see into Finance and Sales
      allow_descendant_access=False,      # Finance can NOT see the parent org or Sales
      allow_cross_tenant_admin=True,      # Your support staff can still help
      cross_tenant_permission="taskflow.cross_tenant",
  )

  What this means in plain English:
  ┌─────────────┬──────────────────────┬────────────────────────┬────────────────────────┬───────────────────────────┐
  │   Person    │      Their org       │ Can they see Finance?  │  Can they see Sales?   │ Can they see Engineering? │
  ├─────────────┼──────────────────────┼────────────────────────┼────────────────────────┼───────────────────────────┤
  │ Alice (CEO) │ Acme Corp (parent)   │ Yes (ancestor access)  │ Yes (ancestor access)  │ Yes (same org)            │
  ├─────────────┼──────────────────────┼────────────────────────┼────────────────────────┼───────────────────────────┤
  │ CFO         │ Acme Finance (child) │ Yes (same org)         │ No (sibling isolation) │ No (can't see parent)     │
  ├─────────────┼──────────────────────┼────────────────────────┼────────────────────────┼───────────────────────────┤
  │ VP Sales    │ Acme Sales (child)   │ No (sibling isolation) │ Yes (same org)         │ No (can't see parent)     │
  ├─────────────┼──────────────────────┼────────────────────────┼────────────────────────┼───────────────────────────┤
  │ Engineer    │ Acme Corp (parent)   │ No (different org)     │ No (different org)     │ Yes (same org)            │
  └─────────────┴──────────────────────┴────────────────────────┴────────────────────────┴───────────────────────────┘
  That's the magic. Alice sees everything (she's in the parent, ancestor access flows down). The CFO sees Finance only. Engineers see Engineering only. Finance and Sales can never see each
  other. All automatic.

  ---
  Step 3: Create Teams Within Each Department

  Departments are the hard walls. Teams are the soft grouping inside.

  Engineering teams (inside Acme parent org)

  # Backend team
  BACKEND=$(curl -s -X POST "$AUTH_URL/organizations/$ACME_ORG_ID/teams" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Backend Engineering",
      "description": "API and infrastructure",
      "permissions": [
        "taskflow.create.tasks", "taskflow.write.tasks",
        "taskflow.read.projects", "taskflow.read.tasks"
      ]
    }')
  BACKEND_TEAM_ID=$(echo "$BACKEND" | jq -r '.id')

  # Engineering parent team (for inheritance)
  ENGINEERING=$(curl -s -X POST "$AUTH_URL/organizations/$ACME_ORG_ID/teams" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Engineering",
      "description": "All engineering",
      "permissions": ["taskflow.read.projects", "taskflow.read.tasks"]
    }')
  ENG_TEAM_ID=$(echo "$ENGINEERING" | jq -r '.id')

  # Frontend is a child team of Engineering — inherits read permissions
  curl -s -X POST "$AUTH_URL/organizations/$ACME_ORG_ID/teams" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Frontend Engineering",
      "description": "Web and mobile UI",
      "parent_team_id": "'"$ENG_TEAM_ID"'",
      "permissions": ["taskflow.create.tasks", "taskflow.write.tasks"]
    }'

  # DevOps — gets extra permissions
  curl -s -X POST "$AUTH_URL/organizations/$ACME_ORG_ID/teams" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "DevOps",
      "parent_team_id": "'"$ENG_TEAM_ID"'",
      "permissions": ["taskflow.admin"]
    }'

  How permission inheritance works:

  Engineering (team)
    permissions: [taskflow.read.projects, taskflow.read.tasks]
      │
      ├── Frontend (child team)
      │   own permissions: [taskflow.create.tasks, taskflow.write.tasks]
      │   effective:       [taskflow.read.*, taskflow.create.tasks, taskflow.write.tasks]
      │                     ^ inherited from parent
      │
      └── DevOps (child team)
          own permissions: [taskflow.admin]
          effective:       [taskflow.read.*, taskflow.admin]

  A Frontend engineer automatically gets read access (from the Engineering parent team) plus create/write (from Frontend). You never grant read access individually — it flows down.

  Finance teams (inside the Finance child org)

  curl -s -X POST "$AUTH_URL/organizations/$FINANCE_ORG_ID/teams" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Accounting",
      "permissions": ["taskflow.read.reports", "taskflow.create.tasks", "taskflow.write.tasks"]
    }'

  curl -s -X POST "$AUTH_URL/organizations/$FINANCE_ORG_ID/teams" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "FP&A",
      "permissions": ["taskflow.read.reports", "taskflow.read.projects"]
    }'

  Sales teams (inside the Sales child org)

  curl -s -X POST "$AUTH_URL/organizations/$SALES_ORG_ID/teams" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Enterprise Sales",
      "permissions": ["taskflow.create.tasks", "taskflow.write.tasks", "taskflow.read.projects"]
    }'

  curl -s -X POST "$AUTH_URL/organizations/$SALES_ORG_ID/teams" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "SDR Team",
      "permissions": ["taskflow.read.projects", "taskflow.create.tasks"]
    }'

  ---
  Step 4: Add People

  Invite department heads as admins of their child org

  # CFO becomes admin of Finance org
  curl -X POST "$AUTH_URL/organizations/$FINANCE_ORG_ID/invite" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -d '{
      "email": "cfo@acme.com",
      "role": "taskflow-admin",
      "permissions": ["taskflow.admin"],
      "message": "You are now the Finance admin on TaskFlow"
    }'

  # VP Sales becomes admin of Sales org
  curl -X POST "$AUTH_URL/organizations/$SALES_ORG_ID/invite" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -d '{
      "email": "vp-sales@acme.com",
      "role": "taskflow-admin",
      "permissions": ["taskflow.admin"],
      "message": "You are now the Sales admin on TaskFlow"
    }'

  What this gives them: The CFO can now manage Finance independently — invite her own people, create teams, manage permissions within Finance. She doesn't need to bother Alice for every new
  hire. But she can't touch Sales or Engineering. She's admin inside her wall, not outside it.

  Department heads invite their people

  Now the CFO invites her team. She doesn't need Alice anymore:

  # CFO invites an accountant
  curl -X POST "$AUTH_URL/organizations/$FINANCE_ORG_ID/invite" \
    -H "Authorization: Bearer $CFO_TOKEN" \
    -d '{
      "email": "accountant@acme.com",
      "role": "taskflow-member",
      "permissions": ["taskflow.read.reports", "taskflow.create.tasks"]
    }'

  Engineering stays in the parent org

  # Invite a backend engineer
  curl -X POST "$AUTH_URL/organizations/$ACME_ORG_ID/invite" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -d '{"email": "dev1@acme.com", "role": "taskflow-member"}'

  # Add them to the Backend team
  curl -X POST "$AUTH_URL/teams/$BACKEND_TEAM_ID/members" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -d '{"user_id": "dev1-user-id", "role": "member"}'

  ---
  Step 5: Enterprise SSO for Employees

  Alice's security team requires SSO for all employees. They use Okta.

  5a: Configure SAML for the parent org

  # Add Okta SAML to the parent Acme org
  curl -X POST "$AUTH_URL/providers/" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "org_id": "'$ACME_ORG_ID'",
      "provider_type": "saml",
      "name": "Continue with Okta",
      "config": {
        "entity_id": "https://acme.com/saml",
        "assertion_consumer_service_url": "https://auth.service.ab0t.com/organizations/acme-corp/auth/sso/callback",
        "idp_entity_id": "https://acme.okta.com",
        "idp_sso_url": "https://acme.okta.com/app/xxx/sso/saml",
        "idp_cert": "MIID..."
      },
      "priority": 0
    }'

  5b: Configure a hosted login page for employees

  curl -X PUT "$AUTH_URL/organizations/$ACME_ORG_ID/login-config" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "branding": {
        "primary_color": "#1E40AF",
        "page_title": "Acme Corp — Employee Login",
        "logo_url": "https://acme.com/logo.png",
        "login_template": "dark"
      },
      "content": {
        "welcome_message": "Welcome back",
        "footer_message": "For IT support contact helpdesk@acme.com"
      },
      "auth_methods": {
        "email_password": true,
        "signup_enabled": false,
        "invitation_only": true
      },
      "registration": {
        "default_role": "member"
      }
    }'

  What just happened: The employee login page at /login/acme-corp shows an "Continue with Okta" button (priority 0 = first) plus email/password. signup_enabled: false and invitation_only: true means nobody can self-register — employees must be invited first. But they can use SSO to log in after being invited.

  The SSO flow:
  Employee clicks "Continue with Okta"
    -> Redirected to Okta
    -> Okta authenticates them
    -> SAML assertion back to auth service
    -> JIT provisions: if new, creates account + adds to org with default_role
    -> If existing, validates membership
    -> Redirects back with auth code

  JIT provisioning means the first time an employee logs in via Okta, their account is auto-created. No separate registration step needed. The security team manages who has Okta access; the auth service trusts the assertion.

  5c: SSO for child orgs

  Finance and Sales can each have their own SSO config if they use different IdPs. Or they can share the parent's:

  # Finance uses the same Okta but with a Finance-specific app
  curl -X POST "$AUTH_URL/providers/" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -d '{
      "org_id": "'$FINANCE_ORG_ID'",
      "provider_type": "saml",
      "name": "Continue with Okta (Finance)",
      "config": {
        "entity_id": "https://acme.com/saml/finance",
        "assertion_consumer_service_url": "https://auth.service.ab0t.com/organizations/acme-finance/auth/sso/callback",
        "idp_entity_id": "https://acme.okta.com",
        "idp_sso_url": "https://acme.okta.com/app/finance/sso/saml",
        "idp_cert": "MIID..."
      },
      "priority": 0
    }'

  Now /login/acme-finance has its own SSO button that goes through the Finance Okta app.

  ---
  Step 6: Customer Portal for Sales

  Here's where it gets interesting. The VP of Sales says: "Our clients need to log in and see their reports. But I don't want to invite each one manually."

  This is the self-registration model applied to a child org.

  6a: Configure the Sales customer portal

  # VP Sales (admin of Acme Sales) configures self-registration
  curl -X PUT "$AUTH_URL/organizations/$SALES_ORG_ID/login-config" \
    -H "Authorization: Bearer $VP_SALES_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "branding": {
        "primary_color": "#059669",
        "page_title": "Acme Sales — Client Portal",
        "logo_url": "https://acme.com/sales-logo.png",
        "login_template": "default"
      },
      "content": {
        "welcome_message": "Welcome to the Acme Client Portal",
        "signup_message": "Create your account to view your reports",
        "terms_url": "https://acme.com/client-terms",
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

  6b: Register an OAuth client for the portal

  CLIENT=$(curl -s -X POST "$AUTH_URL/auth/oauth/register" \
    -H "Authorization: Bearer $VP_SALES_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "client_name": "Acme Sales Client Portal",
      "redirect_uris": ["https://clients.acme.com/callback"],
      "response_types": ["code"],
      "grant_types": ["authorization_code", "refresh_token"],
      "token_endpoint_auth_method": "none"
    }')
  CLIENT_ID=$(echo "$CLIENT" | jq -r '.client_id')

  6c: Point clients to the portal

  https://auth.service.ab0t.com/login/acme-sales?client_id=CLIENT_ID&redirect_uri=https://clients.acme.com/callback&response_type=code&state=RANDOM

  What just happened: The Sales child org now has its own hosted login page at /login/acme-sales. It's green (Sales branding), shows "Acme Client Portal", and lets anyone sign up. Clients get end_user role — they can see reports but can't modify deals.

  This is completely separate from the employee login at /login/acme-corp. Different branding, different rules, different roles.

  6d: What the Sales org looks like now

  [CHILD ORG] Acme Sales
  │
  │  Employee login: /login/acme-corp (invitation_only, SSO)
  │  Client portal:  /login/acme-sales (open signup, end_user)
  │
  ├── VP Sales (admin)         — invited by Alice
  ├── [TEAM] Enterprise Sales  — 10 employees, invited
  ├── [TEAM] SDR Team          — 10 employees, invited
  ├── [TEAM] Sales Ops         — 5 employees, invited
  │
  ├── Client: MegaCorp (end_user) — self-registered via portal
  ├── Client: StartupXY (end_user) — self-registered via portal
  └── Client: BigRetail (end_user) — self-registered via portal

  Employees were invited with member or admin roles. Clients self-registered and got end_user. Same org, different paths, different permissions.

  The VP of Sales can upgrade a client:

  curl -X POST "$AUTH_URL/organizations/$SALES_ORG_ID/invite" \
    -H "Authorization: Bearer $VP_SALES_TOKEN" \
    -d '{"email": "buyer@megacorp.com", "role": "member"}'

  MegaCorp's buyer now has member permissions — can see more reports, submit orders, whatever your app allows for members.

  ---
  Step 7: Social Providers Per Department

  Different departments can have different login providers.

  # Parent org (employees): Okta SSO + email/password
  # Already configured in Step 5

  # Sales (client portal): Google + email/password
  curl -X POST "$AUTH_URL/providers/" \
    -H "Authorization: Bearer $VP_SALES_TOKEN" \
    -d '{
      "org_id": "'$SALES_ORG_ID'",
      "provider_type": "google",
      "name": "Continue with Google",
      "config": {"client_id": "GOOGLE_ID", "client_secret": "GOOGLE_SECRET"},
      "priority": 1
    }'

  Now the client portal at /login/acme-sales shows "Continue with Google" + email/password. The employee login at /login/acme-corp shows "Continue with Okta" + email/password. Each org controls its own login experience.

  ---
  Step 8: Visualize What You Built

  curl -s "$AUTH_URL/organizations/$ACME_ORG_ID/hierarchy" \
    -H "Authorization: Bearer $ALICE_TOKEN" | jq

  The structure:

  Acme Corporation (parent org, 100 people total)
  │
  │  Login: /login/acme-corp
  │    SSO: Okta (priority 0)
  │    Auth: invitation_only, email/password
  │    OAuth client: acme_employee_app
  │
  ├── Alice (CEO, owner) <- sees EVERYTHING via ancestor access
  ├── VP Engineering (admin of parent org)
  │
  ├── [TEAM] Engineering (40 people, soft grouping)
  │   ├── [TEAM] Backend (15 people)
  │   │   └── dev1, dev2, dev3...
  │   ├── [TEAM] Frontend (12 people)
  │   │   └── dev4, dev5, dev6...
  │   ├── [TEAM] DevOps (8 people, extra admin perms)
  │   │   └── ops1, ops2...
  │   └── [TEAM] QA (5 people)
  │
  ├── [TEAM] Operations (20 people, soft grouping)
  │   ├── [TEAM] IT Support
  │   └── [TEAM] Office Management
  │
  ├── [CHILD ORG] Acme Finance (15 people, HARD WALL)
  │   │  Login: /login/acme-finance
  │   │    SSO: Okta Finance app (priority 0)
  │   │    Auth: invitation_only
  │   │
  │   ├── CFO (admin) <- manages Finance independently
  │   ├── [TEAM] Accounting (8 people)
  │   ├── [TEAM] FP&A (5 people)
  │   └── [TEAM] Payroll (2 people)
  │
  └── [CHILD ORG] Acme Sales (25 employees + external clients, HARD WALL)
      │  Employee login: /login/acme-corp (they switch org)
      │  Client portal:  /login/acme-sales
      │    Google (priority 1)
      │    Auth: signup_enabled, default_role=end_user
      │    OAuth client: acme_sales_portal
      │
      ├── VP Sales (admin) <- manages Sales independently
      ├── [TEAM] Enterprise Sales (10 employees)
      ├── [TEAM] SDR Team (10 employees)
      ├── [TEAM] Sales Ops (5 employees)
      │
      ├── MegaCorp buyer (end_user, self-registered)
      ├── StartupXY rep (end_user, self-registered)
      └── BigRetail buyer (member, upgraded by VP Sales)

  ---
  What Everyone Sees (The Payoff)

  Situation 1: Backend engineer opens TaskFlow

  She's in the parent Acme org, on the Backend team. She sees:
  - All Engineering projects (her org)
  - All Operations projects (same org)
  - Her own tasks
  - NOT Finance projects (different org, wall)
  - NOT Sales deal pipeline (different org, wall)

  Situation 2: CFO opens TaskFlow

  She's in the Acme Finance child org, admin role. She sees:
  - All Finance projects (her org)
  - All Finance team members' tasks (admin = org-wide view)
  - NOT Engineering projects (different org, can't look up)
  - NOT Sales deals (sibling isolation)
  - NOT the parent Acme org's stuff (descendant access = false)

  Situation 3: Alice (CEO) opens TaskFlow

  She's in the parent Acme org, owner. She sees:
  - All Engineering and Operations projects (her org)
  - All Finance projects (ancestor access into child org)
  - All Sales projects (ancestor access into child org)
  - Everything. She's the CEO. That's the point.

  Situation 4: MegaCorp buyer logs into the client portal

  They visit /login/acme-sales, log in with Google. They see:
  - Their own reports in the Sales org (end_user = api.read only)
  - NOT internal deal pipeline (end_user doesn't have taskflow.write)
  - NOT Finance data (different org entirely)
  - NOT Engineering data (different org entirely)
  - NOT even that Finance or Engineering exist (org isolation)

  Situation 5: New hire joins Finance

  CFO invites them -> they join Acme Finance org -> add to Accounting team -> they automatically get Accounting's permissions. They can only see Finance stuff. Day one, correct access, zero
  configuration beyond "add to team."

  Situation 6: Sales client upgrades to partner

  VP Sales invites the MegaCorp buyer with role=member:

  curl -X POST "$AUTH_URL/organizations/$SALES_ORG_ID/invite" \
    -H "Authorization: Bearer $VP_SALES_TOKEN" \
    -d '{"email": "buyer@megacorp.com", "role": "member"}'

  MegaCorp's buyer now has member permissions. They can submit orders, update their profile, see extended reports. They still can't see other clients' data or internal Sales team stuff (that's permission-controlled, not org-controlled).

  Situation 7: Someone transfers from Sales to Engineering

  # Remove from Sales org
  # (VP Sales or Alice does this)

  # Invite to parent Acme org
  curl -X POST "$AUTH_URL/organizations/$ACME_ORG_ID/invite" \
    -d '{"email": "transferee@acme.com", "role": "taskflow-member"}'

  # Add to Backend team
  curl -X POST "$AUTH_URL/teams/$BACKEND_TEAM_ID/members" \
    -d '{"user_id": "transferee-id", "role": "member"}'

  They instantly lose all Sales access (removed from Sales org) and gain Engineering access (joined parent org + Backend team). No lingering permissions. No "forgot to revoke."

  Situation 8: External consultant works with both Sales and Finance

  Dave is a consultant. He self-registers on the Sales client portal (/login/acme-sales) -> gets end_user in Sales. Later the CFO invites him to Finance with role=member.

  Dave's memberships:
  ├── Acme Sales   -> end_user (self-registered via client portal)
  └── Acme Finance -> member (invited by CFO)

  He logs into Sales -> sees client reports (read only). He logs into Finance -> sees financial data (read/write). Each org is independent. Login-as-join handles the multi-org membership automatically.

  ---
  Your App Code Barely Changes

  The beauty: your route handlers don't need to know about any of this hierarchy. The auth library + get_user_filter() handles it:

  @router.get("/projects")
  async def list_projects(user: TaskViewer):
      filter = get_user_filter(user)
      # For a Backend engineer:   {"user_id": "dev1", "org_id": "acme-corp-uuid"}
      # For the CFO (admin):      {"org_id": "acme-finance-uuid"}
      # For Alice (ancestor):     includes child org IDs too
      # For MegaCorp buyer:       {"user_id": "buyer1", "org_id": "acme-sales-uuid"}
      return await db.list_projects(**filter)

  One line. The library figures out "which orgs can this user see?" based on their permissions, org membership, and the hierarchy config. Your database query just uses the filter.

  ---
  The Complete Picture

  Auth Service
  │
  ├── YourCompany org (your employees — support, engineering)
  ├── TaskFlow Service org (permissions, API keys, the rulebook)
  │
  ├── Acme Corp (parent) ─── hard wall from other customers
  │   │  Login: /login/acme-corp (SSO + invitation_only)
  │   │  OAuth client: acme_employee_app
  │   │  Providers: Okta SAML
  │   │
  │   ├── Engineers + Ops (teams, soft grouping, invited)
  │   │
  │   ├── Acme Finance (child org, hard wall, SOX compliance)
  │   │   │  Login: /login/acme-finance (SSO + invitation_only)
  │   │   │  Providers: Okta Finance SAML
  │   │   └── Accounting, FP&A, Payroll (teams, invited employees only)
  │   │
  │   └── Acme Sales (child org, hard wall, deal pipeline)
  │       │  Client portal: /login/acme-sales (open signup + Google)
  │       │  OAuth client: acme_sales_portal
  │       │  Providers: Google
  │       ├── Enterprise, SDR, Sales Ops (teams, invited employees)
  │       └── MegaCorp, StartupXY, BigRetail (end_users, self-registered)
  │
  ├── Widgets Inc (flat org, 10 people, no departments needed)
  │   │  Login: /login/widgets-inc (email/password only)
  │   └── Everyone in one org with teams
  │
  └── BigStartup (parent) ─── another enterprise customer
      │  Login: /login/bigstartup (SSO + self-registration)
      ├── BigStartup R&D (child org)
      └── BigStartup Marketing (child org)

  Every customer gets the structure that fits them. Small companies get a flat org. Enterprises get hierarchy with SSO. Departments that face external clients get their own hosted login portals with self-registration. Your code handles all of it the same way.

  The security model across all of this:
  - Cross-org boundaries enforced server-side (403 on any cross-org access attempt)
  - Each org's OAuth client_id is scoped — can't be used on another org's login page
  - Self-registered clients get end_user (api.read only) until upgraded
  - SSO/SAML assertions validated, JIT provisioning respects org membership rules
  - PKCE (S256) enforced on all OAuth flows
  - Ancestor access is one-way: parent -> child, never child -> parent or sibling -> sibling
  - Each org's login config is independent: different branding, different auth methods, different providers
