❯ question: folloing on from that, lets say they are a multi department 100 person company with departments teams and deeply nested orgs (same question and response style) 

● Continuing from Step 5: Acme Corp Goes Enterprise

  Acme Corp just raised their Series B. They're now 100 people across 4 departments. Alice (CEO) calls you and says: "We need Engineering isolated from Finance. Our VP of Engineering needs
  to manage her own people. And our security team requires that Finance data is firewalled."

  Here's what you build for them.

  ---
  The Problem

  Right now Acme is one flat org. Everyone can see everything. That was fine at 10 people. At 100, it's a mess:

  - The intern in Marketing can see Finance's revenue reports
  - The contractor in Engineering can see HR's hiring pipeline
  - The VP of Sales can accidentally delete Engineering's projects

  You need walls inside the company.

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

  Acme Corporation (parent org) ← Alice is owner here
  ├── [CHILD ORG] Acme Finance   ← Hard wall. Isolated.
  ├── [CHILD ORG] Acme Sales     ← Hard wall. Isolated.
  ├── Engineering people          ← Still in the parent org (no wall needed)
  └── Operations people           ← Still in the parent org (no wall needed)

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

  # Frontend team (child of a parent team for inheritance)
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

  # DevOps — gets extra permissions (SSH, deployments)
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
      │                     ↑ inherited from parent
      │
      └── DevOps (child team)
          own permissions: [taskflow.admin]
          effective:       [taskflow.read.*, taskflow.admin]

  A Frontend engineer automatically gets read access (from the Engineering parent team) plus create/write (from Frontend). You never grant read access individually — it flows down.

  Finance teams (inside the Finance child org)

  # Login as Finance org admin first, or Alice uses ancestor access
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

  The VP of Engineering invites engineers to the parent Acme org and assigns them to teams:

  # Invite a backend engineer
  curl -X POST "$AUTH_URL/organizations/$ACME_ORG_ID/invite" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -d '{"email": "dev1@acme.com", "role": "taskflow-member"}'

  # Add them to the Backend team
  curl -X POST "$AUTH_URL/teams/$BACKEND_TEAM_ID/members" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -d '{"user_id": "dev1-user-id", "role": "member"}'

  ---
  Step 5: Visualize What You Built

  # See the full hierarchy
  curl -s "$AUTH_URL/organizations/$ACME_ORG_ID/hierarchy" \
    -H "Authorization: Bearer $ALICE_TOKEN" | jq

  The structure:

  Acme Corporation (parent org, 100 people total)
  │
  ├── Alice (CEO, owner) ← sees EVERYTHING via ancestor access
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
  │   ├── CFO (admin) ← manages Finance independently
  │   ├── [TEAM] Accounting (8 people)
  │   ├── [TEAM] FP&A (5 people)
  │   └── [TEAM] Payroll (2 people)
  │
  └── [CHILD ORG] Acme Sales (25 people, HARD WALL)
      ├── VP Sales (admin) ← manages Sales independently
      ├── [TEAM] Enterprise Sales (10 people)
      ├── [TEAM] SDR Team (10 people)
      └── [TEAM] Sales Ops (5 people)

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

  Situation 4: New hire joins Finance

  CFO invites them → they join Acme Finance org → add to Accounting team → they automatically get Accounting's permissions. They can only see Finance stuff. Day one, correct access, zero
  configuration beyond "add to team."

  Situation 5: Someone transfers from Sales to Engineering

  # Remove from Sales org
  # (VP Sales or Alice does this)

  # Invite to parent Acme org
  curl -X POST "$AUTH_URL/organizations/$ACME_ORG_ID/invite" \
    -d '{"email": "transferee@acme.com", "role": "taskflow-member"}'

  # Add to Backend team
  curl -X POST "$AUTH_URL/teams/$BACKEND_TEAM_ID/members" \
    -d '{"user_id": "transferee-id", "role": "member"}'

  They instantly lose all Sales access (removed from Sales org) and gain Engineering access (joined parent org + Backend team). No lingering permissions. No "forgot to revoke."

  ---
  Your App Code Barely Changes

  The beauty: your route handlers don't need to know about any of this hierarchy. The auth library + get_user_filter() handles it:

  @router.get("/projects")
  async def list_projects(user: TaskViewer):
      filter = get_user_filter(user)
      # For a Backend engineer:   {"user_id": "dev1", "org_id": "acme-corp-uuid"}
      # For the CFO (admin):      {"org_id": "acme-finance-uuid"}
      # For Alice (cross_tenant or ancestor): includes child org IDs too
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
  │   ├── Engineers + Ops (teams, soft grouping)
  │   ├── Acme Finance (child org, hard wall, SOX compliance)
  │   │   └── Accounting, FP&A, Payroll (teams)
  │   └── Acme Sales (child org, hard wall, deal pipeline)
  │       └── Enterprise, SDR, Sales Ops (teams)
  │
  ├── Widgets Inc (flat org, 10 people, no departments needed)
  │   └── Everyone in one org with teams
  │
  └── BigStartup (parent) ─── another enterprise customer
      ├── BigStartup R&D (child org)
      └── BigStartup Marketing (child org)

  Every customer gets the structure that fits them. Small companies get a flat org. Enterprises get hierarchy. Your code handles both the same way.
