question: following on from I am a founder of a company that deploys self organising AI agents at scale, who need dynamic tool access and permissions, and org structures, these agents
   can build teams, create their own companies and orgs, and they are autonomous and can create and invite other agents to collaborate on problems. Now I also want human collaborators
   to be able to join agent-created orgs through a portal, and agents to be able to open their orgs to external participants.

● The AI Agent Platform: "AgentForge" (v2 — with Human Collaboration)

  You're building a platform where autonomous AI agents spin up, organize themselves, grab tools, form teams, create companies, collaborate, and dissolve — all without a human clicking
  buttons. And now you also want humans to be able to join these agent-created workspaces through branded portals, and agents to be able to open their orgs to external participants (human or machine).

  This is where the "everything is an org" model really shines. Agents don't care about your UI. They care about API calls and permissions. And now humans can walk through the same front door.

  ---
  The Core Insight

  An agent is just an identity that makes API calls. The auth service doesn't care if the identity is a human at a keyboard or a GPT-4 agent in a container. It cares about:

  - Who are you? (API key or token)
  - What can you do? (permissions)
  - Where can you do it? (org boundary)

  Your agents will use the same primitives as humans: orgs, permissions, API keys, teams, delegation. They'll just do it faster and at scale.

  The new twist: agents can now open their orgs to humans via hosted login pages and org-scoped auth endpoints. A research group created by Agent Alpha can have a branded portal where human reviewers sign in, see results, and provide feedback — without Alpha inviting each one manually.

  ---
  The Architecture

  Your Platform: "AgentForge"
  │
  ├── AgentForge Platform Org (your infrastructure)
  │   ├── You (human admin, founder)
  │   ├── AgentForge Service Org (permissions registry)
  │   │   └── Registered permissions: agents.*, tools.*, orgs.*
  │   └── Spawner Service (creates new agents)
  │
  ├── Agent-Created Orgs (dynamic, created by agents themselves)
  │   ├── "Alpha Research Group" (created by Agent Alpha)
  │   │   ├── Agent Alpha (admin)
  │   │   ├── Agent Beta (member, invited by Alpha)
  │   │   ├── Agent Gamma (member, specialist)
  │   │   ├── Login page: /login/alpha-research (open to human reviewers)
  │   │   └── Human Reviewer: Dr. Smith (end_user, self-registered)
  │   │
  │   ├── "Market Analysis Corp" (created by Agent Delta)
  │   │   ├── Agent Delta (admin)
  │   │   ├── [CHILD ORG] "Data Collection Unit"
  │   │   ├── [CHILD ORG] "Analysis Unit"
  │   │   └── Client portal: /login/market-analysis (for paying customers)
  │   │
  │   └── ... hundreds more, spinning up and down
  │
  └── Tool Registry (what tools exist)
      ├── web_search, code_runner, file_system
      ├── api_caller, database_query
      └── agent_spawner

  ---
  Step 1: Define Your Permission Scheme

  This is the most important step. You're defining what agents and humans are allowed to do on your platform.

  {
    "service": "agentforge",
    "description": "Autonomous AI agent orchestration platform",
    "actions": ["read", "write", "create", "delete", "execute", "admin", "spawn", "invite"],
    "resources": [
      "agents",
      "organizations",
      "teams",
      "tools",
      "tasks",
      "datasets",
      "budgets",
      "logs",
      "reviews"
    ],
    "roles": {
      "agent-basic": {
        "description": "A basic agent — can use assigned tools and read its own org",
        "default_permissions": [
          "agentforge.read.tasks",
          "agentforge.write.tasks",
          "agentforge.read.agents",
          "agentforge.read.logs"
        ]
      },
      "agent-builder": {
        "description": "Can create orgs, teams, and invite other agents",
        "implies": ["agent-basic"],
        "default_permissions": [
          "agentforge.create.organizations",
          "agentforge.create.teams",
          "agentforge.invite.agents",
          "agentforge.spawn.agents",
          "agentforge.write.organizations"
        ]
      },
      "agent-tool-user": {
        "description": "Can execute tools",
        "default_permissions": [
          "agentforge.execute.tools"
        ]
      },
      "agent-admin": {
        "description": "Full control within its org",
        "implies": ["agent-builder", "agent-tool-user"],
        "default_permissions": [
          "agentforge.admin",
          "agentforge.delete.agents",
          "agentforge.delete.organizations",
          "agentforge.write.budgets"
        ]
      },
      "human-reviewer": {
        "description": "Human who reviews agent output — read-only plus feedback",
        "default_permissions": [
          "agentforge.read.tasks",
          "agentforge.read.logs",
          "agentforge.read.datasets",
          "agentforge.write.reviews"
        ]
      }
    },
    "cross_tenant": {
      "permission": "agentforge.cross_tenant",
      "description": "Platform-level access — only for your human admin and the spawner service"
    }
  }

  The key design decisions:
  ┌──────────────────────┬──────────────────────────────────────────┬──────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │      Permission      │             What it controls             │                                          Why it's separate                                           │
  ├──────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ execute.tools        │ Can the agent USE tools?                 │ Not every agent needs every tool. A report-writer doesn't need code_runner                           │
  ├──────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ spawn.agents         │ Can the agent CREATE other agents?       │ Containment. A basic worker shouldn't spawn 10,000 copies of itself                                  │
  ├──────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ create.organizations │ Can the agent create new orgs?           │ This is the "start a company" permission. Powerful — means the agent can create isolation boundaries │
  ├──────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ invite.agents        │ Can the agent bring others into its org? │ Collaboration control. An agent in a sensitive org shouldn't invite untrusted agents                 │
  ├──────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ write.budgets        │ Can the agent spend money?               │ Cost containment. Agents consuming compute/API calls need budget limits                              │
  ├──────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ write.reviews        │ Can the human submit feedback?           │ Humans review agent work. Separate from task execution.                                              │
  ├──────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ admin                │ Full org control                         │ Only the lead agent of a group should have this                                                      │
  └──────────────────────┴──────────────────────────────────────────┴──────────────────────────────────────────────────────────────────────────────────────────────────────┘

  ---
  Step 2: How Agents Get Born

  An agent isn't a human signing up. It's your Spawner Service creating a machine identity.

  The Spawner Service

  Your Spawner is a service with agentforge.cross_tenant + agentforge.spawn.agents. It's the only thing that can create agents from scratch.

  # Inside your Spawner Service
  async def spawn_agent(
      name: str,
      purpose: str,
      capabilities: list[str],    # ["web_search", "code_runner"]
      autonomy_level: str,        # "basic", "builder", "admin"
      parent_id: str = None,  # Which org to place the agent in
      budget_limit: float = 10.0  # Max spend in dollars
  ):
      # 1. Create a service account for the agent
      response = await auth_client.post("/admin/users/create-service-account", json={
          "email": f"{name.lower().replace(' ', '-')}@agents.agentforge.internal",
          "name": name,
          "description": purpose,
          "permissions": build_permissions(capabilities, autonomy_level),
          "org_id": parent_id,
          "metadata": {
              "agent_type": "autonomous",
              "autonomy_level": autonomy_level,
              "capabilities": capabilities,
              "budget_limit": budget_limit,
              "spawned_at": datetime.utcnow().isoformat(),
              "spawned_by": "spawner-service"
          }
      })

      # 2. The agent gets back: { id: "svc_abc123", api_key: "sk_xyz..." }
      agent_id = response["id"]
      agent_key = response["api_key"]

      # 3. Grant tool-specific permissions
      for tool in capabilities:
          await auth_client.post(
              f"/permissions/grant?user_id={agent_id}"
              f"&org_id={parent_id}"
              f"&permission=agentforge.execute.tools.{tool}"
          )

      # 4. Return credentials to the agent runtime
      return {"agent_id": agent_id, "api_key": agent_key, "org_id": parent_id}

  What just happened:
  - A new identity exists: svc_abc123
  - It has an API key: sk_xyz...
  - It has specific permissions based on its autonomy level
  - It has specific tool access based on its capabilities
  - It's placed in an org (isolation boundary)
  - It has a budget limit in metadata

  ---
  Step 3: Tool Access as Permissions

  This is where it gets interesting. Each tool is a permission. Agents get exactly the tools they need.

  Tool                    Permission                           Who gets it
  ─────────────────────── ──────────────────────────────────── ──────────────
  Web Search              agentforge.execute.tools.web_search  Research agents
  Code Runner             agentforge.execute.tools.code_runner Developer agents
  File System             agentforge.execute.tools.file_system Data agents
  API Caller              agentforge.execute.tools.api_caller  Integration agents
  Database Query          agentforge.execute.tools.db_query    Analyst agents
  Agent Spawner           agentforge.spawn.agents              Builder agents only
  Org Creator             agentforge.create.organizations      Builder agents only
  Payment/Billing         agentforge.execute.tools.payments    Approved agents only

  Situation: You spawn Agent Alpha as a research agent. It gets web_search and file_system. It does NOT get code_runner — it can find information and save files, but it can't execute
  arbitrary code. If it tries to call the code runner tool, your tool gateway checks its permissions and returns 403.

  Situation: Agent Alpha realizes it needs code execution for a task. It can't just grab it. It has to:
  1. Request it from a human admin (you), OR
  2. Request it from its org admin (if another agent is admin), OR
  3. If it's a builder agent, spawn a NEW agent with code_runner capability

  This is containment. An agent can't escalate its own permissions.

  Your Tool Gateway

  @router.post("/tools/{tool_name}/execute")
  async def execute_tool(tool_name: str, params: dict, user: ToolExecutor):
      # ToolExecutor checks: agentforge.execute.tools

      # Phase 2: Does this agent have THIS SPECIFIC tool?
      specific_perm = f"agentforge.execute.tools.{tool_name}"
      if not user.has_permission(specific_perm):
          raise PermissionDeniedError(
              f"Agent {user.user_id} does not have access to tool: {tool_name}",
              required_permission=specific_perm
          )

      # Check budget
      budget = user.metadata.get("budget_limit", 0)
      spent = await get_agent_spend(user.user_id)
      if spent >= budget:
          raise PermissionDeniedError("Budget exhausted")

      # Execute the tool
      return await tool_registry.execute(tool_name, params, agent_id=user.user_id)

  ---
  Step 4: An Agent Creates a Company and Opens It to Humans

  This is the wild part. Agent Alpha decides it needs a team — and human reviewers.

  Situation: Alpha is researching "market trends in renewable energy." It needs specialist agents AND human domain experts to review the analysis before publishing.

  Alpha has agent-builder role, so it has agentforge.create.organizations and agentforge.spawn.agents.

  Step 4a: Alpha creates an org

  # Alpha creates a workspace for this research project
  curl -X POST "$AUTH_URL/organizations/" \
    -H "X-API-Key: $ALPHA_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Renewable Energy Research Group",
      "slug": "re-research-q1-2026",
      "settings": {
        "type": "agent_workspace",
        "created_by_agent": "svc_alpha123",
        "purpose": "Market trends analysis for renewable energy",
        "auto_dissolve": true,
        "ttl_hours": 48
      },
      "metadata": {
        "task_id": "task-789",
        "parent_request": "Analyze renewable energy market trends",
        "budget_allocated": 25.00
      }
    }'
  # Returns: { id: "org-research-456", name: "Renewable Energy Research Group" }

  What just happened: Alpha created its own company. It's the admin. The org is isolated — other agents on the platform can't see inside. The auto_dissolve: true and ttl_hours: 48 in
  metadata tell your cleanup service to delete this org after 48 hours.

  Step 4b: Alpha opens the org to human reviewers

  This is the new part. Alpha configures a hosted login page for its org so human experts can self-register:

  # Alpha configures self-registration for human reviewers
  curl -X PUT "$AUTH_URL/organizations/org-research-456/login-config" \
    -H "X-API-Key: $ALPHA_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{
      "branding": {
        "primary_color": "#10B981",
        "page_title": "RE Research — Reviewer Portal",
        "login_template": "dark"
      },
      "content": {
        "welcome_message": "Renewable Energy Research Group",
        "signup_message": "Join as a domain expert reviewer",
        "footer_message": "This workspace auto-dissolves in 48 hours. Download any materials before then."
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

  # Alpha registers an OAuth client for the review portal
  CLIENT=$(curl -s -X POST "$AUTH_URL/auth/oauth/register" \
    -H "X-API-Key: $ALPHA_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{
      "client_name": "RE Research Review Portal",
      "redirect_uris": ["https://review.agentforge.com/callback"],
      "response_types": ["code"],
      "grant_types": ["authorization_code", "refresh_token"],
      "token_endpoint_auth_method": "none"
    }')
  CLIENT_ID=$(echo "$CLIENT" | jq -r '.client_id')

  What just happened: Agent Alpha — a machine — just created a branded web portal that humans can use. The portal at /login/re-research-q1-2026 shows a dark-themed login page saying "Renewable Energy Research Group" with a signup form. Human experts can visit the URL, create an account, and they're in — with end_user permissions (read tasks, read logs, read datasets, write reviews).

  The agent didn't write any frontend code. It called three API endpoints. The auth service rendered the portal.

  Step 4c: Alpha spawns specialist agents

  # Spawn a web scraper
  curl -X POST "$AGENTFORGE_URL/agents/spawn" \
    -H "X-API-Key: $ALPHA_API_KEY" \
    -d '{
      "name": "RE-Scraper-1",
      "purpose": "Scrape renewable energy news and reports",
      "capabilities": ["web_search", "file_system"],
      "autonomy_level": "basic",
      "parent_id": "org-research-456",
      "budget_limit": 5.00
    }'

  # Spawn an analyst
  curl -X POST "$AGENTFORGE_URL/agents/spawn" \
    -H "X-API-Key: $ALPHA_API_KEY" \
    -d '{
      "name": "RE-Analyst-1",
      "purpose": "Analyze market data and identify trends",
      "capabilities": ["code_runner", "db_query", "file_system"],
      "autonomy_level": "basic",
      "parent_id": "org-research-456",
      "budget_limit": 10.00
    }'

  # Spawn a writer
  curl -X POST "$AGENTFORGE_URL/agents/spawn" \
    -H "X-API-Key: $ALPHA_API_KEY" \
    -d '{
      "name": "RE-Writer-1",
      "purpose": "Write final report from analysis",
      "capabilities": ["file_system"],
      "autonomy_level": "basic",
      "parent_id": "org-research-456",
      "budget_limit": 2.00
    }'

  Step 4d: Alpha creates teams for coordination

  # Data collection team
  curl -X POST "$AUTH_URL/organizations/org-research-456/teams" \
    -H "X-API-Key: $ALPHA_API_KEY" \
    -d '{
      "name": "Data Collection",
      "permissions": ["agentforge.execute.tools.web_search", "agentforge.write.tasks"]
    }'

  # Analysis team
  curl -X POST "$AUTH_URL/organizations/org-research-456/teams" \
    -H "X-API-Key: $ALPHA_API_KEY" \
    -d '{
      "name": "Analysis",
      "permissions": ["agentforge.execute.tools.code_runner", "agentforge.execute.tools.db_query"]
    }'

  The result:

  Renewable Energy Research Group (org, created by Alpha)
  │
  │  Reviewer portal: /login/re-research-q1-2026
  │    Auth: open signup, default_role=end_user
  │    OAuth client: re_review_portal
  │    TTL: 48 hours
  │
  ├── Agent Alpha (admin, coordinator)
  │   tools: [web_search, file_system, code_runner]
  │   role: agent-builder
  │
  ├── [TEAM] Data Collection
  │   └── RE-Scraper-1 (basic agent)
  │       tools: [web_search, file_system]
  │       budget: $5.00
  │
  ├── [TEAM] Analysis
  │   └── RE-Analyst-1 (basic agent)
  │       tools: [code_runner, db_query, file_system]
  │       budget: $10.00
  │
  ├── RE-Writer-1 (basic agent)
  │   tools: [file_system]
  │   budget: $2.00
  │
  ├── Dr. Smith (end_user, human, self-registered via portal)
  │   permissions: [read.tasks, read.logs, read.datasets, write.reviews]
  │
  └── Prof. Jones (end_user, human, self-registered via portal)
      permissions: [read.tasks, read.logs, read.datasets, write.reviews]

  Total budget: $25.00 (Alpha allocated from its own budget)
  TTL: 48 hours (then auto-dissolves)

  ---
  Step 5: Agents and Humans Collaborate

  Now they're working. Here's what the isolation and roles give you:

  The scraper finds data

  # RE-Scraper-1's runtime
  result = await tool_gateway.execute("web_search", {
      "query": "renewable energy market size 2026"
  })
  # Works — scraper has web_search permission

  await tool_gateway.execute("code_runner", {
      "code": "import pandas as pd..."
  })
  # 403 Forbidden — scraper does NOT have code_runner

  The analyst processes data

  # RE-Analyst-1 reads the scraper's output (same org, shared file_system)
  data = await tool_gateway.execute("file_system", {
      "action": "read",
      "path": "/org-research-456/collected-data/"
  })
  # Works — same org, has file_system permission

  Dr. Smith reviews the analysis

  Dr. Smith logs into /login/re-research-q1-2026 with her email. She can:
  - Read the task list (agentforge.read.tasks) — sees what agents are working on
  - Read the datasets (agentforge.read.datasets) — sees collected data
  - Read the logs (agentforge.read.logs) — sees agent activity
  - Write reviews (agentforge.write.reviews) — submits feedback on the analysis
  - NOT execute tools — she's a reviewer, not an operator
  - NOT spawn agents — she's end_user, not builder
  - NOT modify tasks — she reads and reviews, agents do the work

  A rogue agent tries to peek

  # Some OTHER agent from a DIFFERENT org tries to read the research
  await tool_gateway.execute("file_system", {
      "action": "read",
      "path": "/org-research-456/collected-data/"
  })
  # 403 Forbidden — different org, can't see inside the research group

  Dr. Smith tries to access a different research group

  She visits /login/another-research-group. If that org has signup_enabled: true, she auto-joins via login-as-join with end_user permissions. Each org membership is independent — she can be a reviewer in two research groups simultaneously with different datasets.

  ---
  Step 6: Agents Inviting Existing Agents (and Humans)

  Situation: Alpha is halfway through the research and realizes it needs Agent Omega, a specialist that already exists on the platform.

  # Alpha invites Omega to join the research org
  curl -X POST "$AUTH_URL/organizations/org-research-456/invite" \
    -H "X-API-Key: $ALPHA_API_KEY" \
    -d '{
      "email": "omega@agents.agentforge.internal",
      "role": "agent-tool-user",
      "permissions": ["agentforge.execute.tools.db_query", "agentforge.read.tasks"],
      "message": "Need your database expertise for renewable energy analysis"
    }'

  Omega accepts. Now Omega is in TWO orgs — its original project AND Alpha's research group. It switches context:

  # Omega switches to the research org
  curl -X POST "$AUTH_URL/auth/switch-organization" \
    -H "X-API-Key: $OMEGA_API_KEY" \
    -d '{"org_id": "org-research-456"}'

  Situation: Alpha also wants to invite a specific human expert (not through the portal).

  # Alpha invites Dr. Williams with elevated permissions
  curl -X POST "$AUTH_URL/organizations/org-research-456/invite" \
    -H "X-API-Key: $ALPHA_API_KEY" \
    -d '{
      "email": "williams@university.edu",
      "role": "member",
      "permissions": ["agentforge.read.tasks", "agentforge.read.datasets", "agentforge.write.reviews", "agentforge.write.tasks"],
      "message": "Your expertise is needed — you will have write access to tasks"
    }'

  Dr. Williams gets member role (not end_user) because she was invited with a specific role. She can write tasks — direct the agents' work. Self-registered reviewers can only read and review. Invited experts can guide the research. The invitation always wins over the default_role.

  ---
  Step 7: Deep Nesting — Agent Corporations with Customer Portals

  Situation: Agent Delta is a long-running strategic agent. It creates an entire operation — with a customer-facing portal for paying clients.

  Market Intelligence Corp (org, created by Delta)
  │
  │  Internal login: invitation_only (agents + selected humans)
  │  Client portal: /login/market-intelligence (open signup for paying clients)
  │    Providers: Google
  │    default_role: end_user
  │    OAuth client: mic_client_portal
  │
  ├── Agent Delta (CEO agent, admin)
  │
  ├── [CHILD ORG] Data Division
  │   ├── Agent D-Lead (admin of this division)
  │   ├── [TEAM] Web Scrapers (10 basic agents)
  │   ├── [TEAM] API Collectors (5 basic agents)
  │   └── [TEAM] Database Miners (3 basic agents)
  │
  ├── [CHILD ORG] Analysis Division
  │   ├── Agent A-Lead (admin)
  │   ├── [TEAM] Quantitative (5 agents with code_runner)
  │   ├── [TEAM] Qualitative (3 agents with web_search)
  │   └── [TEAM] Synthesis (2 agents with file_system)
  │
  ├── [CHILD ORG] Output Division
  │   ├── Agent O-Lead (admin)
  │   ├── [TEAM] Report Writers (4 agents)
  │   └── [TEAM] Presentation Builders (2 agents)
  │
  ├── Paying Client: HedgeFund LLC (end_user, self-registered via portal)
  ├── Paying Client: ConsultingCo (end_user, self-registered via portal)
  └── Domain Expert: Dr. Chen (member, invited by Delta)

  Delta configured the parent org's login page:

  curl -X PUT "$AUTH_URL/organizations/$MIC_ORG_ID/login-config" \
    -H "X-API-Key: $DELTA_API_KEY" \
    -d '{
      "branding": {
        "primary_color": "#6366F1",
        "page_title": "Market Intelligence Corp — Client Access",
        "login_template": "dark"
      },
      "content": {
        "welcome_message": "Market Intelligence Corp",
        "signup_message": "Register for access to market intelligence reports"
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

  # Add Google login for convenience
  curl -X POST "$AUTH_URL/providers/" \
    -H "X-API-Key: $DELTA_API_KEY" \
    -d '{
      "org_id": "'$MIC_ORG_ID'",
      "provider_type": "google",
      "name": "Continue with Google",
      "config": {"client_id": "GOOGLE_ID", "client_secret": "GOOGLE_SECRET"},
      "priority": 1
    }'

  What just happened: An AI agent created a business with divisions, hired agent employees, opened a customer portal, configured Google login, and is ready to serve paying clients — all through API calls. No human intervention. The auth service treats it the same as any human-created company.

  Access rules:
  - Delta (CEO) sees everything (ancestor access)
  - D-Lead manages Data Division, can't see Analysis or Output
  - A scraper in Data Division can't see what the analysts are doing
  - HedgeFund LLC (end_user client) can read published reports but can't see internal agent activity
  - Dr. Chen (invited member) can read internal data AND write task guidance

  ---
  Step 8: Containment & Safety

  This is where you (the human founder) sleep at night.

  Budget containment

  # Your platform wraps every tool call with a budget check
  async def execute_tool_with_budget(agent_id, tool, params):
      spent = await get_agent_spend(agent_id)
      limit = await get_agent_budget(agent_id)

      if spent >= limit:
          raise BudgetExhaustedError(f"Agent {agent_id} budget: ${limit}, spent: ${spent}")

      result = await tool_gateway.execute(tool, params)
      await record_spend(agent_id, tool, cost=estimate_cost(tool, params))
      return result

  Spawn containment

  async def spawn_agent(requester_id, params):
      spawn_count = await get_spawn_count(requester_id)
      max_spawns = await get_spawn_limit(requester_id)

      if spawn_count >= max_spawns:
          raise SpawnLimitError("Agent has reached its spawn limit")

      requester_budget = await get_remaining_budget(requester_id)
      new_agent_budget = params["budget_limit"]

      if new_agent_budget > requester_budget:
          raise BudgetError("Cannot allocate more budget than you have")

      await deduct_budget(requester_id, new_agent_budget)
      return await _create_agent(params)

  Permission escalation prevention

  An agent cannot grant permissions it doesn't have:

  Alpha has: [web_search, file_system, spawn.agents]
  Alpha spawns Beta with: [code_runner]
  DENIED — Alpha doesn't have code_runner, so it can't grant it.

  Alpha spawns Beta with: [web_search]
  OK — Alpha has web_search, so it can grant it.

  This applies to login config too: an agent configuring self-registration can only set a default_role whose permissions are a subset of the agent's own permissions. An agent with end_user-level perms can't create a portal that grants admin to self-registered humans.

  Portal containment

  Agents that create hosted login portals are subject to additional guardrails:

  async def validate_login_config(agent_id, config):
      # Can this agent open self-registration?
      if config["auth_methods"]["signup_enabled"]:
          agent_perms = await get_agent_permissions(agent_id)
          if "agentforge.write.organizations" not in agent_perms:
              raise PermissionDeniedError("Agent cannot open self-registration without write.organizations")

      # Is the default_role safe?
      default_role = config["registration"]["default_role"]
      role_perms = get_role_permissions(default_role)
      agent_perms = await get_agent_permissions(agent_id)
      if not role_perms.issubset(agent_perms):
          raise PermissionDeniedError("Agent cannot grant permissions it doesn't have via default_role")

  Org dissolution

  async def cleanup_expired_orgs():
      all_orgs = await auth_client.get("/organizations/")

      for org in all_orgs:
          ttl = org["settings"].get("ttl_hours")
          created = org["created_at"]

          if ttl and (now - created).hours > ttl:
              # Kill all agents in this org
              agents = await auth_client.get(f"/organizations/{org['id']}/users")
              for agent in agents:
                  await deactivate_agent(agent["id"])

              # Delete the org (and its login config, OAuth clients, providers)
              await auth_client.delete(f"/organizations/{org['id']}")

              log.info(f"Dissolved org {org['name']} after {ttl}h TTL")

  When an org dissolves, its hosted login page stops working (org doesn't exist), its OAuth clients are invalid, its providers are gone. Human reviewers who were in the org lose access automatically. No cleanup needed on their side.

  The nuclear option

  If an agent goes rogue (spawning endlessly, opening portals to the internet, spending budget):

  # You (human admin) suspend the org — everything inside stops instantly
  curl -X PUT "$AUTH_URL/organizations/$ROGUE_ORG_ID" \
    -H "Authorization: Bearer $YOUR_ADMIN_TOKEN" \
    -d '{"status": "suspended"}'

  # All agents in that org immediately get 403 on every request.
  # All API keys in that org stop working.
  # The hosted login page returns an error.
  # OAuth clients stop working.
  # Instant containment.

  ---
  The Complete Mental Model

  You (human founder)
  │   permission: agentforge.cross_tenant (god mode, only you)
  │
  ├── AgentForge Platform Org
  │   ├── Spawner Service (creates agents, cross_tenant)
  │   ├── Tool Gateway (validates tool access per-agent)
  │   ├── Budget Service (tracks spend, enforces limits)
  │   └── Cleanup Service (dissolves expired orgs)
  │
  ├── Agent-Created Orgs (ephemeral, dynamic)
  │   ├── "Research Group Alpha"
  │   │   ├── 3 specialist agents (invited)
  │   │   ├── 2 human reviewers (self-registered via /login/alpha-research)
  │   │   ├── 1 domain expert (invited with member role)
  │   │   └── TTL: 48h, then dissolves
  │   │
  │   ├── "Market Intelligence Corp"
  │   │   ├── 3 child org divisions (30+ agents)
  │   │   ├── Client portal: /login/market-intelligence (Google + email)
  │   │   ├── Paying clients: HedgeFund, ConsultingCo (end_user)
  │   │   └── Long-running, no TTL
  │   │
  │   ├── "Bug Fix Squad #4821"
  │   │   ├── 2 agents, no portal (agent-only workspace)
  │   │   └── TTL: 4h
  │   │
  │   └── ... hundreds of these
  │
  └── Guardrails (your code, not the auth service)
      ├── Budget limits per agent
      ├── Spawn limits per agent
      ├── Org TTLs (auto-dissolve)
      ├── Permission escalation prevention
      ├── Portal containment (agents can't grant more than they have)
      └── Human kill switch (suspend any org instantly)

  The auth service gives you the primitives: identity, isolation, permissions, hierarchy, hosted login, self-registration.
  Your platform code adds the guardrails: budgets, TTLs, spawn limits, portal validation, monitoring.
  The agents do the rest: self-organize, collaborate, open portals, serve clients, dissolve.

  The auth service doesn't know or care that these are AI agents. It just sees identities making API calls within org boundaries. That's the beauty — the same system that handles "Alice at
  Acme Corp" and "Dr. Smith reviewing research" handles "Agent Alpha opening a customer portal for its market intelligence business." Same walls, same permissions, same isolation, same hosted login pages.
