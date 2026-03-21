❯ question: following on from I am a founder of a company that deploys self organising AI agents at scale, who need dynamic tool access and permissions, and org structures, these agents 
   can build teams, create their own companies and orgs, and they are automous and can create and invite other agents to collerbate on problems 

● The AI Agent Platform: "AgentForge"

  You're building a platform where autonomous AI agents spin up, organize themselves, grab tools, form teams, create companies, collaborate, and dissolve — all without a human clicking
  buttons. This is where the "everything is an org" model really shines, because agents don't care about your UI. They care about API calls and permissions.

  ---
  The Core Insight

  An agent is just an identity that makes API calls. The auth service doesn't care if the identity is a human at a keyboard or a GPT-4 agent in a container. It cares about:

  - Who are you? (API key or token)
  - What can you do? (permissions)
  - Where can you do it? (org boundary)

  Your agents will use the same primitives as humans: orgs, permissions, API keys, teams, delegation. They'll just do it faster and at scale.

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
  │   │   └── Agent Gamma (member, specialist)
  │   │
  │   ├── "Market Analysis Corp" (created by Agent Delta)
  │   │   ├── Agent Delta (admin)
  │   │   ├── [CHILD ORG] "Data Collection Unit"
  │   │   │   ├── Agent Epsilon (scraper)
  │   │   │   └── Agent Zeta (scraper)
  │   │   └── [CHILD ORG] "Analysis Unit"
  │   │       ├── Agent Eta (analyst)
  │   │       └── Agent Theta (report writer)
  │   │
  │   └── ... hundreds more, spinning up and down
  │
  └── Tool Registry (what tools exist)
      ├── web_search
      ├── code_runner
      ├── file_system
      ├── api_caller
      ├── database_query
      └── agent_spawner

  ---
  Step 1: Define Your Permission Scheme

  This is the most important step. You're defining what agents are allowed to do on your platform.

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
      "logs"
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
      parent_org_id: str = None,  # Which org to place the agent in
      budget_limit: float = 10.0  # Max spend in dollars
  ):
      # 1. Create a service account for the agent
      response = await auth_client.post("/admin/users/create-service-account", json={
          "email": f"{name.lower().replace(' ', '-')}@agents.agentforge.internal",
          "name": name,
          "description": purpose,
          "permissions": build_permissions(capabilities, autonomy_level),
          "org_id": parent_org_id,
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
              f"&org_id={parent_org_id}"
              f"&permission=agentforge.execute.tools.{tool}"
          )

      # 4. Return credentials to the agent runtime
      return {"agent_id": agent_id, "api_key": agent_key, "org_id": parent_org_id}

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
  Step 4: An Agent Creates a Company

  This is the wild part. Agent Alpha decides it needs a team.

  Situation: Alpha is researching "market trends in renewable energy." It realizes this is too big for one agent. It needs a scraper, an analyst, and a writer.

  Alpha has agent-builder role, so it has agentforge.create.organizations and agentforge.spawn.agents.

  What Alpha does (autonomously, via API calls):

  Alpha's internal reasoning:
    "This task needs 3 specialists. I should create a workspace,
     spawn agents, and coordinate."

  Alpha calls the auth service:

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

  Step 4b: Alpha spawns specialist agents

  # Alpha calls YOUR spawner service (not the auth service directly)
  # Because spawning is a platform operation, not just an auth operation

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
  # Returns: { agent_id: "svc_scraper1", api_key: "sk_..." }

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

  Step 4c: Alpha creates teams for coordination

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
  └── RE-Writer-1 (basic agent)
      tools: [file_system]
      budget: $2.00

  Total budget: $25.00 (Alpha allocated from its own budget)
  TTL: 48 hours (then auto-dissolves)

  ---
  Step 5: Agents Collaborate

  Now they're working. Here's what the isolation gives you:

  The scraper finds data

  # RE-Scraper-1's runtime
  result = await tool_gateway.execute("web_search", {
      "query": "renewable energy market size 2026"
  })
  # ✅ Works — scraper has web_search permission

  await tool_gateway.execute("code_runner", {
      "code": "import pandas as pd..."
  })
  # ❌ 403 Forbidden — scraper does NOT have code_runner
  # Scraper can't analyze, only collect. That's the analyst's job.

  The analyst processes data

  # RE-Analyst-1 reads the scraper's output (same org, shared file_system)
  data = await tool_gateway.execute("file_system", {
      "action": "read",
      "path": "/org-research-456/collected-data/"
  })
  # ✅ Works — same org, has file_system permission

  # Analyst runs code
  result = await tool_gateway.execute("code_runner", {
      "code": "analyze_trends(data)"
  })
  # ✅ Works — analyst has code_runner permission

  A rogue agent tries to peek

  # Some OTHER agent from a DIFFERENT org tries to read the research
  await tool_gateway.execute("file_system", {
      "action": "read",
      "path": "/org-research-456/collected-data/"
  })
  # ❌ 403 Forbidden — different org, can't see inside the research group

  This is the whole point of orgs. Alpha's research group is a walled garden. The agents inside can collaborate freely. Nobody outside can see in.

  ---
  Step 6: Agents Inviting Existing Agents

  Situation: Alpha is halfway through the research and realizes it needs Agent Omega, a specialist that already exists on the platform (it was spawned for a different project last week and
  is now idle).

  # Alpha invites Omega to join the research org
  curl -X POST "$AUTH_URL/organizations/org-research-456/invite" \
    -H "X-API-Key: $ALPHA_API_KEY" \
    -d '{
      "email": "omega@agents.agentforge.internal",
      "role": "agent-tool-user",
      "permissions": ["agentforge.execute.tools.db_query", "agentforge.read.tasks"],
      "message": "Need your database expertise for renewable energy analysis"
    }'

  Omega accepts (your agent runtime handles the acceptance flow). Now Omega is in TWO orgs — its original project AND Alpha's research group. It switches context:

  # Omega switches to the research org
  curl -X POST "$AUTH_URL/auth/switch-organization" \
    -H "X-API-Key: $OMEGA_API_KEY" \
    -d '{"org_id": "org-research-456"}'

  Now Omega sees the research group's data and tasks. When it's done, it switches back to its original org. Same agent, multiple workspaces, different permissions in each.

  ---
  Step 7: Deep Nesting — Agent Corporations

  Situation: Agent Delta is a long-running strategic agent. It doesn't just create one research group — it creates an entire operation.

  Market Intelligence Corp (org, created by Delta)
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
  └── [CHILD ORG] Output Division
      ├── Agent O-Lead (admin)
      ├── [TEAM] Report Writers (4 agents)
      └── [TEAM] Presentation Builders (2 agents)

  Access rules:
  - Delta (CEO) sees everything (ancestor access)
  - D-Lead manages Data Division, can't see Analysis or Output
  - A scraper in Data Division can't see what the analysts are doing
  - An analyst can read Data Division's output (if Alpha explicitly shares it via Zanzibar or delegation)

  This is a self-organizing hierarchy. Delta decided on this structure. A human didn't design it. The auth service just enforces the boundaries.

  ---
  Step 8: Containment & Safety

  This is where you (the human founder) sleep at night.

  Budget containment

  # Your platform wraps every tool call with a budget check
  async def execute_tool_with_budget(agent_id, tool, params):
      spent = await get_agent_spend(agent_id)
      limit = await get_agent_budget(agent_id)

      if spent >= limit:
          # Agent is broke. Can't do anything that costs money.
          raise BudgetExhaustedError(f"Agent {agent_id} budget: ${limit}, spent: ${spent}")

      result = await tool_gateway.execute(tool, params)
      await record_spend(agent_id, tool, cost=estimate_cost(tool, params))
      return result

  Spawn containment

  # Your spawner service enforces limits
  async def spawn_agent(requester_id, params):
      # How many agents has this agent already spawned?
      spawn_count = await get_spawn_count(requester_id)
      max_spawns = await get_spawn_limit(requester_id)  # e.g., 10

      if spawn_count >= max_spawns:
          raise SpawnLimitError("Agent has reached its spawn limit")

      # Does the requester have enough budget to fund the new agent?
      requester_budget = await get_remaining_budget(requester_id)
      new_agent_budget = params["budget_limit"]

      if new_agent_budget > requester_budget:
          raise BudgetError("Cannot allocate more budget than you have")

      # Deduct from requester, allocate to new agent
      await deduct_budget(requester_id, new_agent_budget)
      return await _create_agent(params)

  Permission escalation prevention

  An agent cannot grant permissions it doesn't have:

  Alpha has: [web_search, file_system, spawn.agents]
  Alpha spawns Beta with: [code_runner]
  ❌ DENIED — Alpha doesn't have code_runner, so it can't grant it.

  Alpha spawns Beta with: [web_search]
  ✅ OK — Alpha has web_search, so it can grant it.

  This is enforced at the auth service level. When Alpha creates an API key or invites an agent with permissions, the auth service checks: "Does the requester have these permissions
  themselves?"

  Org dissolution

  # Your cleanup service runs periodically
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

              # Delete the org
              await auth_client.delete(f"/organizations/{org['id']}")

              log.info(f"Dissolved org {org['name']} after {ttl}h TTL")

  The nuclear option

  If an agent goes rogue (spawning endlessly, spending budget, creating orgs):

  # You (human admin) suspend the org — everything inside stops instantly
  curl -X PUT "$AUTH_URL/organizations/$ROGUE_ORG_ID" \
    -H "Authorization: Bearer $YOUR_ADMIN_TOKEN" \
    -d '{"status": "suspended"}'

  # All agents in that org immediately get 403 on every request.
  # All API keys in that org stop working.
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
  │   ├── "Research Group Alpha" ← created by an agent, TTL 48h
  │   ├── "Market Intelligence Corp" ← created by an agent, long-running
  │   ├── "Bug Fix Squad #4821" ← created 2 hours ago, will dissolve tonight
  │   └── ... hundreds of these
  │
  └── Guardrails (your code, not the auth service)
      ├── Budget limits per agent
      ├── Spawn limits per agent
      ├── Org TTLs (auto-dissolve)
      ├── Permission escalation prevention
      └── Human kill switch (suspend any org instantly)

  The auth service gives you the primitives: identity, isolation, permissions, hierarchy.
  Your platform code adds the guardrails: budgets, TTLs, spawn limits, monitoring.
  The agents do the rest: self-organize, collaborate, dissolve.

  The auth service doesn't know or care that these are AI agents. It just sees identities making API calls within org boundaries. That's the beauty — the same system that handles "Alice at
  Acme Corp" handles "Agent Alpha spawning a research team." Same walls, same permissions, same isolation.

