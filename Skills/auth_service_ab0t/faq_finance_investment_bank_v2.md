question: We are an investment bank — "Apex Capital." We have fund divisions, dozens of analysts, compliance teams, external auditors, and automated trading systems that all need to
  talk to each other. We need fine-grained access control — not just "who can use the app" but "who can see THIS specific portfolio, THIS specific trade, THIS specific document."
  We also need analysts to move between desks, auditors to get temporary access, and our systems to talk to each other securely. Walk us through the whole thing.

● Let's build this. Apex Capital is one of the most demanding auth scenarios there is — regulated, hierarchical, document-level access, automated systems, external parties, and people
  moving around constantly. By the end you'll have:

  - A division/fund org hierarchy (the "hard walls")
  - Zanzibar-backed document-level access (who can see which portfolio, trade, document)
  - API keys for your trading system, risk engine, and reporting service
  - Service-to-service calls with scoped credentials
  - Delegation tokens for external auditors
  - Clean analyst transfers between desks with zero lingering access

  ---
  Concept: Two Layers of Access Control

  Most auth systems give you one layer: "Alice is a member of the Equities Division org." That tells you Alice can use the Equities app. But it doesn't tell you whether Alice can see
  Portfolio #GGF-001 vs Portfolio #TF-002. That's a different question.

  You need two layers:

  ┌─────────────────────────────────┬──────────────────────────────────────────────────────────┬──────────────────────────────────────────────────────┐
  │             Layer               │                       What it answers                    │                      Powered by                      │
  ├─────────────────────────────────┼──────────────────────────────────────────────────────────┼──────────────────────────────────────────────────────┤
  │ Org membership + permissions    │ "Can Alice use the Equities platform at all?"             │ Orgs, roles, permissions (the mesh)                  │
  ├─────────────────────────────────┼──────────────────────────────────────────────────────────┼──────────────────────────────────────────────────────┤
  │ Zanzibar tuples                 │ "Can Alice specifically view Portfolio #GGF-001?"         │ Zanzibar (Google's global auth system, built in)     │
  └─────────────────────────────────┴──────────────────────────────────────────────────────────┴──────────────────────────────────────────────────────┘

  Layer 1 says Alice is an equities analyst. Layer 2 says Alice is assigned to the Global Growth Fund, can view Portfolios GGF-001 through GGF-004, but has no access to the Technology
  Fund's portfolios at all — even though they're in the same division.

  Both layers are enforced by the same auth service. They're complementary, not competing.

  ---
  Concept: What Is Zanzibar?

  Google Zanzibar is the authorization system that powers Google Drive, Docs, Calendar — any Google product where you share a specific document with a specific person.

  The core idea: store (object, relation, subject) tuples.

  "document:trade-note-8821  #viewer    user:james"
  "portfolio:GGF-001          #analyst   user:james"
  "portfolio:GGF-001          #manager   user:marcus"
  "account:acc-4421           #owner     portfolio:GGF-001"

  Then check: "Can james view document:trade-note-8821?" — yes, there's a tuple.
  "Can james view account:acc-4421?" — yes, because james is analyst of GGF-001, and GGF-001 owns acc-4421 (relation chains).

  This is how you get "Alice can see her 4 portfolios but not the other 12 in her division" without storing 12 negative rules. You store the 4 positive tuples. Absence = no access.

  ---
  The Architecture: Apex Capital

  Apex Capital (parent org — compliance, IT, C-suite)
  │
  ├── [CHILD ORG] Equities Division
  │   ├── [CHILD ORG] Global Growth Fund (GGF)
  │   └── [CHILD ORG] Technology Fund (TF)
  │
  ├── [CHILD ORG] Fixed Income Division
  │   ├── [CHILD ORG] Bond Ladder Fund (BLF)
  │   └── [CHILD ORG] Treasury Strategies Fund (TSF)
  │
  ├── [CHILD ORG] Alternative Assets Division
  │   └── [CHILD ORG] Real Estate Opportunity Fund (REOF)
  │
  └── Services (API keys, not orgs)
      ├── Trading System      (API key: apex.execute.trades, apex.read.portfolios)
      ├── Risk Engine         (API key: apex.read.positions, apex.write.risk_scores)
      └── Reporting Service   (API key: apex.read.*, apex.write.reports)

  Characters:
  - Victoria Chen     — CIO, owner of Apex Capital parent org
  - Marcus Webb       — Head of Equities (admin of Equities Division)
  - Sarah Kim         — Head of Fixed Income (admin of Fixed Income Division)
  - James Okafor      — Junior Analyst (starts in Equities, moves to Fixed Income)
  - Dr. Elena Torres  — External Auditor (gets delegated access for Q4 audit)
  - Priya Nair        — Chief Compliance Officer (cross_tenant — sees everything)

  ---
  Step 1: Register Victoria and Create the Bank

  AUTH_URL="https://auth.service.ab0t.com"

  # Victoria creates her account
  curl -X POST "$AUTH_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "victoria@apexcapital.com",
      "password": "VictoriaSecure2026!",
      "name": "Victoria Chen"
    }'

  # Login
  VICTORIA_TOKEN=$(curl -s -X POST "$AUTH_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email": "victoria@apexcapital.com", "password": "VictoriaSecure2026!"}' \
    | jq -r '.access_token')

  # Create Apex Capital parent org
  APEX=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $VICTORIA_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Apex Capital",
      "slug": "apex-capital",
      "domain": "apexcapital.com",
      "billing_type": "enterprise",
      "settings": {"type": "company", "hierarchical": true},
      "metadata": {
        "regulated": true,
        "regulators": ["SEC", "FINRA"],
        "audit_retention_years": 7
      }
    }')
  APEX_ORG_ID=$(echo "$APEX" | jq -r '.id')

  # Switch into Apex context
  VICTORIA_TOKEN=$(curl -s -X POST "$AUTH_URL/auth/switch-organization" \
    -H "Authorization: Bearer $VICTORIA_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"org_id": "'$APEX_ORG_ID'"}' \
    | jq -r '.access_token')

  ---
  Step 2: Define Permissions and Register the Service

  Apex's platform permissions:

  {
    "service": "apex",
    "description": "Apex Capital investment platform",
    "actions": ["read", "write", "create", "delete", "execute", "approve", "delegate", "admin"],
    "resources": [
      "portfolios", "accounts", "trades", "positions",
      "documents", "reports", "risk_scores",
      "audit_logs", "settings", "users"
    ],
    "roles": {
      "apex-viewer": {
        "description": "Read-only access — auditors, regulators, reporting",
        "default_permissions": [
          "apex.read.portfolios", "apex.read.accounts",
          "apex.read.trades", "apex.read.positions",
          "apex.read.documents", "apex.read.reports"
        ]
      },
      "apex-analyst": {
        "description": "Day-to-day analyst — research, propose trades, update documents",
        "implies": ["apex-viewer"],
        "default_permissions": [
          "apex.create.trades", "apex.write.documents",
          "apex.create.documents", "apex.write.positions"
        ]
      },
      "apex-trader": {
        "description": "Can execute approved trades",
        "implies": ["apex-analyst"],
        "default_permissions": [
          "apex.execute.trades", "apex.approve.trades"
        ]
      },
      "apex-fund-manager": {
        "description": "Manages a fund — approves trades, manages analysts",
        "implies": ["apex-trader"],
        "default_permissions": [
          "apex.approve.trades", "apex.write.portfolios",
          "apex.delegate.access", "apex.read.audit_logs"
        ]
      },
      "apex-admin": {
        "description": "Division or bank admin",
        "implies": ["apex-fund-manager"],
        "default_permissions": [
          "apex.admin", "apex.write.settings",
          "apex.delete.documents", "apex.read.users"
        ]
      }
    }
  }

  Concept: Permission Inheritance Chain
  apex-admin -> apex-fund-manager -> apex-trader -> apex-analyst -> apex-viewer

  A fund manager automatically has all analyst and viewer permissions through the implies chain. You never manually assign "can read portfolios" to a manager — it's inherited. This mirrors
  how real financial institutions work: senior roles encompass junior capabilities.

  ./register-service-permissions.sh \
    --service-name "apex" \
    --admin-email "svc+apex@apexcapital.com" \
    --permissions-file apex.permissions.json

  SERVICE_API_KEY="ab0t_sk_live_apex_..."

  ---
  Step 3: Build the Division and Fund Hierarchy

  Concept: Why Child Orgs for Each Division?
  A hard wall between Equities and Fixed Income isn't just good practice — it's regulatory. FINRA requires information barriers ("Chinese walls") between certain business units to prevent
  insider trading. An Equities analyst must not be able to see Fixed Income's deal pipeline. Child orgs enforce this structurally, not just by policy.

  3a: Create division orgs

  # Equities Division
  EQUITIES=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $VICTORIA_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Apex Equities",
      "slug": "apex-equities",
      "parent_id": "'"$APEX_ORG_ID"'",
      "billing_type": "enterprise",
      "settings": {
        "type": "division",
        "information_barrier": true,
        "hierarchical": true
      },
      "metadata": {"division": "equities", "head": "marcus.webb@apexcapital.com"}
    }')
  EQUITIES_ORG_ID=$(echo "$EQUITIES" | jq -r '.id')

  # Fixed Income Division
  FIXED_INCOME=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $VICTORIA_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Apex Fixed Income",
      "slug": "apex-fixed-income",
      "parent_id": "'"$APEX_ORG_ID"'",
      "billing_type": "enterprise",
      "settings": {
        "type": "division",
        "information_barrier": true,
        "hierarchical": true
      },
      "metadata": {"division": "fixed_income", "head": "sarah.kim@apexcapital.com"}
    }')
  FIXED_INCOME_ORG_ID=$(echo "$FIXED_INCOME" | jq -r '.id')

  # Alternative Assets Division
  ALT_ASSETS=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $VICTORIA_TOKEN" \
    -d '{
      "name": "Apex Alternative Assets",
      "slug": "apex-alt-assets",
      "parent_id": "'"$APEX_ORG_ID"'",
      "settings": {"type": "division", "information_barrier": true}
    }')
  ALT_ASSETS_ORG_ID=$(echo "$ALT_ASSETS" | jq -r '.id')

  3b: Create fund orgs (children of divisions)

  # Global Growth Fund — child of Equities
  GGF=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $VICTORIA_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Global Growth Fund",
      "slug": "apex-ggf",
      "parent_id": "'"$EQUITIES_ORG_ID"'",
      "billing_type": "enterprise",
      "settings": {"type": "fund", "hierarchical": false},
      "metadata": {
        "fund_code": "GGF",
        "aum_usd": 2400000000,
        "strategy": "long_only_equity",
        "inception_date": "2019-01-15"
      }
    }')
  GGF_ORG_ID=$(echo "$GGF" | jq -r '.id')

  # Technology Fund — also child of Equities
  TF=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $VICTORIA_TOKEN" \
    -d '{
      "name": "Technology Fund",
      "slug": "apex-tf",
      "parent_id": "'"$EQUITIES_ORG_ID"'",
      "settings": {"type": "fund"},
      "metadata": {"fund_code": "TF", "strategy": "tech_sector_equity"}
    }')
  TF_ORG_ID=$(echo "$TF" | jq -r '.id')

  # Bond Ladder Fund — child of Fixed Income
  BLF=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $VICTORIA_TOKEN" \
    -d '{
      "name": "Bond Ladder Fund",
      "slug": "apex-blf",
      "parent_id": "'"$FIXED_INCOME_ORG_ID"'",
      "settings": {"type": "fund"},
      "metadata": {"fund_code": "BLF", "strategy": "investment_grade_bonds"}
    }')
  BLF_ORG_ID=$(echo "$BLF" | jq -r '.id')

  What the hierarchy looks like now:

  Apex Capital (parent org)          <- Victoria (CIO) sees everything via ancestor access
  │
  ├── Apex Equities (division)       <- Marcus (Head of Equities) sees both equity funds
  │   ├── Global Growth Fund         <- GGF team sees GGF data only
  │   └── Technology Fund            <- TF team sees TF data only
  │
  ├── Apex Fixed Income (division)   <- Sarah (Head of FI) sees both FI funds
  │   ├── Bond Ladder Fund
  │   └── Treasury Strategies Fund
  │
  └── Apex Alternative Assets        <- Alt Assets team, isolated
      └── Real Estate Opportunity Fund

  Information barriers enforced:
  - GGF analyst CANNOT see TF portfolios (sibling fund isolation)
  - Equities analyst CANNOT see Fixed Income trades (sibling division isolation)
  - Victoria CAN see everything (ancestor access flows down)

  ---
  Step 4: Set Up People

  4a: Invite Marcus as Equities Division head

  # Marcus becomes admin of the Equities division
  curl -X POST "$AUTH_URL/organizations/$EQUITIES_ORG_ID/invite" \
    -H "Authorization: Bearer $VICTORIA_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "marcus@apexcapital.com",
      "role": "admin",
      "permissions": ["apex.admin"],
      "message": "You are the Head of Equities. You manage GGF and TF."
    }'

  # Victoria also gives Marcus admin of both equity fund orgs
  curl -X POST "$AUTH_URL/organizations/$GGF_ORG_ID/invite" \
    -H "Authorization: Bearer $VICTORIA_TOKEN" \
    -d '{"email": "marcus@apexcapital.com", "role": "admin", "permissions": ["apex.admin"]}'

  curl -X POST "$AUTH_URL/organizations/$TF_ORG_ID/invite" \
    -H "Authorization: Bearer $VICTORIA_TOKEN" \
    -d '{"email": "marcus@apexcapital.com", "role": "admin", "permissions": ["apex.admin"]}'

  4b: Invite James as a GGF analyst

  # James joins ONLY the Global Growth Fund org — not Technology Fund, not Fixed Income
  curl -X POST "$AUTH_URL/organizations/$GGF_ORG_ID/invite" \
    -H "Authorization: Bearer $MARCUS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "james@apexcapital.com",
      "role": "member",
      "permissions": [
        "apex.read.portfolios", "apex.read.accounts", "apex.read.trades",
        "apex.create.trades", "apex.write.documents", "apex.create.documents",
        "apex.write.positions"
      ],
      "message": "Welcome to the Global Growth Fund team, James."
    }'

  What just happened: James is an analyst in GGF. He can see GGF portfolios, create trade proposals, write research documents. He cannot see Technology Fund's data (different org). He
  cannot see Bond Ladder Fund's trades (different division, information barrier).

  4c: Invite Priya as Chief Compliance Officer

  Compliance must see everything — all divisions, all funds, all trades. That's cross_tenant.

  curl -X POST "$AUTH_URL/organizations/$APEX_ORG_ID/invite" \
    -H "Authorization: Bearer $VICTORIA_TOKEN" \
    -d '{
      "email": "priya@apexcapital.com",
      "role": "admin",
      "permissions": ["apex.admin", "apex.read.audit_logs"]
    }'

  # Grant cross_tenant — Priya can read ANY org's data
  curl -X POST "$AUTH_URL/permissions/grant?user_id=$PRIYA_USER_ID&org_id=$APEX_ORG_ID&permission=apex.cross_tenant" \
    -H "Authorization: Bearer $VICTORIA_TOKEN"

  Concept: cross_tenant in a Financial Context
  Compliance officers have a legitimate legal reason to cross every information barrier. apex.cross_tenant gives Priya the ability to read any org's data regardless of which org she's logged into. This is auditable — every request she makes is logged against her identity. She can't hide who she is by switching orgs.

  ---
  Step 5: Zanzibar — Document-Level Access Control

  Now the interesting part. Org membership says James is "in GGF." But GGF has 12 portfolios. James manages 4 of them. He should not be able to modify the other 8.

  This is where Zanzibar comes in.

  5a: Define your namespaces

  A namespace defines the types of objects and the relations between them.

  # Define the "portfolio" namespace
  curl -X POST "$AUTH_URL/zanzibar/stores/$APEX_ORG_ID/namespaces" \
    -H "Authorization: Bearer $MARCUS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "org_id": "'$GGF_ORG_ID'",
      "namespace": "portfolio",
      "relations": {
        "owner": {},
        "manager": {
          "union": ["owner"]
        },
        "analyst": {
          "union": ["manager"]
        },
        "viewer": {
          "union": ["analyst"]
        }
      },
      "permissions": {
        "read":   {"union": ["viewer"]},
        "write":  {"union": ["analyst"]},
        "trade":  {"union": ["manager"]},
        "delete": {"union": ["owner"]}
      }
    }'

  # Define the "account" namespace — accounts belong to portfolios
  curl -X POST "$AUTH_URL/zanzibar/stores/$APEX_ORG_ID/namespaces" \
    -H "Authorization: Bearer $MARCUS_TOKEN" \
    -d '{
      "org_id": "'$GGF_ORG_ID'",
      "namespace": "account",
      "relations": {
        "parent_portfolio": {},
        "direct_analyst": {},
        "analyst": {
          "union": ["direct_analyst", "parent_portfolio#analyst"]
        },
        "viewer": {
          "union": ["analyst", "parent_portfolio#viewer"]
        }
      },
      "permissions": {
        "read":  {"union": ["viewer"]},
        "write": {"union": ["analyst"]}
      }
    }'

  # Define the "document" namespace — research notes, trade memos
  curl -X POST "$AUTH_URL/zanzibar/stores/$APEX_ORG_ID/namespaces" \
    -H "Authorization: Bearer $MARCUS_TOKEN" \
    -d '{
      "org_id": "'$GGF_ORG_ID'",
      "namespace": "document",
      "relations": {
        "author":  {},
        "editor":  {"union": ["author"]},
        "viewer":  {"union": ["editor"]},
        "org_viewer": {}
      },
      "permissions": {
        "read":   {"union": ["viewer", "org_viewer"]},
        "write":  {"union": ["editor"]},
        "delete": {"union": ["author"]}
      }
    }'

  Concept: Computed Relations (The Power of Zanzibar)
  Look at the portfolio namespace:
  - viewer is the base — they can read
  - analyst includes viewer (via union) — they can also write
  - manager includes analyst — they can also trade
  - owner includes manager — they can also delete

  This means: if you write ONE tuple "james is analyst of portfolio:GGF-001", James automatically gets read + write on that portfolio. You don't need to write three separate tuples.

  Look at the account namespace:
  - "analyst": union of [direct_analyst, parent_portfolio#analyst]

  This means: if James is analyst of portfolio:GGF-001, he automatically has analyst access to ALL accounts under GGF-001. You don't write individual account tuples. The relation chains.

  This is how Google Drive works: share a folder, everything inside is shared. Same model.

  5b: Write tuples to assign James his portfolios

  # Marcus assigns James to 4 specific GGF portfolios
  curl -X POST "$AUTH_URL/zanzibar/stores/$APEX_ORG_ID/relationships" \
    -H "Authorization: Bearer $MARCUS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "org_id": "'$GGF_ORG_ID'",
      "tuples": [
        {"object": "portfolio:GGF-001", "relation": "analyst", "subject": "user:'$JAMES_USER_ID'"},
        {"object": "portfolio:GGF-002", "relation": "analyst", "subject": "user:'$JAMES_USER_ID'"},
        {"object": "portfolio:GGF-003", "relation": "analyst", "subject": "user:'$JAMES_USER_ID'"},
        {"object": "portfolio:GGF-004", "relation": "analyst", "subject": "user:'$JAMES_USER_ID'"}
      ]
    }'

  # Link accounts to their parent portfolios (done once when accounts are created)
  curl -X POST "$AUTH_URL/zanzibar/stores/$APEX_ORG_ID/relationships" \
    -H "Authorization: Bearer $MARCUS_TOKEN" \
    -d '{
      "org_id": "'$GGF_ORG_ID'",
      "tuples": [
        {"object": "account:ACC-4421", "relation": "parent_portfolio", "subject": "portfolio:GGF-001"},
        {"object": "account:ACC-4422", "relation": "parent_portfolio", "subject": "portfolio:GGF-001"},
        {"object": "account:ACC-5501", "relation": "parent_portfolio", "subject": "portfolio:GGF-002"}
      ]
    }'

  # Marcus is manager of all GGF portfolios
  curl -X POST "$AUTH_URL/zanzibar/stores/$APEX_ORG_ID/relationships" \
    -H "Authorization: Bearer $MARCUS_TOKEN" \
    -d '{
      "org_id": "'$GGF_ORG_ID'",
      "tuples": [
        {"object": "portfolio:GGF-001", "relation": "manager", "subject": "user:'$MARCUS_USER_ID'"},
        {"object": "portfolio:GGF-002", "relation": "manager", "subject": "user:'$MARCUS_USER_ID'"},
        {"object": "portfolio:GGF-003", "relation": "manager", "subject": "user:'$MARCUS_USER_ID'"},
        {"object": "portfolio:GGF-004", "relation": "manager", "subject": "user:'$MARCUS_USER_ID'"},
        {"object": "portfolio:GGF-005", "relation": "manager", "subject": "user:'$MARCUS_USER_ID'"}
      ]
    }'

  What this means:
  - James: analyst of GGF-001 through GGF-004 (4 portfolios, and all their accounts)
  - James: NO access to GGF-005 through GGF-012 (the other 8 portfolios)
  - Marcus: manager of all 5 shown (manager implies analyst, so Marcus can trade)

  5c: Check access in your app

  Now in your API, before returning data you check Zanzibar:

  @router.get("/portfolios/{portfolio_id}/positions")
  async def get_positions(portfolio_id: str, user: ApexAnalyst):
      # Layer 1 check: user has apex.read.positions (done by ApexAnalyst badge)

      # Layer 2 check: can this user specifically read THIS portfolio?
      allowed = await zanzibar.check(
          org_id=user.org_id,
          subject=f"user:{user.user_id}",
          permission="read",
          object=f"portfolio:{portfolio_id}"
      )
      if not allowed:
          raise HTTPException(403, "You do not have access to this portfolio")

      return await db.get_positions(portfolio_id=portfolio_id)

  The check call:

  curl -X POST "$AUTH_URL/zanzibar/stores/$APEX_ORG_ID/check" \
    -H "Authorization: Bearer $JAMES_TOKEN" \
    -G \
    --data-urlencode "org_id=$GGF_ORG_ID" \
    --data-urlencode "subject=user:$JAMES_USER_ID" \
    --data-urlencode "permission=read" \
    --data-urlencode "object=portfolio:GGF-001"

  # Returns: {"allowed": true}

  curl -X POST "$AUTH_URL/zanzibar/stores/$APEX_ORG_ID/check" \
    -H "Authorization: Bearer $JAMES_TOKEN" \
    -G \
    --data-urlencode "org_id=$GGF_ORG_ID" \
    --data-urlencode "subject=user:$JAMES_USER_ID" \
    --data-urlencode "permission=read" \
    --data-urlencode "object=portfolio:GGF-009"

  # Returns: {"allowed": false}
  # James has no tuple on GGF-009. Absence = no access.

  5d: Check cascaded access through account -> portfolio

  # Can James read account ACC-4421?
  # He's never directly assigned to it — but it belongs to GGF-001, which he IS assigned to
  curl -X POST "$AUTH_URL/zanzibar/stores/$APEX_ORG_ID/check" \
    -G \
    --data-urlencode "org_id=$GGF_ORG_ID" \
    --data-urlencode "subject=user:$JAMES_USER_ID" \
    --data-urlencode "permission=read" \
    --data-urlencode "object=account:ACC-4421"

  # Returns: {"allowed": true}
  # Chain: james -[analyst]-> portfolio:GGF-001 -[parent_portfolio]-> account:ACC-4421
  # account#viewer includes parent_portfolio#viewer, so James inherits access

  5e: Lookup — what can James access?

  # What portfolios can James read?
  curl -X GET "$AUTH_URL/zanzibar/stores/$APEX_ORG_ID/list-objects" \
    -G \
    --data-urlencode "org_id=$GGF_ORG_ID" \
    --data-urlencode "subject=user:$JAMES_USER_ID" \
    --data-urlencode "permission=read" \
    --data-urlencode "namespace=portfolio"

  # Returns: {"objects": ["portfolio:GGF-001", "portfolio:GGF-002", "portfolio:GGF-003", "portfolio:GGF-004"]}
  # Only his 4. Not GGF-005 through GGF-012.

  Use this in your UI to build filtered lists — "show me all portfolios this user can access" without fetching all 12 and filtering.

  5f: Expand — who can access a portfolio?

  # Who has any access to GGF-001?
  curl -X POST "$AUTH_URL/zanzibar/stores/$APEX_ORG_ID/expand" \
    -G \
    --data-urlencode "org_id=$GGF_ORG_ID" \
    --data-urlencode "object=portfolio:GGF-001" \
    --data-urlencode "relation=viewer"

  # Returns: {
  #   "tree": {
  #     "union": [
  #       {"leaf": {"subjects": ["user:james-uuid"]}},       <- direct analyst (implies viewer)
  #       {"leaf": {"subjects": ["user:marcus-uuid"]}},      <- manager (implies viewer)
  #       {"leaf": {"subjects": ["user:victoria-uuid"]}}     <- CIO (ancestor access)
  #     ]
  #   }
  # }

  Use this for compliance reporting: "who has access to GGF-001?" — instant answer, no manual list.

  ---
  Step 6: Service API Keys — Trading System, Risk Engine, Reporting

  Apex's automated systems are not humans. They don't log in. They use API keys with scoped permissions.

  Concept: Service API Keys
  An API key is a long-lived credential for a machine identity. Unlike tokens (15-minute JWTs), API keys don't expire — but they can be revoked instantly. Each key has exactly the permissions it needs. If the trading system is compromised, you revoke its key. It can't trade, it can't read portfolios. Done.

  6a: Trading System API key

  The trading system executes approved trades. It needs to read portfolios (to know what to trade) and execute trades (to submit orders). That's it. It does NOT need to read documents, write risk scores, or delete anything.

  # Create the trading system's API key — inherits org from bearer token context
  TRADING_KEY=$(curl -s -X POST "$AUTH_URL/api-keys/" \
    -H "Authorization: Bearer $MARCUS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "apex-trading-system",
      "description": "Automated trade execution for Global Growth Fund",
      "permissions": [
        "apex.read.portfolios",
        "apex.read.accounts",
        "apex.read.positions",
        "apex.execute.trades"
      ],
      "metadata": {
        "system": "trading",
        "environment": "production",
        "owner_team": "engineering"
      }
    }')
  TRADING_API_KEY=$(echo "$TRADING_KEY" | jq -r '.key')

  # Store securely: APEX_TRADING_KEY=ab0t_sk_live_...
  echo "APEX_TRADING_KEY=$TRADING_API_KEY" >> .env

  6b: Risk Engine API key

  The risk engine reads positions and writes risk scores. It never touches trades directly.

  RISK_KEY=$(curl -s -X POST "$AUTH_URL/api-keys/" \
    -H "Authorization: Bearer $MARCUS_TOKEN" \
    -d '{
      "name": "apex-risk-engine",
      "description": "Risk calculation engine — reads positions, writes risk scores",
      "permissions": [
        "apex.read.portfolios",
        "apex.read.positions",
        "apex.read.accounts",
        "apex.write.risk_scores",
        "apex.read.risk_scores"
      ],
      "metadata": {"system": "risk", "environment": "production"}
    }')
  RISK_API_KEY=$(echo "$RISK_KEY" | jq -r '.key')

  6c: Reporting Service API key — cross-org

  Reporting needs to pull data from ALL fund orgs to generate consolidated reports. It needs cross_tenant, but scoped only to read permissions. Not write. Not execute.

  # Create the key — inherits org from bearer token context (Victoria's token is in APEX org)
  REPORTING_KEY=$(curl -s -X POST "$AUTH_URL/api-keys/" \
    -H "Authorization: Bearer $VICTORIA_TOKEN" \
    -d '{
      "name": "apex-reporting-service",
      "description": "Consolidated reporting across all funds",
      "permissions": [
        "apex.read.portfolios",
        "apex.read.accounts",
        "apex.read.trades",
        "apex.read.positions",
        "apex.read.risk_scores",
        "apex.write.reports",
        "apex.cross_tenant"
      ],
      "metadata": {"system": "reporting", "environment": "production"}
    }')
  REPORTING_API_KEY=$(echo "$REPORTING_KEY" | jq -r '.key')

  What each service can do:

  ┌───────────────────┬────────────────────┬──────────────┬──────────────────────┬────────────────────┬────────────────┐
  │      Service      │ Read portfolios    │ Read trades  │ Execute trades       │ Write risk scores  │ Cross-tenant   │
  ├───────────────────┼────────────────────┼──────────────┼──────────────────────┼────────────────────┼────────────────┤
  │ Trading System    │ Yes                │ Yes          │ Yes                  │ No                 │ No (GGF only)  │
  ├───────────────────┼────────────────────┼──────────────┼──────────────────────┼────────────────────┼────────────────┤
  │ Risk Engine       │ Yes                │ No           │ No                   │ Yes                │ No (GGF only)  │
  ├───────────────────┼────────────────────┼──────────────┼──────────────────────┼────────────────────┼────────────────┤
  │ Reporting Service │ Yes (all funds)    │ Yes (all)    │ No                   │ No                 │ Yes (all orgs) │
  └───────────────────┴────────────────────┴──────────────┴──────────────────────┴────────────────────┴────────────────┘

  ---
  Step 7: Service-to-Service Communication

  The trading system and risk engine need to talk to each other and to your APIs.

  Concept: How Services Authenticate
  Services send their API key in the X-API-Key header. The auth service validates it and returns the key's permissions. Your platform's API then checks: "does this key have apex.execute.trades?" Same permission check as humans, different credential type.

  In your platform's routes:

  # A service calling your trade execution endpoint
  @router.post("/trades/{trade_id}/execute")
  async def execute_trade(trade_id: str, user: ApexTrader):
      # ApexTrader checks: apex.execute.trades
      # Works for: human traders with the right permission
      #            trading system API key with apex.execute.trades
      # The route doesn't know or care which one is calling

      trade = await db.get_trade(trade_id)
      if trade.org_id != user.org_id:
          raise PermissionDeniedError("Access denied")

      # After execution, notify the risk engine
      await risk_client.notify_trade_executed(trade_id)
      return await execution_engine.execute(trade)

  The trading system calls your API:

  # Trading system (in Python, no human involved)
  import httpx

  async def execute_approved_trade(trade_id: str):
      async with httpx.AsyncClient() as client:
          response = await client.post(
              f"{PLATFORM_URL}/trades/{trade_id}/execute",
              headers={"X-API-Key": os.environ["APEX_TRADING_KEY"]}
          )
          response.raise_for_status()
          return response.json()

  The risk engine calls the auth service directly to validate permissions:

  # Risk engine checks if it's allowed to write a risk score
  async def write_risk_score(portfolio_id: str, score: float):
      # First, verify via Zanzibar that this portfolio exists in our scope
      check = await auth_client.get("/zanzibar/stores/$APEX_ORG_ID/check",
          params={
              "org_id": GGF_ORG_ID,
              "subject": f"service:{RISK_ENGINE_KEY_ID}",
              "permission": "read",
              "object": f"portfolio:{portfolio_id}"
          },
          headers={"X-API-Key": os.environ["APEX_RISK_KEY"]}
      )
      if not check["allowed"]:
          raise PermissionError(f"Risk engine has no access to portfolio {portfolio_id}")

      # Write the score
      await db.write_risk_score(portfolio_id=portfolio_id, score=score)

  Concept: Scoped Compromise
  If the trading system is compromised, the attacker can execute trades and read portfolios in GGF. Bad — but contained. They cannot:
  - Read documents or research notes (no apex.read.documents)
  - Write risk scores (no apex.write.risk_scores)
  - Access Fixed Income or Technology Fund (key is scoped to GGF org)
  - Delete anything (no delete permissions)
  - Access the reporting service's consolidated view (different key, different org)

  Revoke the key, the threat stops. No other system is affected.

  ---
  Step 8: Delegation Tokens — External Auditor Access

  Q4 audit. Dr. Elena Torres from the external audit firm needs to review GGF's trade records and documents for the period October–December 2026. She needs:
  - Read access to all GGF portfolios (not just James's 4 — ALL of them)
  - Read access to all trade documents and memos
  - No write access. No trade execution. Nothing irreversible.
  - Access that expires automatically when the audit is done.

  Concept: Delegation Tokens
  A delegation token is a time-limited, scoped credential that YOU create and hand to someone else. You're saying: "I delegate a subset of MY access to Elena, for THIS purpose, until THIS date."

  The key properties:
  1. Scoped: Elena gets exactly what you specify — not your full access
  2. Time-limited: Token expires automatically (no "forgot to revoke")
  3. Auditable: Every action Elena takes is logged against her identity AND the delegation
  4. Revocable: You can cancel it before the expiry date

  8a: Victoria creates a delegation grant for Elena

  # Step 1: Victoria creates a delegation grant scoping what Elena can do
  GRANT=$(curl -s -X POST "$AUTH_URL/delegation/grant" \
    -H "Authorization: Bearer $VICTORIA_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "actor_id": "'$ELENA_USER_ID'",
      "scope": [
        "apex.read.portfolios",
        "apex.read.accounts",
        "apex.read.trades",
        "apex.read.positions",
        "apex.read.documents",
        "apex.read.audit_logs",
        "apex.read.reports"
      ],
      "expires_in_hours": 2160,
      "metadata": {
        "purpose": "Q4 2026 Annual Audit — Apex Capital GGF",
        "audit_firm": "Torres & Associates",
        "engagement_ref": "APEX-AUDIT-2026-Q4",
        "regulatory_basis": "SEC Rule 17a-4"
      }
    }')
  GRANT_ID=$(echo "$GRANT" | jq -r '.id')

  # Note: For time-limited external access like auditors, Zanzibar relationships
  # with `expires_at` (shown in step 8b below) are the better pattern for scoped
  # temporary access — they tie resource-level visibility to the same expiry window.

  8b: Alongside this, grant Elena Zanzibar read access to ALL GGF portfolios

  # Loop through all GGF portfolios and grant Elena viewer access
  for portfolio_id in GGF-001 GGF-002 GGF-003 GGF-004 GGF-005 GGF-006 GGF-007 GGF-008 GGF-009 GGF-010 GGF-011 GGF-012; do
    curl -s -X POST "$AUTH_URL/zanzibar/stores/$APEX_ORG_ID/relationships" \
      -H "Authorization: Bearer $VICTORIA_TOKEN" \
      -d '{
        "org_id": "'$GGF_ORG_ID'",
        "tuples": [
          {
            "object": "portfolio:'$portfolio_id'",
            "relation": "viewer",
            "subject": "user:'$ELENA_USER_ID'",
            "metadata": {
              "granted_by": "delegation:'$GRANT_ID'",
              "expires_at": "2027-01-31T23:59:59Z"
            }
          }
        ]
      }'
  done

  8c: Elena uses the delegated access

  # Step 2: Elena authenticates (normal login), then Victoria (or Elena) activates the delegation
  ELENA_SESSION=$(curl -s -X POST "$AUTH_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "elena.torres@externalaudit.com",
      "password": "ElenaSecure2026!"
    }')
  ELENA_TOKEN=$(echo "$ELENA_SESSION" | jq -r '.access_token')

  # Step 2b: Delegate — produces a scoped token for Elena acting on Victoria's behalf
  ELENA_DELEGATED=$(curl -s -X POST "$AUTH_URL/auth/delegate" \
    -H "Authorization: Bearer $VICTORIA_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "target_user_id": "'$ELENA_USER_ID'"
    }')
  ELENA_ACCESS_TOKEN=$(echo "$ELENA_DELEGATED" | jq -r '.access_token')

  # Elena calls the platform — she can read everything in scope
  curl -X GET "$PLATFORM_URL/portfolios/GGF-001/trades?from=2026-10-01&to=2026-12-31" \
    -H "Authorization: Bearer $ELENA_ACCESS_TOKEN"
  # Works: GGF-001, viewer tuple exists, delegation grant active, permissions match

  curl -X POST "$PLATFORM_URL/trades/TRD-9921/execute" \
    -H "Authorization: Bearer $ELENA_ACCESS_TOKEN"
  # 403: Elena has no apex.execute.trades in her delegation grant scope

  8d: Audit log shows everything Elena touched

  curl -X GET "$AUTH_URL/audit/logs?actor=$ELENA_USER_ID&org_id=$GGF_ORG_ID" \
    -H "Authorization: Bearer $PRIYA_TOKEN"

  # Returns every API call Elena made, with:
  # - timestamp
  # - endpoint called
  # - resource accessed (portfolio:GGF-001, account:ACC-4421, etc.)
  # - grant_id: "delg-q4-2026-abc123"
  # - result: allowed/denied

  8e: Revoke Elena's access when the audit is done

  # Option 1: Wait for expiry (set via expires_in_hours in the grant) — automatic
  # Option 2: Revoke immediately
  curl -X DELETE "$AUTH_URL/delegation/grant/$ELENA_USER_ID" \
    -H "Authorization: Bearer $VICTORIA_TOKEN"

  # Also clean up the Zanzibar tuples
  curl -X DELETE "$AUTH_URL/zanzibar/stores/$APEX_ORG_ID/relationships" \
    -H "Authorization: Bearer $VICTORIA_TOKEN" \
    -d '{
      "org_id": "'$GGF_ORG_ID'",
      "filter": {
        "subject": "user:'$ELENA_USER_ID'",
        "metadata.granted_by": "delegation:'$GRANT_ID'"
      }
    }'

  Elena's access is gone. Immediately. Completely.

  ---
  Step 9: Moving James Between Desks

  Three months in, James gets an offer: move to the Fixed Income desk and join the Bond Ladder Fund team. This is a real event at investment banks — desk transfers. The information
  barrier means you cannot leave his old access in place.

  Concept: The Transfer Problem
  If you just add James to Fixed Income without removing him from Equities, you've created an information barrier violation. James could see GGF trade data (equities, non-public) while
  working with BLF fixed income data. That's a FINRA violation. The transfer must be atomic: remove ALL equities access, add fixed income access, in the right order.

  9a: Remove James from GGF (Zanzibar tuples first)

  # Step 1: Remove all Zanzibar tuples for James in GGF
  curl -X DELETE "$AUTH_URL/zanzibar/stores/$APEX_ORG_ID/relationships" \
    -H "Authorization: Bearer $MARCUS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "org_id": "'$GGF_ORG_ID'",
      "filter": {
        "subject": "user:'$JAMES_USER_ID'"
      }
    }'

  # Returns: {"deleted": 4}
  # The 4 portfolio analyst tuples are gone.
  # James immediately loses access to GGF-001 through GGF-004.
  # Any in-flight API call from James to GGF portfolios now returns 403.

  9b: Remove James from the GGF org

  # Step 2: Remove org membership
  curl -X DELETE "$AUTH_URL/organizations/$GGF_ORG_ID/users/$JAMES_USER_ID" \
    -H "Authorization: Bearer $MARCUS_TOKEN"

  # James's tokens scoped to GGF are now invalid.
  # He cannot switch-org into GGF anymore.

  9c: Add James to Fixed Income and BLF

  # Sarah (Head of Fixed Income) invites James to BLF
  curl -X POST "$AUTH_URL/organizations/$BLF_ORG_ID/invite" \
    -H "Authorization: Bearer $SARAH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "james@apexcapital.com",
      "role": "member",
      "permissions": [
        "apex.read.portfolios", "apex.read.accounts", "apex.read.trades",
        "apex.create.trades", "apex.write.documents",
        "apex.write.positions"
      ],
      "message": "Welcome to Fixed Income, James. You are assigned to BLF."
    }'

  # James accepts, joins BLF. Now assign him to specific BLF portfolios via Zanzibar
  curl -X POST "$AUTH_URL/zanzibar/stores/$APEX_ORG_ID/relationships" \
    -H "Authorization: Bearer $SARAH_TOKEN" \
    -d '{
      "org_id": "'$BLF_ORG_ID'",
      "tuples": [
        {"object": "portfolio:BLF-001", "relation": "analyst", "subject": "user:'$JAMES_USER_ID'"},
        {"object": "portfolio:BLF-002", "relation": "analyst", "subject": "user:'$JAMES_USER_ID'"}
      ]
    }'

  James's state before and after:

  BEFORE:
  ├── GGF org: member (equities analyst)
  │   └── Zanzibar: analyst of GGF-001, GGF-002, GGF-003, GGF-004
  └── BLF org: not a member

  AFTER (transfer complete):
  ├── GGF org: NOT a member (removed)
  │   └── Zanzibar: zero tuples (all deleted)
  └── BLF org: member (fixed income analyst)
      └── Zanzibar: analyst of BLF-001, BLF-002

  9d: Verify no cross-contamination

  # Can James still read GGF-001? (He should NOT be able to)
  curl -X POST "$AUTH_URL/zanzibar/stores/$APEX_ORG_ID/check" \
    -G \
    --data-urlencode "org_id=$GGF_ORG_ID" \
    --data-urlencode "subject=user:$JAMES_USER_ID" \
    --data-urlencode "permission=read" \
    --data-urlencode "object=portfolio:GGF-001"

  # Returns: {"allowed": false}
  # Clean. No lingering access. Information barrier intact.

  # Can James read BLF-001? (He SHOULD be able to)
  curl -X POST "$AUTH_URL/zanzibar/stores/$APEX_ORG_ID/check" \
    -G \
    --data-urlencode "org_id=$BLF_ORG_ID" \
    --data-urlencode "subject=user:$JAMES_USER_ID" \
    --data-urlencode "permission=read" \
    --data-urlencode "object=portfolio:BLF-001"

  # Returns: {"allowed": true}

  The transfer took 3 API calls. The information barrier is intact. Compliance can verify it via the audit log and the Zanzibar expand endpoint.

  ---
  Step 10: Priya's Compliance View

  Priya (CCO) can see everything. Here's how she uses it.

  # Priya checks who has access to a sensitive portfolio
  curl -X POST "$AUTH_URL/zanzibar/stores/$APEX_ORG_ID/expand" \
    -H "Authorization: Bearer $PRIYA_TOKEN" \
    -G \
    --data-urlencode "org_id=$GGF_ORG_ID" \
    --data-urlencode "object=portfolio:GGF-001" \
    --data-urlencode "relation=analyst"

  # Returns everyone who has analyst-or-above access to GGF-001
  # Priya sees: james was removed on 2026-11-15, new analyst added same day

  # Priya runs a cross-org report via the reporting service
  curl -X GET "$REPORTING_URL/compliance/access-report?date=2026-11-15" \
    -H "X-API-Key: $REPORTING_API_KEY"
  # Reporting service uses its cross_tenant key to pull from all fund orgs
  # Returns: every access change across every division on that date

  # Priya investigates an unusual trade
  curl -X GET "$AUTH_URL/audit/logs?resource=trade:TRD-8821" \
    -H "Authorization: Bearer $PRIYA_TOKEN"
  # Returns: who touched this trade, when, from which IP, which token or API key

  ---
  Summary: The Complete Picture

  Apex Capital
  │
  │  Victoria (CIO) — ancestor access to all divisions and funds
  │  Priya (CCO)    — cross_tenant, reads everything for compliance
  │
  ├── Apex Equities (division org, information barrier)
  │   ├── Marcus (Head of Equities, admin)
  │   │
  │   ├── Global Growth Fund (GGF)
  │   │   ├── 12 portfolios, 40+ accounts
  │   │   ├── Zanzibar: each analyst assigned to their specific portfolios
  │   │   ├── Former: James (analyst, GGF-001..004) — TRANSFERRED OUT
  │   │   ├── Current analysts: assigned to their portfolios via Zanzibar tuples
  │   │   ├── Trading System API key (execute.trades, read.portfolios — GGF only)
  │   │   ├── Risk Engine API key (read.positions, write.risk_scores — GGF only)
  │   │   └── Elena Torres (viewer of ALL GGF portfolios, delegation grant, expires 2027-01-31)
  │   │
  │   └── Technology Fund (TF)
  │       └── TF analysts — CANNOT see GGF (sibling fund isolation)
  │
  ├── Apex Fixed Income (division org, information barrier)
  │   ├── Sarah (Head of Fixed Income, admin)
  │   │
  │   └── Bond Ladder Fund (BLF)
  │       ├── James (analyst, BLF-001..002) — JUST TRANSFERRED IN
  │       └── BLF analysts — CANNOT see Equities (division isolation)
  │
  └── Reporting Service API key (read.*, cross_tenant — all orgs)

  Zanzibar tuples (GGF org):
  ├── portfolio:GGF-001 #manager  user:marcus
  ├── portfolio:GGF-002 #manager  user:marcus
  ├── portfolio:GGF-001 #viewer   user:elena  (delegation, expires 2027-01-31)
  ├── account:ACC-4421  #parent_portfolio  portfolio:GGF-001
  └── ... (cascaded access flows automatically)

  Zanzibar tuples (BLF org):
  ├── portfolio:BLF-001 #analyst  user:james
  └── portfolio:BLF-002 #analyst  user:james

  Key security properties:
  - Information barriers between divisions: enforced by org isolation (not just policy)
  - Portfolio-level access within a fund: enforced by Zanzibar (not just "member of fund")
  - External auditor: time-limited delegation grant, full audit trail, instant revocable
  - Service API keys: least-privilege, no key can do more than it needs
  - Analyst transfer: atomic removal then addition, zero overlap, Zanzibar verified clean
  - Compliance: cross_tenant + Zanzibar expand + audit logs = complete visibility
  - Victoria: ancestor access without needing to be a member of every fund org

  The two-layer model at work:
  Layer 1 (org + permissions): "Is James an analyst who can use the platform?"
  Layer 2 (Zanzibar):          "Can James specifically read portfolio BLF-001 right now?"
  Both must pass. Org membership without a Zanzibar tuple = 403.
  A Zanzibar tuple without org membership = the check is never reached (403 at layer 1).
