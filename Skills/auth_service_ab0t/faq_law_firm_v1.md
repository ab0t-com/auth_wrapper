question: We are building "CaseVault" — a matter management and document system for law firms. We need every case to be a completely isolated workspace, paralegals who can
  only see documents on matters they have been explicitly assigned to, a client portal where clients see only their own documents, conflict-of-interest checks that block an
  attorney from accessing a matter if they already represent an adverse party, ethical walls between matters, and immediate revocation when an attorney withdraws from a case.
  Walk me through the full design with Zanzibar-style computed access, tuples, and how it all fits together.

● Legal is one of the most demanding auth designs for a different reason than government. Government is about clearance levels. Law is about relationships — who represents whom,
  who is adverse to whom, who touched which file. Access is not just permission-checked, it is relationship-computed. Every access decision answers: "is there a reason this person
  should NOT see this, even if they technically have the role?"

  The scenario: CaseVault — matter management for Meridian Law, a 40-attorney firm.

  The rules that govern everything:
  1. A matter is the unit of isolation. Every case is its own walled workspace.
  2. Assignment is the only path in. No attorney, paralegal, or staff member can access a matter unless explicitly assigned by a supervising partner.
  3. Paralegals are double-scoped: assigned to the matter AND to specific document categories within it.
  4. Clients see only their own documents. Not the internal strategy memos. Not billing records. Not the other clients on the matter.
  5. Conflict of interest is a structural check, not a policy reminder. If an attorney represents an adverse party anywhere in the system, the assignment is blocked.
  6. An ethical wall is total. Once erected, neither side can see the other's matters.
  7. Revocation is immediate and complete. Withdrawing from a matter removes all access before the next API call.

  ---
  Concept: Matters, Parties, and the Relationship Graph

  A legal matter has:
  - Matter name: "Acme Corp — Series B Financing"
  - Matter type: transactional, litigation, estate, etc.
  - Assigned attorneys: partners and associates working on it
  - Paralegals: support staff assigned to specific tasks
  - Clients: the people or entities the firm represents
  - Adverse parties: the other side (in litigation) or counterparties (in transactions)

  A conflict of interest exists when:
    Attorney A already represents Party X in Matter 1
    AND Party X is an adverse party or counterparty in Matter 2
    AND Attorney A is being considered for Matter 2

  The Zanzibar model lets us express this as computed relations:

    matter:acme_financing#attorney computed from:
      user is assigned(matter, attorney_role)
      AND NOT conflict_exists(user, matter.adverse_parties)
      AND NOT ethical_wall_exists(user, matter)

  The "NOT" conditions are the novel part for legal. Most auth systems add. Legal also subtracts.

  ---
  The Architecture

  CaseVault
  │
  ├── Meridian Law (firm org) ← all attorneys, staff, practice groups
  │
  ├── [MATTER ORG] Acme Corp — Series B         ← per-case hard wall
  ├── [MATTER ORG] Rivera v. Coastal (Lit.)     ← per-case hard wall
  ├── [MATTER ORG] Chen Estate Planning         ← per-case hard wall
  │
  ├── [CLIENT PORTAL ORG] Acme Corp             ← client sees their documents
  ├── [CLIENT PORTAL ORG] Rivera Family         ← client sees their documents
  │
  └── [ETHICAL WALL ORG] Wall: Acme/Coastal     ← separates conflicted groups

  ---
  Step 1: Define the Permission Schema

  casevault.permissions.json:

  {
    "service": "casevault",
    "description": "Legal matter management — Meridian Law",
    "actions": ["read", "write", "create", "delete", "share", "print", "download", "admin"],
    "resources": [
      "documents",
      "strategy_memos",
      "correspondence",
      "billing_records",
      "client_docs",
      "matter_metadata",
      "conflict_reports",
      "members",
      "audit_logs"
    ],
    "roles": {
      "casevault-paralegal": {
        "description": "Paralegal — reads and drafts documents on assigned matters only",
        "default_permissions": [
          "casevault.read.documents",
          "casevault.write.documents",
          "casevault.read.correspondence",
          "casevault.create.correspondence",
          "casevault.read.matter_metadata"
        ]
      },
      "casevault-associate": {
        "description": "Associate attorney — full document access on assigned matters",
        "implies": ["casevault-paralegal"],
        "default_permissions": [
          "casevault.read.strategy_memos",
          "casevault.write.strategy_memos",
          "casevault.create.documents",
          "casevault.download.documents",
          "casevault.read.billing_records"
        ]
      },
      "casevault-partner": {
        "description": "Partner — full matter access including billing and admin",
        "implies": ["casevault-associate"],
        "default_permissions": [
          "casevault.admin",
          "casevault.delete.documents",
          "casevault.write.billing_records",
          "casevault.write.members",
          "casevault.share.documents",
          "casevault.read.conflict_reports",
          "casevault.print.documents"
        ]
      },
      "casevault-client": {
        "description": "Client portal — client sees their own documents only",
        "default_permissions": [
          "casevault.read.client_docs",
          "casevault.read.correspondence",
          "casevault.read.matter_metadata"
        ]
      }
    }
  }

  Note what paralegals cannot do: read strategy_memos, read billing_records, delete, share, or print. Those are attorney-only. Within a matter, a paralegal and a partner both have access to the matter org — but they see different documents depending on their permissions. The org wall isolates matters from each other. The permission layer isolates document types within a matter.

  Register permissions:

  ./register-service-permissions.sh \
    --auth-url "$AUTH_URL" \
    --service-name "casevault" \
    --admin-email "it@meridianlaw.com" \
    --permissions-file casevault.permissions.json

  SERVICE_ORG_ID="casevault-service-org-uuid"
  SERVICE_API_KEY="ab0t_sk_live_..."

  ---
  Step 2: Create the Firm Org

  AUTH_URL="https://auth.service.ab0t.com"

  # Elena Cross — Managing Partner registers and creates the firm
  TOKEN=$(curl -s -X POST "$AUTH_URL/auth/register" \
    -d '{"email": "e.cross@meridianlaw.com", "password": "ManagingPartner2026!", "name": "Elena Cross"}' \
    | jq -r '.access_token')

  # Wait — she needs to log in to get a full token first
  TOKEN=$(curl -s -X POST "$AUTH_URL/auth/login" \
    -d '{"email": "e.cross@meridianlaw.com", "password": "ManagingPartner2026!"}' \
    | jq -r '.access_token')

  FIRM=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Meridian Law LLP",
      "slug": "meridian-law",
      "domain": "meridianlaw.com",
      "billing_type": "enterprise",
      "settings": {"type": "law_firm", "hierarchical": true},
      "metadata": {
        "bar_jurisdiction": "NY, CA, DC",
        "malpractice_carrier": "Lawyers Mutual",
        "conflicts_system": "casevault"
      }
    }')
  FIRM_ORG_ID=$(echo "$FIRM" | jq -r '.id')

  ELENA_TOKEN=$(curl -s -X POST "$AUTH_URL/auth/switch-organization" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"org_id": "'"$FIRM_ORG_ID"'"}' | jq -r '.access_token')

  # Invite core team to the firm org
  # Partners
  curl -X POST "$AUTH_URL/organizations/$FIRM_ORG_ID/invite" \
    -H "Authorization: Bearer $ELENA_TOKEN" \
    -d '{"email": "d.osei@meridianlaw.com", "role": "casevault-partner", "name": "David Osei"}'

  # Associates
  curl -X POST "$AUTH_URL/organizations/$FIRM_ORG_ID/invite" \
    -H "Authorization: Bearer $ELENA_TOKEN" \
    -d '{"email": "p.shah@meridianlaw.com", "role": "casevault-associate", "name": "Priya Shah"}'

  # Paralegals
  curl -X POST "$AUTH_URL/organizations/$FIRM_ORG_ID/invite" \
    -H "Authorization: Bearer $ELENA_TOKEN" \
    -d '{"email": "b.nakamura@meridianlaw.com", "role": "casevault-paralegal", "name": "Beth Nakamura"}'

  What just happened: Everyone is in the firm org. This is the "lobby" — they exist at Meridian Law. But being in the firm org gives them NO access to any matter. The firm org holds identity and firm-level settings. Every matter is a separate org. Nobody can read a document yet.

  Concept: The Lobby Pattern
  The firm org is the lobby. You know everyone who works here. But the meeting rooms (matters) are locked. You get a key (matter assignment) only when a partner explicitly gives you one. The lobby and the meeting rooms are different orgs.

  ---
  Step 3: Create a Matter Org

  Situation: Acme Corp hires Meridian for a Series B financing. David Osei (partner) is the lead attorney.

  # David creates the matter org
  ACME=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $DAVID_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Acme Corp — Series B Financing",
      "slug": "matter-acme-series-b",
      "parent_id": "'"$FIRM_ORG_ID"'",
      "billing_type": "enterprise",
      "settings": {
        "type": "matter",
        "matter_type": "transactional",
        "invitation_only": true
      },
      "metadata": {
        "matter_number": "2026-0441",
        "client": "Acme Corp",
        "adverse_parties": ["Sequoia Capital", "Andreessen Horowitz"],
        "opened_date": "2026-02-25",
        "lead_partner": "d.osei@meridianlaw.com",
        "billing_rate": 850,
        "status": "active"
      }
    }')
  ACME_MATTER_ID=$(echo "$ACME" | jq -r '.id')

  What just happened: A new isolated workspace exists for this matter. It is a child of Meridian Law (Elena as managing partner has ancestor access — she can see all matters). It has invitation_only: true — nobody can self-register. Every person added must be explicitly invited by a partner.

  Notice: adverse_parties is stored in metadata — ["Sequoia Capital", "Andreessen Horowitz"]. This is the conflict check index. When any attorney is proposed for this matter, the system will look up their existing client relationships and check for intersection.

  Assign David and Priya to the matter:

  # David (lead partner) adds himself
  curl -X POST "$AUTH_URL/organizations/$ACME_MATTER_ID/invite" \
    -H "Authorization: Bearer $DAVID_TOKEN" \
    -d '{
      "email": "d.osei@meridianlaw.com",
      "role": "casevault-partner",
      "message": "Lead partner — Acme Series B"
    }'

  # David adds Priya as the associate
  curl -X POST "$AUTH_URL/organizations/$ACME_MATTER_ID/invite" \
    -H "Authorization: Bearer $DAVID_TOKEN" \
    -d '{
      "email": "p.shah@meridianlaw.com",
      "role": "casevault-associate",
      "message": "Associate — corporate financing documents"
    }'

  The matter org now:

  Acme Corp — Series B Financing (matter org)
  ├── David Osei (partner — lead)
  ├── Priya Shah (associate)
  └── invitation_only: true
      adverse_parties: [Sequoia Capital, Andreessen Horowitz]

  Beth (paralegal), Elena (managing partner via ancestor access), and every other attorney at the firm cannot see inside this matter. Not because they lack a permission — because they are not in the org.

  ---
  Step 4: Zanzibar Tuples — Matter Access as Computed Relations

  Concept: Zanzibar Relationship Tuples
  In Google Zanzibar, access is modelled as a set of (object, relation, user) triples called tuples:

    matter:acme_series_b#attorney        @user:david.osei
    matter:acme_series_b#attorney        @user:priya.shah
    matter:acme_series_b#lead_partner    @user:david.osei
    matter:acme_series_b#client_rep      @user:john.chen (Acme CEO)

  Access to a document inside the matter is then COMPUTED from these tuples:

    document:acme_series_b_termsheet#reader computed from:
      user in matter:acme_series_b#attorney
      OR user in matter:acme_series_b#lead_partner

    document:acme_series_b_strategy#reader computed from:
      user in matter:acme_series_b#attorney    ← attorneys only
      NOT user in matter:acme_series_b#paralegal  ← not paralegals

  The beauty: you do not store "David can read the termsheet" and "Priya can read the termsheet" as two separate records. You store "David and Priya are attorneys on acme_series_b" and "attorneys can read documents in their matter." The document access is derived.

  Implement it in ClearPath as a two-layer check:

  app/access.py:

  from dataclasses import dataclass, field
  from typing import List, Optional
  from ab0t_auth import AuthenticatedUser
  from ab0t_auth.errors import PermissionDeniedError

  @dataclass
  class Matter:
      id: str
      org_id: str              # The matter's own org_id
      matter_number: str
      client: str
      adverse_parties: List[str]
      status: str              # "active" | "closed" | "suspended"

  @dataclass
  class CaseDocument:
      id: str
      matter_id: str
      org_id: str              # Same as matter's org_id
      doc_type: str            # "strategy_memo" | "correspondence" | "client_doc" | "billing"
      privilege: str           # "attorney_client" | "work_product" | "none"
      visible_to_client: bool  # Can client portal see this?

  def compute_document_access(user: AuthenticatedUser, doc: CaseDocument) -> tuple[bool, str]:
      """
      Zanzibar computed relation:

        can_read(user, document) :-
          user.org_id == document.org_id                           -- assigned to matter
          AND has_permission_for_doc_type(user, document.doc_type) -- role allows this type
          AND matter.status != "closed"                            -- matter still active
          AND NOT ethical_wall_blocks(user, document.matter_id)    -- no wall

      All conditions computed from stored facts. None stored as direct grants.
      """

      # Tuple check 1: Is the user assigned to this matter's org?
      if user.org_id != doc.org_id:
          return False, "not assigned to this matter"

      # Tuple check 2: Does the user's role allow this document type?
      doc_type_permission = {
          "strategy_memo":  "casevault.read.strategy_memos",
          "correspondence": "casevault.read.correspondence",
          "client_doc":     "casevault.read.client_docs",
          "billing":        "casevault.read.billing_records",
          "document":       "casevault.read.documents",
      }.get(doc.doc_type, "casevault.read.documents")

      if not user.has_permission(doc_type_permission):
          return False, f"role does not permit reading {doc.doc_type}"

      # Tuple check 3: Attorney-client privilege — work product not for clients
      if doc.privilege == "work_product" and user.has_permission("casevault.read.client_docs"):
          if not user.has_permission("casevault.read.strategy_memos"):
              return False, "work product is not visible to client portal"

      return True, "access granted"

  Use in routes:

  @router.get("/matters/{matter_id}/documents/{document_id}")
  async def read_document(matter_id: str, document_id: str, user: CaseVaultUser):
      doc = await db.get_document(document_id)
      if not doc or doc.matter_id != matter_id:
          raise HTTPException(404)

      allowed, reason = compute_document_access(user, doc)
      if not allowed:
          await audit_log.record(user, "read", doc, outcome="denied", reason=reason)
          raise HTTPException(403, detail="Access denied")

      await audit_log.record(user, "read", doc, outcome="granted")
      return doc

  ---
  Step 5: Paralegal Scoping — Double Assignment

  Paralegals are the most constrained users. They are assigned to a matter (Gate 1) and then further scoped to document categories within it (Gate 2).

  Situation: Beth (paralegal) is assigned to the Acme matter but only for correspondence drafting. She cannot read strategy memos or billing records.

  5a: Add Beth to the matter with paralegal role

  curl -X POST "$AUTH_URL/organizations/$ACME_MATTER_ID/invite" \
    -H "Authorization: Bearer $DAVID_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "b.nakamura@meridianlaw.com",
      "role": "casevault-paralegal",
      "permissions": [
        "casevault.read.documents",
        "casevault.write.documents",
        "casevault.read.correspondence",
        "casevault.create.correspondence"
      ],
      "message": "Assigned to Acme matter — correspondence and document prep only"
    }'

  5b: What Beth can and cannot access

  ┌──────────────────────────────┬─────────────────┬──────────────────────────────────────────┐
  │         Document Type        │   Beth Can See? │               Why                        │
  ├──────────────────────────────┼─────────────────┼──────────────────────────────────────────┤
  │ Term sheet (document)        │ YES             │ casevault.read.documents                 │
  ├──────────────────────────────┼─────────────────┼──────────────────────────────────────────┤
  │ Client email (correspondence)│ YES             │ casevault.read.correspondence            │
  ├──────────────────────────────┼─────────────────┼──────────────────────────────────────────┤
  │ Strategy memo                │ NO              │ no casevault.read.strategy_memos         │
  ├──────────────────────────────┼─────────────────┼──────────────────────────────────────────┤
  │ Invoice / billing record     │ NO              │ no casevault.read.billing_records        │
  ├──────────────────────────────┼─────────────────┼──────────────────────────────────────────┤
  │ ANY document in Rivera matter│ NO              │ not in Rivera matter org (Gate 1 fails)  │
  └──────────────────────────────┴─────────────────┴──────────────────────────────────────────┘

  5c: Listing documents from Beth's perspective

  async def list_documents_for_user(user: AuthenticatedUser, matter_id: str):
      """
      Zanzibar bulk check — return only documents the user can actually read.
      Build the access tuple from user permissions, query once.
      """

      # What document types is this user allowed to read?
      readable_types = []
      if user.has_permission("casevault.read.documents"):
          readable_types.append("document")
      if user.has_permission("casevault.read.strategy_memos"):
          readable_types.append("strategy_memo")
      if user.has_permission("casevault.read.correspondence"):
          readable_types.append("correspondence")
      if user.has_permission("casevault.read.billing_records"):
          readable_types.append("billing")
      if user.has_permission("casevault.read.client_docs"):
          readable_types.append("client_doc")

      # Single query — database returns only what this user's tuple allows
      return await db.query(
          "SELECT * FROM documents WHERE matter_id = :matter_id AND org_id = :org_id AND doc_type IN :readable_types",
          {"matter_id": matter_id, "org_id": user.org_id, "readable_types": readable_types}
      )

  Beth calls GET /matters/acme-series-b/documents. The query returns: term sheets, NDAs, correspondence. Strategy memos and billing records are filtered at the query level — they are not returned and then hidden. They do not exist in Beth's view of the matter.

  ---
  Step 6: Client Portal — Client Sees Only Their Documents

  Situation: Mr. Chen (Acme CEO) wants to review the documents Meridian has prepared for him. He should see correspondence, his own signed documents, and status updates. He must NOT see strategy memos, other clients' documents, or billing rates.

  6a: Create a client portal org for Acme

  CLIENT_PORTAL=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $DAVID_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Acme Corp — Client Portal",
      "slug": "client-acme-corp",
      "parent_id": "'"$FIRM_ORG_ID"'",
      "billing_type": "enterprise",
      "settings": {
        "type": "client_portal",
        "invitation_only": true,
        "linked_matter": "'"$ACME_MATTER_ID"'"
      },
      "metadata": {
        "client": "Acme Corp",
        "matter_number": "2026-0441"
      }
    }')
  CLIENT_PORTAL_ID=$(echo "$CLIENT_PORTAL" | jq -r '.id')

  6b: Configure the client login page (OAuth 2.1 — clients sign in with Google)

  curl -X PUT "$AUTH_URL/organizations/$CLIENT_PORTAL_ID/login-config" \
    -H "Authorization: Bearer $DAVID_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "branding": {
        "primary_color": "#1E3A5F",
        "page_title": "Meridian Law — Client Portal",
        "logo_url": "https://meridianlaw.com/logo.png",
        "login_template": "dark"
      },
      "content": {
        "welcome_message": "Meridian Law Client Portal",
        "signup_message": "Sign in to view your matter documents",
        "footer_message": "Privileged and Confidential — Attorney-Client Communication"
      },
      "auth_methods": {
        "email_password": false,
        "signup_enabled": false,
        "invitation_only": true
      }
    }'

  email_password: false — clients use Google only. signup_enabled: false — clients cannot self-register. A partner must send the invitation.

  6c: Invite Mr. Chen to the client portal

  curl -X POST "$AUTH_URL/organizations/$CLIENT_PORTAL_ID/invite" \
    -H "Authorization: Bearer $DAVID_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "j.chen@acmecorp.com",
      "role": "casevault-client",
      "permissions": [
        "casevault.read.client_docs",
        "casevault.read.correspondence",
        "casevault.read.matter_metadata"
      ],
      "message": "Welcome to your Meridian Law client portal — Series B matter documents"
    }'

  6d: Sharing documents to the client portal

  When David wants Mr. Chen to review a document, he explicitly flags it as client-visible:

  # David marks the executed NDA as visible to the client
  curl -X PATCH "$CASEVAULT_API/documents/$NDA_DOC_ID" \
    -H "Authorization: Bearer $DAVID_TOKEN" \
    -d '{
      "visible_to_client": true,
      "client_portal_org_id": "'"$CLIENT_PORTAL_ID"'",
      "shared_by": "d.osei@meridianlaw.com",
      "shared_at": "2026-02-25T14:00:00Z",
      "note": "Signed NDA — client copy"
    }'

  Mr. Chen logs into /login/client-acme-corp. He sees: the executed NDA, correspondence from David, status updates. He does not see: the strategy memo about negotiation tactics, the fee arrangement, Priya's internal notes. The compute_document_access function checks doc.visible_to_client — if false, the client's casevault.read.client_docs permission is irrelevant. The document does not appear in his listing.

  Concept: The Two-Layer Client Model
  Layer 1: The client portal is a separate org. Mr. Chen is not in the Acme matter org — he cannot browse matter files.
  Layer 2: Only documents explicitly shared (visible_to_client: true) appear in his portal. Even within the portal org, the document-level flag is a second gate.

  This matches attorney-client privilege rules: the attorney decides what to share with the client, not the other way around. The client cannot see un-shared documents even if they somehow got into the matter org.

  ---
  Step 7: Conflict of Interest Checks

  This is the most legally critical feature. An attorney who represents an adverse party on a different matter cannot work on this matter. The check must happen at assignment time, not discovery time.

  7a: Store client and adverse party relationships

  Every matter carries its relationship index in metadata:

  matter: Acme Corp — Series B
    metadata.client: "Acme Corp"
    metadata.adverse_parties: ["Sequoia Capital", "Andreessen Horowitz"]

  Every attorney needs a relationship index too — which clients do they currently represent:

  # When David is assigned to any matter, record the relationship
  # NOTE: current API takes query params. Full data model with metadata (store in your
  # matter management system or POST body when API is extended to support it):
  # { "user_id": "$DAVID_USER_ID", "org_id": "$FIRM_ORG_ID",
  #   "permission": "casevault.represents.acme_corp",
  #   "metadata": { "matter_id": "$ACME_MATTER_ID", "client_name": "Acme Corp",
  #                 "representation_type": "transactional", "started": "2026-02-25" } }
  curl -X POST "$AUTH_URL/permissions/grant?user_id=$DAVID_USER_ID&org_id=$FIRM_ORG_ID&permission=casevault.represents.acme_corp" \
    -H "Authorization: Bearer $ELENA_TOKEN"

  The permission casevault.represents.acme_corp is a dynamic, namespaced permission that records the relationship. It is queryable: "which permissions does David have that start with casevault.represents.?" gives you his full current client list.

  7b: The conflict check function

  app/conflicts.py:

  async def check_conflict_of_interest(
      attorney_user_id: str,
      target_matter: Matter,
      db,
      auth_client
  ) -> tuple[bool, list[str]]:
      """
      Zanzibar computed relation:

        conflict_free(attorney, matter) :-
          for all adverse_party in matter.adverse_parties:
            NOT represents(attorney, adverse_party)
          AND
          for all matter2 where represents(attorney, matter2.client):
            NOT adverse_party_in(matter.client, matter2)

      Returns (conflict_free: bool, conflicts: list of conflict descriptions)
      """

      conflicts = []

      # Fetch the attorney's current client relationships
      attorney_perms = await auth_client.get(
          f"/users/{attorney_user_id}/permissions",
          params={"prefix": "casevault.represents."}
      )
      # e.g., ["casevault.represents.acme_corp", "casevault.represents.tech_startup_llc"]

      current_clients = {
          p["permission"].replace("casevault.represents.", ""): p["metadata"]
          for p in attorney_perms
      }
      # e.g., {"acme_corp": {...}, "tech_startup_llc": {...}}

      # Check 1: Does the attorney represent any adverse party in the new matter?
      for adverse_party in target_matter.adverse_parties:
          party_key = slugify(adverse_party)  # "Sequoia Capital" -> "sequoia_capital"
          if party_key in current_clients:
              conflicts.append(
                  f"Direct conflict: {attorney_user_id} represents {adverse_party} "
                  f"(matter {current_clients[party_key]['matter_id']}), "
                  f"who is an adverse party in {target_matter.matter_number}"
              )

      # Check 2: Does any current client of the attorney appear as adverse in the new matter?
      for client_key, client_meta in current_clients.items():
          existing_matter = await db.get_matter(client_meta["matter_id"])
          if existing_matter and target_matter.client in existing_matter.adverse_parties:
              conflicts.append(
                  f"Reverse conflict: {target_matter.client} is adverse to "
                  f"{client_meta['client_name']} in matter {existing_matter.matter_number}"
              )

      return len(conflicts) == 0, conflicts

  7c: Enforce the check at assignment time

  @router.post("/matters/{matter_id}/members")
  async def assign_to_matter(matter_id: str, assignment: MatterAssignment, user: CaseVaultPartner):
      matter = await db.get_matter(matter_id)
      if not matter:
          raise HTTPException(404)

      # Run conflict check BEFORE creating the invitation
      conflict_free, conflicts = await check_conflict_of_interest(
          assignment.attorney_user_id,
          matter,
          db,
          auth_client
      )

      if not conflict_free:
          # Log the blocked assignment — this is an audit event
          await audit_log.record(
              actor=user,
              action="assignment_blocked",
              matter_id=matter_id,
              target_user_id=assignment.attorney_user_id,
              conflicts=conflicts
          )
          raise HTTPException(409, detail={
              "error": "conflict_of_interest",
              "message": "Assignment blocked due to conflict of interest",
              "conflicts": conflicts
          })

      # No conflict — proceed with invitation
      await auth_client.post(f"/organizations/{matter.org_id}/invite", json={
          "email": assignment.email,
          "role": assignment.role,
          "message": f"Assigned to {matter.matter_number} — conflict check passed"
      })

      # Record the new representation relationship
      # NOTE: current API takes query params. Store the full metadata in your matter
      # management system; POST body with metadata should be added to the API.
      # Full data model:
      # { "user_id": attorney_user_id, "org_id": FIRM_ORG_ID,
      #   "permission": f"casevault.represents.{client_slug}",
      #   "metadata": { "matter_id": matter_id, "client_name": matter.client,
      #                 "started": datetime.utcnow().isoformat() } }
      await auth_client.post(
          f"/permissions/grant?user_id={assignment.attorney_user_id}&org_id={FIRM_ORG_ID}&permission=casevault.represents.{slugify(matter.client)}"
      )

  Situation: Priya is offered as associate on a new matter — Rivera v. Coastal Logistics. The adverse party is Coastal Logistics. The system runs the conflict check:

  - Priya's current representations: ["acme_corp"] (from the Series B matter)
  - New matter adverse_parties: ["Coastal Logistics"]
  - Intersection: empty. Acme Corp is not Coastal Logistics.
  - Check 2: Is Coastal Logistics adverse to Acme Corp anywhere? No.
  - Result: conflict_free = True. Assignment proceeds.

  Situation: David is asked to take on a new matter — Sequoia Capital fund formation. The new client is Sequoia Capital. But Sequoia Capital is in the adverse_parties list for the Acme Series B matter, where David represents Acme.

  - David's current representations: ["acme_corp"]
  - New matter client: "Sequoia Capital"
  - Check 2: Is Sequoia Capital an adverse party in any matter where David represents the client?
  - Acme Series B: adverse_parties = ["Sequoia Capital"] — YES.
  - Result: conflict_free = False.
  - Conflict: "Reverse conflict: Sequoia Capital is adverse to Acme Corp in matter 2026-0441"
  - Assignment blocked. David is informed. Elena reviews.

  ---
  Step 8: Ethical Walls

  An ethical wall (also called a Chinese wall or screen) goes further than a conflict check. It is a structural barrier erected when a conflict is identified but the firm decides to represent both parties under certain conditions (with consent, or in different unrelated matters). The wall ensures neither side of the firm can access the other's matters.

  Situation: Meridian acquired a smaller firm. Two former colleagues now work on opposite sides of a dispute — Alex represents Rivera, Morgan represents Coastal. They must be structurally separated.

  8a: Create the ethical wall org

  # An ethical wall is its own org that defines who is on which side
  WALL=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $ELENA_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Ethical Wall — Rivera/Coastal",
      "slug": "wall-rivera-coastal",
      "parent_id": "'"$FIRM_ORG_ID"'",
      "settings": {"type": "ethical_wall"},
      "metadata": {
        "side_a": {
          "attorneys": ["a.reyes@meridianlaw.com"],
          "matters": ["'"$RIVERA_MATTER_ID"'"]
        },
        "side_b": {
          "attorneys": ["m.blake@meridianlaw.com"],
          "matters": ["'"$COASTAL_MATTER_ID"'"]
        },
        "erected_by": "e.cross@meridianlaw.com",
        "erected_date": "2026-02-25",
        "consent_obtained": true
      }
    }')
  WALL_ORG_ID=$(echo "$WALL" | jq -r '.id')

  8b: Enforce the wall in access computation

  app/access.py — add wall check to compute_document_access:

  async def ethical_wall_blocks(user_id: str, matter_id: str, db) -> tuple[bool, str]:
      """
      Check if an ethical wall prevents this user from accessing this matter.

      A wall blocks if:
        - The user is on Side A AND the matter is a Side B matter
        - The user is on Side B AND the matter is a Side A matter
      """

      walls = await db.get_active_walls_for_matter(matter_id)
      for wall in walls:
          metadata = wall["metadata"]
          user_email = await get_user_email(user_id)

          # Is user on Side A trying to access a Side B matter?
          if (user_email in metadata["side_a"]["attorneys"] and
              matter_id in metadata["side_b"]["matters"]):
              return True, f"Ethical wall {wall['slug']} blocks side A from side B matters"

          # Is user on Side B trying to access a Side A matter?
          if (user_email in metadata["side_b"]["attorneys"] and
              matter_id in metadata["side_a"]["matters"]):
              return True, f"Ethical wall {wall['slug']} blocks side B from side A matters"

      return False, ""

  # Updated compute_document_access:
  async def compute_document_access(user: AuthenticatedUser, doc: CaseDocument, db) -> tuple[bool, str]:
      # Gate 1: Org membership
      if user.org_id != doc.org_id:
          return False, "not assigned to this matter"

      # Gate 2: Ethical wall check — BEFORE permission check
      wall_blocks, wall_reason = await ethical_wall_blocks(user.user_id, doc.matter_id, db)
      if wall_blocks:
          return False, wall_reason

      # Gate 3: Document type permission
      doc_type_permission = get_permission_for_doc_type(doc.doc_type)
      if not user.has_permission(doc_type_permission):
          return False, f"role does not permit reading {doc.doc_type}"

      # Gate 4: Privilege check for client portal users
      if doc.privilege == "work_product":
          if user.has_permission("casevault.read.client_docs") and \
             not user.has_permission("casevault.read.strategy_memos"):
              return False, "work product not visible to client"

      return True, "access granted"

  What this means for Alex and Morgan:

  Alex tries to read a Coastal matter document:
    Gate 1: Org check — Alex is NOT in the Coastal matter org. DENIED. Wall check never even runs.

  Morgan tries to read a Rivera matter document:
    Gate 1: Org check — Morgan IS in the Rivera matter org (assigned before the wall).
    Gate 2: Wall check — wall blocks side B (Morgan) from side A (Rivera) matters. DENIED.
    Morgan loses access immediately. The wall is retroactive.

  Concept: Why the Wall Is Retroactive
  When you add Morgan to the wall's Side B, compute_document_access now returns DENIED for all Rivera documents even though Morgan is still in the Rivera matter org. The org membership is not removed — the wall computation overrides it. This is intentional: you want an audit trail showing Morgan was on the matter and was walled off, not just silently removed.

  ---
  Step 9: Closing a Matter and Transferring Personnel

  9a: Attorney withdraws from a matter

  Situation: Priya is leaving the Acme matter — she's being moved to Rivera litigation full-time.

  # Remove Priya from the Acme matter org
  curl -X DELETE "$AUTH_URL/organizations/$ACME_MATTER_ID/members/$PRIYA_USER_ID" \
    -H "Authorization: Bearer $DAVID_TOKEN"

  # Revoke the client representation record
  curl -X DELETE "$AUTH_URL/permissions/revoke" \
    -H "Authorization: Bearer $ELENA_TOKEN" \
    -d '{
      "user_id": "'"$PRIYA_USER_ID"'",
      "org_id": "'"$FIRM_ORG_ID"'",
      "permission": "casevault.represents.acme_corp"
    }'

  # Terminate active sessions for Priya in the Acme matter context
  curl -X DELETE "$AUTH_URL/organizations/$ACME_MATTER_ID/users/$PRIYA_USER_ID/sessions" \
    -H "Authorization: Bearer $DAVID_TOKEN"

  Priya's next request to any Acme document returns 403. She can now be assigned to Rivera without an Acme conflict in the relationship graph.

  9b: Closing a matter

  The Acme Series B closes successfully. The matter is archived.

  # Suspend the matter org — all access frozen
  curl -X PUT "$AUTH_URL/organizations/$ACME_MATTER_ID" \
    -H "Authorization: Bearer $ELENA_TOKEN" \
    -d '{"status": "suspended", "metadata": {"closed_date": "2026-09-01", "outcome": "success"}}'

  # Revoke the representation records for all attorneys
  # (They no longer actively represent Acme — though they did)
  for attorney_id in $DAVID_ID $PRIYA_ID; do
    curl -X DELETE "$AUTH_URL/permissions/revoke" \
      -H "Authorization: Bearer $ELENA_TOKEN" \
      -d '{
        "user_id": "'"$attorney_id"'",
        "org_id": "'"$FIRM_ORG_ID"'",
        "permission": "casevault.represents.acme_corp",
        "metadata": {"revoked_reason": "matter_closed", "closed_date": "2026-09-01"}
      }'
  done

  # The client portal also suspends — Mr. Chen can no longer log in
  curl -X PUT "$AUTH_URL/organizations/$CLIENT_PORTAL_ID" \
    -H "Authorization: Bearer $ELENA_TOKEN" \
    -d '{"status": "suspended"}'

  What just happened: The matter org is suspended. All API calls to matter-scoped resources return 403. The representation records are revoked. David and Priya are now free to take on matters where Acme Corp is an adverse party (because they no longer represent them). The documents are preserved in cold storage — you can reopen the org if needed. The audit trail is permanent.

  ---
  Step 10: Service Accounts — Automated Pipelines

  CaseVault runs background services: a document ingestion pipeline (email-to-matter), a billing time-entry aggregator, and a court filing connector.

  10a: Document ingestion service

  # Reads incoming emails, routes attachments to correct matter
  INGESTOR=$(curl -s -X POST "$AUTH_URL/admin/users/create-service-account" \
    -H "Authorization: Bearer $ELENA_TOKEN" \
    -d '{
      "email": "doc-ingestor@workers.casevault.internal",
      "name": "CaseVault Document Ingestor",
      "org_id": "'"$SERVICE_ORG_ID"'",
      "permissions": [
        "casevault.create.documents",
        "casevault.write.documents",
        "casevault.read.matter_metadata"
      ],
      "metadata": {
        "worker_type": "email_ingestor",
        "cross_matter_access": true,
        "justification": "Ingestor must write to any active matter by matter number"
      }
    }')
  INGESTOR_API_KEY=$(echo "$INGESTOR" | jq -r '.api_key')

  The ingestor has casevault.read.matter_metadata — it looks up the matter number from the email subject line. It has casevault.create.documents — it writes the attachment to the correct matter org. It does NOT have casevault.read.documents — it is write-only. It cannot read back documents it ingested. Least privilege.

  10b: Conflict check service — used at new matter intake

  # The intake system runs conflict checks for new client enquiries
  CONFLICT_SVC=$(curl -s -X POST "$AUTH_URL/admin/users/create-service-account" \
    -H "Authorization: Bearer $ELENA_TOKEN" \
    -d '{
      "email": "conflict-checker@workers.casevault.internal",
      "name": "CaseVault Conflict Checker",
      "org_id": "'"$SERVICE_ORG_ID"'",
      "permissions": [
        "casevault.read.conflict_reports",
        "casevault.read.matter_metadata"
      ]
    }')
  CONFLICT_API_KEY=$(echo "$CONFLICT_SVC" | jq -r '.api_key')

  The conflict checker can read matter metadata (including adverse_parties lists) and conflict reports. It cannot read documents. It runs the check_conflict_of_interest function, produces a report, and returns it to the intake attorney. It never persists anything — read-only, ephemeral results.

  ---
  The Full Picture

  CaseVault Authorization System
  │
  ├── Meridian Law LLP (firm org)
  │   ├── Elena Cross (managing partner, ancestor access to all matters)
  │   ├── David Osei (partner)    represents: [acme_corp (closed)]
  │   ├── Priya Shah (associate)  represents: [rivera_family]
  │   ├── Beth Nakamura (paralegal) — no representation records
  │   ├── Alex Reyes (associate)  represents: [rivera_family] | ethical wall side A
  │   └── Morgan Blake (associate) represents: [] | ethical wall side B
  │
  ├── CaseVault Service
  │   ├── [Svc Acct] doc-ingestor    — create/write documents, cross-matter
  │   ├── [Svc Acct] conflict-checker — read matter metadata and conflict reports
  │   └── [Svc Acct] billing-agg     — read/write billing records only
  │
  ├── [MATTER ORG] Acme Corp — Series B (CLOSED — suspended)
  │   ├── David Osei (partner) — was lead
  │   ├── Priya Shah (associate) — transferred out mid-matter
  │   └── Beth Nakamura (paralegal) — correspondence only
  │
  ├── [MATTER ORG] Rivera v. Coastal (ACTIVE)
  │   ├── Priya Shah (associate — lead) | Alex Reyes (associate)
  │   └── Ethical wall side A
  │
  ├── [MATTER ORG] Coastal Logistics Defence (ACTIVE)
  │   ├── Morgan Blake (associate)
  │   └── Ethical wall side B
  │
  ├── [CLIENT PORTAL ORG] Acme Corp — Mr. Chen (SUSPENDED — matter closed)
  └── [CLIENT PORTAL ORG] Rivera Family — Mrs. Rivera (ACTIVE, Google login)

  The Zanzibar tuple set that drives every access decision:

  matter:acme_series_b#attorney      @user:david.osei       (REVOKED — matter closed)
  matter:acme_series_b#attorney      @user:priya.shah       (REVOKED — transferred)
  matter:acme_series_b#paralegal     @user:beth.nakamura    (REVOKED — matter closed)
  matter:acme_series_b#client        @user:john.chen        (REVOKED — matter closed)

  matter:rivera_v_coastal#attorney   @user:priya.shah       (ACTIVE)
  matter:rivera_v_coastal#attorney   @user:alex.reyes       (ACTIVE — wall side A)

  matter:coastal_defence#attorney    @user:morgan.blake     (ACTIVE — wall side B)

  wall:rivera_coastal#side_a         @user:alex.reyes
  wall:rivera_coastal#side_b         @user:morgan.blake

  represents:acme_corp               @user:david.osei       (REVOKED — matter closed)
  represents:rivera_family           @user:priya.shah       (ACTIVE)

  Every access decision is computed from this tuple set. No stored per-document grants. No access control lists per file. Change one tuple — revoke a representation, close a matter, erect a wall — and every access decision derived from that tuple changes instantly, everywhere, for every document in every matter it touches.
