question: We are building a classified document management system for a government intelligence agency. We need clearance levels (Unclassified through TS/SCI), need-to-know
  compartments so that even TS-cleared analysts can only read documents in their assigned programs, Zanzibar-style computed relations so that access is derived from clearance
  AND compartment AND org membership, audit trails on every access, automatic revocation when someone leaves a program, and service accounts for our automated processing
  pipeline. Walk me through the full design.

● This is one of the more demanding auth designs you can build. Let us go through it carefully.

  The scenario: "ClearPath" — a classified document management system for the National Intelligence Coordination Agency (NICA).

  The rules that govern everything:
  1. Clearance is necessary but not sufficient. A TS-cleared analyst cannot read a TS document unless they also have need-to-know for that specific program.
  2. Classification is hierarchical: TS/SCI dominates Top Secret dominates Secret dominates Confidential. If you can read TS/SCI you can read Secret. Not the other way.
  3. Compartments are non-hierarchical. Having AETHER clearance does not give you PRISM. Each compartment is a separate gate.
  4. Access is computed from the intersection: clearance level AND all required compartments AND org membership. All three must be satisfied simultaneously.
  5. Every access attempt — read, write, failed, denied — is logged with identity, timestamp, document classification, and compartment.
  6. Revocation is immediate. When an analyst leaves a program, they lose access before they can reach the door.

  ---
  Concept: The Three-Gate Model

  Think of classified document access as three gates you must pass in sequence:

  Gate 1 — Clearance Level
  "Are you cleared to handle this classification?"
  Unclassified < CUI < Confidential < Secret < Top Secret < TS/SCI
  Hierarchical: TS implies Secret implies Confidential. A TS-cleared person can read Secret automatically.

  Gate 2 — Compartment
  "Do you have need-to-know for this specific program?"
  AETHER, PRISM, IRONWALL, VERIDIAN — each is a separate gate.
  Non-hierarchical: AETHER does not imply PRISM. Each requires explicit assignment.
  Even the Director cannot read AETHER documents without an explicit AETHER assignment.

  Gate 3 — Org Membership
  "Are you assigned to the directorate that owns this document?"
  The Directorate of Intelligence cannot read Directorate of Operations documents
  even if clearance and compartment match. The org boundary is the physical wall.

  All three must pass. Fail any one and the document is inaccessible.

  ---
  The Architecture

  ClearPath
  │
  ├── NICA Platform Org        ← your engineering team, the system itself
  ├── ClearPath Service        ← permission definitions, audit API keys
  │
  ├── NICA (parent org)        ← agency-wide, ancestor access for Director
  │   ├── [CHILD ORG] DI       ← Directorate of Intelligence, hard wall
  │   ├── [CHILD ORG] DO       ← Directorate of Operations, hard wall
  │   ├── [CHILD ORG] DS&T     ← Directorate of Science & Technology
  │   │
  │   ├── [COMPARTMENT ORG] AETHER   ← cross-directorate, need-to-know only
  │   └── [COMPARTMENT ORG] PRISM    ← cross-directorate, need-to-know only

  Why compartments are also orgs: a compartment like AETHER spans multiple directorates. An analyst in DI and an analyst in DO can both be on AETHER. Org membership is the mechanism that puts them in the same walled space. The compartment permission (Gate 2) ensures they were explicitly assigned — they did not accidentally drift in.

  ---
  Step 1: Define the Permission Schema

  This is the most important design decision. Model both clearance levels and compartments as permissions.

  clearpath.permissions.json:

  {
    "service": "clearpath",
    "description": "Classified document management — NICA",
    "actions": ["read", "write", "create", "delete", "declassify", "share", "audit", "admin"],
    "resources": [
      "documents",
      "folders",
      "attachments",
      "versions",
      "audit_logs",
      "members",
      "settings"
    ],
    "clearance_levels": {
      "clearpath.clearance.unclassified":  "Level 0 — public documents",
      "clearpath.clearance.cui":           "Level 1 — Controlled Unclassified",
      "clearpath.clearance.confidential":  "Level 2 — Confidential",
      "clearpath.clearance.secret":        "Level 3 — Secret",
      "clearpath.clearance.top_secret":    "Level 4 — Top Secret",
      "clearpath.clearance.ts_sci":        "Level 5 — TS/SCI"
    },
    "compartments": {
      "clearpath.compartment.aether":    "Project AETHER — signals collection",
      "clearpath.compartment.prism":     "Project PRISM — human intelligence",
      "clearpath.compartment.ironwall":  "Project IRONWALL — infrastructure protection",
      "clearpath.compartment.veridian":  "Project VERIDIAN — foreign liaison"
    },
    "roles": {
      "clearpath-analyst": {
        "description": "Analyst — can read and annotate documents within granted clearance",
        "default_permissions": [
          "clearpath.read.documents",
          "clearpath.read.folders",
          "clearpath.write.documents",
          "clearpath.read.versions"
        ]
      },
      "clearpath-author": {
        "description": "Can create and classify documents",
        "implies": ["clearpath-analyst"],
        "default_permissions": [
          "clearpath.create.documents",
          "clearpath.create.folders",
          "clearpath.write.folders"
        ]
      },
      "clearpath-reviewer": {
        "description": "Declassification review — can propose downgrade",
        "implies": ["clearpath-author"],
        "default_permissions": [
          "clearpath.declassify.documents"
        ]
      },
      "clearpath-admin": {
        "description": "System admin — manage members, settings",
        "implies": ["clearpath-reviewer"],
        "default_permissions": [
          "clearpath.admin",
          "clearpath.delete.documents",
          "clearpath.write.members",
          "clearpath.read.audit_logs"
        ]
      }
    }
  }

  Concept: Clearance as a Permission
  Clearance level is modelled as a permission string: clearpath.clearance.secret.
  When document metadata says classification: "secret", your code checks user.has_permission("clearpath.clearance.secret").
  The hierarchical dominance (TS implies Secret) is implemented via role inheritance — the ts_sci role implies top_secret which implies secret. More on this in Step 5.

  Concept: Compartment as a Permission
  Each compartment is also a permission: clearpath.compartment.aether.
  Compartments do NOT use role inheritance — there is no "implies" chain between them. AETHER does not imply PRISM. Each must be granted explicitly by a cleared administrator.
  A person can have clearpath.clearance.ts_sci without having any compartment. They can read unclassified TS/SCI documents but not any compartmented ones.

  Register permissions:

  ./register-service-permissions.sh \
    --auth-url "$AUTH_URL" \
    --service-name "clearpath" \
    --admin-email "isso@nica.gov" \
    --permissions-file clearpath.permissions.json

  SERVICE_ORG_ID="clearpath-service-org-uuid"
  SERVICE_API_KEY="ab0t_sk_live_..."

  ---
  Step 2: Create the Agency Org Structure

  AUTH_URL="https://auth.service.ab0t.com"

  # Dr. Rachel Torres (ISSO) registers and logs in
  curl -X POST "$AUTH_URL/auth/register" \
    -d '{"email": "r.torres@nica.gov", "password": "ISSOMandatoryRotation90!", "name": "Dr. Rachel Torres"}'

  TOKEN=$(curl -s -X POST "$AUTH_URL/auth/login" \
    -d '{"email": "r.torres@nica.gov", "password": "ISSOMandatoryRotation90!"}' \
    | jq -r '.access_token')

  # Parent org — the whole agency
  NICA=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "National Intelligence Coordination Agency",
      "slug": "nica",
      "domain": "nica.gov",
      "billing_type": "enterprise",
      "settings": {"type": "government_agency", "hierarchical": true, "classification_enabled": true},
      "metadata": {"accreditation": "ATO-2026-001", "issm": "r.torres@nica.gov"}
    }')
  NICA_ORG_ID=$(echo "$NICA" | jq -r '.id')

  RACHEL_TOKEN=$(curl -s -X POST "$AUTH_URL/auth/switch-organization" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"org_id": "'"$NICA_ORG_ID"'"}' | jq -r '.access_token')

  # Directorate of Intelligence — hard wall
  DI=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $RACHEL_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Directorate of Intelligence",
      "slug": "nica-di",
      "parent_id": "'"$NICA_ORG_ID"'",
      "billing_type": "enterprise",
      "settings": {"type": "directorate", "hierarchical": false},
      "metadata": {"director": "j.kim@nica.gov", "classification_ceiling": "TS/SCI"}
    }')
  DI_ORG_ID=$(echo "$DI" | jq -r '.id')

  # Directorate of Operations — hard wall, higher sensitivity
  DO=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $RACHEL_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Directorate of Operations",
      "slug": "nica-do",
      "parent_id": "'"$NICA_ORG_ID"'",
      "billing_type": "enterprise",
      "settings": {"type": "directorate", "hierarchical": false},
      "metadata": {"director": "m.voss@nica.gov", "classification_ceiling": "TS/SCI"}
    }')
  DO_ORG_ID=$(echo "$DO" | jq -r '.id')

  # Directorate of Science & Technology
  DST=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $RACHEL_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Directorate of Science and Technology",
      "slug": "nica-dst",
      "parent_id": "'"$NICA_ORG_ID"'",
      "billing_type": "enterprise",
      "settings": {"type": "directorate"},
      "metadata": {"director": "a.chen@nica.gov"}
    }')
  DST_ORG_ID=$(echo "$DST" | jq -r '.id')

  What just happened:

  National Intelligence Coordination Agency (parent)
  ├── Rachel Torres (ISSO, owner) ← ancestor access — sees all directorates
  │
  ├── [CHILD ORG] Directorate of Intelligence  ← hard wall
  ├── [CHILD ORG] Directorate of Operations    ← hard wall
  └── [CHILD ORG] Directorate of S&T           ← hard wall

  DI cannot see DO. DO cannot see DI. Even if a DI analyst guesses a DO document ID and makes the API call, the org boundary check rejects it before any permission check runs.

  ---
  Step 3: Create Compartment Orgs

  Compartments span directorates. An AETHER analyst could be from DI or DO. The compartment org holds them together in an isolated space that cuts across the directorate walls.

  # Project AETHER — signals collection, cross-directorate
  AETHER=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $RACHEL_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Project AETHER",
      "slug": "nica-aether",
      "parent_id": "'"$NICA_ORG_ID"'",
      "billing_type": "enterprise",
      "settings": {
        "type": "compartment",
        "hierarchical": false,
        "classification_floor": "top_secret",
        "invitation_only": true
      },
      "metadata": {
        "compartment_code": "AETHER",
        "program_manager": "l.santos@nica.gov",
        "access_requires": ["clearpath.clearance.top_secret", "clearpath.compartment.aether"]
      }
    }')
  AETHER_ORG_ID=$(echo "$AETHER" | jq -r '.id')

  # Project PRISM — human intelligence, restricted
  PRISM=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $RACHEL_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Project PRISM",
      "slug": "nica-prism",
      "parent_id": "'"$NICA_ORG_ID"'",
      "billing_type": "enterprise",
      "settings": {
        "type": "compartment",
        "hierarchical": false,
        "classification_floor": "ts_sci",
        "invitation_only": true
      },
      "metadata": {
        "compartment_code": "PRISM",
        "access_requires": ["clearpath.clearance.ts_sci", "clearpath.compartment.prism"]
      }
    }')
  PRISM_ORG_ID=$(echo "$PRISM" | jq -r '.id')

  The full structure:

  NICA (parent, ancestor access for Director + Rachel)
  │
  ├── [CHILD ORG] DI     ← directorate hard wall
  ├── [CHILD ORG] DO     ← directorate hard wall
  ├── [CHILD ORG] DS&T   ← directorate hard wall
  │
  ├── [COMPARTMENT ORG] AETHER   ← cross-cutting, invitation_only, floor: TS
  └── [COMPARTMENT ORG] PRISM    ← cross-cutting, invitation_only, floor: TS/SCI

  Concept: Compartment Orgs Are NOT Sub-Orgs of Directorates
  AETHER is a child of NICA (the agency), not of DI or DO. This means:
  - DI cannot see into AETHER even though some AETHER members are in DI
  - DO cannot see into AETHER even though some AETHER members are in DO
  - Only the Director (Rachel, ancestor of NICA) can see into AETHER
  - An AETHER member from DI can switch context to AETHER to access AETHER documents,
    then switch back to DI to access DI documents. The two namespaces never bleed.

  ---
  Step 4: Grant Clearances to Personnel

  Adding someone to an org gives them org membership (Gate 3). Granting clearance permissions gives them clearance level (Gate 1). Granting compartment permissions gives them need-to-know (Gate 2). All three are separate actions.

  Situation: Marcus Webb (DI analyst) gets a Top Secret clearance.

  # Invite Marcus to the DI org first (Gate 3 — org membership)
  curl -X POST "$AUTH_URL/organizations/$DI_ORG_ID/invite" \
    -H "Authorization: Bearer $RACHEL_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "m.webb@nica.gov",
      "role": "clearpath-analyst",
      "message": "DI onboarding — clearance to be granted separately"
    }'
  MARCUS_USER_ID="marcus-uuid"

  # Grant clearance level (Gate 1) — this is a separate admin action, not part of invitation
  # Only Rachel (ISSO) or a designated Security Officer can do this
  curl -X POST "$AUTH_URL/permissions/grant?user_id=$MARCUS_USER_ID&org_id=$DI_ORG_ID&permission=clearpath.clearance.top_secret" \
    -H "Authorization: Bearer $RACHEL_TOKEN"

  What just happened: Marcus is in DI (Gate 3) and has Top Secret clearance (Gate 1). He has NO compartments yet (Gate 2). He can read TS documents in DI that are NOT compartmented. He cannot read AETHER documents. He cannot read any PRISM documents (requires TS/SCI AND PRISM compartment).

  Concept: Why Clearance Is Separate from Invitation
  Invitation = "you work here." Clearance = "you have been investigated and adjudicated." These are separate real-world processes with separate approval chains. The security officer (Rachel) has to sign off on clearance grants. The directorate admin can handle org invitations without security clearance authority. Separating them means a compromised directorate admin cannot self-grant clearances.

  Grant clearances to the team:

  # Dr. Yuki Tanaka — DI senior analyst, TS/SCI
  curl -X POST "$AUTH_URL/permissions/grant?user_id=$YUKI_ID&org_id=$DI_ORG_ID&permission=clearpath.clearance.ts_sci" \
    -H "Authorization: Bearer $RACHEL_TOKEN"

  # Agent Dana Reeves — DO operations officer, TS/SCI
  curl -X POST "$AUTH_URL/permissions/grant?user_id=$DANA_ID&org_id=$DO_ORG_ID&permission=clearpath.clearance.ts_sci" \
    -H "Authorization: Bearer $RACHEL_TOKEN"

  # Intern Sam Park — DI intern, Secret clearance only
  curl -X POST "$AUTH_URL/permissions/grant?user_id=$SAM_ID&org_id=$DI_ORG_ID&permission=clearpath.clearance.secret" \
    -H "Authorization: Bearer $RACHEL_TOKEN"

  Clearance summary so far:

  ┌───────────────┬──────────┬───────────────────────────┬────────────────┐
  │     Person    │    Org   │      Clearance Level       │  Compartments  │
  ├───────────────┼──────────┼───────────────────────────┼────────────────┤
  │ Marcus Webb   │ DI       │ Top Secret                 │ none yet       │
  ├───────────────┼──────────┼───────────────────────────┼────────────────┤
  │ Dr. Yuki      │ DI       │ TS/SCI                    │ none yet       │
  ├───────────────┼──────────┼───────────────────────────┼────────────────┤
  │ Agent Dana    │ DO       │ TS/SCI                    │ none yet       │
  ├───────────────┼──────────┼───────────────────────────┼────────────────┤
  │ Sam Park      │ DI       │ Secret                    │ none yet       │
  └───────────────┴──────────┴───────────────────────────┴────────────────┘

  ---
  Step 5: Zanzibar Computed Relations — Clearance Hierarchy

  This is where it gets interesting. The classification hierarchy (TS implies Secret) must be implemented as computed relations, not as stored grants for each level.

  Concept: Google Zanzibar Computed Relations
  Zanzibar (the authorization system behind Google Drive, Docs, Calendar) introduced the idea that access is not a stored yes/no — it is computed from a graph of relations.

  In Zanzibar terms:
    document:aether-report-001#viewer computed from:
      user.has_permission("clearpath.clearance.top_secret")
      AND user.has_permission("clearpath.compartment.aether")
      AND user.org_id in document.allowed_orgs

  The "computed from" part is the key. You do not store "Yuki can read aether-report-001." You compute it at query time from the graph of facts: Yuki's clearance, Yuki's compartments, the document's classification, the document's compartments, and the org membership.

  This means when Yuki's AETHER compartment is revoked, ALL AETHER documents become inaccessible instantly — you do not need to find and delete every individual access record.

  5a: Model clearance hierarchy via role implication

  Register clearance roles that encode the hierarchy:

  # These are pseudo-roles that encode "if you have this, you also have lower levels"
  # Register them via the permissions API

  curl -X POST "$AUTH_URL/permissions/roles/define" \
    -H "X-API-Key: $SERVICE_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{
      "service": "clearpath",
      "role": "cleared-ts-sci",
      "description": "TS/SCI clearance — implies all lower levels",
      "permissions": ["clearpath.clearance.ts_sci"],
      "implies_permissions": [
        "clearpath.clearance.top_secret",
        "clearpath.clearance.secret",
        "clearpath.clearance.confidential",
        "clearpath.clearance.cui",
        "clearpath.clearance.unclassified"
      ]
    }'

  curl -X POST "$AUTH_URL/permissions/roles/define" \
    -H "X-API-Key: $SERVICE_API_KEY" \
    -d '{
      "service": "clearpath",
      "role": "cleared-top-secret",
      "description": "Top Secret clearance — implies Secret and below",
      "permissions": ["clearpath.clearance.top_secret"],
      "implies_permissions": [
        "clearpath.clearance.secret",
        "clearpath.clearance.confidential",
        "clearpath.clearance.cui",
        "clearpath.clearance.unclassified"
      ]
    }'

  curl -X POST "$AUTH_URL/permissions/roles/define" \
    -H "X-API-Key: $SERVICE_API_KEY" \
    -d '{
      "service": "clearpath",
      "role": "cleared-secret",
      "description": "Secret clearance — implies Confidential and below",
      "permissions": ["clearpath.clearance.secret"],
      "implies_permissions": [
        "clearpath.clearance.confidential",
        "clearpath.clearance.cui",
        "clearpath.clearance.unclassified"
      ]
    }'

  Now when Rachel grants Marcus clearpath.clearance.top_secret, he automatically and computedly has clearpath.clearance.secret, clearpath.clearance.confidential, etc. She only grants one permission. The system resolves the rest.

  Dominance graph:

  clearpath.clearance.ts_sci
    └── implies clearpath.clearance.top_secret
          └── implies clearpath.clearance.secret
                └── implies clearpath.clearance.confidential
                      └── implies clearpath.clearance.cui
                            └── implies clearpath.clearance.unclassified

  Marcus (Top Secret) can read: Top Secret, Secret, Confidential, CUI, Unclassified
  Marcus (Top Secret) cannot read: TS/SCI

  Yuki (TS/SCI) can read: everything
  Sam (Secret) can read: Secret, Confidential, CUI, Unclassified

  This is computed. Not stored. If Sam's clearance is upgraded to TS later, you change one permission grant. All access resolves correctly from that moment forward.

  5b: Implement Zanzibar relations in ClearPath (app/access.py)

  from ab0t_auth import AuthenticatedUser
  from dataclasses import dataclass
  from typing import List

  @dataclass
  class ClassifiedDocument:
      id: str
      org_id: str
      classification: str          # "unclassified" | "secret" | "top_secret" | "ts_sci" | ...
      compartments: List[str]      # ["aether"] or [] or ["aether", "prism"]
      title: str
      content_url: str

  def compute_document_access(user: AuthenticatedUser, doc: ClassifiedDocument) -> tuple[bool, str]:
      """
      Zanzibar computed relation:
        can_read(user, document) :-
          has_clearance(user, document.classification)     -- Gate 1
          AND has_all_compartments(user, document.compartments)  -- Gate 2
          AND in_org(user, document.org_id)               -- Gate 3

      Returns (allowed: bool, reason: str)
      """

      # Gate 3: Org membership (fastest check — do first)
      if user.org_id != doc.org_id:
          return False, f"Org boundary: user is in {user.org_id}, document is in {doc.org_id}"

      # Gate 1: Clearance level
      clearance_perm = f"clearpath.clearance.{doc.classification}"
      if not user.has_permission(clearance_perm):
          return False, f"Insufficient clearance: {doc.classification} required"

      # Gate 2: All compartments must match
      for compartment in doc.compartments:
          compartment_perm = f"clearpath.compartment.{compartment}"
          if not user.has_permission(compartment_perm):
              return False, f"Missing need-to-know: compartment {compartment.upper()} required"

      return True, "access granted"

  Use it in routes:

  @router.get("/documents/{document_id}")
  async def read_document(document_id: str, user: ClearPathAnalyst):
      doc = await db.get_document(document_id)
      if not doc:
          raise HTTPException(404)

      allowed, reason = compute_document_access(user, doc)
      if not allowed:
          # Log the denial — this is mandatory in classified systems
          await audit_log.record(
              user_id=user.user_id,
              action="read",
              document_id=document_id,
              classification=doc.classification,
              compartments=doc.compartments,
              outcome="denied",
              reason=reason
          )
          raise HTTPException(403, detail="Access denied")

      # Log the successful access — also mandatory
      await audit_log.record(
          user_id=user.user_id,
          action="read",
          document_id=document_id,
          classification=doc.classification,
          compartments=doc.compartments,
          outcome="granted"
      )

      return doc

  Concept: Why Log Both Grant and Deny?
  In classified systems, denial is as important as access. A pattern of denied access attempts — even from cleared personnel — signals insider threat, misconfiguration, or an attempt to probe for documents the person knows exist but should not be accessing. Security teams review denial logs, not just access logs.

  5c: Zanzibar tuple model for bulk queries

  When listing documents, you cannot check each one individually (too slow). Zanzibar solves this with tuple-based lookups. Your database query embeds the access check:

  async def list_accessible_documents(user: AuthenticatedUser, folder_id: str):
      """
      Zanzibar style: compute the set of accessible documents in one query
      by building the access tuple from the user's permissions.
      """

      # Build clearance ceiling from user's permissions
      clearance_ceiling = compute_clearance_ceiling(user)
      # e.g., if user has clearpath.clearance.top_secret -> ceiling = ["top_secret", "secret", "confidential", "cui", "unclassified"]

      # Build compartment set from user's permissions
      user_compartments = [
          p.split("clearpath.compartment.")[1]
          for p in user.permissions
          if p.startswith("clearpath.compartment.")
      ]
      # e.g., ["aether"] if user has clearpath.compartment.aether

      # Single database query with access tuple embedded
      # "Give me all documents in this folder where:
      #   classification is in my clearance ceiling
      #   AND every document compartment is in my compartment set
      #   AND org_id matches my org"
      docs = await db.query("""
          SELECT * FROM documents
          WHERE folder_id = :folder_id
            AND org_id = :org_id
            AND classification IN :clearance_ceiling
            AND (
              compartments = '[]'          -- no compartments required
              OR (
                -- every compartment on the document is in the user's set
                -- (JSON array subset check, syntax varies by DB)
                compartments_subset_of(:user_compartments)
              )
            )
      """, {
          "folder_id": folder_id,
          "org_id": user.org_id,
          "clearance_ceiling": clearance_ceiling,
          "user_compartments": user_compartments
      })

      return docs

  What Zanzibar gives you: you do not maintain a per-user per-document access list (which explodes at scale). You store the facts (user's clearance, compartments; document's classification, compartments) and compute the intersection. A single query replaces what would otherwise be a many-to-many join across millions of rows.

  ---
  Step 6: Assigning Compartment Access

  Now assign need-to-know for specific programs.

  Situation: Dr. Yuki Tanaka (DI, TS/SCI) is read into Project AETHER.

  "Reading in" requires two actions:
  1. Add Yuki to the AETHER compartment org (Gate 3 for AETHER)
  2. Grant Yuki the clearpath.compartment.aether permission (Gate 2)

  # Step A: Add Yuki to the AETHER org (org membership)
  # Only the AETHER Program Manager or Rachel (ISSO) can do this
  curl -X POST "$AUTH_URL/organizations/$AETHER_ORG_ID/invite" \
    -H "Authorization: Bearer $RACHEL_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "y.tanaka@nica.gov",
      "role": "clearpath-analyst",
      "message": "Read-in to Project AETHER — 2026-02-25 — Authorised by ISSO Torres"
    }'

  # Step B: Grant the compartment permission
  # NOTE: current API takes query params for the core grant. The metadata fields below
  # represent the full data model for a read-in — the API should be extended to accept
  # a POST body with metadata, or store it in your clearance management system alongside.
  curl -X POST "$AUTH_URL/permissions/grant?user_id=$YUKI_ID&org_id=$AETHER_ORG_ID&permission=clearpath.compartment.aether" \
    -H "Authorization: Bearer $RACHEL_TOKEN"
  # Full read-in record (store in clearance DB / POST body when API supports it):
  # {
  #   "user_id": "$YUKI_ID",
  #   "org_id": "$AETHER_ORG_ID",
  #   "permission": "clearpath.compartment.aether",
  #   "metadata": {
  #     "authorised_by": "r.torres@nica.gov",
  #     "read_in_date": "2026-02-25",
  #     "need_to_know_justification": "AETHER collection analysis — DI/SIGINT branch",
  #     "review_date": "2027-02-25"
  #   }
  # }

  What Yuki can now access:

  ┌──────────────────────────────────────────┬────────────────────┬──────────────────┐
  │              Document Type               │   Yuki Can Read?   │       Why        │
  ├──────────────────────────────────────────┼────────────────────┼──────────────────┤
  │ DI Secret document (no compartment)      │ YES                │ TS/SCI >= Secret │
  │                                          │                    │ no compartment   │
  │                                          │                    │ required         │
  ├──────────────────────────────────────────┼────────────────────┼──────────────────┤
  │ AETHER TS document (compartment: AETHER) │ YES                │ TS/SCI + AETHER  │
  │ — accessed via AETHER org context        │                    │ compartment      │
  ├──────────────────────────────────────────┼────────────────────┼──────────────────┤
  │ PRISM TS/SCI document (compt: PRISM)     │ NO                 │ TS/SCI but no    │
  │                                          │                    │ PRISM compartmt  │
  ├──────────────────────────────────────────┼────────────────────┼──────────────────┤
  │ DO Secret document (no compartment)      │ NO                 │ Not in DO org    │
  │                                          │                    │ (Gate 3 fails)   │
  └──────────────────────────────────────────┴────────────────────┴──────────────────┘

  How Yuki switches context to access AETHER documents:

  # Yuki logs in, gets a DI-scoped token by default
  YUKI_DI_TOKEN=$(curl -s ... | jq -r '.access_token')
  # This token: org_id = DI, clearance = ts_sci, compartments = [aether]

  # Switch to AETHER context to work on AETHER documents
  YUKI_AETHER_TOKEN=$(curl -s -X POST "$AUTH_URL/auth/switch-organization" \
    -H "Authorization: Bearer $YUKI_DI_TOKEN" \
    -d '{"org_id": "'"$AETHER_ORG_ID"'"}' \
    | jq -r '.access_token')
  # This token: org_id = AETHER, clearance = ts_sci, compartments = [aether]

  Now Yuki's requests carry the AETHER org context. Documents owned by AETHER org pass Gate 3. Her clearance passes Gate 1. Her compartment permission passes Gate 2. She reads the document.

  When done, she switches back to DI context. Her AETHER token stops being sent. She can no longer accidentally access AETHER documents from the DI context.

  ---
  Step 7: Moving Personnel Between Orgs (Reassignments)

  Classified systems have constant personnel movement: transfers, rotations, clearance upgrades, security incidents. Each has a different handling procedure.

  7a: Clearance upgrade — Sam Park goes from Secret to Top Secret

  Sam's background investigation completed. Rachel upgrades his clearance:

  # Revoke the old clearance level
  curl -X DELETE "$AUTH_URL/permissions/revoke" \
    -H "Authorization: Bearer $RACHEL_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "user_id": "'"$SAM_ID"'",
      "org_id": "'"$DI_ORG_ID"'",
      "permission": "clearpath.clearance.secret"
    }'

  # Grant the new clearance
  # NOTE: current API takes query params. Full data model with metadata (store in clearance
  # DB or POST body when API is extended to support it):
  # { "user_id": "$SAM_ID", "org_id": "$DI_ORG_ID", "permission": "clearpath.clearance.top_secret",
  #   "metadata": { "investigation_case": "OPM-2026-1847", "effective_date": "2026-02-25" } }
  curl -X POST "$AUTH_URL/permissions/grant?user_id=$SAM_ID&org_id=$DI_ORG_ID&permission=clearpath.clearance.top_secret" \
    -H "Authorization: Bearer $RACHEL_TOKEN"

  What just happened: The moment the new grant is written, Sam's next token (on refresh or re-login) carries clearpath.clearance.top_secret. Because of the Zanzibar computed hierarchy, he now also computedly has clearpath.clearance.secret and below. He can read Top Secret documents that had been invisible to him. The change is atomic — there is no window where he has neither or both.

  7b: Transfer — Marcus moves from DI to DS&T

  Marcus is transferring directorates. His DI access ends. His DS&T access begins. They must not overlap.

  # Step 1: Remove from DI org
  curl -X DELETE "$AUTH_URL/organizations/$DI_ORG_ID/members/$MARCUS_USER_ID" \
    -H "Authorization: Bearer $RACHEL_TOKEN"

  # The moment this runs:
  # - Marcus's existing token, on its next server-mode validation, gets 403
  # - His DI clearance permission in DI org context is orphaned (can't be used — no membership)
  # - He cannot list files, read documents, or see DI members

  # Step 2: Add to DS&T org (simultaneously or immediately after)
  curl -X POST "$AUTH_URL/organizations/$DST_ORG_ID/invite" \
    -H "Authorization: Bearer $RACHEL_TOKEN" \
    -d '{"email": "m.webb@nica.gov", "role": "clearpath-analyst"}'

  # Step 3: Grant clearance in new org context
  curl -X POST "$AUTH_URL/permissions/grant?user_id=$MARCUS_USER_ID&org_id=$DST_ORG_ID&permission=clearpath.clearance.top_secret" \
    -H "Authorization: Bearer $RACHEL_TOKEN"

  Concept: Permissions Are Org-Scoped
  Marcus's Top Secret clearance was granted in DI context: { user_id: marcus, org_id: DI, permission: clearpath.clearance.top_secret }. When he leaves DI, that grant is no longer effective (no membership to activate it). He needs a fresh grant in DS&T. This is correct — a transfer is not a copy. It is a fresh adjudication in the new context.

  7c: Security incident — Yuki's AETHER access immediately revoked

  Situation: A security incident requires immediate removal of Yuki from AETHER. This is a two-step operation and it must be fast.

  # Step 1: Remove org membership (instant — Gate 3 fails on next token validation)
  curl -X DELETE "$AUTH_URL/organizations/$AETHER_ORG_ID/members/$YUKI_USER_ID" \
    -H "Authorization: Bearer $RACHEL_TOKEN"

  # Step 2: Revoke compartment permission (belt and braces)
  curl -X DELETE "$AUTH_URL/permissions/revoke" \
    -H "Authorization: Bearer $RACHEL_TOKEN" \
    -d '{
      "user_id": "'"$YUKI_USER_ID"'",
      "org_id": "'"$AETHER_ORG_ID"'",
      "permission": "clearpath.compartment.aether"
    }'

  # Step 3: Revoke all active sessions (terminate any in-flight requests)
  curl -X DELETE "$AUTH_URL/organizations/$AETHER_ORG_ID/users/$YUKI_USER_ID/sessions" \
    -H "Authorization: Bearer $RACHEL_TOKEN"

  # Result: Yuki's AETHER token, even if she is mid-session, returns 403 on the very next request.
  # She cannot read a single additional AETHER document.
  # Her DI membership and DI clearance are untouched — she can still work in DI.

  Concept: Belt and Braces Revocation
  In classified systems, do both: remove org membership AND revoke the permission AND kill active sessions. Any one of these alone is sufficient in server mode. All three together means:
  - The org boundary check (Gate 3) fails: no membership
  - The permission check (Gate 2) fails: no compartment permission
  - Active tokens are invalid: sessions terminated
  There is no path to continued access. Defense in depth.

  7d: "Read out" — closing a compartment program entirely

  Project AETHER concludes. Shut down the compartment:

  # Get all AETHER members
  MEMBERS=$(curl -s "$AUTH_URL/organizations/$AETHER_ORG_ID/users" \
    -H "Authorization: Bearer $RACHEL_TOKEN")

  # Revoke sessions for all members
  curl -X DELETE "$AUTH_URL/organizations/$AETHER_ORG_ID/sessions" \
    -H "Authorization: Bearer $RACHEL_TOKEN"

  # Suspend the org (all API calls to AETHER-scoped resources return 403 immediately)
  curl -X PUT "$AUTH_URL/organizations/$AETHER_ORG_ID" \
    -H "Authorization: Bearer $RACHEL_TOKEN" \
    -d '{"status": "suspended"}'

  # Archive documents before deletion (compliance requirement)
  # ... your archival pipeline runs here ...

  # Delete the org (removes all membership records, permission grants, OAuth tokens)
  curl -X DELETE "$AUTH_URL/organizations/$AETHER_ORG_ID" \
    -H "Authorization: Bearer $RACHEL_TOKEN"

  What just happened: Every person who was in AETHER — whether from DI, DO, or DS&T — simultaneously loses access. There is no list to iterate. Deleting the org removes the Gate 3 foundation for every member at once. The Zanzibar computed relation collapses: if the org does not exist, org_id membership cannot be satisfied, and no amount of clearance or compartment permissions grants access.

  ---
  Step 8: Service Accounts for Automated Processing

  ClearPath runs background pipelines: an OCR service that indexes documents, a redaction service that strips classified markings before declassification review, and an audit aggregation service.

  These workers operate on classified material. They need identities, clearances, and strict scope limits.

  8a: OCR indexer service account

  # The OCR service needs to read documents and write index entries
  curl -X POST "$AUTH_URL/admin/users/create-service-account" \
    -H "Authorization: Bearer $RACHEL_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "ocr-indexer@workers.clearpath.internal",
      "name": "ClearPath OCR Indexer",
      "description": "Reads document content for full-text search indexing",
      "org_id": "'"$SERVICE_ORG_ID"'",
      "permissions": [
        "clearpath.read.documents",
        "clearpath.write.documents"
      ],
      "metadata": {
        "worker_type": "ocr_indexer",
        "approved_by": "r.torres@nica.gov",
        "approval_date": "2026-02-25",
        "accreditation": "ATO-2026-001-OCR"
      }
    }'

  OCR_API_KEY="ab0t_sk_live_ocr_..."

  Important: the OCR service has clearpath.read.documents but NO clearance level permissions. When OCR calls your API, compute_document_access runs. Gate 1 fails. The OCR service cannot read the document content through the API.

  How does it work then? The OCR service calls a separate internal pipeline endpoint that the auth middleware does not protect — it is your private message queue, not a public API. Documents flow from your encrypted storage directly to the OCR container, bypassing the end-user API surface. OCR writes back only the index (word positions, not content). The index itself is stored with the same classification metadata as the source document — if someone queries the index, their access is still gated.

  8b: Redaction service account — with compartment access

  The redaction service actually needs to read classified content to propose redactions. This is the highest-risk service account. It needs explicit clearance and compartment grants.

  REDACTION=$(curl -s -X POST "$AUTH_URL/admin/users/create-service-account" \
    -H "Authorization: Bearer $RACHEL_TOKEN" \
    -d '{
      "email": "redaction-svc@workers.clearpath.internal",
      "name": "ClearPath Automated Redaction",
      "description": "AI-assisted redaction for declassification review pipeline",
      "org_id": "'"$SERVICE_ORG_ID"'",
      "permissions": [
        "clearpath.read.documents",
        "clearpath.write.documents"
      ]
    }')
  REDACTION_USER_ID=$(echo "$REDACTION" | jq -r '.id')
  REDACTION_API_KEY=$(echo "$REDACTION" | jq -r '.api_key')

  # Grant TS/SCI clearance to the redaction service (it reads the most sensitive material)
  # NOTE: current API takes query params. Full data model (store in clearance DB or
  # POST body when API is extended to support it):
  # { "user_id": "$REDACTION_USER_ID", "org_id": "$SERVICE_ORG_ID",
  #   "permission": "clearpath.clearance.ts_sci",
  #   "metadata": { "rationale": "Automated redaction requires access to all classification levels",
  #                 "reviewed_annually": true, "next_review": "2027-02-25" } }
  curl -X POST "$AUTH_URL/permissions/grant?user_id=$REDACTION_USER_ID&org_id=$SERVICE_ORG_ID&permission=clearpath.clearance.ts_sci" \
    -H "Authorization: Bearer $RACHEL_TOKEN"

  # Grant AETHER compartment for redaction service
  curl -X POST "$AUTH_URL/permissions/grant?user_id=$REDACTION_USER_ID&org_id=$SERVICE_ORG_ID&permission=clearpath.compartment.aether" \
    -H "Authorization: Bearer $RACHEL_TOKEN"

  Concept: Service Accounts in Regulated Environments
  Service accounts in a classified system need the same vetting as humans:
  - The account must be listed in the System Security Plan
  - Clearance grants must have documented authorisation
  - Permissions must be reviewed annually (stored in metadata.next_review)
  - API keys must rotate on a schedule
  - Every action the service account takes is logged under its identity

  The audit log will show: "redaction-svc read AETHER-2026-047 at 03:14 UTC." If you cannot explain why the redaction service accessed a document, you have an incident.

  ---
  Step 9: Audit Trail — Every Access Logged

  In classified systems, audit logging is not optional. It is a compliance requirement (FISMA, ICD 503, NIST 800-53 AU controls).

  9a: The audit log service account

  AUDIT_SVC=$(curl -s -X POST "$AUTH_URL/admin/users/create-service-account" \
    -H "Authorization: Bearer $RACHEL_TOKEN" \
    -d '{
      "email": "audit-writer@workers.clearpath.internal",
      "name": "ClearPath Audit Writer",
      "org_id": "'"$SERVICE_ORG_ID"'",
      "permissions": ["clearpath.write.audit_logs"]
    }')
  AUDIT_API_KEY=$(echo "$AUDIT_SVC" | jq -r '.api_key')

  AUDIT_READER=$(curl -s -X POST "$AUTH_URL/admin/users/create-service-account" \
    -H "Authorization: Bearer $RACHEL_TOKEN" \
    -d '{
      "email": "audit-reader@workers.clearpath.internal",
      "name": "ClearPath Audit Reader (ISSO only)",
      "org_id": "'"$SERVICE_ORG_ID"'",
      "permissions": ["clearpath.read.audit_logs"]
    }')
  AUDIT_READ_KEY=$(echo "$AUDIT_READER" | jq -r '.api_key')

  Read and write are separate keys. The audit writer can write but not read its own log (prevents tampering). The audit reader can read but not write (prevents injection). Rachel's human token can do both — but every audit API call is itself logged.

  9b: Audit log schema

  Every document access creates an immutable record:

  {
    "event_id": "evt_abc123",
    "timestamp": "2026-02-25T14:23:11.847Z",
    "actor": {
      "user_id": "yuki-tanaka-uuid",
      "email": "y.tanaka@nica.gov",
      "org_id": "nica-aether-uuid",
      "clearance": "ts_sci",
      "compartments": ["aether"],
      "token_type": "user_session",
      "session_id": "sess_xyz"
    },
    "action": "read",
    "resource": {
      "document_id": "doc_aether_2026_047",
      "title": "AETHER Collection Summary Q1 2026",
      "classification": "top_secret",
      "compartments": ["aether"],
      "org_id": "nica-aether-uuid"
    },
    "outcome": "granted",
    "ip_address": "10.1.4.22",
    "user_agent": "ClearPath-Web/2.1",
    "server_id": "clearpath-prod-03"
  }

  9c: Querying the audit log

  Rachel reviewing AETHER access over 30 days:

  curl "$AUTH_URL/audit/events" \
    -H "X-API-Key: $AUDIT_READ_KEY" \
    -H "Content-Type: application/json" \
    -d '{
      "filter": {
        "org_id": "'"$AETHER_ORG_ID"'",
        "classification": ["top_secret", "ts_sci"],
        "compartments": ["aether"],
        "date_from": "2026-01-25",
        "date_to": "2026-02-25"
      },
      "include": ["denied", "granted"],
      "order": "desc"
    }'

  Anomaly detection — who accessed documents outside business hours:

  curl "$AUTH_URL/audit/events" \
    -H "X-API-Key: $AUDIT_READ_KEY" \
    -d '{
      "filter": {
        "org_id": "'"$AETHER_ORG_ID"'",
        "time_of_day_outside": {"start": "08:00", "end": "20:00"},
        "date_from": "2026-01-01"
      }
    }'

  ---
  The Full Picture

  ClearPath Authorization System
  │
  ├── ClearPath Platform (your engineering team)
  │   └── Rachel Torres (ISSO — only person who can grant clearances)
  │
  ├── ClearPath Service (permission definitions)
  │   ├── Permissions: clearpath.clearance.*, clearpath.compartment.*
  │   ├── Zanzibar roles: cleared-ts-sci implies cleared-top-secret implies cleared-secret...
  │   │
  │   ├── [Service Account] ocr-indexer
  │   │   Key: ab0t_sk_live_ocr — read/write documents, NO clearance
  │   │
  │   ├── [Service Account] redaction-svc
  │   │   Key: ab0t_sk_live_redaction — TS/SCI + AETHER compartment
  │   │
  │   ├── [Service Account] audit-writer
  │   │   Key: ab0t_sk_live_audit_w — write audit_logs only
  │   │
  │   └── [Service Account] audit-reader
  │       Key: ab0t_sk_live_audit_r — read audit_logs only (Rachel's eyes)
  │
  ├── NICA (parent — Rachel has ancestor access to all children)
  │   │
  │   ├── [CHILD ORG] Directorate of Intelligence
  │   │   ├── Dr. Yuki Tanaka  — TS/SCI, [aether]
  │   │   ├── Marcus Webb      — Top Secret, no compartments
  │   │   └── Sam Park         — Top Secret (upgraded from Secret)
  │   │
  │   ├── [CHILD ORG] Directorate of Operations
  │   │   └── Agent Dana Reeves — TS/SCI, no compartments
  │   │
  │   ├── [CHILD ORG] Directorate of S&T
  │   │   └── Marcus Webb (transferred from DI — fresh clearance grant)
  │   │
  │   ├── [COMPARTMENT ORG] Project AETHER
  │   │   ├── Dr. Yuki (from DI — switches context)
  │   │   └── [redaction-svc has compartment permission]
  │   │
  │   └── [COMPARTMENT ORG] Project PRISM — floor: TS/SCI
  │       └── Agent Dana (from DO — switches context)

  The three-gate model in practice:

  ┌──────────────────────────────────────┬────────┬────────┬────────┬────────────┐
  │            Access Attempt            │ Gate 3 │ Gate 1 │ Gate 2 │  Result    │
  │                                      │  Org   │Clearance│ Compt │            │
  ├──────────────────────────────────────┼────────┼────────┼────────┼────────────┤
  │ Yuki reads DI Secret doc             │  PASS  │  PASS  │  N/A  │ GRANTED    │
  ├──────────────────────────────────────┼────────┼────────┼────────┼────────────┤
  │ Yuki reads AETHER TS doc (in AETHER) │  PASS  │  PASS  │  PASS  │ GRANTED    │
  ├──────────────────────────────────────┼────────┼────────┼────────┼────────────┤
  │ Yuki reads PRISM doc                 │  FAIL  │  —     │  —     │ DENIED     │
  │ (she's not in PRISM org)             │        │        │        │            │
  ├──────────────────────────────────────┼────────┼────────┼────────┼────────────┤
  │ Sam reads TS doc (post-upgrade)      │  PASS  │  PASS  │  N/A  │ GRANTED    │
  ├──────────────────────────────────────┼────────┼────────┼────────┼────────────┤
  │ Sam reads AETHER doc                 │  FAIL  │  —     │  —     │ DENIED     │
  │ (not in AETHER org)                  │        │        │        │            │
  ├──────────────────────────────────────┼────────┼────────┼────────┼────────────┤
  │ Dana reads DI TS doc                 │  FAIL  │  —     │  —     │ DENIED     │
  │ (she's in DO, not DI)                │        │        │        │            │
  ├──────────────────────────────────────┼────────┼────────┼────────┼────────────┤
  │ Dana reads PRISM TS/SCI doc          │  PASS  │  PASS  │  PASS  │ GRANTED    │
  │ (in PRISM org, TS/SCI, PRISM compt)  │        │        │        │            │
  ├──────────────────────────────────────┼────────┼────────┼────────┼────────────┤
  │ redaction-svc reads AETHER doc       │  PASS* │  PASS  │  PASS  │ GRANTED    │
  │ (*service org has cross-org access)  │        │        │        │            │
  └──────────────────────────────────────┴────────┴────────┴────────┴────────────┘

  All of the above is computed. Not stored per-pair. When Yuki's AETHER compartment is revoked, every row in that table that says GRANTED for Yuki+AETHER flips to DENIED on the next request. No cleanup loop. No stale access records. The Zanzibar model is correct by construction.
