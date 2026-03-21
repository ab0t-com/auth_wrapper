question: We run a hospital. We're building "MedCore" — a clinical platform for patient records, orders, notes, medications, labs, and imaging. We need ward isolation so
  Cardiology can't browse Oncology patients. We need patient-level access control — a doctor is assigned to specific patients, not "all patients in the hospital." We need
  temporary consultant access that auto-expires. We need a full audit trail of every record touched. We need a patient portal. And we need our lab system and PACS (radiology)
  talking to the platform via API keys. Walk us through the whole thing.

● Healthcare is one of the hardest access control problems: the data is maximally sensitive, the isolation requirements are strict (HIPAA), access patterns are dynamic (care teams
  change, consultants come and go), and there's a hard override requirement — in an emergency, a clinician must be able to access any patient record, even if not assigned.

  This guide builds all of it. By the end you'll have:
  - Department and ward orgs with hard walls between them
  - Patient-scoped access via Zanzibar (Dr. Chen sees his 12 patients, not the ward's 80)
  - Consultant access that expires automatically after the consult period
  - Break-glass emergency override — with mandatory audit flagging
  - A patient portal for self-service record access
  - Family proxy access delegation
  - Lab system and PACS API keys with least-privilege
  - A full HIPAA-style audit trail on every record access
  - Nurse transferring between wards with zero access overlap

  ---
  Concept: Why Healthcare Needs Two Access Layers

  An org membership check answers: "Is Dr. Chen a member of the Cardiology department?"
  A Zanzibar check answers: "Is Dr. Chen the attending physician for Patient #P-8821?"

  Both questions matter. Both must be enforced.

  Layer 1 (org): Dr. Chen is a cardiologist. He works in Cardiology. He cannot browse Oncology patients even in passing. The ward wall stops him before he gets close.

  Layer 2 (Zanzibar): Dr. Chen is in Cardiology. Cardiology has 80 inpatients. Dr. Chen is personally responsible for 12 of them. He can pull up those 12 charts. He cannot pull up the other 68 — they're someone else's patients.

  This isn't just policy — it's HIPAA minimum necessary. A clinician should only access the records they need for their work.

  ---
  The Architecture: MedCore Hospital System

  MedCore Hospital (root org — administration, compliance, IT)
  │
  ├── [CHILD ORG] Cardiology Department
  │   ├── [CHILD ORG] Cardiology Ward (general inpatients)
  │   └── [CHILD ORG] Cardiac ICU
  │
  ├── [CHILD ORG] Neurology Department
  │   └── [CHILD ORG] Neurology Ward
  │
  ├── [CHILD ORG] Pediatrics Department
  │   └── [CHILD ORG] Pediatrics Ward
  │
  ├── [CHILD ORG] Oncology Department
  │
  ├── [CHILD ORG] Emergency Department
  │
  └── Services (API keys, not orgs)
      ├── Lab System        (medcore.write.lab_results, medcore.read.orders)
      ├── PACS (Radiology)  (medcore.write.imaging_results, medcore.read.imaging_orders)
      └── Pharmacy System   (medcore.read.prescriptions, medcore.write.dispensing)

  Characters:
  - Dr. Sarah Okafor     — CMO, owns root org, can see everything
  - Dr. James Chen       — Attending Physician, Cardiology Ward
  - Dr. Priya Patel      — Resident, Cardiology Ward (supervised by Chen)
  - Nurse Maria Santos   — RN, Cardiology Ward (transfers to Pediatrics in Step 11)
  - Dr. Elena Webb       — External Neurologist (consults on one Cardiology patient)
  - Robert Kim           — Patient, Cardiology Ward (uses patient portal)
  - Linda Kim            — Robert's wife (proxy access to his records)
  - HIPAA Compliance Officer — cross_tenant, audit-only

  ---
  Step 1: Register and Create MedCore

  AUTH_URL="https://auth.service.ab0t.com"

  curl -X POST "$AUTH_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "sarah.okafor@medcore.hospital",
      "password": "SarahSecure2026!",
      "name": "Dr. Sarah Okafor"
    }'

  TOKEN=$(curl -s -X POST "$AUTH_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email": "sarah.okafor@medcore.hospital", "password": "SarahSecure2026!"}' \
    | jq -r '.access_token')

  MEDCORE=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "MedCore Hospital",
      "slug": "medcore",
      "domain": "medcore.hospital",
      "billing_type": "enterprise",
      "settings": {
        "type": "hospital",
        "hierarchical": true,
        "hipaa_mode": true
      },
      "metadata": {
        "regulated": true,
        "frameworks": ["HIPAA", "HITECH"],
        "audit_retention_years": 6,
        "break_glass_enabled": true
      }
    }')
  MEDCORE_ORG_ID=$(echo "$MEDCORE" | jq -r '.id')

  SARAH_TOKEN=$(curl -s -X POST "$AUTH_URL/auth/switch-organization" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"org_id": "'$MEDCORE_ORG_ID'"}' | jq -r '.access_token')

  ---
  Step 2: Define Clinical Permissions

  {
    "service": "medcore",
    "description": "Clinical platform — patient records, orders, notes, medications",
    "actions": ["read", "write", "create", "delete", "order", "prescribe", "administer",
                "view_full", "break_glass", "admin", "audit"],
    "resources": [
      "patient_demographics", "clinical_notes", "medications",
      "lab_orders", "lab_results", "imaging_orders", "imaging_results",
      "vitals", "prescriptions", "care_plans", "discharge_summaries",
      "audit_logs", "settings"
    ],
    "roles": {
      "medcore-patient": {
        "description": "Patient — views own records via patient portal",
        "default_permissions": [
          "medcore.read.patient_demographics",
          "medcore.read.lab_results",
          "medcore.read.imaging_results",
          "medcore.read.vitals",
          "medcore.read.medications",
          "medcore.read.discharge_summaries"
        ]
      },
      "medcore-cna": {
        "description": "Certified Nursing Assistant — vitals and basic care",
        "default_permissions": [
          "medcore.read.patient_demographics",
          "medcore.read.vitals",
          "medcore.write.vitals",
          "medcore.read.care_plans"
        ]
      },
      "medcore-rn": {
        "description": "Registered Nurse — clinical notes, medications, vitals",
        "implies": ["medcore-cna"],
        "default_permissions": [
          "medcore.read.clinical_notes",
          "medcore.write.clinical_notes",
          "medcore.read.medications",
          "medcore.administer.medications",
          "medcore.read.lab_results",
          "medcore.read.imaging_results",
          "medcore.read.lab_orders",
          "medcore.create.clinical_notes"
        ]
      },
      "medcore-resident": {
        "description": "Resident physician — orders, notes, supervised prescribing",
        "implies": ["medcore-rn"],
        "default_permissions": [
          "medcore.order.labs",
          "medcore.order.imaging",
          "medcore.prescribe.medications",
          "medcore.write.care_plans",
          "medcore.create.care_plans"
        ]
      },
      "medcore-attending": {
        "description": "Attending physician — full clinical access, approves resident orders",
        "implies": ["medcore-resident"],
        "default_permissions": [
          "medcore.view_full",
          "medcore.read.discharge_summaries",
          "medcore.write.discharge_summaries",
          "medcore.delete.clinical_notes"
        ]
      },
      "medcore-admin": {
        "description": "Department/ward administrator",
        "implies": ["medcore-attending"],
        "default_permissions": [
          "medcore.admin",
          "medcore.read.audit_logs",
          "medcore.write.settings"
        ]
      }
    }
  }

  Concept: Clinical Role Hierarchy
  The chain is: CNA -> RN -> Resident -> Attending -> Admin.

  Each level implies all levels below it. An attending can do everything a resident can.
  A resident can do everything an RN can. You never have to manually list "read vitals"
  for an attending — they get it from the RN role, which they imply through resident.

  This mirrors how hospitals actually work: seniority unlocks capability.

  ./register-service-permissions.sh \
    --service-name "medcore" \
    --admin-email "svc+medcore@medcore.hospital" \
    --permissions-file medcore.permissions.json

  SERVICE_API_KEY="ab0t_sk_live_medcore_..."

  ---
  Step 3: Build the Department and Ward Hierarchy

  3a: Cardiology (department + wards)

  # Cardiology Department
  CARDIO_DEPT=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $SARAH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Cardiology Department",
      "slug": "medcore-cardiology",
      "parent_id": "'"$MEDCORE_ORG_ID"'",
      "settings": {
        "type": "department",
        "hierarchical": true,
        "specialty": "cardiology"
      }
    }')
  CARDIO_DEPT_ID=$(echo "$CARDIO_DEPT" | jq -r '.id')

  # Cardiology Ward (general inpatients)
  CARDIO_WARD=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $SARAH_TOKEN" \
    -d '{
      "name": "Cardiology Ward",
      "slug": "medcore-cardio-ward",
      "parent_id": "'"$CARDIO_DEPT_ID"'",
      "settings": {"type": "ward", "beds": 24, "ward_code": "CW"}
    }')
  CARDIO_WARD_ID=$(echo "$CARDIO_WARD" | jq -r '.id')

  # Cardiac ICU
  CICU=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $SARAH_TOKEN" \
    -d '{
      "name": "Cardiac ICU",
      "slug": "medcore-cicu",
      "parent_id": "'"$CARDIO_DEPT_ID"'",
      "settings": {"type": "ward", "icu": true, "beds": 8, "ward_code": "CICU"}
    }')
  CICU_ID=$(echo "$CICU" | jq -r '.id')

  3b: Other departments

  # Repeat for Neurology, Pediatrics, Oncology, Emergency
  for dept in \
    "Neurology Department:medcore-neuro:neurology" \
    "Pediatrics Department:medcore-peds:pediatrics" \
    "Oncology Department:medcore-onco:oncology" \
    "Emergency Department:medcore-ed:emergency"; do

    NAME=$(echo $dept | cut -d: -f1)
    SLUG=$(echo $dept | cut -d: -f2)
    SPECIALTY=$(echo $dept | cut -d: -f3)

    curl -s -X POST "$AUTH_URL/organizations/" \
      -H "Authorization: Bearer $SARAH_TOKEN" \
      -d '{
        "name": "'"$NAME"'",
        "slug": "'"$SLUG"'",
        "parent_id": "'"$MEDCORE_ORG_ID"'",
        "settings": {"type": "department", "specialty": "'"$SPECIALTY"'"}
      }' | jq '{id, name}'
  done

  What the hierarchy looks like:

  MedCore Hospital <- Sarah (CMO) sees everything via ancestor access
  │
  ├── Cardiology Department <- Cardiology head sees all cardio wards
  │   ├── Cardiology Ward   <- Dr. Chen, Nurse Maria, Dr. Patel (their patients only)
  │   └── Cardiac ICU       <- ICU attending, ICU nurses (ICU patients only)
  │
  ├── Neurology Department  <- Completely isolated from Cardiology
  ├── Pediatrics Department <- Completely isolated from Cardiology
  ├── Oncology Department   <- Completely isolated
  └── Emergency Department  <- Has break-glass that can reach all departments

  Concept: Ward Isolation in Healthcare
  A cardiologist working on the Cardiology Ward cannot casually browse Pediatrics or Oncology
  patients. The child org structure enforces this at the infrastructure level — it's not a
  UI filter that could be bypassed. Even if Dr. Chen somehow got a valid token, his org_id
  is "medcore-cardio-ward" — and every patient record in Oncology has org_id "medcore-onco."
  The Phase 2 check in your API catches any cross-ward access attempt before the data leaves
  the database.

  ---
  Step 4: Staff the Cardiology Ward

  4a: Dr. James Chen — Attending Physician

  curl -X POST "$AUTH_URL/organizations/$CARDIO_WARD_ID/invite" \
    -H "Authorization: Bearer $SARAH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "james.chen@medcore.hospital",
      "role": "member",
      "permissions": [
        "medcore.view_full",
        "medcore.read.patient_demographics", "medcore.read.clinical_notes",
        "medcore.write.clinical_notes", "medcore.create.clinical_notes",
        "medcore.read.medications", "medcore.prescribe.medications",
        "medcore.order.labs", "medcore.order.imaging",
        "medcore.read.lab_results", "medcore.read.imaging_results",
        "medcore.read.vitals", "medcore.write.discharge_summaries",
        "medcore.read.care_plans", "medcore.write.care_plans"
      ],
      "metadata": {
        "clinical_role": "attending_physician",
        "npi": "1234567890",
        "specialty": "interventional_cardiology",
        "license": "CA-MD-88821"
      }
    }'

  4b: Dr. Priya Patel — Resident (supervised by Chen)

  curl -X POST "$AUTH_URL/organizations/$CARDIO_WARD_ID/invite" \
    -H "Authorization: Bearer $SARAH_TOKEN" \
    -d '{
      "email": "priya.patel@medcore.hospital",
      "role": "member",
      "permissions": [
        "medcore.read.patient_demographics", "medcore.read.clinical_notes",
        "medcore.write.clinical_notes", "medcore.create.clinical_notes",
        "medcore.read.medications", "medcore.prescribe.medications",
        "medcore.order.labs", "medcore.order.imaging",
        "medcore.read.lab_results", "medcore.read.imaging_results",
        "medcore.read.vitals", "medcore.write.vitals"
      ],
      "metadata": {
        "clinical_role": "resident",
        "supervising_physician_id": "'$CHEN_USER_ID'",
        "residency_year": 2
      }
    }'

  4c: Nurse Maria Santos — RN

  curl -X POST "$AUTH_URL/organizations/$CARDIO_WARD_ID/invite" \
    -H "Authorization: Bearer $SARAH_TOKEN" \
    -d '{
      "email": "maria.santos@medcore.hospital",
      "role": "member",
      "permissions": [
        "medcore.read.patient_demographics",
        "medcore.read.clinical_notes", "medcore.write.clinical_notes",
        "medcore.create.clinical_notes",
        "medcore.read.medications", "medcore.administer.medications",
        "medcore.read.lab_results", "medcore.read.imaging_results",
        "medcore.read.vitals", "medcore.write.vitals",
        "medcore.read.care_plans"
      ],
      "metadata": {
        "clinical_role": "rn",
        "license": "CA-RN-55512"
      }
    }'

  ---
  Step 5: Zanzibar — Patient-Level Access Control

  Dr. Chen is an attending in Cardiology Ward. But the ward has 24 inpatients. Dr. Chen
  is personally responsible for 12 of them. He should not be able to pull up the other 12.

  5a: Define the patient namespace

  curl -X POST "$AUTH_URL/zanzibar/stores/$MEDCORE_ORG_ID/namespaces" \
    -H "Authorization: Bearer $SARAH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "org_id": "'$CARDIO_WARD_ID'",
      "namespace": "patient",
      "relations": {
        "attending_physician": {},
        "resident": {
          "comment": "Supervised resident — has read access, write access supervised"
        },
        "care_team": {
          "union": ["attending_physician", "resident"]
        },
        "nurse": {},
        "clinical_viewer": {
          "union": ["care_team", "nurse"]
        },
        "consultant": {
          "comment": "Temporary — usually created with expiry metadata"
        },
        "patient_self": {
          "comment": "The patient themselves, via patient portal"
        },
        "family_proxy": {
          "comment": "Authorized family member"
        }
      },
      "permissions": {
        "read_demographics": {"union": ["clinical_viewer", "consultant", "patient_self", "family_proxy"]},
        "read_notes":        {"union": ["clinical_viewer", "consultant"]},
        "write_notes":       {"union": ["care_team", "consultant"]},
        "read_medications":  {"union": ["clinical_viewer", "consultant", "patient_self"]},
        "prescribe":         {"union": ["attending_physician", "resident"]},
        "read_labs":         {"union": ["clinical_viewer", "consultant", "patient_self", "family_proxy"]},
        "read_imaging":      {"union": ["clinical_viewer", "consultant", "patient_self"]},
        "read_vitals":       {"union": ["clinical_viewer", "nurse", "consultant", "patient_self"]},
        "write_vitals":      {"union": ["nurse", "care_team"]},
        "discharge":         {"union": ["attending_physician"]}
      }
    }'

  5b: Assign clinical staff to patients when admitted

  # Robert Kim admitted to Cardiology Ward — Dr. Chen is attending, Dr. Patel is resident
  PATIENT_ID="P-8821"

  curl -X POST "$AUTH_URL/zanzibar/stores/$MEDCORE_ORG_ID/relationships" \
    -H "Authorization: Bearer $SARAH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "org_id": "'$CARDIO_WARD_ID'",
      "tuples": [
        {
          "object": "patient:'$PATIENT_ID'",
          "relation": "attending_physician",
          "subject": "user:'$CHEN_USER_ID'"
        },
        {
          "object": "patient:'$PATIENT_ID'",
          "relation": "resident",
          "subject": "user:'$PRIYA_USER_ID'"
        },
        {
          "object": "patient:'$PATIENT_ID'",
          "relation": "nurse",
          "subject": "user:'$MARIA_USER_ID'"
        }
      ]
    }'

  # Patients that Dr. Chen does NOT cover — no tuple = no access
  # Patient P-8850 is covered by Dr. Rodriguez (different attending)
  # No tuple for Chen on P-8850.

  5c: Enforce patient-level access in your API

  @router.get("/patients/{patient_id}/clinical-notes")
  async def get_clinical_notes(patient_id: str, user: MedcoreRN):
      # Layer 1: user has medcore.read.clinical_notes (checked by MedcoreRN badge)

      # Layer 2: is this user assigned to this patient?
      allowed = await zanzibar.check(
          org_id=user.org_id,
          subject=f"user:{user.user_id}",
          permission="read_notes",
          object=f"patient:{patient_id}"
      )
      if not allowed:
          raise HTTPException(403, "You are not assigned to this patient")

      # Layer 3: log every access (HIPAA)
      await audit_log.record(
          actor=user.user_id,
          action="read_notes",
          resource=f"patient:{patient_id}",
          org_id=user.org_id,
          timestamp=datetime.utcnow().isoformat()
      )

      return await db.get_clinical_notes(patient_id=patient_id, org_id=user.org_id)

  5d: Check access

  # Can Dr. Chen read Patient P-8821's notes?
  curl -X POST "$AUTH_URL/zanzibar/stores/$MEDCORE_ORG_ID/check" \
    -G \
    --data-urlencode "org_id=$CARDIO_WARD_ID" \
    --data-urlencode "subject=user:$CHEN_USER_ID" \
    --data-urlencode "permission=read_notes" \
    --data-urlencode "object=patient:P-8821"
  # {"allowed": true} — Chen is attending_physician on P-8821

  # Can Dr. Chen read Patient P-8850's notes? (covered by Dr. Rodriguez)
  curl -X POST "$AUTH_URL/zanzibar/stores/$MEDCORE_ORG_ID/check" \
    -G \
    --data-urlencode "org_id=$CARDIO_WARD_ID" \
    --data-urlencode "subject=user:$CHEN_USER_ID" \
    --data-urlencode "permission=read_notes" \
    --data-urlencode "object=patient:P-8850"
  # {"allowed": false} — no tuple for Chen on P-8850

  # Can Dr. Chen prescribe for P-8821?
  curl -X POST "$AUTH_URL/zanzibar/stores/$MEDCORE_ORG_ID/check" \
    -G \
    --data-urlencode "org_id=$CARDIO_WARD_ID" \
    --data-urlencode "subject=user:$CHEN_USER_ID" \
    --data-urlencode "permission=prescribe" \
    --data-urlencode "object=patient:P-8821"
  # {"allowed": true} — attending_physician relation includes prescribe

  # Can Nurse Maria prescribe for P-8821?
  curl -X POST "$AUTH_URL/zanzibar/stores/$MEDCORE_ORG_ID/check" \
    -G \
    --data-urlencode "org_id=$CARDIO_WARD_ID" \
    --data-urlencode "subject=user:$MARIA_USER_ID" \
    --data-urlencode "permission=prescribe" \
    --data-urlencode "object=patient:P-8821"
  # {"allowed": false} — nurse relation does not include prescribe

  ---
  Step 6: Temporary Consultant Access — Dr. Elena Webb

  Situation: Robert Kim (P-8821) is showing unusual neurological symptoms alongside his
  cardiac issues. Dr. Chen requests a neurology consult from Dr. Elena Webb, an external
  neurologist. She needs access to Robert's full chart for 72 hours. After that, access
  ends automatically.

  6a: Dr. Chen creates a delegation grant for Dr. Webb

  Concept: Consultant Access via Delegation
  A delegation grant is time-limited and scoped to exactly what the consultant needs.
  Dr. Webb gets read access to one patient for 72 hours. She cannot access any other patient.
  She cannot write prescriptions (that's the attending's responsibility). She can write a
  consult note. Every action she takes is logged under her identity and the delegation grant ID.

  Note: For time-limited external access like guest consultants, Zanzibar relationships
  with `expires_at` (shown below) are the better pattern for scoped temporary access —
  they tie resource-level visibility to the same expiry window.

  # Step 1: Dr. Chen creates a delegation grant scoping what Dr. Webb can do
  CONSULT_GRANT=$(curl -s -X POST "$AUTH_URL/delegation/grant" \
    -H "Authorization: Bearer $CHEN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "actor_id": "'$WEBB_USER_ID'",
      "scope": [
        "medcore.read.patient_demographics",
        "medcore.read.clinical_notes",
        "medcore.write.clinical_notes",
        "medcore.create.clinical_notes",
        "medcore.read.medications",
        "medcore.read.lab_results",
        "medcore.read.imaging_results",
        "medcore.read.vitals"
      ],
      "expires_in_hours": 72,
      "metadata": {
        "purpose": "Neurology consult — Patient P-8821, Robert Kim",
        "consult_type": "neurology",
        "requesting_physician": "'$CHEN_USER_ID'",
        "patient_id": "P-8821",
        "consult_ref": "CONS-2026-4821"
      }
    }')
  CONSULT_GRANT_ID=$(echo "$CONSULT_GRANT" | jq -r '.id')

  # Write a Zanzibar tuple giving Dr. Webb consultant access to P-8821 only
  curl -X POST "$AUTH_URL/zanzibar/stores/$MEDCORE_ORG_ID/relationships" \
    -H "Authorization: Bearer $CHEN_TOKEN" \
    -d '{
      "org_id": "'$CARDIO_WARD_ID'",
      "tuples": [{
        "object": "patient:P-8821",
        "relation": "consultant",
        "subject": "user:'$WEBB_USER_ID'",
        "metadata": {
          "delegation_id": "'$CONSULT_GRANT_ID'",
          "expires_at": "'$(date -d '+72 hours' -u +%Y-%m-%dT%H:%M:%SZ)'"
        }
      }]
    }'

  6b: Dr. Webb gets delegated access and accesses the chart

  # Step 2: Dr. Chen (or Dr. Webb after normal login) activates the delegation
  WEBB_DELEGATED=$(curl -s -X POST "$AUTH_URL/auth/delegate" \
    -H "Authorization: Bearer $CHEN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "target_user_id": "'$WEBB_USER_ID'"
    }')
  WEBB_TOKEN=$(echo "$WEBB_DELEGATED" | jq -r '.access_token')

  # Dr. Webb reads the chart
  curl -X GET "$PLATFORM_URL/patients/P-8821/clinical-notes" \
    -H "Authorization: Bearer $WEBB_TOKEN"
  # Allowed: consultant relation on P-8821, delegation grant active

  # Dr. Webb tries to access a different patient
  curl -X GET "$PLATFORM_URL/patients/P-8850/clinical-notes" \
    -H "Authorization: Bearer $WEBB_TOKEN"
  # 403: Webb has no Zanzibar tuple on P-8850

  # Dr. Webb writes her consult note
  curl -X POST "$PLATFORM_URL/patients/P-8821/clinical-notes" \
    -H "Authorization: Bearer $WEBB_TOKEN" \
    -d '{"type": "consult", "specialty": "neurology", "content": "..."}'
  # Allowed: write_notes includes consultant relation

  # Dr. Webb tries to prescribe
  curl -X POST "$PLATFORM_URL/patients/P-8821/prescriptions" \
    -H "Authorization: Bearer $WEBB_TOKEN"
  # 403: prescribe permission NOT in her delegation grant scope. Attendings prescribe.

  6c: After 72 hours — access expires automatically

  The delegation grant has expires_in_hours set. After 72 hours:
  - The delegation grant is expired
  - The auth service rejects further delegated requests
  - Dr. Webb's session tokens that came from this delegation also expire

  No manual cleanup needed. You can also revoke early:

  # Dr. Chen revokes the consult access (consult complete before 72 hours)
  curl -X DELETE "$AUTH_URL/delegation/grant/$WEBB_USER_ID" \
    -H "Authorization: Bearer $CHEN_TOKEN"

  # Clean up the Zanzibar tuple
  curl -X DELETE "$AUTH_URL/zanzibar/stores/$MEDCORE_ORG_ID/relationships" \
    -H "Authorization: Bearer $CHEN_TOKEN" \
    -d '{
      "org_id": "'$CARDIO_WARD_ID'",
      "filter": {
        "subject": "user:'$WEBB_USER_ID'",
        "object": "patient:P-8821",
        "relation": "consultant"
      }
    }'

  ---
  Step 7: Break-Glass Emergency Access

  Concept: Break-Glass
  In a cardiac arrest, you don't have time to check Zanzibar. Any attending physician on
  duty must be able to pull up any patient chart instantly. But this is a privilege that
  must be tracked — "break-glass" is named after the fire emergency boxes where you break
  glass to pull an alarm. You can do it, but everyone will know you did.

  Break-glass is not a permission you grant permanently. It's a special override path:

  7a: The break-glass endpoint in your platform

  @router.post("/patients/{patient_id}/break-glass")
  async def break_glass_access(
      patient_id: str,
      reason: str,
      user: MedcoreAttending  # Must have medcore.view_full at minimum
  ):
      # Check if user is already authorized (normal path)
      already_authorized = await zanzibar.check(
          org_id=user.org_id,
          subject=f"user:{user.user_id}",
          permission="read_notes",
          object=f"patient:{patient_id}"
      )
      if already_authorized:
          return {"message": "Already authorized — no break-glass needed"}

      # Log the break-glass event — this is the HIPAA audit trail entry
      await audit_log.record_break_glass(
          actor=user.user_id,
          patient_id=patient_id,
          reason=reason,
          org_id=user.org_id,
          timestamp=datetime.utcnow().isoformat(),
          severity="HIGH",
          requires_review=True
      )

      # Grant temporary emergency access via Zanzibar (30 minutes)
      await zanzibar.write_tuple(
          org_id=user.org_id,
          object=f"patient:{patient_id}",
          relation="clinical_viewer",
          subject=f"user:{user.user_id}",
          metadata={
              "break_glass": True,
              "reason": reason,
              "expires_at": (datetime.utcnow() + timedelta(minutes=30)).isoformat(),
              "requires_review": True
          }
      )

      # Alert the compliance officer and department head
      await alerts.send_break_glass_alert(
          actor=user.user_id,
          patient_id=patient_id,
          reason=reason
      )

      return {"message": "Emergency access granted for 30 minutes", "requires_review": True}

  # Dr. Rodriguez (covers P-8821's ward colleague) is first on scene for P-8850
  curl -X POST "$PLATFORM_URL/patients/P-8850/break-glass" \
    -H "Authorization: Bearer $RODRIGUEZ_TOKEN" \
    -d '{"reason": "Patient unresponsive, code blue, primary attending unreachable"}'

  What just happened:
  - Dr. Rodriguez gets 30 minutes of access to P-8850
  - An audit log entry is created, flagged HIGH severity, marked requires_review
  - The compliance officer gets an alert immediately
  - The department head gets an alert
  - After 30 minutes, the temporary tuple expires automatically
  - Compliance reviews the access at the end of the shift

  7b: Compliance reviews break-glass events

  curl -X GET "$AUTH_URL/audit/logs?event_type=break_glass&org_id=$CARDIO_WARD_ID" \
    -H "Authorization: Bearer $COMPLIANCE_TOKEN"

  # Returns all break-glass events with:
  # - who accessed (user_id, name, role)
  # - which patient (patient_id)
  # - reason given
  # - timestamp
  # - duration of access
  # - what they did during that access (sub-events)

  This is your HIPAA audit log. Every break-glass is reviewed. If Dr. Rodriguez's reason
  is legitimate — emergency, code blue, primary unreachable — it's signed off. If someone
  break-glassed to look at a celebrity patient out of curiosity, that's a HIPAA violation
  and the audit log proves it.

  ---
  Step 8: The Patient Portal

  Robert Kim is recovering. He wants to check his lab results and discharge summary from
  his phone. The patient portal lets him self-register and view his own records.

  8a: Configure the patient portal login page

  curl -X PUT "$AUTH_URL/organizations/$CARDIO_WARD_ID/login-config" \
    -H "Authorization: Bearer $SARAH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "branding": {
        "primary_color": "#0D9488",
        "page_title": "MedCore — Patient Portal",
        "logo_url": "https://medcore.hospital/logo.png",
        "login_template": "default"
      },
      "content": {
        "welcome_message": "Welcome to MedCore Patient Portal",
        "signup_message": "View your health records and test results",
        "terms_url": "https://medcore.hospital/patient-terms",
        "privacy_url": "https://medcore.hospital/hipaa-notice",
        "footer_message": "For medical emergencies call 911. For portal help: 1-800-MEDCORE"
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

  Concept: Patients as end_users
  When Robert registers on the patient portal, he gets end_user role (api.read by default).
  But that alone is not enough — end_user doesn't know which patient chart is his. You still
  need Zanzibar. When a patient registers, your system matches them to their patient record
  and writes the patient_self Zanzibar tuple.

  8b: Patient registers and is linked to their record

  Your platform's registration webhook:

  @router.post("/webhooks/patient-registered")
  async def on_patient_registered(user_id: str, org_id: str, email: str):
      # Find the patient record in your EMR by email
      patient = await emr.find_patient_by_email(email)
      if not patient:
          # Patient record not found — hold for manual verification
          await pending_verification.add(user_id=user_id, email=email)
          return

      # Link the portal account to the patient record
      await zanzibar.write_tuple(
          org_id=org_id,
          object=f"patient:{patient.id}",
          relation="patient_self",
          subject=f"user:{user_id}",
          metadata={"verified": True, "linked_at": datetime.utcnow().isoformat()}
      )

  Now Robert (patient_self on P-8821) can:
  - Read his own demographics (read_demographics includes patient_self)
  - Read his lab results (read_labs includes patient_self)
  - Read his imaging results (read_imaging includes patient_self)
  - Read his vitals (read_vitals includes patient_self)
  - Read his medications (read_medications includes patient_self)
  - NOT read clinical notes (read_notes does NOT include patient_self — notes are for clinicians)
  - NOT see any other patient's records (no tuples on any other patient)

  8c: Family proxy access — Robert authorizes his wife Linda

  Robert wants Linda to be able to check his results while he's resting.

  # Step 1: Robert creates a delegation grant for Linda
  FAMILY_GRANT=$(curl -s -X POST "$AUTH_URL/delegation/grant" \
    -H "Authorization: Bearer $ROBERT_PORTAL_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "actor_id": "'$LINDA_USER_ID'",
      "scope": [
        "medcore.read.patient_demographics",
        "medcore.read.lab_results",
        "medcore.read.vitals",
        "medcore.read.discharge_summaries"
      ],
      "expires_in_hours": 720,
      "metadata": {
        "purpose": "Family proxy access — authorized by patient Robert Kim",
        "relationship": "spouse",
        "authorized_by_patient": "'$ROBERT_USER_ID'",
        "patient_id": "P-8821"
      }
    }')

  # Step 2: Delegate — produces a scoped token for Linda
  LINDA_DELEGATED=$(curl -s -X POST "$AUTH_URL/auth/delegate" \
    -H "Authorization: Bearer $ROBERT_PORTAL_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "target_user_id": "'$LINDA_USER_ID'"
    }')

  # Write the Zanzibar tuple for Linda
  curl -X POST "$AUTH_URL/zanzibar/stores/$MEDCORE_ORG_ID/relationships" \
    -H "Authorization: Bearer $ROBERT_PORTAL_TOKEN" \
    -d '{
      "org_id": "'$CARDIO_WARD_ID'",
      "tuples": [{
        "object": "patient:P-8821",
        "relation": "family_proxy",
        "subject": "user:'$LINDA_USER_ID'",
        "metadata": {"authorized_by": "'$ROBERT_USER_ID'", "relationship": "spouse"}
      }]
    }'

  Linda can now log into the patient portal and view Robert's demographics, labs, vitals, and
  discharge summaries. She cannot read clinical notes (family_proxy doesn't have that). She
  cannot see any other patient.

  Robert can revoke her access at any time from his portal account.

  ---
  Step 9: Service API Keys — Lab System, PACS, Pharmacy

  Automated systems that write results back to MedCore.

  9a: Lab System API key

  The lab system receives orders and writes results back. It needs to read pending orders
  and write results. That's it.

  LAB_KEY=$(curl -s -X POST "$AUTH_URL/api-keys/" \
    -H "Authorization: Bearer $SARAH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "lab-system-integration",
      "description": "Automated lab result delivery from LabCore LIS",
      "permissions": [
        "medcore.read.lab_orders",
        "medcore.write.lab_results",
        "medcore.read.patient_demographics"
      ],
      "metadata": {
        "system": "labcore_lis",
        "vendor": "LabCore Inc",
        "environment": "production",
        "hl7_version": "2.5.1"
      }
    }')
  LAB_API_KEY=$(echo "$LAB_KEY" | jq -r '.key')

  9b: PACS (Radiology) API key

  PACS_KEY=$(curl -s -X POST "$AUTH_URL/api-keys/" \
    -H "Authorization: Bearer $SARAH_TOKEN" \
    -d '{
      "name": "pacs-radiology-integration",
      "description": "DICOM imaging results from Radiology PACS",
      "permissions": [
        "medcore.read.imaging_orders",
        "medcore.write.imaging_results",
        "medcore.read.patient_demographics"
      ],
      "metadata": {
        "system": "radiology_pacs",
        "vendor": "ImagingPro Systems",
        "dicom_version": "3.0"
      }
    }')
  PACS_API_KEY=$(echo "$PACS_KEY" | jq -r '.key')

  9c: Pharmacy System API key

  PHARMACY_KEY=$(curl -s -X POST "$AUTH_URL/api-keys/" \
    -H "Authorization: Bearer $SARAH_TOKEN" \
    -d '{
      "name": "pharmacy-system",
      "description": "Pharmacy dispensing confirmation and interaction checking",
      "permissions": [
        "medcore.read.prescriptions",
        "medcore.write.dispensing",
        "medcore.read.medications",
        "medcore.read.patient_demographics"
      ],
      "metadata": {
        "system": "pharmsoft",
        "vendor": "PharmSoft Solutions"
      }
    }')

  What each service can do:

  ┌──────────────────┬──────────────────────┬─────────────────────┬──────────────────────┬─────────────────────┐
  │     Service      │  Read patient info   │  Read orders        │  Write results       │  Write prescriptions│
  ├──────────────────┼──────────────────────┼─────────────────────┼──────────────────────┼─────────────────────┤
  │ Lab System       │ Demographics only    │ Lab orders only     │ Lab results only     │ No                  │
  ├──────────────────┼──────────────────────┼─────────────────────┼──────────────────────┼─────────────────────┤
  │ PACS (Radiology) │ Demographics only    │ Imaging orders only │ Imaging results only │ No                  │
  ├──────────────────┼──────────────────────┼─────────────────────┼──────────────────────┼─────────────────────┤
  │ Pharmacy         │ Demographics only    │ Prescriptions only  │ Dispensing records   │ No                  │
  └──────────────────┴──────────────────────┴─────────────────────┴──────────────────────┴─────────────────────┘

  None of these systems can read clinical notes. None can prescribe. If the lab system is
  compromised, the attacker can read pending orders and write false lab results — serious,
  but contained. They cannot access patient notes, cannot prescribe, cannot see imaging.

  ---
  Step 10: The HIPAA Audit Trail

  Every record access is logged. Here is how.

  10a: Middleware that logs every clinical access

  # app/middleware/hipaa_audit.py
  class HIPAAAuditMiddleware:
      AUDITED_ROUTES = [
          "/patients/", "/clinical-notes/", "/medications/",
          "/lab-results/", "/imaging/", "/vitals/"
      ]

      async def __call__(self, request: Request, call_next):
          # Only audit clinical data routes
          if not any(r in request.url.path for r in self.AUDITED_ROUTES):
              return await call_next(request)

          # Extract identity from token or API key
          actor = request.state.user  # Set by auth middleware

          start = time.time()
          response = await call_next(request)
          duration_ms = int((time.time() - start) * 1000)

          # Write audit log entry
          await audit_client.post("/audit/logs", json={
              "actor_id":      actor.user_id,
              "actor_type":    "user" if not actor.is_service else "service",
              "actor_role":    actor.metadata.get("clinical_role", "unknown"),
              "action":        request.method,
              "resource_path": request.url.path,
              "resource_id":   extract_patient_id(request.url.path),
              "org_id":        actor.org_id,
              "result":        "allowed" if response.status_code < 400 else "denied",
              "status_code":   response.status_code,
              "duration_ms":   duration_ms,
              "ip_address":    request.client.host,
              "user_agent":    request.headers.get("user-agent"),
              "timestamp":     datetime.utcnow().isoformat(),
              "session_id":    actor.session_id,
              "delegation_id": actor.metadata.get("delegation_id")
          })

          return response

  10b: Querying the audit log

  # Who accessed Patient P-8821 in the last 24 hours?
  curl -X GET "$AUTH_URL/audit/logs" \
    -H "Authorization: Bearer $COMPLIANCE_TOKEN" \
    -G \
    --data-urlencode "resource_id=P-8821" \
    --data-urlencode "since=2026-11-14T00:00:00Z"

  # Returns every access, by whom, when, what they read, whether it was allowed or denied

  # Did Dr. Webb access any patient other than P-8821 during her consult?
  curl -X GET "$AUTH_URL/audit/logs" \
    -H "Authorization: Bearer $COMPLIANCE_TOKEN" \
    -G \
    --data-urlencode "actor_id=$WEBB_USER_ID" \
    --data-urlencode "since=2026-11-14T00:00:00Z"

  # Returns all of Webb's actions — should only show P-8821 access
  # If she somehow accessed P-8850, it would show here as "denied"

  # Show all break-glass events this week
  curl -X GET "$AUTH_URL/audit/logs" \
    -H "Authorization: Bearer $COMPLIANCE_TOKEN" \
    -G \
    --data-urlencode "event_type=break_glass" \
    --data-urlencode "org_id=$MEDCORE_ORG_ID"

  10c: The compliance officer's cross-org view

  The compliance officer is in the MedCore root org with cross_tenant:

  curl -X POST "$AUTH_URL/permissions/grant?user_id=$COMPLIANCE_OFFICER_USER_ID&org_id=$MEDCORE_ORG_ID&permission=medcore.cross_tenant" \
    -H "Authorization: Bearer $SARAH_TOKEN"

  # Now compliance can query audit logs across ALL departments
  curl -X GET "$AUTH_URL/audit/logs?event_type=break_glass&org_id=ALL" \
    -H "Authorization: Bearer $COMPLIANCE_TOKEN"

  ---
  Step 11: Moving Maria Between Wards

  Situation: Nurse Maria Santos is transferring from Cardiology Ward to Pediatrics.

  This must be clean. Maria cannot retain access to Cardiology patients after she leaves.
  HIPAA minimum necessary means she should only have access to patients she's actively caring for.

  11a: Remove Maria's patient assignments (Zanzibar first)

  # Remove all Zanzibar tuples for Maria in Cardiology Ward
  curl -X DELETE "$AUTH_URL/zanzibar/stores/$MEDCORE_ORG_ID/relationships" \
    -H "Authorization: Bearer $SARAH_TOKEN" \
    -d '{
      "org_id": "'$CARDIO_WARD_ID'",
      "filter": {
        "subject": "user:'$MARIA_USER_ID'"
      }
    }'
  # Returns: {"deleted": 12}
  # Maria was nurse on 12 patients. All 12 assignments gone instantly.
  # Any in-flight request from Maria to those patients now returns 403.

  11b: Remove Maria from the Cardiology Ward org

  curl -X DELETE "$AUTH_URL/organizations/$CARDIO_WARD_ID/users/$MARIA_USER_ID" \
    -H "Authorization: Bearer $SARAH_TOKEN"

  # Maria's tokens scoped to the Cardiology Ward are now invalid.
  # She cannot switch-org back into the ward.

  11c: Reassign Maria's Cardiology patients to the on-call nurse

  # Cardiology head reassigns Maria's 12 patients to Nurse Chen (on-call)
  for patient_id in P-8821 P-8823 P-8825 P-8827 P-8829 P-8831 P-8833 P-8835 P-8837 P-8839 P-8841 P-8843; do
    curl -s -X POST "$AUTH_URL/zanzibar/stores/$MEDCORE_ORG_ID/relationships" \
      -H "Authorization: Bearer $CARDIO_HEAD_TOKEN" \
      -d '{
        "org_id": "'$CARDIO_WARD_ID'",
        "tuples": [{
          "object": "patient:'$patient_id'",
          "relation": "nurse",
          "subject": "user:'$CHEN_ON_CALL_USER_ID'"
        }]
      }'
  done

  11d: Add Maria to Pediatrics Ward

  # Pediatrics head invites Maria
  curl -X POST "$AUTH_URL/organizations/$PEDS_WARD_ID/invite" \
    -H "Authorization: Bearer $PEDS_HEAD_TOKEN" \
    -d '{
      "email": "maria.santos@medcore.hospital",
      "role": "member",
      "permissions": [
        "medcore.read.patient_demographics",
        "medcore.read.clinical_notes", "medcore.write.clinical_notes",
        "medcore.create.clinical_notes",
        "medcore.read.medications", "medcore.administer.medications",
        "medcore.read.lab_results", "medcore.read.imaging_results",
        "medcore.read.vitals", "medcore.write.vitals",
        "medcore.read.care_plans"
      ],
      "metadata": {"clinical_role": "rn", "transfer_from": "cardiology"}
    }'

  # Assign Maria to her new Pediatrics patients
  curl -X POST "$AUTH_URL/zanzibar/stores/$MEDCORE_ORG_ID/relationships" \
    -H "Authorization: Bearer $PEDS_HEAD_TOKEN" \
    -d '{
      "org_id": "'$PEDS_WARD_ID'",
      "tuples": [
        {"object": "patient:P-2201", "relation": "nurse", "subject": "user:'$MARIA_USER_ID'"},
        {"object": "patient:P-2202", "relation": "nurse", "subject": "user:'$MARIA_USER_ID'"}
      ]
    }'

  Maria's state before and after:

  BEFORE transfer:
  ├── Cardiology Ward org: member
  │   └── Zanzibar: nurse on P-8821, P-8823, ..., P-8843 (12 patients)
  └── Pediatrics Ward org: not a member

  AFTER transfer:
  ├── Cardiology Ward org: NOT a member, zero tuples
  └── Pediatrics Ward org: member
      └── Zanzibar: nurse on P-2201, P-2202 (new patients)

  Verify clean separation:

  # Can Maria still read a Cardiology patient? (she should NOT)
  curl -X POST "$AUTH_URL/zanzibar/stores/$MEDCORE_ORG_ID/check" \
    -G \
    --data-urlencode "org_id=$CARDIO_WARD_ID" \
    --data-urlencode "subject=user:$MARIA_USER_ID" \
    --data-urlencode "permission=read_notes" \
    --data-urlencode "object=patient:P-8821"
  # {"allowed": false} — clean

  ---
  Summary: The Complete MedCore Architecture

  MedCore Hospital (root org)
  │  Dr. Sarah Okafor (CMO, ancestor access to all departments)
  │  HIPAA Compliance Officer (cross_tenant, reads all audit logs)
  │  SERVICE_API_KEY: manages the whole platform
  │
  ├── Cardiology Department (information boundary)
  │   │
  │   ├── Cardiology Ward
  │   │   │  Staff: Dr. Chen (attending), Dr. Patel (resident), Nurse Maria -> TRANSFERRED
  │   │   │  Staff: Nurse Chen On-Call (now covers Maria's patients)
  │   │   │
  │   │   │  Zanzibar patient assignments:
  │   │   │    P-8821: attending=Chen, resident=Patel, consultant=Webb (72h), patient_self=Robert, family_proxy=Linda
  │   │   │    P-8850: attending=Rodriguez, break_glass_event logged
  │   │   │    P-8821..P-8843: nurse=Chen-On-Call (Maria's former patients reassigned)
  │   │   │
  │   │   └── Patient Portal: /login/medcore (open signup, default_role=end_user)
  │   │
  │   └── Cardiac ICU
  │       └── ICU team, isolated from Cardiology Ward ward patients
  │
  ├── Neurology Department (isolated from Cardiology)
  │   └── Dr. Webb's home department — her consult was in Cardiology via delegation
  │
  ├── Pediatrics Department
  │   └── Pediatrics Ward: Nurse Maria (just transferred in, 2 patient assignments)
  │
  ├── Oncology, Emergency departments (each isolated)
  │
  └── Services
      ├── Lab System API key      (read.lab_orders, write.lab_results only)
      ├── PACS API key            (read.imaging_orders, write.imaging_results only)
      └── Pharmacy API key        (read.prescriptions, write.dispensing only)

  Access control summary:

  ┌────────────────────────┬──────────────────┬───────────────────────────────────────────────────────┐
  │       Who              │  Can see         │  Cannot see                                           │
  ├────────────────────────┼──────────────────┼───────────────────────────────────────────────────────┤
  │ Dr. Chen               │ His 12 patients  │ The other 68 patients in the ward                     │
  │                        │ (Zanzibar)        │ Any patient in any other department                   │
  ├────────────────────────┼──────────────────┼───────────────────────────────────────────────────────┤
  │ Dr. Webb (consult)     │ P-8821 only,      │ Any other patient, anywhere                           │
  │                        │ 72 hours          │ (delegation scoped + single Zanzibar tuple)           │
  ├────────────────────────┼──────────────────┼───────────────────────────────────────────────────────┤
  │ Nurse Maria (post-xfer)│ Her 2 Peds        │ Her 12 former Cardiology patients (tuples deleted)    │
  │                        │ patients          │ Any Oncology, Neuro, ED patients                      │
  ├────────────────────────┼──────────────────┼───────────────────────────────────────────────────────┤
  │ Robert Kim (portal)    │ His own records   │ Any clinical notes (not in patient_self permissions)  │
  │                        │ (patient_self)    │ Any other patient                                     │
  ├────────────────────────┼──────────────────┼───────────────────────────────────────────────────────┤
  │ Linda Kim (proxy)      │ Robert's labs,    │ Robert's clinical notes, prescriptions                │
  │                        │ vitals, demos     │ Any other patient                                     │
  ├────────────────────────┼──────────────────┼───────────────────────────────────────────────────────┤
  │ Lab System (API key)   │ Pending lab       │ Clinical notes, imaging, medications, vitals          │
  │                        │ orders only        │ Any patient without an open lab order                 │
  ├────────────────────────┼──────────────────┼───────────────────────────────────────────────────────┤
  │ Sarah (CMO)            │ Everything        │ Nothing (ancestor access to all departments)          │
  ├────────────────────────┼──────────────────┼───────────────────────────────────────────────────────┤
  │ Compliance Officer     │ All audit logs    │ Patient data (audit.cross_tenant, not clinical)       │
  └────────────────────────┴──────────────────┴───────────────────────────────────────────────────────┘

  HIPAA compliance properties:
  - Minimum necessary: every access is scoped to exactly what the role requires
  - Audit trail: every clinical record access is logged with actor, resource, timestamp
  - Break-glass: emergency override exists but triggers immediate compliance alert
  - Automatic expiry: consultant delegations, break-glass tuples expire automatically
  - Transfer cleanup: nurse transfer removes all old tuples atomically before adding new
  - Patient control: patients authorize their own proxy access and can revoke it
  - Service isolation: lab, PACS, pharmacy can only write their own result type — nothing else
