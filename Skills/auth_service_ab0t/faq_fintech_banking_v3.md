# Fintech / Banking — Complete Auth Guide
## ArcPay: A Licensed Payment Institution at Scale

**Scenario:** Sofia Reyes co-founded ArcPay, a licensed e-money institution (EMI) regulated
by the FCA in the UK and FinCEN in the US. ArcPay processes high-value wire transfers and
ACH payments for corporate clients, issues virtual cards for expense management, and holds
client funds in segregated accounts. They process £2.4B annually. Getting auth wrong is not
a compliance footnote — it is a licence-revocation event.

**What they need:**
- **PCI-DSS isolation** — cardholder data (PANs, CVVs) in a hardened vault org; access is
  time-scoped and logged to the individual, not the service
- **Transaction-scoped access** — a permission to act on a specific transaction, not a blanket
  "approve transfers" that could be replayed
- **Dual-control (4-eyes)** — high-value transfers require two independent humans to authorise;
  the initiator cannot be one of the approvers; enforced structurally, not by policy
- **Regulator read-only accounts** — FCA and FinCEN examiners get time-bounded, cross-tenant,
  read-only access during examination windows; every action they take is logged at higher retention
- **Segregation of duties** — payment ops who initiate transfers have a different permission set
  than those who approve them; no single person holds both
- **Instant revocation** — a suspicious analyst's access to all client accounts and card vault
  is killed in one call, active sessions terminated, in-flight approvals invalidated

**Characters:**
- **Sofia Reyes** — CTO/co-founder, owns the master org
- **David Park** — Head of Compliance, manages regulator access and audit
- **Marcus Webb** — Payment Ops Analyst (initiates transfers, cannot approve)
- **Chen Zhao** — Payment Ops Approver (approves transfers, cannot initiate)
- **Priya Singh** — second approver on the dual-control team
- **Janet Mills** — FCA Examiner (regulator, read-only)
- **Robert Torres** — FinCEN Examiner (regulator, read-only)
- **ACME Corp** — enterprise client, corporate payments

```bash
AUTH_URL="https://auth.service.ab0t.com"
MASTER_SLUG="arcpay"
```

---

## Step 1: Sofia bootstraps the ArcPay platform

**Situation:** ArcPay's auth structure reflects its regulatory obligations. There are four
top-level organisational concerns, each isolated from the others.

```bash
# Register Sofia
SOFIA_TOKEN=$(curl -s -X POST "$AUTH_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "sofia@arcpay.io",
    "password": "...",
    "name": "Sofia Reyes"
  }' | jq -r '.access_token')

# 1. Master platform org — ArcPay staff, technicians, finance
MASTER_ORG=$(curl -s -X POST "$AUTH_URL/organizations" \
  -H "Authorization: Bearer $SOFIA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ArcPay",
    "slug": "arcpay",
    "billing_type": "enterprise",
    "metadata": {"org_type": "platform_master", "regulated": true}
  }')
MASTER_ORG_ID=$(echo $MASTER_ORG | jq -r '.id')

# 2. PCI-DSS vault — cardholder data ONLY, separate namespace
PCI_ORG=$(curl -s -X POST "$AUTH_URL/organizations" \
  -H "Authorization: Bearer $SOFIA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ArcPay PCI Vault",
    "slug": "arcpay-pci-vault",
    "parent_id": "'"$MASTER_ORG_ID"'",
    "billing_type": "enterprise",
    "metadata": {
      "org_type": "pci_vault",
      "pci_dss_scope": "CDE",
      "data_classification": "cardholder_data",
      "access_logging": "full",
      "session_max_minutes": 15
    }
  }')
PCI_ORG_ID=$(echo $PCI_ORG | jq -r '.id')

# 3. Regulator portal — examiners from FCA, FinCEN, OCC
REGULATOR_ORG=$(curl -s -X POST "$AUTH_URL/organizations" \
  -H "Authorization: Bearer $SOFIA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ArcPay Regulatory Portal",
    "slug": "arcpay-regulators",
    "parent_id": "'"$MASTER_ORG_ID"'",
    "billing_type": "enterprise",
    "metadata": {
      "org_type": "regulator_portal",
      "access_logging": "extended_retention_7yr",
      "mfa_required": true
    }
  }')
REGULATOR_ORG_ID=$(echo $REGULATOR_ORG | jq -r '.id')

# 4. Client workspaces will be created per-customer (Step 3)

echo "Platform orgs provisioned:"
echo "  Master:     $MASTER_ORG_ID"
echo "  PCI Vault:  $PCI_ORG_ID"
echo "  Regulators: $REGULATOR_ORG_ID"
```

### Define payment operations roles

```bash
# Initiator — can create transfer requests, CANNOT approve
curl -s -X POST "$AUTH_URL/organizations/$MASTER_ORG_ID/roles" \
  -H "Authorization: Bearer $SOFIA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "payments_initiator",
    "permissions": [
      "payments.initiate.wire_transfers",
      "payments.initiate.ach_transfers",
      "payments.read.transfers",
      "payments.read.accounts",
      "payments.write.transfer_notes"
    ]
  }'

# Approver — can approve/reject requests, CANNOT initiate
curl -s -X POST "$AUTH_URL/organizations/$MASTER_ORG_ID/roles" \
  -H "Authorization: Bearer $SOFIA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "payments_approver",
    "permissions": [
      "payments.approve.wire_transfers",
      "payments.approve.ach_transfers",
      "payments.reject.transfers",
      "payments.read.transfers",
      "payments.read.accounts",
      "payments.read.compliance_flags"
    ]
  }'

# Compliance officer — read everything, approve compliance holds
curl -s -X POST "$AUTH_URL/organizations/$MASTER_ORG_ID/roles" \
  -H "Authorization: Bearer $SOFIA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "compliance_officer",
    "permissions": [
      "payments.read.transfers",
      "payments.read.accounts",
      "payments.read.audit_logs",
      "payments.approve.compliance_holds",
      "payments.write.sar_reports",
      "payments.read.kyc_data",
      "cross_tenant"
    ]
  }'

# PCI analyst — time-limited card data access (granted via delegation, not standing)
# NOTE: no standing role grants pci.read.card_data — only delegation tokens do
curl -s -X POST "$AUTH_URL/organizations/$PCI_ORG_ID/roles" \
  -H "Authorization: Bearer $SOFIA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "pci_analyst",
    "permissions": [
      "pci.read.card_metadata",
      "pci.write.dispute_flags"
    ]
  }'
# Note: pci.read.card_data (full PAN) is NEVER a standing role — see Step 4
```

> **Concept: Segregation of duties (SoD) by permission design**
>
> The `payments_initiator` and `payments_approver` roles contain **disjoint permission sets**.
> No role holds both `payments.initiate.*` and `payments.approve.*`. A single user cannot
> hold both roles simultaneously (enforced by the application layer in Step 5).
>
> This is the auth-level implementation of the dual-control principle. The structural
> impossibility of one person holding both capabilities is more reliable than a policy
> that says "don't approve your own transfers."

---

## Step 2: Assign Marcus and Chen

```bash
# Marcus — initiator only
MARCUS_TOKEN=$(curl -s -X POST "$AUTH_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "marcus@arcpay.io",
    "password": "...",
    "name": "Marcus Webb"
  }' | jq -r '.access_token')

MARCUS_USER_ID=$(curl -s "$AUTH_URL/users/me" \
  -H "Authorization: Bearer $MARCUS_TOKEN" | jq -r '.id')

curl -s -X POST "$AUTH_URL/organizations/$MASTER_ORG_ID/members/$MARCUS_USER_ID" \
  -H "Authorization: Bearer $SOFIA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "payments_initiator"}'

# Chen — approver only
CHEN_USER_ID="usr_chen"
curl -s -X POST "$AUTH_URL/organizations/$MASTER_ORG_ID/members/$CHEN_USER_ID" \
  -H "Authorization: Bearer $SOFIA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "payments_approver"}'

# Priya — second approver (required for high-value transfers)
PRIYA_USER_ID="usr_priya"
curl -s -X POST "$AUTH_URL/organizations/$MASTER_ORG_ID/members/$PRIYA_USER_ID" \
  -H "Authorization: Bearer $SOFIA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "payments_approver"}'
```

> **What Marcus can and cannot do:**
>
> | Action | Marcus (initiator) | Chen/Priya (approver) |
> |--------|-------------------|----------------------|
> | Create transfer request | ✓ | ✗ (403) |
> | Approve a transfer | ✗ (403) | ✓ |
> | Reject a transfer | ✗ (403) | ✓ |
> | Read transfer status | ✓ | ✓ |
> | View compliance flags | ✗ (403) | ✓ |
> | View full card PAN | ✗ (requires delegation) | ✗ (requires delegation) |
>
> These are not application-level checks on top of auth — they are auth-level permission
> failures. The API returns 403 before ArcPay's business logic even runs.

---

## Step 3: Client workspace onboarding — ACME Corp

**Situation:** ACME Corp is a corporate client. Their finance team uses ArcPay to process
international wire transfers. Their workspace is completely isolated — their transaction
history, account balances, and user list are invisible to other ArcPay clients.

```bash
# Provision ACME Corp workspace
ACME_ORG=$(curl -s -X POST "$AUTH_URL/organizations" \
  -H "Authorization: Bearer $SOFIA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ACME Corp — ArcPay",
    "slug": "acme-arcpay",
    "parent_id": "'"$MASTER_ORG_ID"'",
    "billing_type": "postpaid",
    "metadata": {
      "org_type": "client_workspace",
      "kyb_status": "verified",
      "kyb_verified_at": "2026-01-15",
      "risk_tier": "standard",
      "transfer_limit_daily_gbp": 500000
    }
  }')
ACME_ORG_ID=$(echo $ACME_ORG | jq -r '.id')

# Client login config — ACME finance team uses SSO (Okta), invitation only
curl -s -X PUT "$AUTH_URL/organizations/$ACME_ORG_ID/login-config" \
  -H "Authorization: Bearer $SOFIA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "auth_methods": {
      "email_password": false,
      "signup_enabled": false,
      "invitation_only": true
    },
    "providers": [{
      "type": "saml",
      "config": {
        "sso_url": "https://acmecorp.okta.com/app/saml/sso",
        "entity_id": "https://acmecorp.okta.com",
        "certificate": "'"$ACME_SAML_CERT"'"
      },
      "jit_provisioning": true,
      "jit_default_role": "member"
    }],
    "session_config": {
      "session_duration_hours": 8,
      "idle_timeout_minutes": 30,
      "require_mfa": true
    },
    "branding": {
      "company_name": "ACME Corp Payments",
      "logo_url": "https://cdn.arcpay.io/clients/acme/logo.png",
      "primary_color": "#003087"
    }
  }'

# ACME finance director as org admin
curl -s -X POST "$AUTH_URL/organizations/$ACME_ORG_ID/invite" \
  -H "Authorization: Bearer $SOFIA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "finance-director@acmecorp.com",
    "role": "admin"
  }'
```

---

## Step 4: PCI-DSS isolation — the cardholder data vault

**Situation:** ACME Corp's finance team has ArcPay virtual cards. The card numbers (PANs),
expiry dates, and CVVs are stored in `arcpay-pci-vault`. No one has standing access to
full card data. Access is granted per-session, per-purpose, time-bounded, and logged to
the second.

> **PCI-DSS Requirement 7:** "Restrict access to system components and cardholder data
> by business need to know." This translates to: no standing permissions on full PAN data.
> Access is ephemeral, always justified, always attributed to a named individual.

### 4a. The PCI vault org configuration

```bash
# PCI vault login config — maximally restrictive
curl -s -X PUT "$AUTH_URL/organizations/$PCI_ORG_ID/login-config" \
  -H "Authorization: Bearer $SOFIA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "auth_methods": {
      "email_password": false,
      "signup_enabled": false,
      "invitation_only": true
    },
    "session_config": {
      "session_duration_minutes": 15,
      "idle_timeout_minutes": 5,
      "require_mfa": true,
      "single_session_only": true
    },
    "audit": {
      "log_all_requests": true,
      "retention_years": 7,
      "pci_mode": true
    }
  }'
```

### 4b. Requesting time-limited PAN access

```bash
# A support analyst needs to view a specific card's PAN to resolve a dispute
# They submit a request with a business justification

# ArcPay's support system calls:
# POST /auth/delegate creates a JWT where Sofia acts AS the analyst.
# NOTE: /auth/delegate only accepts {"target_user_id"} — permission/resource scoping
# and reason logging must be handled at the application layer (record in incident system).
PAN_ACCESS=$(curl -s -X POST "$AUTH_URL/auth/delegate" \
  -H "Authorization: Bearer $SOFIA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target_user_id": "'"$ANALYST_USER_ID"'"
  }')

PAN_TOKEN=$(echo $PAN_ACCESS | jq -r '.access_token')
# The caller (Sofia) now has a token acting as the analyst.
# Log the justification externally:
# DISPUTE-2026-0847: Cardholder disputes TXN-9912. PAN access approved by compliance@arcpay.io.
# Scoped to card_acme_4521. Caller: sofia@arcpay.io. Time: $(date -u)
```

### 4c. What the audit log records for every PAN access

```json
{
  "timestamp": "2026-02-25T14:23:01Z",
  "event": "pci.card_data.read",
  "actor": {
    "user_id": "usr_analyst_kim",
    "email": "kim@arcpay.io",
    "ip": "10.0.14.22",
    "user_agent": "ArcPay-Support/2.1"
  },
  "resource": {
    "card_id": "card_acme_4521",
    "org_id": "org_acme_arcpay",
    "pan_last4": "4521"
  },
  "delegation": {
    "authorized_by": "compliance@arcpay.io",
    "reason": "DISPUTE-2026-0847: ...",
    "token_issued_at": "2026-02-25T14:22:55Z",
    "token_expires_at": "2026-02-25T14:37:55Z"
  },
  "pci_retention_until": "2033-02-25"
}
```

> **Why this matters for PCI-DSS audits:**
>
> PCI-DSS Requirement 10 mandates audit trails with: who accessed cardholder data, when,
> from where, and what they did. This log record satisfies every field:
> - **Who**: `kim@arcpay.io` (individual, not a service account)
> - **When**: `2026-02-25T14:23:01Z` (millisecond precision)
> - **From where**: IP `10.0.14.22` (on-network, not remote — would flag otherwise)
> - **Why**: `DISPUTE-2026-0847` (business justification, approval chain)
> - **What**: read only, scoped to one card, token expired after 15 minutes
>
> During a QSA audit, ArcPay can produce this log for every PAN access in the past 12
> months. The answer to "who had access to cardholder data?" is not "our payment ops team"
> — it is a named log entry for every single access event.

### 4d. The vault in ArcPay's API

```python
# ArcPay's card data endpoint
from ab0t_auth import AuthGuard, AuthenticatedUser
from fastapi import Depends, HTTPException

@router.get("/cards/{card_id}/pan")
async def get_card_pan(
    card_id: str,
    user: AuthenticatedUser = Depends(AuthGuard(
        required_permissions=["pci.read.card_data"],
        org_slug="arcpay-pci-vault"  # must be authenticated into the vault org
    ))
):
    """
    No standing permission grants pci.read.card_data.
    This endpoint is only reachable via a delegation token.
    The delegation token is scoped to a specific card_id.
    """
    # Verify the token scope matches the requested card
    if user.resource_scope.get("card_id") != card_id:
        raise HTTPException(403, "Token not scoped to this card")

    # Every read is logged at the auth service level AND here
    await audit_log.record_pan_access(
        user_id=user.user_id,
        card_id=card_id,
        reason=user.delegation_reason
    )

    card = await pci_vault.get_card(card_id)
    return {"pan": card.pan, "expiry": card.expiry, "cvv": card.cvv}
    # Token expires in 15 min — after that, 401 on all requests
```

---

## Step 5: Dual-control (4-eyes) — high-value wire transfers

**Situation:** ACME Corp's finance director initiates a £450,000 wire transfer to a
supplier in Germany. ArcPay's policy requires:

- Transfers over £10,000: one approver (different person from initiator)
- Transfers over £250,000: **two independent approvers** (neither can be the initiator)
- Transfers over £1,000,000: two approvers + compliance officer sign-off

This is the 4-eyes (dual-control) principle: no single individual can move large sums.

### 5a. Marcus initiates the transfer

```bash
# Marcus creates the transfer request
TRANSFER=$(curl -s -X POST "$ARCPAY_API/transfers" \
  -H "Authorization: Bearer $MARCUS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 450000,
    "currency": "GBP",
    "destination_iban": "DE89370400440532013000",
    "destination_name": "Muller GmbH",
    "reference": "INV-2026-0312",
    "org_id": "'"$ACME_ORG_ID"'",
    "initiated_by": "'"$MARCUS_USER_ID"'"
  }')

TRANSFER_ID=$(echo $TRANSFER | jq -r '.id')
echo "Transfer created: $TRANSFER_ID — status: pending_approval"
# Marcus cannot approve this — he lacks payments.approve.wire_transfers
```

### 5b. ArcPay's backend creates transaction-scoped approval tokens

```python
# When a transfer is created, ArcPay's backend generates scoped approval tokens
# These tokens authorise a specific approver to act on a specific transfer ONLY

async def create_approval_request(transfer_id: str, amount: float, initiator_id: str):
    """Create approval tokens scoped to this exact transfer."""

    required_approvers = 2 if amount >= 250_000 else 1

    approval_requests = []
    for i in range(required_approvers):
        # NOTE: /auth/delegate only accepts {"target_user_id"} and creates a JWT
        # where the caller acts AS the target. For transfer approval workflows,
        # the permission scoping and one-time-use constraints are application-layer
        # concerns — enforce them in your transfer service, not in the auth delegate call.
        #
        # Pattern: grant each eligible approver the ability to act — your transfer
        # service checks that the approver is not the initiator before accepting.
        token_resp = await auth_client.post("/delegation/grant", json={
            "actor_id": f"approver_slot_{i+1}",  # your internal approval token concept
            "scope": [f"payments.approve.wire_transfer:{transfer_id}"],
            "expires_in_hours": 24  # 24 hours to approve
            # initiator exclusion + one_time_use enforced by your transfer service
        })

        approval_requests.append({
            "slot": i + 1,
            "approval_token": token_resp["access_token"],
            "required_permission": f"payments.approve.wire_transfer:{transfer_id}",
            "expires_at": token_resp.get("expires_at")
        })

    # Store approval slots against the transfer
    await db.create_approval_slots(transfer_id, approval_requests)

    # Notify eligible approvers (Chen, Priya — not Marcus)
    await notify_approvers(transfer_id, required_approvers, exclude=[initiator_id])

    return approval_requests
```

> **Concept: Transaction-scoped permissions**
>
> `payments.approve.wire_transfer:txn_abc123` is a permission scoped to one transfer.
> It is not "approve any transfer" — it is "approve THIS transfer". This means:
>
> - An approver token for transfer A cannot be used on transfer B (cryptographically blocked)
> - Once used (one_time_use), the approval token is consumed — cannot be replayed
> - An attacker who intercepts an approval token can only approve the one transfer
>   it was created for, and only before it expires
> - The audit log shows: "Chen approved transfer txn_abc123 at 14:32" — not just
>   "Chen approved a transfer"

### 5c. Chen approves — slot 1 of 2

```bash
# Chen receives a notification with the approval token embedded in a secure link
# He reviews the transfer details and approves

curl -s -X POST "$ARCPAY_API/transfers/$TRANSFER_ID/approve" \
  -H "Authorization: Bearer $CHEN_APPROVAL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "decision": "approved",
    "note": "Verified against PO-2026-0312. Supplier KYC on file."
  }'

# Response:
# {
#   "transfer_id": "txn_abc123",
#   "approval_slot": 1,
#   "approved_by": "chen@arcpay.io",
#   "approved_at": "2026-02-25T14:32:11Z",
#   "remaining_approvals_required": 1,
#   "status": "pending_second_approval"
# }
```

### 5d. Priya approves — slot 2 of 2

```bash
curl -s -X POST "$ARCPAY_API/transfers/$TRANSFER_ID/approve" \
  -H "Authorization: Bearer $PRIYA_APPROVAL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "decision": "approved",
    "note": "Second approval confirmed. Amounts match contract schedule."
  }'

# Response:
# {
#   "transfer_id": "txn_abc123",
#   "approval_slot": 2,
#   "approved_by": "priya@arcpay.io",
#   "approved_at": "2026-02-25T14:41:07Z",
#   "remaining_approvals_required": 0,
#   "status": "executing"
# }
# Transfer is now submitted to the payment network
```

### 5e. What happens if Marcus tries to approve his own transfer

```bash
curl -s -X POST "$ARCPAY_API/transfers/$TRANSFER_ID/approve" \
  -H "Authorization: Bearer $MARCUS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"decision": "approved"}'

# 403 — two separate reasons:
# {
#   "detail": "Approval not permitted",
#   "reasons": [
#     "User does not hold payments.approve.wire_transfers permission",
#     "User is the transfer initiator — self-approval is prohibited"
#   ]
# }
```

> **Why two independent checks?**
>
> The first check (permission) is enforced by the auth service. The second check
> (not the initiator) is enforced by ArcPay's application layer. Both must pass.
>
> Defence in depth: if there were a bug in ArcPay's application check, the permission
> check would still block it. If somehow Marcus were accidentally granted approver
> permissions, the application check would still block it. Neither layer alone is
> sufficient; together they are robust.

### 5f. The full approval chain for £450,000 transfer

```
Marcus (initiator)  →  creates TXN-ABC123  →  status: pending_approval
                                               ↓
                        Auth service issues:
                        - Approval token #1 (scoped: payments.approve.wire_transfer:TXN-ABC123)
                        - Approval token #2 (scoped: payments.approve.wire_transfer:TXN-ABC123)
                        - Both: exclude_user_ids=[marcus], one_time_use=true
                                               ↓
Chen (approver)     →  uses token #1       →  status: pending_second_approval
                        (token #1 consumed)
                                               ↓
Priya (approver)    →  uses token #2       →  status: executing
                        (token #2 consumed)
                                               ↓
Payment network     →  transfer submitted  →  status: settled
```

---

## Step 6: Regulator read-only access — FCA examination

**Situation:** The FCA schedules an annual examination of ArcPay's payment operations.
Examiner Janet Mills needs read access to: all client transaction histories, audit logs,
KYC records, and compliance reports — across ALL client orgs. She cannot modify anything.
Her access is active for the 6-week examination window.

> **The challenge:** Regulators need genuine, unfiltered access to everything. They
> cannot work from a curated export — they need live query capability. But they must
> be completely read-only, and every single query they run must be logged.

### 6a. Configure the regulator portal

```bash
# Regulator portal — strict config
curl -s -X PUT "$AUTH_URL/organizations/$REGULATOR_ORG_ID/login-config" \
  -H "Authorization: Bearer $SOFIA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "auth_methods": {
      "email_password": false,
      "signup_enabled": false,
      "invitation_only": true
    },
    "providers": [{
      "type": "saml",
      "config": {
        "sso_url": "https://fca.gov.uk/saml/sso",
        "entity_id": "fca.gov.uk",
        "certificate": "'"$FCA_SAML_CERT"'"
      }
    }],
    "session_config": {
      "session_duration_hours": 4,
      "idle_timeout_minutes": 30,
      "require_mfa": true,
      "single_session_only": true
    },
    "audit": {
      "log_all_requests": true,
      "retention_years": 10,
      "regulator_mode": true,
      "notify_on_access": "david@arcpay.io"
    },
    "branding": {
      "company_name": "ArcPay Regulatory Portal",
      "tagline": "FCA Examination Access"
    }
  }'
```

### 6b. Create the FCA examiner account

```bash
# David (Head of Compliance) invites Janet for the examination window
curl -s -X POST "$AUTH_URL/organizations/$REGULATOR_ORG_ID/invite" \
  -H "Authorization: Bearer $DAVID_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "janet.mills@fca.org.uk",
    "role": "regulator_examiner",
    "expires_at": "2026-04-08T18:00:00Z",
    "metadata": {
      "regulator": "FCA",
      "examination_ref": "FCA-EXAM-2026-ARC-001",
      "authorised_by": "david@arcpay.io",
      "purpose": "Annual supervisory review under PSREGS 2017"
    }
  }'
```

### 6c. Regulator role — read everything, write nothing

```bash
# Define the examiner role — cross_tenant read-only, no writes anywhere
curl -s -X POST "$AUTH_URL/organizations/$REGULATOR_ORG_ID/roles" \
  -H "Authorization: Bearer $SOFIA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "regulator_examiner",
    "permissions": [
      "payments.read.transfers",
      "payments.read.accounts",
      "payments.read.audit_logs",
      "payments.read.kyc_data",
      "payments.read.sar_reports",
      "payments.read.compliance_reports",
      "payments.read.client_orgs",
      "cross_tenant"
    ]
  }'
# Note: zero payments.write.*, payments.initiate.*, payments.approve.*
# Note: cross_tenant is read-scoped — examiner can query all client orgs
```

### 6d. What Janet sees when she logs in

```bash
# Janet authenticates via FCA SAML SSO
# Gets a token in the arcpay-regulators org

# She can query any client org — e.g., all wire transfers > £100,000 last quarter
curl -s "$ARCPAY_API/transfers" \
  -H "Authorization: Bearer $JANET_TOKEN" \
  -G \
  --data-urlencode "min_amount=100000" \
  --data-urlencode "currency=GBP" \
  --data-urlencode "start=2025-11-01" \
  --data-urlencode "end=2026-01-31" \
  --data-urlencode "cross_tenant=true"
# Returns transfers across ALL client orgs — Janet sees everything

# She can drill into a specific client
curl -s "$ARCPAY_API/organizations/acme-arcpay/kyc" \
  -H "Authorization: Bearer $JANET_TOKEN"
# Returns ACME Corp's KYC records — read only

# She CANNOT do this:
curl -s -X POST "$ARCPAY_API/transfers" \
  -H "Authorization: Bearer $JANET_TOKEN" \
  -d '{"amount": 1, "destination_iban": "...", ...}'
# 403 — Janet does not hold payments.initiate.wire_transfers
```

### 6e. Every regulator query is logged with extended retention

```json
{
  "timestamp": "2026-02-25T10:14:22Z",
  "event": "payments.transfers.list",
  "actor": {
    "user_id": "usr_janet_mills",
    "email": "janet.mills@fca.org.uk",
    "org": "arcpay-regulators",
    "regulator": "FCA",
    "examination_ref": "FCA-EXAM-2026-ARC-001"
  },
  "query": {
    "min_amount": 100000,
    "currency": "GBP",
    "date_range": "2025-11-01/2026-01-31",
    "cross_tenant": true
  },
  "results_returned": 847,
  "log_retention_until": "2036-02-25",
  "notified": ["david@arcpay.io"]
}
```

> **Concept: Why notify David on every regulator access?**
>
> `notify_on_access: "david@arcpay.io"` means ArcPay's Head of Compliance receives
> an email every time Janet logs in and every time she makes a query. This is not
> obstructionism — it is required by FCA Supervision rules: the firm must know when
> regulators are actively examining their systems.
>
> David can also see Janet's full query history in real time. If the regulator is
> drilling into a specific client, David knows to prepare a response. There is no
> surprise in a well-run compliance function.

### 6f. Examination window expires automatically

```bash
# Janet's account invitation included expires_at: 2026-04-08T18:00:00Z
# After that date:
# - Login attempts return 401 (invitation expired)
# - Any active session tokens are invalidated
# - The account remains in the org (for audit) but is non-functional
# David does not need to remember to revoke access — it happens automatically

# If the examination is extended, David updates the expiry:
curl -s -X PATCH "$AUTH_URL/organizations/$REGULATOR_ORG_ID/members/$JANET_USER_ID" \
  -H "Authorization: Bearer $DAVID_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"expires_at": "2026-04-22T18:00:00Z"}'
```

---

## Step 7: Compliance hold — blocking a suspicious transfer

**Situation:** ArcPay's automated AML screening flags a £180,000 transfer from a new
ACME Corp account as suspicious. The compliance system places a hold. David needs to
review it. The transfer cannot proceed until the hold is released.

```python
# AML screening service (service account) places a compliance hold
async def place_compliance_hold(transfer_id: str, reason: str, flags: list):
    # AML service account holds payments.write.compliance_holds
    await arcpay_api.post(f"/transfers/{transfer_id}/hold", {
        "reason": reason,
        "flags": flags,
        "placed_by": "aml-screening-engine",
        "requires_review_by": ["compliance_officer"]
    })

    # Notify compliance team
    await notify_compliance_team(transfer_id, reason)

# David reviews and releases (or escalates to SAR)
@router.post("/transfers/{transfer_id}/hold/release")
async def release_hold(
    transfer_id: str,
    user: AuthenticatedUser = Depends(AuthGuard(
        required_permissions=["payments.approve.compliance_holds"]
    ))
):
    # Only compliance_officer role reaches here
    transfer = await db.get_transfer(transfer_id)

    # David must document his decision
    if not request.json.get("resolution_note"):
        raise HTTPException(422, "Compliance release requires written resolution")

    await db.release_hold(
        transfer_id=transfer_id,
        released_by=user.user_id,
        resolution=request.json["resolution_note"]
    )

    # Audit: hold → release with attribution
    await audit_log.record(
        event="compliance_hold.released",
        transfer_id=transfer_id,
        officer=user.email,
        resolution=request.json["resolution_note"]
    )
```

> **Separation at the compliance layer:**
>
> The AML engine that PLACES holds is a service account — machine identity, no human.
> The compliance officer who RELEASES holds is a human — personal account, MFA required.
> The payment ops team that INITIATED the transfer cannot interact with holds at all.
>
> Three separate identities, three separate permissions, zero overlap.

---

## Step 8: Emergency wire recall — break-glass with dual auth

**Situation:** A fraudulent wire transfer slips through at 11:47 PM. £620,000 is on the
way to a known fraud account. The recall window is 2 hours. This requires emergency action
that bypasses the normal 4-eyes queue — but must still require two people.

```bash
# Sofia (CTO) and David (Compliance) are both paged
# They each call the emergency recall endpoint simultaneously

# Sofia initiates emergency recall
SOFIA_RECALL=$(curl -s -X POST "$ARCPAY_API/transfers/$TRANSFER_ID/emergency-recall" \
  -H "Authorization: Bearer $SOFIA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "FRAUD-2026-0225: Destination flagged by NatWest fraud intelligence at 23:47",
    "authorised_by_role": "owner"
  }')

RECALL_ID=$(echo $SOFIA_RECALL | jq -r '.recall_id')
echo "Recall initiated: $RECALL_ID — awaiting second authorisation"

# David co-authorises (simultaneously, different credential)
curl -s -X POST "$ARCPAY_API/recalls/$RECALL_ID/co-authorise" \
  -H "Authorization: Bearer $DAVID_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "Compliance co-authorisation — FCA reportable incident FRAUD-2026-0225",
    "authorised_by_role": "compliance_officer"
  }'

# Both authorisations received — recall submitted to payment network
# Status: recall_submitted | 23:49:31 — within the recall window
```

> **What makes this different from normal dual-control:**
>
> Normal approvals are async — Chen approves on his next login. Emergency recalls are
> **synchronous and time-critical**. Both Sofia and David must act within minutes of each
> other. The system:
> - Requires two distinct users with two distinct roles (owner + compliance_officer)
> - Sends simultaneous notifications to both via PagerDuty
> - Opens a 30-minute window for the second authorisation
> - If the window expires before second auth, the recall lapses (no one can replay it)
> - Both actors' credentials, IP addresses, and timestamps are logged in the incident record
>
> This creates an incontrovertible record for the FCA Incident Report that will follow.

---

## Step 9: Offboarding a suspicious employee — immediate revocation

**Situation:** An internal investigation flags Marcus as a potential insider threat. At
13:00 on a Tuesday, HR and Security make the decision. By 13:01, Marcus must have zero
access — including killing his current active session mid-workflow.

```bash
#!/bin/bash
# Emergency employee lockout — sub-60-second execution

echo "SECURITY: Locking out $MARCUS_USER_ID — $(date -u)"

# Step 1: Deactivate account immediately — auto-kills all sessions + API keys.
# Single call replaces separate suspend + revoke-sessions + revoke-tokens calls.
curl -s -X POST "$AUTH_URL/users/$MARCUS_USER_ID/deactivate" \
  -H "Authorization: Bearer $SOFIA_TOKEN"
echo "  Account deactivated (all sessions and API keys terminated instantly)"

# To kill sessions in one org only (without full deactivation):
# DELETE /organizations/$ORG_ID/users/$MARCUS_USER_ID/sessions

# Step 2: Remove from all orgs (master + any client orgs)
MARCUS_ORGS=$(curl -s "$AUTH_URL/users/$MARCUS_USER_ID/organizations" \
  -H "Authorization: Bearer $SOFIA_TOKEN" | jq -r '.[].id')

for ORG_ID in $MARCUS_ORGS; do
  curl -s -X DELETE "$AUTH_URL/organizations/$ORG_ID/members/$MARCUS_USER_ID" \
    -H "Authorization: Bearer $SOFIA_TOKEN"
done
echo "  Removed from all orgs"

# Total time: ~8 seconds
echo "Lockout complete: $(date -u)"
```

> **What Marcus experiences at 13:01:**
>
> His current browser session returns 401 on the next API call. The UI shows "Session
> expired — please log in." He cannot log in (account deactivated). Any pending transfer
> he created — if it has not yet entered the approval queue — remains as a pending record
> attributable to him in the audit log, frozen, awaiting a compliance decision.
>
> The audit log records: who deactivated him, at what time, every action he took before
> deactivation, and every action attempted after (all rejected with timestamps).

---

## Step 10: The full ArcPay identity model

```
ArcPay Platform (org_arcpay)
├── Staff
│   ├── Sofia Reyes         (owner)
│   ├── David Park          (compliance_officer, cross_tenant)
│   ├── Marcus Webb         (payments_initiator)
│   ├── Chen Zhao           (payments_approver)
│   └── Priya Singh         (payments_approver)
│
├── Service Accounts
│   ├── aml-screening       [payments.write.compliance_holds]
│   ├── payment-network     [payments.submit.wire_transfers, payments.delegate]
│   └── ops-dashboard       [payments.read.*, cross_tenant, read-only]
│
├── ArcPay PCI Vault (org_arcpay-pci-vault)  ← hard namespace boundary
│   ├── No standing human members
│   ├── Access ONLY via time-limited delegation tokens
│   └── Service Account: card-vault-api [pci.read.card_metadata, pci.write.dispute_flags]
│
├── ArcPay Regulatory Portal (org_arcpay-regulators)
│   ├── Janet Mills (FCA)   [regulator_examiner, cross_tenant, expires 2026-04-08]
│   └── Robert Torres (FinCEN) [regulator_examiner, cross_tenant, expires 2026-03-15]
│
└── Client Workspaces
    ├── ACME Corp (org_acme-arcpay)      [SAML SSO, MFA required]
    ├── TechFlow Ltd (org_techflow-arcpay)
    └── ... (N more clients)
```

---

## Compliance summary — what each regulation gets

| Regulation | Requirement | Implementation |
|------------|-------------|----------------|
| PCI-DSS Req 7 | Restrict access to cardholder data by need-to-know | No standing `pci.read.card_data` — delegation only, per-dispute |
| PCI-DSS Req 10 | Audit trail: who, when, what for cardholder data | Every PAN access logged with user, IP, delegation reason, 7yr retention |
| PCI-DSS Req 8 | Individual user IDs, no shared accounts | Service accounts are named entities; no shared credentials |
| FCA PSREGS 2017 | Operational resilience, access controls | Regulator portal with cross_tenant read, examination window, notify-on-access |
| FCA SUP 15 | Regulator cooperation — access on request | Self-service examiner onboarding, SAML SSO, time-bounded invitation |
| AML/CTF | Segregation: AML screening ≠ payment ops | AML screening is a service account; compliance hold release requires compliance_officer |
| SOX (US) | SoD: no single person can initiate + approve | `payments_initiator` and `payments_approver` are structurally disjoint |
| GDPR Art 25 | Data minimisation, access controls | PCI vault is a separate namespace; clients cannot see other clients |

---

## Quick reference

```bash
# Initiate transfer (initiator role only)
POST /transfers
     {"amount", "currency", "destination_iban", "reference", "org_id"}

# Approve transfer (approver role, scoped token, not initiator)
POST /transfers/{id}/approve
     {"decision": "approved|rejected", "note": "..."}

# Request time-limited PAN access — caller acts AS target user
POST /auth/delegate
     {"target_user_id": "usr_analyst"}
# NOTE: Only accepts target_user_id. Log reason/scope/resource in your compliance system.

# User-to-user delegation (user grants someone to act as them):
POST /delegation/grant
     {"actor_id": "usr_approver", "scope": ["payments.approve.wire_transfer:{txn_id}"], "expires_in_hours": 24}
# Permission scoping + one_time_use enforced by your application layer

# Invite regulator (time-bounded)
POST /organizations/{regulator-org-id}/invite
     {"email": "examiner@fca.org.uk", "role": "regulator_examiner", "expires_at": "..."}

# Emergency lockout — deactivate kills sessions + API keys in one call
POST /users/{user-id}/deactivate
# To kill sessions in one org only (without deactivating):
DELETE /organizations/{org-id}/users/{user-id}/sessions

# Compliance hold
POST /transfers/{id}/hold        {"reason", "flags"}
POST /transfers/{id}/hold/release  {"resolution_note"}  (compliance_officer only)
```
