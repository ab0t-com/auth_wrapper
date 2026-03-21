# MSP / IT Services — Complete Auth Guide
## ClearBridge IT: A Managed Service Provider at Scale

**Scenario:** Rachel Kim founded ClearBridge IT eight years ago. Today they manage IT
for 140 small-to-medium businesses — law firms, manufacturers, dental practices, real
estate agencies. They also have two sub-resellers (TechForce and Pacific IT) who manage
their own clients under the ClearBridge umbrella. ClearBridge uses a single platform auth
service to power every customer portal, every technician login, and every service-to-service
connection across all 140 clients.

**What they need:**
- Each client gets an **isolated org** with **white-label branding** — their own logo, colors,
  and login domain (`login.hendricks-mfg.com` not `clearbridge.com`)
- **Technicians scoped** to specific clients — a junior tech sees only their assigned accounts
- **Service tiers** — monitoring-only technicians (read) vs managed-service technicians (admin)
- **Sub-MSP hierarchy** — TechForce is a reseller under ClearBridge; TechForce's techs
  cannot see ClearBridge's other clients
- **Break-glass access** — emergency elevated access, time-bound, fully audited
- **Client self-service** — each client's IT admin manages their own users without calling ClearBridge
- **RMM service accounts** — the monitoring platform authenticates as a service account per client
- **Instant offboarding** — one call revokes a technician's access to all 140 clients simultaneously

**Characters:**
- **Rachel Kim** — ClearBridge founder/CTO, owns the master org
- **Marcus Webb** — senior tech, has access to all ClearBridge clients
- **Diana Osei** — junior tech, scoped to 3 assigned accounts only
- **Mr. Hendricks** — owner of Hendricks Manufacturing (ClearBridge client, 45 users)
- **TechForce** — sub-reseller under ClearBridge, manages 28 of their own clients
- **AutoServ** — a client of TechForce (not visible to ClearBridge's other techs)

```bash
AUTH_URL="https://auth.service.ab0t.com"
MASTER_SLUG="clearbridge"
```

---

## Step 1: Rachel bootstraps ClearBridge as the master org

**Situation:** Rachel migrates ClearBridge off Okta. She registers the master MSP org —
every client org and sub-reseller will be children of this.

```bash
# Register Rachel
RACHEL_TOKEN=$(curl -s -X POST "$AUTH_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "rachel@clearbridge.io",
    "password": "...",
    "name": "Rachel Kim"
  }' | jq -r '.access_token')

# Create the master MSP org
MASTER_ORG=$(curl -s -X POST "$AUTH_URL/organizations" \
  -H "Authorization: Bearer $RACHEL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ClearBridge IT",
    "slug": "clearbridge",
    "billing_type": "enterprise",
    "metadata": {
      "org_type": "msp_master",
      "region": "us-west"
    }
  }')

MASTER_ORG_ID=$(echo $MASTER_ORG | jq -r '.id')
echo "Master org: $MASTER_ORG_ID"
```

### Define MSP-specific roles

```bash
# Senior tech — full access to managed clients
curl -s -X POST "$AUTH_URL/organizations/$MASTER_ORG_ID/roles" \
  -H "Authorization: Bearer $RACHEL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "senior_technician",
    "permissions": [
      "msp.manage.clients",
      "msp.read.clients",
      "msp.write.tickets",
      "msp.read.audit_logs",
      "msp.admin.users",
      "msp.admin.devices",
      "cross_tenant"
    ]
  }'

# Junior tech — scoped to assigned accounts, no admin
curl -s -X POST "$AUTH_URL/organizations/$MASTER_ORG_ID/roles" \
  -H "Authorization: Bearer $RACHEL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "junior_technician",
    "permissions": [
      "msp.read.clients",
      "msp.write.tickets",
      "msp.admin.users",
      "msp.admin.devices"
    ]
  }'

# Monitoring-only — read-only, no changes
curl -s -X POST "$AUTH_URL/organizations/$MASTER_ORG_ID/roles" \
  -H "Authorization: Bearer $RACHEL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "monitoring_tech",
    "permissions": [
      "msp.read.clients",
      "msp.read.devices",
      "msp.read.alerts",
      "msp.write.tickets"
    ]
  }'

# Account manager — business view, no technical access
curl -s -X POST "$AUTH_URL/organizations/$MASTER_ORG_ID/roles" \
  -H "Authorization: Bearer $RACHEL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "account_manager",
    "permissions": [
      "msp.read.clients",
      "msp.read.contracts",
      "msp.write.contracts",
      "msp.read.billing"
    ]
  }'
```

> **Concept: `cross_tenant` permission**
>
> A user with `cross_tenant` can call endpoints across ALL child orgs in a hierarchy.
> This is what lets Marcus (senior tech) see all 140 client orgs. Without it, a user
> in the master org cannot see into child orgs.
>
> Junior techs do NOT get `cross_tenant`. Instead, they are individually invited into
> each client org they are assigned to. This is the structural enforcement of account
> scoping — not policy, not a flag, but Zanzibar membership boundaries.

---

## Step 2: Onboarding a new client — automated provisioning

**Situation:** ClearBridge signs Hendricks Manufacturing. Rachel's team runs an onboarding
script. This is the power of the platform: one script provisions a completely isolated,
branded workspace in under 10 seconds.

```bash
#!/bin/bash
# /home/clearbridge/scripts/onboard_client.sh
# Usage: ./onboard_client.sh \
#   --name "Hendricks Manufacturing" \
#   --slug "hendricks-manufacturing" \
#   --domain "login.hendricks-mfg.com" \
#   --admin-email "it@hendricks-mfg.com" \
#   --primary-color "#1A3C6B" \
#   --logo-url "https://cdn.clearbridge.io/clients/hendricks/logo.png"

set -e

AUTH_URL="https://auth.service.ab0t.com"
CLIENT_NAME="$1"
CLIENT_SLUG="$2"
CUSTOM_DOMAIN="$3"
ADMIN_EMAIL="$4"
PRIMARY_COLOR="$5"
LOGO_URL="$6"

echo "Provisioning: $CLIENT_NAME..."

# 1. Create the client org as a child of ClearBridge master
CLIENT_ORG=$(curl -s -X POST "$AUTH_URL/organizations" \
  -H "Authorization: Bearer $RACHEL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "'"$CLIENT_NAME"'",
    "slug": "'"$CLIENT_SLUG"'",
    "parent_id": "'"$MASTER_ORG_ID"'",
    "billing_type": "prepaid",
    "metadata": {
      "org_type": "msp_client",
      "managed_by": "clearbridge",
      "contract_start": "2026-02-25"
    }
  }')

CLIENT_ORG_ID=$(echo $CLIENT_ORG | jq -r '.id')
echo "  Created org: $CLIENT_ORG_ID"

# 2. Configure white-label branding
curl -s -X PUT "$AUTH_URL/organizations/$CLIENT_ORG_ID/login-config" \
  -H "Authorization: Bearer $RACHEL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "auth_methods": {
      "email_password": true,
      "signup_enabled": false,
      "invitation_only": true
    },
    "branding": {
      "company_name": "'"$CLIENT_NAME"' IT Portal",
      "logo_url": "'"$LOGO_URL"'",
      "primary_color": "'"$PRIMARY_COLOR"'",
      "favicon_url": "'"${LOGO_URL/logo/favicon}"'",
      "support_email": "support@clearbridge.io",
      "tagline": "Managed by ClearBridge IT"
    },
    "custom_domain": "'"$CUSTOM_DOMAIN"'",
    "session_config": {
      "session_duration_hours": 8,
      "idle_timeout_minutes": 60
    }
  }'
echo "  Configured branding + custom domain"

# 3. Invite the client's IT admin
curl -s -X POST "$AUTH_URL/organizations/$CLIENT_ORG_ID/invite" \
  -H "Authorization: Bearer $RACHEL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "'"$ADMIN_EMAIL"'",
    "role": "admin",
    "metadata": {
      "invited_by": "clearbridge-onboarding",
      "is_client_admin": true
    }
  }'
echo "  Invited client admin: $ADMIN_EMAIL"

# 4. Create RMM service account for this client
RMM_SA=$(curl -s -X POST "$AUTH_URL/admin/users/create-service-account" \
  -H "Authorization: Bearer $RACHEL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "rmm-'"$CLIENT_SLUG"'@svc.clearbridge.internal",
    "name": "rmm-'"$CLIENT_SLUG"'",
    "description": "ConnectWise RMM agent for '"$CLIENT_NAME"'",
    "permissions": [
      "msp.read.devices",
      "msp.write.alerts",
      "msp.write.tickets",
      "msp.read.users"
    ],
    "org_id": "'"$CLIENT_ORG_ID"'"
  }')

RMM_KEY=$(echo $RMM_SA | jq -r '.api_key')

# 5. Store RMM key in secrets manager
aws secretsmanager put-secret-value \
  --secret-id "clearbridge/rmm/$CLIENT_SLUG/api-key" \
  --secret-string "$RMM_KEY"

echo "  RMM service account configured"
echo ""
echo "Done. Login page: https://$CUSTOM_DOMAIN"
echo "       (also at: $AUTH_URL/login/$CLIENT_SLUG)"
```

> **What just happened in those 5 steps:**
>
> 1. An isolated Zanzibar namespace created — Hendricks users are completely walled from
>    other ClearBridge clients at the database level, not just at the application layer
> 2. The login page at `login.hendricks-mfg.com` shows Hendricks Manufacturing's logo,
>    colors, and name — no ClearBridge branding visible to Hendricks employees
> 3. The client's IT admin received an invite to manage their own users
> 4. The RMM monitoring agent has a service account scoped ONLY to Hendricks — even if the
>    ConnectWise agent is compromised, it cannot access other ClearBridge clients
> 5. `invitation_only: true` means no one can self-register — every Hendricks user must be
>    invited by either the client admin or a ClearBridge tech

---

## Step 3: White-label — what Hendricks employees see

**Situation:** Linda in Hendricks Manufacturing's accounting department needs to log into
the IT portal to submit a ticket. She goes to `login.hendricks-mfg.com`.

```
╔══════════════════════════════════════════════════════╗
║  [HENDRICKS MANUFACTURING LOGO]                      ║
║                                                      ║
║          Hendricks Manufacturing IT Portal           ║
║                                                      ║
║  Email ________________________________              ║
║  Password _____________________________              ║
║                                                      ║
║           [Sign In]                                  ║
║                                                      ║
║  Forgot password?                                    ║
║                                                      ║
║  Need help? support@clearbridge.io                   ║
╚══════════════════════════════════════════════════════╝
```

Linda has no idea ClearBridge IT uses `auth.service.ab0t.com`. She just sees Hendricks'
branding. The URL `login.hendricks-mfg.com` is a CNAME pointing to the auth service, with
TLS terminated and the org slug injected via the `custom_domain` mapping.

> **Concept: Custom domain mapping**
>
> `custom_domain: "login.hendricks-mfg.com"` registers the domain with the auth service.
> ClearBridge adds a DNS record:
>
> ```
> login.hendricks-mfg.com  CNAME  custom.auth.service.ab0t.com
> ```
>
> The auth service receives the request, looks up which org owns that domain,
> and serves the branded login page for that org. TLS certificates are provisioned
> automatically. Hendricks' IT admin can also access the same page via the canonical
> URL `auth.service.ab0t.com/login/hendricks-manufacturing` — useful for testing.
>
> Each of ClearBridge's 140 clients can have their own custom domain. Zero per-client
> infrastructure. One auth service handles all of them.

---

## Step 4: Technician scoping — who sees what

### 4a. Marcus — senior tech, accesses all clients

```bash
# Add Marcus to ClearBridge master org with senior_technician role
curl -s -X POST "$AUTH_URL/organizations/$MASTER_ORG_ID/users/$MARCUS_USER_ID/roles" \
  -H "Authorization: Bearer $RACHEL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "senior_technician"}'

# Marcus now has cross_tenant — he can query any client org from the master org context
# GET /organizations/clearbridge/clients → lists all 140 client orgs
# GET /organizations/hendricks-manufacturing/users → lists Hendricks users
# No additional invitation to each client org required
```

### 4b. Diana — junior tech, assigned to 3 accounts only

```bash
# Diana gets junior_technician in the master org (no cross_tenant)
curl -s -X POST "$AUTH_URL/organizations/$MASTER_ORG_ID/users/$DIANA_USER_ID/roles" \
  -H "Authorization: Bearer $RACHEL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "junior_technician"}'

# Diana is explicitly invited into her 3 assigned client orgs
for CLIENT_ORG_ID in $HENDRICKS_ORG_ID $RIVERSIDE_ORG_ID $METRO_DENTAL_ORG_ID; do
  curl -s -X POST "$AUTH_URL/organizations/$CLIENT_ORG_ID/members/$DIANA_USER_ID" \
    -H "Authorization: Bearer $RACHEL_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"role": "technician"}'
done

# Diana can only see:
# - The 3 orgs she's been explicitly added to
# - Nothing about the other 137 ClearBridge clients
# This is enforced by Zanzibar — not a filter, not a flag, a hard membership boundary
```

```
ClearBridge Master Org
├── Marcus  ← senior_technician (cross_tenant) — sees ALL 140
├── Diana   ← junior_technician (no cross_tenant) — sees 3
│
├── Hendricks Manufacturing ← Diana + Marcus both members
├── Riverside Dental       ← Diana + Marcus both members
├── Metro Property Group   ← Diana + Marcus both members
├── Acme Auto Parts        ← Marcus only
├── Pacific Plumbing       ← Marcus only
└── ... (136 more clients)
```

> **Concept: Two levels of technician membership**
>
> `cross_tenant` in the parent org is a "skeleton key" — it grants visibility into all
> children without explicit membership. It is reserved for senior staff and service accounts.
>
> Without `cross_tenant`, a technician must be individually invited to each client org.
> This explicit, per-client invitation is the audit trail: you can ask "which clients does
> Diana have access to?" and get an exact list. You can add or remove one client without
> touching the others. When Diana leaves ClearBridge, you remove her from the master org
> AND her 3 client orgs — two operations, complete revocation.

### 4c. Service tier enforcement

```python
# ClearBridge's ticket management API enforces tier-based access
# A monitoring_tech can only read; a senior_tech can modify

from ab0t_auth import AuthGuard, AuthenticatedUser
from fastapi import Depends

@router.post("/clients/{client_slug}/devices/{device_id}/restart")
async def restart_device(
    client_slug: str,
    device_id: str,
    user: AuthenticatedUser = Depends(AuthGuard(
        required_permissions=["msp.manage.clients"]
    ))
):
    """Only senior_technician and above — monitoring_tech gets 403"""
    # Phase 2: verify this tech has access to this specific client
    client_org = await db.get_org_by_slug(client_slug)
    await verify_resource_access(user, client_org.id)  # Zanzibar membership check

    return await rmm.restart_device(device_id)

@router.get("/clients/{client_slug}/alerts")
async def list_alerts(
    client_slug: str,
    user: AuthenticatedUser = Depends(AuthGuard(
        required_permissions=["msp.read.alerts"]
    ))
):
    """monitoring_tech, junior_technician, senior_technician — all can read"""
    client_org = await db.get_org_by_slug(client_slug)
    await verify_resource_access(user, client_org.id)

    return await rmm.get_alerts(client_org.id)
```

---

## Step 5: Client self-service — Mr. Hendricks manages his own users

**Situation:** Hendricks Manufacturing hires two new employees. Mr. Hendricks' IT contact
wants to add them herself without calling ClearBridge. The invitation_only config means
she controls who gets in — no one self-registers.

```bash
# Mrs. Hendricks (client admin) invites new employees
# She logs into login.hendricks-mfg.com and uses the user management UI
# Behind the scenes, the UI calls:

curl -s -X POST "$AUTH_URL/organizations/$HENDRICKS_ORG_ID/invite" \
  -H "Authorization: Bearer $HENDRICKS_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "linda.park@hendricks-mfg.com",
    "role": "member",
    "metadata": {"department": "Accounting"}
  }'

curl -s -X POST "$AUTH_URL/organizations/$HENDRICKS_ORG_ID/invite" \
  -H "Authorization: Bearer $HENDRICKS_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "james.wu@hendricks-mfg.com",
    "role": "member",
    "metadata": {"department": "Engineering"}
  }'
```

> **Concept: Delegated administration**
>
> Mrs. Hendricks (client admin) can manage users, roles, and settings within
> her org. She cannot:
> - See any other ClearBridge client org
> - Change the custom_domain or branding (locked to ClearBridge owner)
> - Create service accounts (restricted to org owner or higher)
> - See ClearBridge's internal tech assignments
>
> ClearBridge can restrict which settings client admins can touch via the
> `admin_capabilities` config on the child org. The client feels like they have full
> control of "their" system, but the boundaries are structural.

### Client org structure after onboarding

```
Hendricks Manufacturing (org_hendricks)
├── Members (client employees)
│   ├── Mrs. Hendricks (admin)
│   ├── Linda Park (member)
│   └── James Wu (member)
│
├── Technicians (ClearBridge staff in this org)
│   ├── Marcus Webb (senior_technician)
│   └── Diana Osei (junior_technician)
│
└── Service Accounts
    └── rmm-hendricks-manufacturing [read.devices, write.alerts, write.tickets]
```

---

## Step 6: RMM integration — monitoring service account

**Situation:** ClearBridge uses ConnectWise RMM to monitor all client machines. The
ConnectWise agent on Hendricks' network sends alerts, device inventory, and patch status
to ClearBridge's platform. It authenticates as the `rmm-hendricks-manufacturing` service
account created during onboarding.

```python
# ConnectWise RMM agent (Python) — authenticates per client
import os
from clearbridge_sdk import RMMClient

class HendricksRMMAgent:
    def __init__(self):
        # Each client's agent has its own key — scoped to that org ONLY
        self.api_key = os.environ["HENDRICKS_RMM_API_KEY"]
        self.client = RMMClient(api_key=self.api_key)

    async def report_alert(self, device_id: str, alert_type: str, severity: str):
        # This API key can ONLY write alerts to Hendricks org
        # Attempting to write to a different org returns 403
        await self.client.post("/alerts", {
            "device_id": device_id,
            "alert_type": alert_type,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat()
        })

    async def sync_device_inventory(self, devices: list):
        await self.client.put("/devices/inventory", {"devices": devices})
```

> **Why one service account per client?**
>
> If ClearBridge used a single RMM service account for all clients:
> - A compromised key exposes all 140 clients' monitoring data
> - You cannot revoke one client's RMM access without affecting others
> - The audit log shows "rmm-agent" not "rmm-hendricks" — no attribution
>
> With one service account per client:
> - Compromised key = one client affected, 139 safe
> - When ClearBridge offboards a client, they delete that org —
>   the service account and its key are destroyed automatically
> - Audit log shows exactly which client's agent fired which alert
>
> The provisioning script creates this automatically. Zero human overhead per new client.

---

## Step 7: Break-glass emergency access

**Situation:** It's 2 AM. A ransomware incident is detected at Hendricks Manufacturing.
Marcus needs elevated access immediately to isolate machines and pull logs — but he needs
this to be time-bound and fully audited.

```bash
# Rachel (or the on-call manager) issues a break-glass delegation token
# /auth/delegate creates a JWT where Rachel acts AS Marcus — Marcus gets Rachel's
# elevated permissions for the duration of this token.
#
# NOTE: /auth/delegate only accepts {"target_user_id"} — permission scoping and
# reason logging are application-layer concerns (store in your incident tracker).
# For user-to-user consent delegation, use POST /delegation/grant instead.
BREAK_GLASS=$(curl -s -X POST "$AUTH_URL/auth/delegate" \
  -H "Authorization: Bearer $RACHEL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target_user_id": "'"$MARCUS_USER_ID"'"
  }')

BREAK_GLASS_TOKEN=$(echo $BREAK_GLASS | jq -r '.access_token')

# Log reason + scope in your incident management system before issuing token:
# INCIDENT-2026-0225: Ransomware response — Hendricks Manufacturing
# Authorized by Rachel Kim, issued to Marcus Chen, 4h window

echo "Break-glass token issued"
echo "Token sent to Marcus via secure channel"

# Alternatively — if Marcus should grant Rachel the ability to act on his behalf:
# POST /delegation/grant
# {"actor_id": "$RACHEL_USER_ID", "scope": ["msp.manage.clients", "msp.isolate.devices"], "expires_in_hours": 4}
```

Marcus uses the token. When the JWT's `exp` is reached (set by the auth service),
the token is rejected. No manual cleanup required.

> **What the audit log records:**
>
> ```json
> {
>   "timestamp": "2026-02-25T02:14:33Z",
>   "event": "device.isolated",
>   "actor": "usr_marcus",
>   "delegated_by": "usr_rachel",
>   "org_id": "org_hendricks",
>   "resource": "device:HENDRICKS-WS-042",
>   "reason": "INCIDENT-2026-0225: Ransomware response...",
>   "token_type": "delegation",
>   "token_expires": "2026-02-25T06:14:33Z"
> }
> ```
>
> The audit record shows Rachel authorized Marcus to act. Hendricks' cyber insurance
> adjuster sees: who approved emergency access, at what time, for how long, and exactly
> which actions were taken under that authorization. This is the chain of custody that
> compliance and insurance require.

### Self-expiring break-glass — no cleanup debt

```
Normal Marcus permissions:     senior_technician  (msp.manage.clients, cross_tenant)
During incident (0–4h):        + msp.isolate.devices, msp.write.incident_response
After 4h (automatic):          senior_technician  (break-glass expired)
```

No one has to remember to revoke elevated access. The token's `exp` is enforced by the
auth service. Rachel gets a system notification when the break-glass token expires.

---

## Step 8: Sub-MSP / reseller hierarchy

**Situation:** TechForce is a smaller IT company that uses ClearBridge's platform under
a reseller agreement. TechForce manages 28 of their own clients. TechForce's techs should:
- See TechForce's 28 clients
- NOT see ClearBridge's other 112 clients
- White-label under TechForce's own brand

```bash
# Rachel creates TechForce as a sub-MSP org under ClearBridge
TECHFORCE_ORG=$(curl -s -X POST "$AUTH_URL/organizations" \
  -H "Authorization: Bearer $RACHEL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "TechForce IT",
    "slug": "techforce",
    "parent_id": "'"$MASTER_ORG_ID"'",
    "billing_type": "enterprise",
    "metadata": {
      "org_type": "msp_reseller",
      "reseller_tier": "silver",
      "contract_id": "RES-2024-047"
    }
  }')

TECHFORCE_ORG_ID=$(echo $TECHFORCE_ORG | jq -r '.id')

# TechForce gets their own branded portal
curl -s -X PUT "$AUTH_URL/organizations/$TECHFORCE_ORG_ID/login-config" \
  -H "Authorization: Bearer $RACHEL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "branding": {
      "company_name": "TechForce IT",
      "logo_url": "https://techforce.io/logo.png",
      "primary_color": "#E84B10"
    },
    "custom_domain": "portal.techforce.io"
  }'

# Invite TechForce's owner as their org admin
curl -s -X POST "$AUTH_URL/organizations/$TECHFORCE_ORG_ID/invite" \
  -H "Authorization: Bearer $RACHEL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "owner@techforce.io",
    "role": "owner"
  }'
```

### TechForce provisions their own clients

```bash
# TechForce owner is now logged in and creates their client orgs
# Same provisioning script, different parent_id

AUTOSERV_ORG=$(curl -s -X POST "$AUTH_URL/organizations" \
  -H "Authorization: Bearer $TECHFORCE_OWNER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "AutoServ Dealership Group",
    "slug": "autoserv",
    "parent_id": "'"$TECHFORCE_ORG_ID"'",
    "billing_type": "prepaid"
  }')
```

### The isolation guarantee

```
ClearBridge Master (org_clearbridge)
├── ClearBridge Techs
│   ├── Marcus  (cross_tenant → sees ALL below)
│   └── Diana   (explicit only → sees 3 clients)
│
├── [CLIENT] Hendricks Manufacturing    ← ClearBridge direct client
├── [CLIENT] Riverside Dental           ← ClearBridge direct client
├── ... (110 more ClearBridge clients)
│
└── TechForce IT (org_techforce)        ← Sub-MSP
    ├── TechForce Techs
    │   ├── Jordan (techforce, cross_tenant within techforce subtree)
    │   └── Sam    (techforce, explicit to 5 clients)
    │
    ├── [CLIENT] AutoServ Dealership     ← TechForce client
    ├── [CLIENT] Bay Area Bakery         ← TechForce client
    └── ... (26 more TechForce clients)
```

> **The critical isolation properties:**
>
> **TechForce techs cannot see ClearBridge's direct clients.** Jordan has `cross_tenant`
> within the TechForce sub-tree — but `cross_tenant` only traverses the hierarchy
> downward from the org where it was granted. Jordan's membership is in `org_techforce`,
> not `org_clearbridge`. He cannot see Hendricks Manufacturing, Riverside Dental, or any
> other ClearBridge-direct client.
>
> **ClearBridge can see TechForce's clients.** Marcus has `cross_tenant` in `org_clearbridge`
> (the root). He can reach all descendants — including TechForce's clients — for escalation
> support. Rachel can see everything. TechForce knows this (it's in the reseller agreement).
>
> **TechForce clients see only TechForce branding.** AutoServ logs into
> `portal.techforce.io` — they never see ClearBridge's name. TechForce is white-labeling
> the full auth platform under their own brand.

---

## Step 9: Offboarding a technician — complete revocation in two calls

**Situation:** Diana is leaving ClearBridge. Her last day is today. At 5 PM, Rachel needs
to ensure Diana has zero access to any client system within seconds.

```bash
#!/bin/bash
# /home/clearbridge/scripts/offboard_technician.sh
# Usage: ./offboard_technician.sh diana@clearbridge.io

TECH_USER_ID=$(curl -s "$AUTH_URL/users?email=$1" \
  -H "Authorization: Bearer $RACHEL_TOKEN" | jq -r '.id')

echo "Offboarding: $1 (user_id: $TECH_USER_ID)"

# Step 1: Remove from master org (kills cross_tenant and master org access)
curl -s -X DELETE "$AUTH_URL/organizations/$MASTER_ORG_ID/members/$TECH_USER_ID" \
  -H "Authorization: Bearer $RACHEL_TOKEN"
echo "  Removed from master org"

# Step 2: Remove from all explicitly-assigned client orgs
# (Get the list of orgs Diana is in, then remove her from each)
DIANA_ORGS=$(curl -s "$AUTH_URL/users/$TECH_USER_ID/organizations" \
  -H "Authorization: Bearer $RACHEL_TOKEN" | jq -r '.[].id')

for ORG_ID in $DIANA_ORGS; do
  curl -s -X DELETE "$AUTH_URL/organizations/$ORG_ID/members/$TECH_USER_ID" \
    -H "Authorization: Bearer $RACHEL_TOKEN"
  echo "  Removed from org: $ORG_ID"
done

# Step 3: Deactivate the account — auto-kills all sessions + API keys instantly.
# This is a single call; no separate session-revoke needed.
curl -s -X POST "$AUTH_URL/users/$TECH_USER_ID/deactivate" \
  -H "Authorization: Bearer $RACHEL_TOKEN"
echo "  Account deactivated (all sessions and API keys terminated)"

# To kill sessions within one org only (without full deactivation), use:
# DELETE /organizations/$ORG_ID/users/$TECH_USER_ID/sessions

echo ""
echo "Offboarding complete. Diana has zero access to all systems."
```

> **What just happened — the Okta comparison:**
>
> **With Okta:** An MSP with 140 clients has 140 separate Okta tenants (or a complex
> multi-tenant setup). Offboarding Diana requires revoking her from each tenant individually,
> or maintaining a complex group policy across all tenants. Miss one tenant = security gap.
>
> **With this platform:** One auth service, one hierarchy. Removing Diana from the master
> org is sufficient — her membership propagates through Zanzibar. The explicit client org
> memberships are cleaned up by the script, and session revocation is a single API call.
> The whole thing runs in under 5 seconds for 140 clients.
>
> **Cost:** Okta charges per Monthly Active User (MAU) per tenant. For an MSP with 140
> clients averaging 30 users each = 4,200 users × $2–8/MAU = $8,400–33,600/month in auth
> costs alone, before any MSP markup features. This platform charges per-platform, not
> per-tenant. ClearBridge adds a new client at zero marginal auth cost.

---

## Step 10: Audit trail — who did what in which client org

**Situation:** Hendricks Manufacturing is audited by their cyber insurance provider after
the ransomware incident. They need logs showing which ClearBridge technicians accessed
their systems, when, and what they did.

```bash
# ClearBridge pulls the audit log for Hendricks — filtered to ClearBridge tech actions
curl -s "$AUTH_URL/organizations/$HENDRICKS_ORG_ID/audit-log" \
  -H "Authorization: Bearer $RACHEL_TOKEN" \
  -G \
  --data-urlencode "start=2026-02-01T00:00:00Z" \
  --data-urlencode "end=2026-02-28T23:59:59Z" \
  --data-urlencode "actor_org=clearbridge" \
  | jq '.events[] | {
    timestamp,
    actor: .actor.email,
    action: .event_type,
    resource: .resource_id,
    delegated_by: .delegation.authorized_by,
    ip: .context.ip_address
  }'

# Output:
# {
#   "timestamp": "2026-02-25T02:14:33Z",
#   "actor": "marcus@clearbridge.io",
#   "action": "device.isolated",
#   "resource": "device:HENDRICKS-WS-042",
#   "delegated_by": "rachel@clearbridge.io",
#   "ip": "203.0.113.42"
# }
# {
#   "timestamp": "2026-02-25T02:31:17Z",
#   "actor": "marcus@clearbridge.io",
#   "action": "user.password_reset",
#   "resource": "user:linda.park@hendricks-mfg.com",
#   "delegated_by": "rachel@clearbridge.io",
#   "ip": "203.0.113.42"
# }
```

> **Concept: Cross-org audit visibility**
>
> Rachel (master org owner) can query audit logs for any child org — this is the `cross_tenant`
> privilege applied to observability. Mrs. Hendricks (client admin) can query her own org's
> audit log and sees the same events — there is no shadow activity. Every action a ClearBridge
> tech takes inside a client org is visible to that client.
>
> This is a feature, not a bug. Clients audit their MSP. The full audit trail is the trust
> foundation of the managed services relationship.

---

## Step 11: Microsoft 365 / Entra ID SSO for enterprise clients

**Situation:** Hendricks Manufacturing upgrades to a managed security package. They want
employees to use their existing Microsoft 365 accounts to log into the Hendricks IT portal.
No separate password. Leavers are automatically blocked when their M365 account is disabled.

```bash
# Configure Microsoft / Entra ID SSO for Hendricks
curl -s -X POST "$AUTH_URL/organizations/$HENDRICKS_ORG_ID/providers" \
  -H "Authorization: Bearer $RACHEL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "microsoft",
    "config": {
      "tenant_id": "hendricks-mfg.onmicrosoft.com",
      "client_id": "'"$AZURE_APP_CLIENT_ID"'",
      "client_secret": "'"$AZURE_APP_CLIENT_SECRET"'",
      "allowed_domains": ["hendricks-mfg.com"]
    },
    "jit_provisioning": true,
    "jit_default_role": "member",
    "disable_password_login": true
  }'
```

> **What `jit_provisioning: true` does:**
>
> When Linda logs in with her Microsoft account for the first time, she is automatically
> added to `org_hendricks` as a `member`. ClearBridge doesn't need to pre-invite her.
> Her M365 identity IS her Hendricks IT portal identity.
>
> When Linda's M365 account is disabled (she left Hendricks), her next login attempt
> to the IT portal fails — Microsoft returns an error during the OAuth callback, and
> the auth service rejects the login. Her IT portal access is revoked automatically,
> even without a call to ClearBridge.
>
> `disable_password_login: true` removes the email/password form entirely from
> `login.hendricks-mfg.com`. Employees can ONLY log in via Microsoft. No weak passwords,
> no credential stuffing risk.

---

## Step 12: Automated client metrics — reporting dashboard

**Situation:** ClearBridge's operations team wants a live dashboard: how many users per
client, last login dates, which clients have stale accounts, MFA adoption rate.

```bash
# ClearBridge operations service account — read-only, cross-tenant
OPS_SA=$(curl -s -X POST "$AUTH_URL/admin/users/create-service-account" \
  -H "Authorization: Bearer $RACHEL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "ops-dashboard@svc.clearbridge.internal",
    "name": "ops-dashboard",
    "permissions": [
      "msp.read.clients",
      "msp.read.users",
      "msp.read.audit_logs",
      "cross_tenant"
    ],
    "org_id": "'"$MASTER_ORG_ID"'"
  }')

OPS_API_KEY=$(echo $OPS_SA | jq -r '.api_key')
```

```python
# ClearBridge operations dashboard backend
import httpx

async def get_client_health_report(master_org_id: str):
    async with httpx.AsyncClient() as client:
        # Get all child orgs (all clients)
        orgs_response = await client.get(
            f"{AUTH_URL}/organizations/{master_org_id}/children",
            headers={"X-API-Key": OPS_API_KEY}
        )
        client_orgs = orgs_response.json()

        report = []
        for org in client_orgs:
            users = await client.get(
                f"{AUTH_URL}/organizations/{org['id']}/users",
                headers={"X-API-Key": OPS_API_KEY}
            )

            user_list = users.json()
            report.append({
                "client": org["name"],
                "total_users": len(user_list),
                "active_last_30d": sum(
                    1 for u in user_list
                    if u.get("last_login_at")
                    and days_ago(u["last_login_at"]) <= 30
                ),
                "stale_accounts": sum(
                    1 for u in user_list
                    if not u.get("last_login_at")
                    or days_ago(u["last_login_at"]) > 90
                ),
                "mfa_enabled": sum(1 for u in user_list if u.get("mfa_enabled")),
                "has_sso": org.get("metadata", {}).get("sso_enabled", False)
            })

        return sorted(report, key=lambda x: x["stale_accounts"], reverse=True)
```

---

## Step 13: The Okta displacement story — why MSPs switch

> This section summarizes the architectural differences for sales conversations.

```
                    OKTA / TRADITIONAL IAM          THIS PLATFORM
                    ─────────────────────────        ──────────────────────────

Tenant model        One Okta org per customer        One auth service, unlimited
                    (~$200-800/mo per tenant)        child orgs, flat pricing

White-label         Custom domain per tenant         Custom domain per org
                    Manual TLS, manual config        Automated, one API call

Reseller hierarchy  Not native — requires            Native hierarchy: master →
                    complex admin delegation         sub-MSP → client, enforced
                    workarounds                      by Zanzibar at DB level

Technician scoping  Groups + policies per tenant     Explicit org membership OR
                    Must be maintained per-org       cross_tenant flag — one place

Offboarding         Remove tech from N tenants       Remove from master org;
                    manually (or via script +        session revocation in 1 call
                    Okta Terraform provider)

Break-glass         Temporary admin role             Delegation token: time-bound,
                    (must remember to remove)        auto-expires, audit-stamped

Cost (140 clients,  140 tenants × avg 30 MAU         Single platform subscription
avg 30 users each)  × $4/MAU = ~$16,800/month        No per-tenant or per-MAU fee

New client time     15–30 min (Okta tenant           < 10 seconds (one provisioning
                    + policies + groups              script call)
                    + SSO config)

Audit               Per-tenant audit logs,           Cross-tenant audit log,
                    no unified view                  unified view from master org
```

---

## Full org tree — ClearBridge after 6 months

```
ClearBridge IT (org_clearbridge)  [master MSP]
├── Staff
│   ├── Rachel Kim         (owner)
│   ├── Marcus Webb        (senior_technician, cross_tenant)
│   ├── Diana Osei         (junior_technician, 3 clients only)
│   └── ops-dashboard      (service account, cross_tenant, read-only)
│
├── Service Accounts
│   └── break-glass-manager (owner, issues delegation tokens)
│
├── [CLIENTS — ClearBridge direct, 112 orgs]
│   ├── Hendricks Manufacturing   (custom domain, M365 SSO, 45 users)
│   ├── Riverside Dental          (email/password, invitation_only, 12 users)
│   └── ... (110 more)
│
└── TechForce IT (org_techforce)  [sub-MSP reseller]
    ├── Staff
    │   ├── Jordan (techforce senior, cross_tenant within techforce)
    │   └── Sam    (techforce junior, 5 explicit clients)
    │
    └── [CLIENTS — TechForce clients, 28 orgs]
        ├── AutoServ Dealership Group
        ├── Bay Area Bakery
        └── ... (26 more)
```

---

## Quick reference

```bash
# Provision new client (full script above)
./onboard_client.sh "Name" "slug" "login.domain.com" "admin@client.com" "#COLOR" "logo-url"

# Add technician to specific client
POST /organizations/{client-org-id}/members/{user-id}
     {"role": "technician"}

# Grant cross_tenant to senior tech
POST /organizations/{master-org-id}/users/{user-id}/roles
     {"role": "senior_technician"}  # includes cross_tenant

# Issue break-glass delegation token (caller acts AS target user)
POST /auth/delegate
     {"target_user_id": "usr_marcus"}
# Returns: {access_token, refresh_token, expires_in, ...}
# Log reason/scope/expiry in your incident management system separately

# User-to-user consent delegation (user grants someone to act as them):
POST /delegation/grant
     {"actor_id": "usr_rachel", "scope": ["msp.manage.clients"], "expires_in_hours": 4}

# Offboard technician (full script above)
./offboard_technician.sh tech@clearbridge.io

# Query client audit log
GET  /organizations/{client-org-id}/audit-log
     ?start=...&end=...&actor_org=clearbridge

# List all clients (cross_tenant required)
GET  /organizations/{master-org-id}/children

# Configure SSO for a client
POST /organizations/{client-org-id}/providers
     {"type": "microsoft", "config": {...}, "jit_provisioning": true}
```
