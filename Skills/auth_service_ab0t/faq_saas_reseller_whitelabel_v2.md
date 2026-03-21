question: We built a form and workflow automation platform called "FormFlow." We want to sell it through resellers — agencies and system integrators who rebrand it as their own
  product and sell it to their clients. The resellers manage their own customers. Their customers should see the reseller's brand, not ours. Resellers need API keys to build on top
  of us. And we need to be able to see everything for support, but resellers should only see their own customers. Walk us through the whole thing.

● This is a 3-tier white-label architecture. It's one of the more sophisticated setups you can build on this platform — but every piece maps cleanly to primitives you already
  understand from simpler guides. New concept here: permission ceilings, reseller-scoped API keys, and brand inheritance down the hierarchy.

  By the end you'll have:
  - FormFlow (your platform) at the root
  - Reseller orgs as children — each reseller manages their own subtree
  - Customer orgs as children of resellers — double-isolated from each other
  - Three distinct branded login experiences per tier
  - Resellers creating and managing customers via API (not manually)
  - Permission ceilings — resellers can only grant what FormFlow gave them
  - FormFlow support sees everything; reseller support sees only their customers

  ---
  Concept: The 3-Tier Model

  Most multi-tenant platforms have 2 tiers: you and your customers. A reseller model adds a middle tier:

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Tier 0: FormFlow (you)                                                         │
  │  The platform. You own the infrastructure, the code, the permissions registry.  │
  │  You have full visibility into everything.                                       │
  └────────────────────────────────────┬────────────────────────────────────────────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
  ┌───────────▼──────────┐  ┌──────────▼───────────┐  ┌────────▼─────────────┐
  │  Tier 1: NovaTech    │  │  Tier 1: CloudBridge  │  │  Tier 1: SkyAgency   │
  │  (Reseller)          │  │  (Reseller)            │  │  (Reseller)          │
  │  White-labels as     │  │  White-labels as       │  │  White-labels as     │
  │  "NovaTech Forms"    │  │  "CloudBridge Flow"    │  │  "SkyForms Pro"      │
  └───────────┬──────────┘  └──────────┬─────────────┘  └────────┬─────────────┘
              │                        │                          │
       ┌──────┼──────┐          ┌──────┼──────┐            ┌─────┴──────┐
       │      │      │          │      │      │             │            │
    BrightSpark Summit  ...  PacLog  RetailCo ...       TechCorp   BizGroup
    (customer) (customer)   (customer) (customer)       (customer) (customer)
  │  Tier 2   │  Tier 2   │  Tier 2    │  Tier 2   │  Tier 2    │  Tier 2

  Key rules of this model:
  - NovaTech can see all of NovaTech's customers
  - NovaTech CANNOT see CloudBridge's customers
  - BrightSpark CANNOT see Summit (even though both are NovaTech customers)
  - FormFlow can see everyone
  - A reseller's customer never knows FormFlow exists (white-label)

  ---
  Concept: Permission Ceilings

  This is the critical new concept. When FormFlow gives NovaTech reseller access, it grants them a set of permissions. NovaTech can only grant their customers a SUBSET of those permissions.
  They cannot give customers more than FormFlow gave them.

  FormFlow gives NovaTech:
    formflow.read.*, formflow.write.forms, formflow.create.workflows,
    formflow.write.workflows, formflow.read.analytics — but NOT formflow.admin

  NovaTech gives BrightSpark:
    formflow.read.*, formflow.write.forms  — fine, NovaTech has these
    formflow.admin                          — BLOCKED, NovaTech doesn't have this

  This is enforced server-side. A reseller calling POST /organizations/{id}/invite cannot include a permission they don't have. The auth service rejects it.

  Think of it like a bank. FormFlow is the reserve bank. It issues credit to NovaTech. NovaTech can lend to BrightSpark — but only up to what they have. They can't lend money they don't have.

  ---
  The Architecture

  FormFlow Platform (root org)
  │
  ├── FormFlow Service Org (permissions registry, API keys)
  ├── Priya Kapoor (founder, owner of root org)
  ├── FormFlow Support Team (cross_tenant — sees all customers of all resellers)
  │
  ├── NovaTech Solutions (reseller org, child of FormFlow)
  │   ├── Omar Hassan (NovaTech admin)
  │   ├── NovaTech Support (can see NovaTech's customers only)
  │   ├── NovaTech Reseller API Key (for provisioning customers)
  │   ├── Login page: /login/novatech (NovaTech's own branded portal)
  │   │
  │   ├── BrightSpark Retail (customer org, child of NovaTech)
  │   │   ├── Login page: /login/brightspark (BrightSpark's brand, NOT NovaTech's)
  │   │   └── BrightSpark users (self-registered or invited)
  │   │
  │   └── Summit Hotels (customer org, child of NovaTech)
  │       ├── Login page: /login/summit-hotels (Summit's brand)
  │       └── Summit users
  │
  └── CloudBridge Systems (reseller org, child of FormFlow)
      ├── Ana Lima (CloudBridge admin)
      ├── CloudBridge Reseller API Key
      │
      └── Pacific Logistics (customer org, child of CloudBridge)
          └── Login page: /login/pacific-logistics

  ---
  Step 1: Priya Sets Up FormFlow

  AUTH_URL="https://auth.service.ab0t.com"

  # Register
  curl -X POST "$AUTH_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "priya@formflow.io",
      "password": "PriyaSecure2026!",
      "name": "Priya Kapoor"
    }'

  # Login
  TOKEN=$(curl -s -X POST "$AUTH_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email": "priya@formflow.io", "password": "PriyaSecure2026!"}' \
    | jq -r '.access_token')

  # Create the root platform org
  FORMFLOW=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "FormFlow",
      "slug": "formflow",
      "domain": "formflow.io",
      "billing_type": "postpaid",
      "settings": {
        "type": "platform",
        "hierarchical": true,
        "is_root_platform": true
      },
      "metadata": {
        "tier": "platform",
        "reseller_enabled": true
      }
    }')
  FORMFLOW_ORG_ID=$(echo "$FORMFLOW" | jq -r '.id')

  # Switch into FormFlow context
  PRIYA_TOKEN=$(curl -s -X POST "$AUTH_URL/auth/switch-organization" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"org_id": "'$FORMFLOW_ORG_ID'"}' \
    | jq -r '.access_token')

  ---
  Step 2: Define FormFlow's Permissions

  {
    "service": "formflow",
    "description": "Form and workflow automation platform",
    "actions": ["read", "write", "create", "delete", "publish", "submit", "admin", "resell"],
    "resources": [
      "forms", "workflows", "submissions", "responses",
      "templates", "analytics", "webhooks", "integrations",
      "users", "settings", "branding", "customers"
    ],
    "roles": {
      "formflow-viewer": {
        "description": "View forms and submitted responses — read only",
        "default_permissions": [
          "formflow.read.forms",
          "formflow.read.submissions",
          "formflow.read.responses"
        ]
      },
      "formflow-member": {
        "description": "Build forms, manage workflows, view analytics",
        "implies": ["formflow-viewer"],
        "default_permissions": [
          "formflow.create.forms", "formflow.write.forms",
          "formflow.create.workflows", "formflow.write.workflows",
          "formflow.publish.forms", "formflow.read.analytics",
          "formflow.create.webhooks", "formflow.write.webhooks"
        ]
      },
      "formflow-admin": {
        "description": "Full org admin — manage users, branding, billing, integrations",
        "implies": ["formflow-member"],
        "default_permissions": [
          "formflow.admin",
          "formflow.delete.forms", "formflow.delete.workflows",
          "formflow.write.settings", "formflow.write.branding",
          "formflow.read.users", "formflow.write.integrations"
        ]
      },
      "formflow-reseller": {
        "description": "Can provision and manage customer orgs — resellers only",
        "implies": ["formflow-admin"],
        "default_permissions": [
          "formflow.create.customers",
          "formflow.write.customers",
          "formflow.read.customers",
          "formflow.delete.customers",
          "formflow.resell"
        ]
      }
    }
  }

  Note the formflow-reseller role — it includes formflow.create.customers and formflow.resell. Only resellers have these. A regular customer admin cannot create sub-customers.

  ./register-service-permissions.sh \
    --service-name "formflow" \
    --admin-email "svc+formflow@formflow.io" \
    --permissions-file formflow.permissions.json

  SERVICE_API_KEY="ab0t_sk_live_formflow_..."

  ---
  Step 3: Create the Reseller Orgs

  3a: NovaTech Solutions

  NOVATECH=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $PRIYA_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "NovaTech Solutions",
      "slug": "novatech",
      "domain": "novatech-solutions.com",
      "parent_id": "'"$FORMFLOW_ORG_ID"'",
      "billing_type": "enterprise",
      "settings": {
        "type": "reseller",
        "hierarchical": true,
        "white_label": true,
        "brand_name": "NovaTech Forms",
        "max_customers": 100
      },
      "metadata": {
        "tier": "reseller",
        "contract_ref": "NTR-2026-001",
        "revenue_share_pct": 30
      }
    }')
  NOVATECH_ORG_ID=$(echo "$NOVATECH" | jq -r '.id')

  3b: Invite Omar as NovaTech admin and give him reseller permissions

  # Omar joins NovaTech — gets formflow-reseller role
  curl -X POST "$AUTH_URL/organizations/$NOVATECH_ORG_ID/invite" \
    -H "Authorization: Bearer $PRIYA_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "omar@novatech-solutions.com",
      "role": "admin",
      "permissions": [
        "formflow.admin",
        "formflow.create.customers",
        "formflow.write.customers",
        "formflow.read.customers",
        "formflow.delete.customers",
        "formflow.resell",
        "formflow.write.branding",
        "formflow.read.analytics"
      ],
      "message": "Welcome to FormFlow Reseller Program, Omar. You can now provision customer orgs."
    }'

  What just happened: Omar has formflow.create.customers — he can create child orgs under NovaTech. He has formflow.resell — the permission gate that lets him use the reseller APIs. He does NOT have formflow.admin at the FormFlow platform level — he can only admin within NovaTech and its children.

  3c: Create CloudBridge similarly

  CLOUDBRIDGE=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $PRIYA_TOKEN" \
    -d '{
      "name": "CloudBridge Systems",
      "slug": "cloudbridge",
      "parent_id": "'"$FORMFLOW_ORG_ID"'",
      "settings": {
        "type": "reseller",
        "hierarchical": true,
        "white_label": true,
        "brand_name": "CloudBridge Flow"
      },
      "metadata": {"tier": "reseller", "contract_ref": "CBR-2026-002"}
    }')
  CLOUDBRIDGE_ORG_ID=$(echo "$CLOUDBRIDGE" | jq -r '.id')

  ---
  Step 4: Give NovaTech a Reseller API Key

  NovaTech needs to automate customer provisioning. When one of their sales reps closes a deal, their CRM should automatically spin up a customer org — not wait for Omar to do it manually.

  Concept: Reseller API Keys
  A reseller API key is an API key in the reseller's org with reseller-level permissions. NovaTech's CRM uses it to create/manage customer orgs programmatically. It's scoped to NovaTech — it cannot touch CloudBridge's customers or FormFlow's own config.

  # Omar creates a reseller API key for NovaTech's CRM integration
  NOVATECH_KEY=$(curl -s -X POST "$AUTH_URL/api-keys/" \
    -H "Authorization: Bearer $OMAR_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "novatech-crm-integration",
      "description": "NovaTech CRM auto-provisions customer orgs on deal close",
      "permissions": [
        "formflow.create.customers",
        "formflow.write.customers",
        "formflow.read.customers",
        "formflow.resell",
        "formflow.read.analytics"
      ],
      "metadata": {
        "system": "crm",
        "crm_platform": "HubSpot",
        "environment": "production"
      }
    }')
  NOVATECH_API_KEY=$(echo "$NOVATECH_KEY" | jq -r '.key')

  # NovaTech stores this in HubSpot's webhook config
  # FORMFLOW_RESELLER_KEY=ab0t_sk_live_novatech_...

  What NovaTech can do with this key:
  - Create customer orgs (children of NovaTech)
  - Update customer org settings and branding
  - Read analytics across their customers
  - NOT create orgs at the FormFlow root level
  - NOT access CloudBridge's data
  - NOT grant more permissions than NovaTech has

  ---
  Step 5: NovaTech Provisions a Customer

  Situation: NovaTech's sales team closes a deal with BrightSpark Retail. Their HubSpot sends a webhook. NovaTech's provisioning service fires.

  # NovaTech's provisioning service creates BrightSpark's org
  BRIGHTSPARK=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "X-API-Key: $NOVATECH_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "BrightSpark Retail",
      "slug": "brightspark",
      "domain": "brightspark.com",
      "parent_id": "'"$NOVATECH_ORG_ID"'",
      "billing_type": "postpaid",
      "settings": {
        "type": "customer",
        "provisioned_by": "novatech",
        "plan": "professional"
      },
      "metadata": {
        "tier": "customer",
        "reseller": "novatech",
        "crm_deal_id": "deal-48821",
        "industry": "retail",
        "employee_count": 45
      }
    }')
  BRIGHTSPARK_ORG_ID=$(echo "$BRIGHTSPARK" | jq -r '.id')

  # NovaTech creates BrightSpark's admin account
  curl -X POST "$AUTH_URL/organizations/$BRIGHTSPARK_ORG_ID/invite" \
    -H "X-API-Key: $NOVATECH_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "admin@brightspark.com",
      "role": "admin",
      "permissions": [
        "formflow.admin",
        "formflow.write.branding",
        "formflow.create.forms", "formflow.write.forms",
        "formflow.create.workflows", "formflow.write.workflows",
        "formflow.publish.forms", "formflow.read.analytics",
        "formflow.write.settings"
      ],
      "message": "Welcome to NovaTech Forms! Your account is ready."
    }'

  Notice: The invitation says "Welcome to NovaTech Forms" — not "FormFlow." The customer never knows they're on FormFlow. That's white-label.

  Notice: BrightSpark's admin does NOT get formflow.resell or formflow.create.customers. They're a customer, not a reseller. They can admin their own org but can't create sub-orgs.

  Concept: Permission Ceiling in Practice
  NovaTech has formflow.create.customers. They CAN grant it to BrightSpark's admin.
  But Omar chose not to — BrightSpark doesn't need it.
  If Omar tried to give BrightSpark formflow.admin at the PLATFORM level, the auth service would reject it.
  The ceiling is enforced — Omar can't give more than he has.

  NovaTech provisions Summit Hotels the same way:

  SUMMIT=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "X-API-Key: $NOVATECH_API_KEY" \
    -d '{
      "name": "Summit Hotels",
      "slug": "summit-hotels",
      "domain": "summithotels.com",
      "parent_id": "'"$NOVATECH_ORG_ID"'",
      "settings": {"type": "customer", "provisioned_by": "novatech", "plan": "starter"},
      "metadata": {"tier": "customer", "reseller": "novatech", "industry": "hospitality"}
    }')
  SUMMIT_ORG_ID=$(echo "$SUMMIT" | jq -r '.id')

  ---
  Step 6: Branding — Three Tiers, Three Identities

  This is the white-label magic. Three different login pages at three different URLs, each looking like a completely different product.

  6a: FormFlow's own internal login (for Priya and the FormFlow team)

  # Priya configures FormFlow's internal login page
  curl -X PUT "$AUTH_URL/organizations/$FORMFLOW_ORG_ID/login-config" \
    -H "Authorization: Bearer $PRIYA_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "branding": {
        "primary_color": "#7C3AED",
        "page_title": "FormFlow — Internal",
        "logo_url": "https://formflow.io/logo.png",
        "login_template": "dark"
      },
      "content": {
        "welcome_message": "FormFlow Platform",
        "signup_message": "Internal access only"
      },
      "auth_methods": {
        "email_password": true,
        "signup_enabled": false,
        "invitation_only": true
      }
    }'

  # URL: https://auth.service.ab0t.com/login/formflow
  # Who uses it: Priya, FormFlow engineers, support staff — nobody else

  6b: NovaTech's reseller portal (NovaTech's own staff)

  # Omar configures NovaTech's login page
  curl -X PUT "$AUTH_URL/organizations/$NOVATECH_ORG_ID/login-config" \
    -H "Authorization: Bearer $OMAR_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "branding": {
        "primary_color": "#0284C7",
        "page_title": "NovaTech Forms — Partner Portal",
        "logo_url": "https://novatech-solutions.com/forms-logo.png",
        "login_template": "dark",
        "custom_css": ".powered-by { display: none !important; }"
      },
      "content": {
        "welcome_message": "NovaTech Forms",
        "signup_message": "Partner access only",
        "footer_message": "NovaTech Solutions — Powered by our platform"
      },
      "auth_methods": {
        "email_password": true,
        "signup_enabled": false,
        "invitation_only": true
      }
    }'

  Concept: Hiding the Underlying Platform
  The custom_css hides any "powered by" branding. The logo is NovaTech's. The page title says "NovaTech Forms." Omar's users never see "FormFlow."

  # URL: https://auth.service.ab0t.com/login/novatech
  # Who uses it: Omar, NovaTech's account managers, NovaTech's support staff

  6c: BrightSpark's customer login page — the real white-label

  # NovaTech configures BrightSpark's login page on their behalf
  curl -X PUT "$AUTH_URL/organizations/$BRIGHTSPARK_ORG_ID/login-config" \
    -H "X-API-Key: $NOVATECH_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{
      "branding": {
        "primary_color": "#DC2626",
        "background_color": "#FFF7F7",
        "page_title": "BrightSpark — Sign In",
        "logo_url": "https://brightspark.com/logo.png",
        "login_template": "default",
        "custom_css": ".powered-by { display: none !important; }"
      },
      "content": {
        "welcome_message": "Welcome to BrightSpark",
        "signup_message": "Create your BrightSpark account",
        "terms_url": "https://brightspark.com/terms",
        "privacy_url": "https://brightspark.com/privacy",
        "footer_message": "Need help? Contact support@brightspark.com"
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

  # URL: https://auth.service.ab0t.com/login/brightspark
  # Who uses it: BrightSpark's 45 employees — they see BrightSpark red branding, BrightSpark logo
  # They have no idea NovaTech is involved. They have no idea FormFlow exists.

  What each person sees when they visit their login page:

  ┌────────────────────────────────────┬─────────────────────────────────────────────────────────┐
  │            Who visits              │                   What they see                         │
  ├────────────────────────────────────┼─────────────────────────────────────────────────────────┤
  │ Priya at /login/formflow           │ Purple theme, "FormFlow Platform" — Priya's product     │
  ├────────────────────────────────────┼─────────────────────────────────────────────────────────┤
  │ Omar at /login/novatech            │ Blue theme, "NovaTech Forms" — Omar's brand             │
  ├────────────────────────────────────┼─────────────────────────────────────────────────────────┤
  │ BrightSpark staff /login/brightspark│ Red theme, "BrightSpark" logo — BrightSpark's brand    │
  ├────────────────────────────────────┼─────────────────────────────────────────────────────────┤
  │ Summit staff /login/summit-hotels  │ Summit Hotels branding — Summit's brand                 │
  └────────────────────────────────────┴─────────────────────────────────────────────────────────┘

  All four are the same auth service. All four look completely different.

  6d: BrightSpark's admin can further customize their own branding

  BrightSpark's admin (Rosa at BrightSpark) can update the login config within her org. She can change colors, update the logo, edit the welcome message. She can't change things that would require reseller-level permissions. She's customizing her own org's appearance.

  curl -X PUT "$AUTH_URL/organizations/$BRIGHTSPARK_ORG_ID/login-config" \
    -H "Authorization: Bearer $BRIGHTSPARK_ADMIN_TOKEN" \
    -d '{
      "content": {
        "welcome_message": "Welcome to BrightSpark Retail Platform",
        "signup_message": "Create your team account"
      }
    }'

  ---
  Step 7: OAuth Clients — One Per Customer App Instance

  Each customer needs their own OAuth client so their login page redirects back to their app. NovaTech's CRM creates these automatically during provisioning.

  # NovaTech creates an OAuth client for BrightSpark's app
  BRIGHTSPARK_CLIENT=$(curl -s -X POST "$AUTH_URL/auth/oauth/register" \
    -H "X-API-Key: $NOVATECH_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{
      "client_name": "BrightSpark App (NovaTech provisioned)",
      "redirect_uris": [
        "https://app.brightspark.com/callback",
        "https://brightspark.novatech-forms.com/callback"
      ],
      "response_types": ["code"],
      "grant_types": ["authorization_code", "refresh_token"],
      "token_endpoint_auth_method": "none"
    }')
  BRIGHTSPARK_CLIENT_ID=$(echo "$BRIGHTSPARK_CLIENT" | jq -r '.client_id')

  # Store against the BrightSpark org record in NovaTech's CRM
  # NovaTech's app then sends BrightSpark this URL for their "Sign In" button:
  # https://auth.service.ab0t.com/login/brightspark?client_id=BRIGHTSPARK_CLIENT_ID
  #   &redirect_uri=https://app.brightspark.com/callback
  #   &response_type=code&state=RANDOM

  Concept: Client Scoping in the Reseller Model
  The OAuth client was created with NovaTech's API key while "inside" BrightSpark's org context. So it's scoped to BrightSpark. It can only be used on /login/brightspark. If someone tries to use BrightSpark's client_id on /login/summit-hotels — rejected. Different orgs, client doesn't match.

  This means: even if BrightSpark's client_id leaked, it can't be used to phish Summit Hotels users.

  ---
  Step 8: Social Providers — Reseller Sets Defaults, Customer Can Add More

  NovaTech wants all their customers to have Google login available by default. They configure it at the NovaTech org level. Then BrightSpark can add Microsoft on top.

  8a: NovaTech sets up Google for their entire customer base

  # NovaTech's Google OAuth app (created in Google Cloud for NovaTech's domain)
  curl -X POST "$AUTH_URL/providers/" \
    -H "X-API-Key: $NOVATECH_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{
      "org_id": "'$BRIGHTSPARK_ORG_ID'",
      "provider_type": "google",
      "name": "Continue with Google",
      "config": {
        "client_id": "NOVATECH_GOOGLE_CLIENT_ID.apps.googleusercontent.com",
        "client_secret": "NOVATECH_GOOGLE_SECRET"
      },
      "priority": 1
    }'

  NovaTech uses ONE Google OAuth app they manage — all their customers get Google login through it. BrightSpark doesn't need their own Google console setup. NovaTech handles it.

  8b: BrightSpark's admin adds Microsoft for their own users

  # BrightSpark admin (Rosa) adds Microsoft for her team (most use Office 365)
  curl -X POST "$AUTH_URL/providers/" \
    -H "Authorization: Bearer $BRIGHTSPARK_ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "org_id": "'$BRIGHTSPARK_ORG_ID'",
      "provider_type": "microsoft",
      "name": "Continue with Microsoft",
      "config": {
        "client_id": "BRIGHTSPARK_MS_CLIENT_ID",
        "client_secret": "BRIGHTSPARK_MS_SECRET"
      },
      "priority": 2
    }'

  BrightSpark's login page now shows: Google (from NovaTech) + Microsoft (from BrightSpark) + email/password. Summit Hotels might have only Google (NovaTech's) + email/password if they didn't add their own.

  ---
  Step 9: Visibility Rules — Who Can See Whose Data

  9a: Omar (NovaTech) can see all NovaTech customers

  Omar's token is scoped to NovaTech. NovaTech is the parent of BrightSpark and Summit. With ancestor access enabled, Omar can:

  # Omar sees all NovaTech customer orgs
  curl -X GET "$AUTH_URL/organizations/$NOVATECH_ORG_ID/hierarchy" \
    -H "Authorization: Bearer $OMAR_TOKEN"

  # Returns: NovaTech -> [BrightSpark, Summit Hotels, ...]

  # Omar sees BrightSpark's users (for support)
  curl -X GET "$AUTH_URL/organizations/$BRIGHTSPARK_ORG_ID/users" \
    -H "Authorization: Bearer $OMAR_TOKEN"
  # Works — ancestor access: NovaTech is parent of BrightSpark

  # Omar tries to see CloudBridge's customers
  curl -X GET "$AUTH_URL/organizations/$CLOUDBRIDGE_ORG_ID/users" \
    -H "Authorization: Bearer $OMAR_TOKEN"
  # 403 — Omar is not in CloudBridge's org or ancestry. Sibling isolation.

  9b: NovaTech support team — scoped cross_tenant

  NovaTech has a support team of 3 people. They need to see any NovaTech customer's data. Not CloudBridge customers, not FormFlow internals. Just NovaTech's subtree.

  # Omar grants NovaTech support cross_tenant WITHIN the NovaTech subtree
  # The cross_tenant permission respects org ancestry — it doesn't jump to sibling orgs
  curl -X POST "$AUTH_URL/permissions/grant?user_id=$NOVATECH_SUPPORT_USER_ID&org_id=$NOVATECH_ORG_ID&permission=formflow.cross_tenant" \
    -H "Authorization: Bearer $OMAR_TOKEN"

  NovaTech support can now access data in BrightSpark and Summit (NovaTech's children). They CANNOT access CloudBridge's Pacific Logistics (different reseller branch — no ancestry connection).

  9c: FormFlow support can see everyone

  Priya's support team has cross_tenant granted in the FormFlow ROOT org. That means they can see the entire tree — all resellers, all customers.

  # Priya grants FormFlow support cross_tenant at the platform level
  curl -X POST "$AUTH_URL/permissions/grant?user_id=$FORMFLOW_SUPPORT_USER_ID&org_id=$FORMFLOW_ORG_ID&permission=formflow.cross_tenant" \
    -H "Authorization: Bearer $PRIYA_TOKEN"

  # FormFlow support can now see NovaTech, CloudBridge, and all their customers
  # They're the "god mode" support — for platform-level issues only

  What everyone can see:

  ┌──────────────────────┬──────────────────────┬────────────────────────┬─────────────────────────┬──────────────────────┐
  │        Person        │    BrightSpark       │    Summit Hotels       │   Pacific Logistics      │  NovaTech internal   │
  ├──────────────────────┼──────────────────────┼────────────────────────┼─────────────────────────┼──────────────────────┤
  │ Priya (FormFlow CIO) │ Yes (ancestor)       │ Yes (ancestor)         │ Yes (ancestor)           │ Yes (ancestor)       │
  ├──────────────────────┼──────────────────────┼────────────────────────┼─────────────────────────┼──────────────────────┤
  │ FormFlow Support     │ Yes (cross_tenant)   │ Yes (cross_tenant)     │ Yes (cross_tenant)       │ Yes (cross_tenant)   │
  ├──────────────────────┼──────────────────────┼────────────────────────┼─────────────────────────┼──────────────────────┤
  │ Omar (NovaTech)      │ Yes (ancestor)       │ Yes (ancestor)         │ No (sibling reseller)    │ Yes (own org)        │
  ├──────────────────────┼──────────────────────┼────────────────────────┼─────────────────────────┼──────────────────────┤
  │ NovaTech Support     │ Yes (cross_tenant    │ Yes (cross_tenant      │ No (different branch)    │ Yes                  │
  │                      │  within NovaTech)    │  within NovaTech)      │                          │                      │
  ├──────────────────────┼──────────────────────┼────────────────────────┼─────────────────────────┼──────────────────────┤
  │ Ana (CloudBridge)    │ No                   │ No                     │ Yes (ancestor)           │ No                   │
  ├──────────────────────┼──────────────────────┼────────────────────────┼─────────────────────────┼──────────────────────┤
  │ Rosa (BrightSpark)   │ Yes (own org)        │ No                     │ No                       │ No                   │
  └──────────────────────┴──────────────────────┴────────────────────────┴─────────────────────────┴──────────────────────┘

  ---
  Step 10: Self-Registration for BrightSpark's End Users

  BrightSpark has 45 employees. Rosa doesn't want to invite them all. She turns on self-registration (already configured in Step 6c). Now her staff visit /login/brightspark and sign up themselves.

  What happens when an employee signs up:

  1. They visit: https://auth.service.ab0t.com/login/brightspark?client_id=BRIGHTSPARK_CLIENT_ID&redirect_uri=https://app.brightspark.com/callback&response_type=code&state=xyz
  2. They see BrightSpark red branding (not NovaTech, not FormFlow)
  3. They sign up — or use Google (provided by NovaTech) or Microsoft (added by Rosa)
  4. POST /organizations/brightspark/auth/register is called
  5. They're added to BrightSpark's org with end_user role
  6. Redirected to https://app.brightspark.com/callback?code=abc&state=xyz
  7. BrightSpark's app exchanges the code for tokens

  Rosa can upgrade her staff from the BrightSpark admin panel:

  # Rosa upgrades an employee from end_user to member
  curl -X POST "$AUTH_URL/organizations/$BRIGHTSPARK_ORG_ID/invite" \
    -H "Authorization: Bearer $BRIGHTSPARK_ADMIN_TOKEN" \
    -d '{
      "email": "staffmember@brightspark.com",
      "role": "member",
      "permissions": [
        "formflow.create.forms", "formflow.write.forms",
        "formflow.publish.forms", "formflow.read.analytics"
      ]
    }'

  From BrightSpark's staff perspective: they signed up for "BrightSpark." They use "BrightSpark Forms." Rosa manages them in "the BrightSpark admin panel." FormFlow is invisible.

  ---
  Step 11: NovaTech Offboards a Customer

  Situation: BrightSpark stops paying. NovaTech needs to suspend their access.

  11a: NovaTech suspends BrightSpark's org

  # Omar suspends BrightSpark — all their users immediately lose access
  curl -X PUT "$AUTH_URL/organizations/$BRIGHTSPARK_ORG_ID" \
    -H "X-API-Key: $NOVATECH_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{
      "status": "suspended",
      "metadata": {
        "suspension_reason": "payment_overdue",
        "suspended_at": "2026-11-01T09:00:00Z",
        "suspended_by": "omar@novatech-solutions.com"
      }
    }'

  What just happened: Every token scoped to BrightSpark's org is now invalid. Every API key in BrightSpark's org stops working. The login page at /login/brightspark returns an error. BrightSpark's 45 users cannot log in.

  NovaTech didn't need FormFlow's involvement. They manage their own customer lifecycle.

  11b: NovaTech reactivates once payment is received

  curl -X PUT "$AUTH_URL/organizations/$BRIGHTSPARK_ORG_ID" \
    -H "X-API-Key: $NOVATECH_API_KEY" \
    -d '{"status": "active"}'

  Access restored instantly. No data was lost.

  11c: NovaTech fully offboards a customer (permanent)

  # Full deletion — removes org, all users' memberships, all data
  curl -X DELETE "$AUTH_URL/organizations/$BRIGHTSPARK_ORG_ID" \
    -H "X-API-Key: $NOVATECH_API_KEY"

  NovaTech manages the full customer lifecycle — provisioning, suspension, reactivation, deletion — without ever involving FormFlow support.

  ---
  Step 12: FormFlow Adds a New Reseller

  New reseller onboarding is automated. When NovaTech joined, Priya did it manually. Now FormFlow has a reseller signup flow.

  # Reseller self-service signup (FormFlow's backend)
  async def onboard_reseller(company_name: str, slug: str, domain: str,
                              admin_email: str, contract_ref: str):
      # 1. Create the reseller org (child of FormFlow)
      org = await auth_client.post("/organizations/", json={
          "name": company_name,
          "slug": slug,
          "domain": domain,
          "parent_id": FORMFLOW_ORG_ID,
          "settings": {"type": "reseller", "hierarchical": True, "white_label": True},
          "metadata": {"tier": "reseller", "contract_ref": contract_ref}
      }, headers={"X-API-Key": SERVICE_API_KEY})
      reseller_org_id = org["id"]

      # 2. Invite the reseller admin
      await auth_client.post(f"/organizations/{reseller_org_id}/invite", json={
          "email": admin_email,
          "role": "admin",
          "permissions": [
              "formflow.admin", "formflow.create.customers",
              "formflow.write.customers", "formflow.read.customers",
              "formflow.delete.customers", "formflow.resell",
              "formflow.write.branding", "formflow.read.analytics"
          ]
      }, headers={"X-API-Key": SERVICE_API_KEY})

      # 3. Create their reseller API key — inherits org from bearer token context
      key = await auth_client.post("/api-keys/", json={
          "name": f"{slug}-crm-integration",
          "permissions": [
              "formflow.create.customers", "formflow.write.customers",
              "formflow.read.customers", "formflow.resell", "formflow.read.analytics"
          ]
      }, headers={"X-API-Key": SERVICE_API_KEY})

      # 4. Send the reseller their API key + documentation
      await email_service.send_reseller_welcome(admin_email, api_key=key["key"])

      return {"org_id": reseller_org_id, "api_key": key["key"]}

  A new reseller is fully onboarded in one function call.

  ---
  Summary: The Complete 3-Tier Picture

  FormFlow (root)
  │  Login: /login/formflow (invitation_only, FormFlow purple)
  │  Priya + FormFlow team (20 people, invitation_only)
  │  FormFlow Support (cross_tenant — sees entire tree)
  │  SERVICE_API_KEY: ab0t_sk_live_formflow_... (manages resellers)
  │
  ├── NovaTech Solutions (reseller, child of FormFlow)
  │   │  Login: /login/novatech (invitation_only, NovaTech blue, "NovaTech Forms")
  │   │  Omar + NovaTech team (10 people)
  │   │  NovaTech Support (cross_tenant within NovaTech subtree only)
  │   │  NOVATECH_API_KEY: ab0t_sk_live_novatech_... (manages NovaTech customers)
  │   │  Ancestor access: Omar sees BrightSpark + Summit (not CloudBridge)
  │   │
  │   ├── BrightSpark Retail (customer, child of NovaTech)
  │   │   │  Login: /login/brightspark (open signup, BrightSpark red, BrightSpark logo)
  │   │   │  OAuth client: brightspark_client_xxx (scoped to brightspark org)
  │   │   │  Providers: Google (NovaTech's), Microsoft (BrightSpark's own)
  │   │   │  Rosa (admin, invited by NovaTech provisioning)
  │   │   └── 44 staff (members/end_users, self-registered or invited by Rosa)
  │   │
  │   └── Summit Hotels (customer, child of NovaTech)
  │       │  Login: /login/summit-hotels (Summit branding)
  │       │  OAuth client: summit_client_yyy
  │       │  Providers: Google (NovaTech's)
  │       └── Summit team (self-registered)
  │
  └── CloudBridge Systems (reseller, child of FormFlow)
      │  Login: /login/cloudbridge (invitation_only, "CloudBridge Flow")
      │  Ana + CloudBridge team
      │  CLOUDBRIDGE_API_KEY: ab0t_sk_live_cloudbridge_...
      │  Ancestor access: Ana sees Pacific Logistics (not NovaTech customers)
      │
      └── Pacific Logistics (customer, child of CloudBridge)
          └── Login: /login/pacific-logistics (Pacific branding)

  Key properties of this architecture:
  - BrightSpark and Summit cannot see each other (sibling isolation within NovaTech)
  - NovaTech and CloudBridge cannot see each other (sibling isolation at reseller tier)
  - Omar can see his customers, not Ana's (ancestry, not cross_tenant)
  - Ana can see her customers, not Omar's (same)
  - FormFlow sees everyone (platform-level cross_tenant + root ancestry)
  - Permission ceilings enforced: nobody can grant more than they have
  - Each tier has its own branded login page — FormFlow is invisible to end customers
  - NovaTech manages their customer lifecycle (provision, suspend, delete) without FormFlow
  - One reseller's compromised API key cannot touch another reseller's customers
