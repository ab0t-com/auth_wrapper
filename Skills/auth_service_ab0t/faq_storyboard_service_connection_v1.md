question: We built an AI screenplay writing app called "Screenplay." We don't handle billing or payments ourselves — we use a separate Billing Company and a separate Payment Company
  that both run on the same auth mesh. Our users (writers) log into Screenplay. When they view their invoices, that data lives in Billing Company. When they pay for a subscription,
  that goes through Payment Company. How do we wire this up? We need our backend to talk to both services, and ideally our frontend can call them directly too. What's the right way
  to model this — do we need a sub-org per user per service, or is there a simpler approach?

● This is the "service mesh consumer" pattern — your app isn't a service provider, it's a customer of multiple service providers that all share the same auth infrastructure.
  Good news: this is way simpler than most people make it. We'll use a real case study (Screenplay's own v3 setup) to show the over-engineered version first, then strip it down
  to what you actually need.

  By the end you'll have:

  - Screenplay's own org (where your users and employees live)
  - ONE customer account under Billing Company (not one per user)
  - ONE merchant account under Payment Company (not one per user)
  - Backend API keys for batch operations (reports, webhooks, cron jobs)
  - Frontend access via user tokens + org context (no API keys in the browser)
  - Per-user data isolation via customer references (not per-user sub-orgs)
  - Optional Zanzibar upgrade for fine-grained access control

  ---
  Concept: Two Ways to Isolate User Data Across Services

  When Screenplay's users interact with Billing Company, someone needs to make sure Jane sees only Jane's invoices. There are two approaches:

  ┌──────────────────────────────────────────────────────────────────────────────────────────┐
  │  Approach A: Per-User Workspace Isolation (what Screenplay v3 did)                       │
  │                                                                                          │
  │  Billing Company                                                                         │
  │  └── Screenplay Customer (sub-org)                                                       │
  │      ├── Jane's Billing Workspace (sub-sub-org, own service account, own API key)        │
  │      ├── Bob's Billing Workspace  (sub-sub-org, own service account, own API key)        │
  │      └── ... × every user                                                                │
  │                                                                                          │
  │  Cost: N users × M services = N×M orgs, N×M service accounts, N×M API keys              │
  │  1,000 users × 2 services = 2,000 extra orgs to manage                                  │
  └──────────────────────────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────────────────────────────┐
  │  Approach B: Shared Org + Customer References (what you should do)                       │
  │                                                                                          │
  │  Billing Company                                                                         │
  │  └── Screenplay Customer (sub-org, ONE service account, ONE API key)                     │
  │      └── All Screenplay users' billing data, keyed by customer_ref                       │
  │                                                                                          │
  │  Cost: M services = M orgs, M API keys. Period.                                          │
  │  1,000 users × 2 services = still just 2 sub-orgs                                       │
  └──────────────────────────────────────────────────────────────────────────────────────────┘

  Approach B is simpler because:
  - Billing Company already knows how to store data per-customer. Every billing system has a customer_id field. You use it: `customer_ref: "screenplay:{user_id}"`.
  - Your backend holds ONE API key per service. When Jane asks for her invoices, your backend calls Billing with that API key and filters by Jane's customer_ref.
  - No sub-org creation during user signup. No service account per user. No API key per user.

  Approach A (what v3 did) is valid when:
  - You need per-user API keys exposed to the user themselves (e.g., a developer platform where users build integrations)
  - Regulatory requirements demand per-user org-level isolation (HIPAA, certain PCI-DSS interpretations)
  - Each "user" is actually a company with their own sub-users

  For a consumer SaaS like Screenplay (individual writers), Approach B is the right call.

  ---
  Concept: The Service Mesh Consumer Architecture

  Here's what Screenplay's org tree looks like with Approach B:

  Auth Service
  │
  ├── Billing Company (root org, independent service provider)
  │   ├── Billing Company's own employees
  │   ├── Screenplay Customer Account (child org, parent_id = Billing Company)
  │   │   └── Service account + API key (Screenplay's backend uses this)
  │   ├── SomeOtherApp Customer Account (sibling — Screenplay can't see this)
  │   └── ...
  │
  ├── Payment Company (root org, independent service provider)
  │   ├── Payment Company's own employees
  │   ├── Screenplay Merchant Account (child org, parent_id = Payment Company)
  │   │   └── Service account + API key (Screenplay's backend uses this)
  │   └── ...
  │
  └── Screenplay (root org, the app)
      ├── admin@screenplay.dev (owner)
      ├── jane@screenplay.dev (writer, end user)
      ├── bob@screenplay.dev (writer, end user)
      └── Engineering Team (employees who build the app)

  Key points:
  - Screenplay is a ROOT org, not a child of anyone. It's an independent company.
  - Screenplay has child orgs INSIDE Billing Company and Payment Company — these represent the business relationship "Screenplay is a customer of Billing Company."
  - Those child orgs are created by the service provider (or jointly during onboarding).
  - Screenplay's users do NOT exist in the billing/payment sub-orgs. They exist only in the Screenplay org.
  - Screenplay's backend bridges the gap: it authenticates the user via their Screenplay JWT, then calls billing/payment using its API keys, passing the user's identity as a customer reference.

  ---
  Concept: Frontend vs Backend Access Patterns

  Your app has two halves that talk to external services differently:

  ┌──────────────┬──────────────────────────────────────┬──────────────────────────────────┐
  │              │ Frontend (browser)                    │ Backend (server)                 │
  ├──────────────┼──────────────────────────────────────┼──────────────────────────────────┤
  │ Auth method  │ User's JWT token                     │ API key (X-API-Key header)       │
  │ Scope        │ That user's data only                │ All users in Screenplay's sub-org│
  │ Lifetime     │ 15 min (auto-refreshes)              │ No expiry (rotate periodically)  │
  │ Storage      │ sessionStorage (never localStorage)  │ Environment variable             │
  │ Use cases    │ Jane views her invoices              │ Generate monthly report for all  │
  │              │ Jane updates payment method           │ Process payment webhooks         │
  │              │ Jane checks subscription status       │ Batch usage updates              │
  │ Isolation    │ Service enforces: token = one user   │ Your code filters by customer_ref│
  └──────────────┴──────────────────────────────────────┴──────────────────────────────────┘

  Rule of thumb: if a human clicked a button, use their JWT. If a cron job or webhook triggered it, use the API key.

  Note: frontend direct access requires the service provider to accept Screenplay user tokens with X-Org-Context headers pointing to Screenplay's sub-org. If the service provider doesn't support this, all calls go through your backend.

  ---
  Characters

  - Yuki Tanaka       — Screenplay founder/CTO
  - Jane Doe          — Screenplay user (writer, the customer)
  - Marcus Webb       — Screenplay backend engineer
  - Billing Company   — Independent service provider (already exists on the mesh)
  - Payment Company   — Independent service provider (already exists on the mesh)

  ---

## Step 1: Yuki Creates the Screenplay Org

  Yuki registers and creates Screenplay's home org. This is where all Screenplay users will live.

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /auth/register                                                           │
  └────────────────────────────────────────────────────────────────────────────────┘

  AUTH_URL="https://auth.service.ab0t.com"

  curl -X POST "$AUTH_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "yuki@screenplay.dev",
      "password": "YukiSecure2026!",
      "name": "Yuki Tanaka"
    }'

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /auth/login                                                              │
  └────────────────────────────────────────────────────────────────────────────────┘

  TOKEN=$(curl -s -X POST "$AUTH_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email": "yuki@screenplay.dev", "password": "YukiSecure2026!"}' \
    | jq -r '.access_token')

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /organizations/                                                          │
  └────────────────────────────────────────────────────────────────────────────────┘

  SCREENPLAY_ORG=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Screenplay",
      "slug": "screenplay",
      "domain": "screenplay.dev",
      "billing_type": "prepaid",
      "settings": {
        "type": "software_company",
        "integrations": ["billing", "payment"]
      },
      "metadata": {
        "product": "ai_screenplay_writer",
        "industry": "software"
      }
    }')

  SCREENPLAY_ORG_ID=$(echo "$SCREENPLAY_ORG" | jq -r '.id')

  What just happened: Yuki now has a personal account and a company org. The Screenplay org is a root org — it doesn't live under Billing Company or Payment Company. It's an
  independent entity on the mesh, just like them.

  ---

## Step 2: Register Screenplay as a Customer of Billing Company

  Billing Company already exists on the mesh with its own root org. Screenplay needs a customer account under it. This is a business relationship: "Screenplay buys billing
  services from Billing Company."

  There are two ways this happens in practice:
  - The service provider has a self-service onboarding flow (like Stripe's dashboard)
  - The service provider's admin creates the sub-org manually

  Either way, the result is the same: a child org under Billing Company that belongs to Screenplay.

  Assuming Billing Company's admin has set up an onboarding flow, or Yuki coordinates with them:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /organizations/                                                          │
  │  Authorization: Bearer $BILLING_ADMIN_TOKEN                                    │
  │  (Billing Company's admin creates this, or Screenplay self-serves)             │
  └────────────────────────────────────────────────────────────────────────────────┘

  BILLING_SUB_ORG=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $BILLING_ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Screenplay - Billing Account",
      "slug": "screenplay-billing",
      "parent_id": "'$BILLING_COMPANY_ORG_ID'",
      "settings": {
        "type": "customer_account",
        "customer_org_id": "'$SCREENPLAY_ORG_ID'",
        "billing_type": "prepaid"
      },
      "metadata": {
        "customer": "Screenplay",
        "onboarded_at": "2026-02-25"
      }
    }')

  BILLING_SUB_ORG_ID=$(echo "$BILLING_SUB_ORG" | jq -r '.id')

  What just happened: Billing Company now has a child org specifically for Screenplay. Think of this like opening a business bank account — the bank (Billing Company) creates
  an account (sub-org) for you (Screenplay). All of Screenplay's billing data will live inside this one sub-org. There is NOT one sub-org per Screenplay user — there's one
  sub-org for the entire company.

  This is the key difference from the v3 approach: v3 created a sub-org per user (Jane's Billing Workspace, Bob's Billing Workspace, etc.). That's like opening a separate bank
  account for every employee. Unnecessary — one company account with internal ledger entries is how banks actually work.

  ---

## Step 3: Create a Service Account + API Key for Screenplay's Backend

  Screenplay's backend server needs to call Billing Company's API. It needs credentials scoped to Screenplay's billing sub-org.

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /admin/users/create-service-account                                      │
  │  Authorization: Bearer $BILLING_ADMIN_TOKEN                                    │
  └────────────────────────────────────────────────────────────────────────────────┘

  BILLING_SERVICE_ACCOUNT=$(curl -s -X POST "$AUTH_URL/admin/users/create-service-account" \
    -H "Authorization: Bearer $BILLING_ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "screenplay@billing.customers",
      "name": "Screenplay Billing Service Account",
      "description": "Backend access for Screenplay to billing data",
      "org_id": "'$BILLING_SUB_ORG_ID'",
      "permissions": [
        "billing.read.accounts",
        "billing.write.accounts",
        "billing.write.usage",
        "billing.read.invoices",
        "billing.generate.reports"
      ]
    }')

  # The response includes an api_key field
  BILLING_SERVICE_API_KEY=$(echo "$BILLING_SERVICE_ACCOUNT" | jq -r '.api_key')

  Now create an API key for ongoing access:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /api-keys/                                                               │
  │  Authorization: Bearer $BILLING_SERVICE_TOKEN                                  │
  └────────────────────────────────────────────────────────────────────────────────┘

  BILLING_KEY_RESPONSE=$(curl -s -X POST "$AUTH_URL/api-keys/" \
    -H "Authorization: Bearer $BILLING_SERVICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Screenplay Billing Backend Key",
      "permissions": [
        "billing.read.accounts",
        "billing.write.accounts",
        "billing.write.usage",
        "billing.read.invoices",
        "billing.generate.reports"
      ],
      "metadata": {
        "environment": "production",
        "created_by": "setup_script"
      }
    }')

  BILLING_API_KEY=$(echo "$BILLING_KEY_RESPONSE" | jq -r '.key')

  What just happened: Screenplay now has ONE service account and ONE API key for all billing operations. When Jane asks for her invoices, Screenplay's backend uses this key
  and filters by `customer_ref: "screenplay:jane_user_id"`. When the backend generates a monthly report for all users, it uses the same key without a customer_ref filter.

  One key. All users. The service provider's API handles per-customer filtering because that's what billing systems do.

  ---

## Step 4: Same Thing for Payment Company

  Identical pattern. One sub-org, one service account, one API key.

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /organizations/                                                          │
  │  Authorization: Bearer $PAYMENT_ADMIN_TOKEN                                    │
  └────────────────────────────────────────────────────────────────────────────────┘

  PAYMENT_SUB_ORG=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $PAYMENT_ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Screenplay - Merchant Account",
      "slug": "screenplay-merchant",
      "parent_id": "'$PAYMENT_COMPANY_ORG_ID'",
      "settings": {
        "type": "merchant_account",
        "customer_org_id": "'$SCREENPLAY_ORG_ID'"
      },
      "metadata": {
        "customer": "Screenplay"
      }
    }')

  PAYMENT_SUB_ORG_ID=$(echo "$PAYMENT_SUB_ORG" | jq -r '.id')

  # Service account
  PAYMENT_SERVICE_ACCOUNT=$(curl -s -X POST "$AUTH_URL/admin/users/create-service-account" \
    -H "Authorization: Bearer $PAYMENT_ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "screenplay@payment.merchants",
      "name": "Screenplay Payment Service Account",
      "description": "Backend access for Screenplay to payment processing",
      "org_id": "'$PAYMENT_SUB_ORG_ID'",
      "permissions": [
        "payment.create.intents",
        "payment.read.intents",
        "payment.read.methods",
        "payment.create.methods",
        "payment.verify.webhooks",
        "payment.create.refunds"
      ]
    }')

  # API key
  PAYMENT_KEY_RESPONSE=$(curl -s -X POST "$AUTH_URL/api-keys/" \
    -H "Authorization: Bearer $PAYMENT_SERVICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Screenplay Payment Backend Key",
      "permissions": [
        "payment.create.intents",
        "payment.read.intents",
        "payment.read.methods",
        "payment.create.methods",
        "payment.verify.webhooks",
        "payment.create.refunds"
      ]
    }')

  PAYMENT_API_KEY=$(echo "$PAYMENT_KEY_RESPONSE" | jq -r '.key')

  What just happened: Same pattern as billing. Screenplay now has credentials for both external services. The complete credential set is:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  Screenplay's Service Credentials                                              │
  │                                                                                │
  │  BILLING_SUB_ORG_ID=8d7e82c9-...     (Screenplay's account under Billing Co)  │
  │  BILLING_API_KEY=ab0t_sk_live_...     (backend key for billing operations)     │
  │                                                                                │
  │  PAYMENT_SUB_ORG_ID=f76e008e-...     (Screenplay's account under Payment Co)  │
  │  PAYMENT_API_KEY=ab0t_sk_live_...     (backend key for payment operations)     │
  │                                                                                │
  │  Store these in .env.production. Never in frontend code.                       │
  └────────────────────────────────────────────────────────────────────────────────┘

  ---

## Step 5: Register Service Permissions

  Before Screenplay can assign billing/payment permissions to API keys, those permissions need to exist in the auth service's permission registry. The service providers do this
  when they set up their services — but if they haven't, or if you're testing locally, here's how:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /permissions/registry/register                                           │
  └────────────────────────────────────────────────────────────────────────────────┘

  # Register billing permissions
  curl -X POST "$AUTH_URL/permissions/registry/register" \
    -H "Content-Type: application/json" \
    -d '{
      "service": "billing",
      "description": "Billing, accounting, and subscription management",
      "actions": ["read", "write", "create", "update", "delete", "generate", "admin"],
      "resources": ["accounts", "usage", "invoices", "reports", "subscriptions", "payments", "credits"]
    }'

  # Register payment permissions
  curl -X POST "$AUTH_URL/permissions/registry/register" \
    -H "Content-Type: application/json" \
    -d '{
      "service": "payment",
      "description": "Payment processing and merchant services",
      "actions": ["create", "read", "update", "delete", "verify", "capture", "cancel", "refund"],
      "resources": ["intents", "methods", "charges", "refunds", "disputes", "webhooks", "subscriptions", "plans"]
    }'

  What just happened: The auth service now recognizes every combination of `service.action.resource` — for example `billing.read.invoices`, `payment.create.intents`,
  `billing.generate.reports`. These are the building blocks for API key permissions.

  The format is always: `{service}.{action}.{resource}`

  The registration call creates all valid combinations from the cartesian product of actions × resources. You don't list them individually — you declare the axes and the
  registry generates the matrix.

  ---

## Step 6: Wire Up the Backend

  Marcus (Screenplay's backend engineer) adds the credentials to the backend service.

  .env.production:

  # Auth Service
  AUTH_SERVICE_URL=https://auth.service.ab0t.com

  # Screenplay's own org
  SCREENPLAY_ORG_ID=33c03cc0-61cf-4adc-a4cb-7b9c6b2310ac

  # Billing integration
  BILLING_SERVICE_URL=https://billing.service.ab0t.com
  BILLING_SUB_ORG_ID=8d7e82c9-4104-4f94-871f-ab5f21331164
  BILLING_API_KEY=ab0t_sk_live_gmtWJ6ePnd3xh3vdMuAq0VkBXEPAq9gg

  # Payment integration
  PAYMENT_SERVICE_URL=https://payment.service.ab0t.com
  PAYMENT_SUB_ORG_ID=f76e008e-7043-4f28-af2a-f1bd05b6cfce
  PAYMENT_API_KEY=ab0t_sk_live_44iHh7Jsiy4JY72OS5GdT7vKx66fybt9

  Backend code (Python):

  import httpx, os

  BILLING_API_KEY = os.environ["BILLING_API_KEY"]
  BILLING_SUB_ORG_ID = os.environ["BILLING_SUB_ORG_ID"]
  BILLING_SERVICE_URL = os.environ["BILLING_SERVICE_URL"]

  PAYMENT_API_KEY = os.environ["PAYMENT_API_KEY"]
  PAYMENT_SUB_ORG_ID = os.environ["PAYMENT_SUB_ORG_ID"]
  PAYMENT_SERVICE_URL = os.environ["PAYMENT_SERVICE_URL"]

  async def get_user_invoices(user_id: str):
      """Jane clicks 'My Invoices' → backend fetches from billing service"""
      async with httpx.AsyncClient() as client:
          response = await client.get(
              f"{BILLING_SERVICE_URL}/invoices",
              headers={
                  "X-API-Key": BILLING_API_KEY,
                  "X-Org-Context": BILLING_SUB_ORG_ID
              },
              params={"customer_ref": f"screenplay:{user_id}"}
          )
          return response.json()

  async def create_payment_intent(user_id: str, amount: float):
      """Jane subscribes to Pro → backend creates payment intent"""
      async with httpx.AsyncClient() as client:
          response = await client.post(
              f"{PAYMENT_SERVICE_URL}/payments/intent",
              headers={
                  "X-API-Key": PAYMENT_API_KEY,
                  "X-Org-Context": PAYMENT_SUB_ORG_ID
              },
              json={
                  "amount": int(amount * 100),  # cents
                  "currency": "usd",
                  "customer_ref": f"screenplay:{user_id}",
                  "metadata": {"product": "screenplay_pro"}
              }
          )
          return response.json()

  async def generate_monthly_report(month: str):
      """Cron job: generate billing report for ALL users"""
      async with httpx.AsyncClient() as client:
          response = await client.post(
              f"{BILLING_SERVICE_URL}/reports/monthly",
              headers={
                  "X-API-Key": BILLING_API_KEY,
                  "X-Org-Context": BILLING_SUB_ORG_ID
              },
              json={"month": month, "include_all_customers": True}
          )
          return response.json()

  async def handle_payment_webhook(data: dict, signature: str):
      """Payment Company calls Screenplay when a payment succeeds/fails"""
      async with httpx.AsyncClient() as client:
          response = await client.post(
              f"{PAYMENT_SERVICE_URL}/webhooks/verify",
              headers={
                  "X-API-Key": PAYMENT_API_KEY,
                  "X-Org-Context": PAYMENT_SUB_ORG_ID,
                  "X-Webhook-Signature": signature
              },
              json=data
          )
          return response.json()

  What just happened: The backend is a thin proxy. For user-specific operations (Jane's invoices), it adds `customer_ref: "screenplay:{user_id}"` to filter results.
  For system operations (monthly reports, webhook processing), it uses the same API key without a customer_ref filter — the key has access to all of Screenplay's data
  within the billing sub-org.

  ---

## Step 7: Frontend Direct Access (Optional)

  If the service providers support it, Screenplay's frontend can call them directly using the user's JWT and an X-Org-Context header. No API key needed in the browser.

  Frontend code (JavaScript):

  class ScreenplayServices {
      constructor(config) {
          this.authUrl = config.auth_url;
          this.billingUrl = config.billing_url;
          this.billingOrgId = config.billing_sub_org_id;
          this.paymentUrl = config.payment_url;
          this.paymentOrgId = config.payment_sub_org_id;
      }

      getUserToken() {
          return sessionStorage.getItem('access_token');
      }

      // Jane views her invoices — direct call to billing service
      async getMyInvoices() {
          const response = await fetch(`${this.billingUrl}/invoices/me`, {
              headers: {
                  'Authorization': `Bearer ${this.getUserToken()}`,
                  'X-Org-Context': this.billingOrgId
              }
          });
          return response.json();
      }

      // Jane updates her payment method — direct call to payment service
      async updatePaymentMethod(methodData) {
          const response = await fetch(`${this.paymentUrl}/payment-methods`, {
              method: 'POST',
              headers: {
                  'Authorization': `Bearer ${this.getUserToken()}`,
                  'X-Org-Context': this.paymentOrgId,
                  'Content-Type': 'application/json'
              },
              body: JSON.stringify(methodData)
          });
          return response.json();
      }
  }

  Frontend config (no secrets — safe to embed):

  window.SCREENPLAY_CONFIG = {
      auth_url: 'https://auth.service.ab0t.com',
      billing_url: 'https://billing.service.ab0t.com',
      billing_sub_org_id: '8d7e82c9-4104-4f94-871f-ab5f21331164',
      payment_url: 'https://payment.service.ab0t.com',
      payment_sub_org_id: 'f76e008e-7043-4f28-af2a-f1bd05b6cfce'
  };

  What just happened: The frontend sends Jane's JWT directly to the billing/payment services. Those services validate the token with the auth service, see that Jane is a
  member of the Screenplay org, and use the X-Org-Context to scope the request to Screenplay's billing sub-org. The service then filters by Jane's user_id (from the JWT).

  No API key is ever exposed to the browser. The sub-org IDs are not secrets — they're like Stripe's publishable key. They identify which account to use, but they don't
  grant access on their own.

  Important: This only works if the service provider validates auth service JWTs. If they have their own auth system, all calls must go through Screenplay's backend.

  ---

## Step 8: User Signup (No Per-User Service Account Needed)

  When a new writer signs up for Screenplay, you do NOT need to create billing/payment workspace orgs for them.

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /auth/register  (user registers on Screenplay)                           │
  └────────────────────────────────────────────────────────────────────────────────┘

  curl -X POST "$AUTH_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "jane@gmail.com",
      "password": "JaneSecure2026!",
      "name": "Jane Doe"
    }'

  Then invite Jane to the Screenplay org (or use hosted login for self-service):

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /organizations/{org_id}/invite                                           │
  └────────────────────────────────────────────────────────────────────────────────┘

  curl -X POST "$AUTH_URL/organizations/$SCREENPLAY_ORG_ID/invite" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "jane@gmail.com",
      "role": "member"
    }'

  That's it. Jane is now a Screenplay user. When she views invoices, Screenplay's backend passes her user_id to the billing service as a customer_ref. No sub-org created.
  No service account created. No API key created.

  If you want self-service signup (no invitation needed), set up a hosted login page:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /organizations/{org_id}/login-config                                     │
  └────────────────────────────────────────────────────────────────────────────────┘

  curl -X POST "$AUTH_URL/organizations/$SCREENPLAY_ORG_ID/login-config" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "allow_registration": true,
      "default_role": "member",
      "branding": {
        "company_name": "Screenplay",
        "logo_url": "https://screenplay.dev/logo.png",
        "primary_color": "#6366f1"
      }
    }'

  Now anyone can sign up at: https://auth.service.ab0t.com/login/screenplay

  What just happened: New users create their own accounts and automatically join the Screenplay org with the "member" role. Zero manual work per user. Zero billing/payment
  sub-orgs created. The first time Jane makes a purchase, your backend creates a billing customer_ref for her — just like any normal SaaS.

  ---

## Step 9: Delegation for Support Scenarios

  Delegation is NOT for regular user access to billing/payment. It's for admin/support scenarios: "Support agent needs to see Jane's account to debug an issue."

  Jane grants delegation to support:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /delegation/grant                                                        │
  │  Authorization: Bearer $JANE_TOKEN                                             │
  └────────────────────────────────────────────────────────────────────────────────┘

  curl -X POST "$AUTH_URL/delegation/grant" \
    -H "Authorization: Bearer $JANE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "actor_id": "'$SUPPORT_AGENT_USER_ID'",
      "scope": ["users.read", "billing.read"],
      "expires_in_hours": 1
    }'

  Support agent gets a delegated token:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /auth/delegate                                                           │
  │  Authorization: Bearer $SUPPORT_TOKEN                                          │
  └────────────────────────────────────────────────────────────────────────────────┘

  curl -X POST "$AUTH_URL/auth/delegate" \
    -H "Authorization: Bearer $SUPPORT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "target_user_id": "'$JANE_USER_ID'"
    }'

  Response: a short-lived JWT that lets the support agent act as Jane, scoped to the permissions Jane granted. Auto-expires in 1 hour.

  What just happened: This is the "act as me" pattern. Jane explicitly grants a specific person access to specific data for a specific time. The support agent can now see
  Jane's billing data, but not modify it (only `billing.read` was granted). After 1 hour, the delegation expires automatically.

  This is NOT how Jane accesses her own billing data. For that, she uses her own JWT (frontend) or Screenplay's backend uses the API key with her customer_ref.

  ---
  Case Study: Why Screenplay v3 Over-Engineered This

  Screenplay's v3 setup (the real production code in ~/random/storyboard/setup/v3/) used Approach A — per-user workspace isolation. Here's what they built and why it was more
  than necessary:

  What v3 did:
  1. Created Screenplay's org (correct, same as above)
  2. Created ONE billing sub-org under Billing Company (correct)
  3. Created ONE payment sub-org under Payment Company (correct)
  4. For each user (Jane), created ANOTHER sub-org under the billing sub-org (over-engineered)
  5. For each user, created ANOTHER sub-org under the payment sub-org (over-engineered)
  6. For each user sub-org, created a service account with a unique email (over-engineered)
  7. For each service account, generated an API key (over-engineered)

  Steps 1-3 are correct. Steps 4-7 add complexity that scales with user count.

  Why they did it: At the time, the team didn't realize the billing/payment services could filter by customer_ref within a shared sub-org. They assumed the only way to isolate
  Jane's data from Bob's was to put them in separate orgs. This is like building a separate filing cabinet for each employee instead of using labeled folders in one cabinet.

  When per-user isolation IS correct:
  - Developer platforms (GitHub-style) where each user needs their OWN API key to build integrations
  - Regulated industries where per-user data must be in separate DynamoDB partitions / S3 prefixes
  - White-label reseller models where each "user" is actually a company with sub-users
  - Marketplace sellers (each seller IS a business — see the marketplace guide)

  When per-user isolation is overkill:
  - Consumer SaaS (writers using Screenplay)
  - Any case where users don't need their own API keys
  - Any case where the service provider's API supports customer_ref filtering

  ---
  Decision Matrix: When to Use Each Approach

  ┌──────────────────────────────────┬─────────────────────────┬───────────────────────────────┐
  │  Question                        │  If YES → Approach A    │  If NO → Approach B           │
  │                                  │  (per-user sub-orgs)    │  (shared org + customer_ref)  │
  ├──────────────────────────────────┼─────────────────────────┼───────────────────────────────┤
  │  Do users need their own         │  ✓ Use per-user orgs    │  ✗ Backend holds one key      │
  │  API keys?                       │                         │                               │
  ├──────────────────────────────────┼─────────────────────────┼───────────────────────────────┤
  │  Is each "user" actually a       │  ✓ Each company = org   │  ✗ Users are individuals      │
  │  company with sub-users?         │                         │                               │
  ├──────────────────────────────────┼─────────────────────────┼───────────────────────────────┤
  │  Does regulation require per-    │  ✓ Separate orgs for    │  ✗ customer_ref filtering     │
  │  user org-level isolation?       │    audit boundaries     │    is sufficient              │
  ├──────────────────────────────────┼─────────────────────────┼───────────────────────────────┤
  │  Do users manage their own       │  ✓ Per-user org with    │  ✗ Platform manages billing   │
  │  billing/payment settings?       │    user as owner        │    on behalf of users         │
  ├──────────────────────────────────┼─────────────────────────┼───────────────────────────────┤
  │  Will you have >100 users?       │  Consider the ops cost  │  ✓ Shared org scales to ∞    │
  │                                  │  of N×M orgs            │                               │
  └──────────────────────────────────┴─────────────────────────┴───────────────────────────────┘

  ---
  Complete Architecture Summary

  Auth Service (Central Identity Provider)
  │
  ├── Billing Company (root org)                          ← Independent service provider
  │   └── Screenplay Customer Account (child org)         ← ONE sub-org, not one per user
  │       ├── Service Account: screenplay@billing.customers
  │       ├── API Key: ab0t_sk_live_... (backend only)
  │       └── Data: all Screenplay users' billing, keyed by customer_ref
  │
  ├── Payment Company (root org)                          ← Independent service provider
  │   └── Screenplay Merchant Account (child org)         ← ONE sub-org, not one per user
  │       ├── Service Account: screenplay@payment.merchants
  │       ├── API Key: ab0t_sk_live_... (backend only)
  │       └── Data: all Screenplay users' payments, keyed by customer_ref
  │
  └── Screenplay (root org)                               ← Independent company
      ├── Yuki Tanaka (owner)
      ├── Marcus Webb (engineer, member)
      ├── Jane Doe (writer, member)                       ← NO sub-orgs created for Jane
      ├── Bob Chen (writer, member)
      ├── Engineering Team
      └── Hosted Login: /login/screenplay                 ← Self-service user signup

  Data flow for "Jane views her invoices":
  1. Jane's browser → Screenplay backend (JWT auth)
  2. Screenplay backend → Billing Service (API key + customer_ref=screenplay:jane_id)
  3. Billing Service → returns Jane's invoices only
  4. Screenplay backend → Jane's browser

  Data flow for "Monthly billing report" (cron):
  1. Cron → Screenplay backend
  2. Screenplay backend → Billing Service (API key, no customer_ref filter)
  3. Billing Service → returns ALL Screenplay customer data
  4. Screenplay backend → generates report

  ---
  Checklist: Service Mesh Consumer Setup

  □ Create your company's root org
  □ Coordinate with each service provider to create a customer sub-org under them
  □ Create ONE service account per service provider sub-org
  □ Create ONE API key per service provider sub-org
  □ Register service permissions if not already done
  □ Store API keys in .env.production (NEVER in frontend)
  □ Wire backend to use API key + X-Org-Context + customer_ref for per-user operations
  □ (Optional) Enable frontend direct access via user JWT + X-Org-Context
  □ (Optional) Set up hosted login for self-service user registration
  □ (Optional) Configure delegation for support agent scenarios
  □ Do NOT create sub-orgs per user unless you have a specific reason from the decision matrix

  ---
  References

  - Screenplay v3 setup scripts: ~/random/storyboard/setup/v3/
  - v3 architecture docs: ~/random/storyboard/setup/v3/MULTI_TENANT_AUTH_MESH_ARCHITECTURE.md
  - v3 security analysis: ~/random/storyboard/setup/v3/SECURITY_ANALYSIS.md
  - Simple company guide: ~/Skills/auth_service_ab0t/faq_simple_company_v2.md
  - Marketplace guide (where per-seller orgs ARE correct): ~/Skills/auth_service_ab0t/faq_marketplace_twosided_v1.md
  - SaaS reseller guide (where per-reseller orgs ARE correct): ~/Skills/auth_service_ab0t/faq_saas_reseller_whitelabel_v2.md
