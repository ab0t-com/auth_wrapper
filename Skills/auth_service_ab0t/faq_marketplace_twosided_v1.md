question: We are building "CraftMarket" — a two-sided marketplace for handmade goods. We have sellers who each run their own stores, buyers who shop across all stores, and a platform
  team that manages everything. We need sellers isolated from each other, buyers to have access only to their own order history, escrow-style delegation when an order is placed
  (seller needs the buyer's shipping address, but only for that order, and only until it ships), and dispute resolution agents who need to see both sides of a transaction without
  seeing everything. How do we model this?

● Two-sided marketplaces are one of the trickiest auth scenarios because you have three fundamentally different identities — platform, sellers, buyers — that need selective,
  purpose-driven cross-boundary access. Zanzibar is the key: orders become first-class authorization objects linking buyers and sellers without either side getting a blank pass
  into the other's data.

  By the end you'll have:

  - A platform/seller org hierarchy (sellers isolated in their own orgs)
  - Buyers as platform-level users (end_user) — no seller org membership needed
  - Zanzibar-backed order objects linking buyer and seller across org boundaries
  - Escrow-style delegation tokens: seller gets shipping address for one order, auto-revoked on delivery
  - Dispute resolution: symmetric, scoped access to one transaction without opening the whole store
  - Service API keys for your Payment Processor, Escrow Service, and Notification system

  ---
  Concept: The Three Identity Types

  Most auth tutorials assume one type of user. Marketplaces have three, each with a different relationship to data:

  ┌─────────────────┬────────────────────────────────────────────────────┬───────────────────────────────────────────────────┐
  │   Identity Type │ What they own                                      │ What they must NOT see                            │
  ├─────────────────┼────────────────────────────────────────────────────┼───────────────────────────────────────────────────┤
  │ Platform        │ Everything (orgs, users, orders, disputes)         │ N/A — operates with cross_tenant                 │
  ├─────────────────┼────────────────────────────────────────────────────┼───────────────────────────────────────────────────┤
  │ Seller          │ Their store inventory, pricing, fulfillment queue  │ Other sellers' inventory, pricing, customer lists │
  ├─────────────────┼────────────────────────────────────────────────────┼───────────────────────────────────────────────────┤
  │ Buyer           │ Their own orders, messages, reviews, addresses     │ Other buyers' data, seller back-office data       │
  └─────────────────┴────────────────────────────────────────────────────┴───────────────────────────────────────────────────┘

  The key insight: buyers and sellers are not in the same org. They're connected only at the transaction level — through Zanzibar order tuples. Before a purchase, a buyer has
  zero connection to a seller. The moment an order is placed, Zanzibar creates a scoped, purpose-specific link. After delivery, that link is severed.

  This is the "escrow" pattern: access is granted for the duration of a transaction, scoped to what the transaction requires, and automatically revoked when the transaction ends.

  ---
  Concept: Why Not Just Put Everyone in One Org?

  If you put buyers and sellers in the same org, two things break:

  1. Sellers can see each other. Tom at WoodCraft Studio should not be able to see Ana's Pottery Plus inventory, pricing strategy, or sales volume. Separate orgs give you hard
     walls enforced by the auth server — not by application-level if-statements that someone forgets.

  2. Buyers accidentally get seller permissions. If you rely on roles to separate them in one org, you need negative permissions or complex role hierarchies. Mistakes expose
     seller financial data to buyers. Separate orgs make this impossible by default.

  The tradeoff: buyers in their own isolated orgs would mean they can't discover or buy from sellers. The solution is to put buyers in the platform org (not a seller org), and
  use Zanzibar to create per-transaction cross-org linkage. Buyers exist at the platform layer; their connection to any given seller is expressed purely through order tuples.

  ---
  The Architecture: CraftMarket

  CraftMarket (platform org — Sofia, support team, dispute agents)
  │
  ├── [CHILD ORG] WoodCraft Studio       (Tom Baker — handmade wood furniture)
  │   └── Members: Tom (owner), Rachel (fulfillment manager)
  │
  ├── [CHILD ORG] Pottery Plus           (Ana Rivera — ceramic goods)
  │   └── Members: Ana (owner), Diego (assistant)
  │
  ├── [CHILD ORG] TextileWorks           (future seller — same pattern)
  │
  └── Buyers live in the platform org as end_user (Marcus, Lisa, Chen Wei, ...)
      They are NOT members of any seller org.

  Services (API keys, not orgs):
  ├── Payment Processor   (store.write.orders, store.read.inventory)
  ├── Escrow Service      (store.write.delegations, store.read.orders)
  └── Notification Svc    (store.read.orders — read-only, sends emails)

  Characters:
  - Sofia Reyes        — CraftMarket founder/CTO (platform owner)
  - Tom Baker          — WoodCraft Studio owner (seller)
  - Rachel Ng          — WoodCraft fulfillment manager
  - Ana Rivera         — Pottery Plus owner (seller)
  - Diego Santos       — Pottery Plus assistant
  - Marcus Kim         — Buyer (registered on CraftMarket)
  - Diana Osei         — Dispute Resolution Agent (cross_tenant, scoped)

  ---

## Step 1: The Platform Org

  Sofia starts by creating the CraftMarket platform org. This will be the parent of all seller orgs, and where buyers register.

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /auth/register                                                           │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "email": "sofia@craftmarket.io",
    "password": "...",
    "name":  "Sofia Reyes",
    "org_name": "CraftMarket",
    "org_slug": "craftmarket"
  }

  Response:
  {
    "user": { "id": "usr_sofia_001", "email": "sofia@craftmarket.io" },
    "org":  { "id": "org_craftmarket", "slug": "craftmarket", "name": "CraftMarket" },
    "token": "eyJ..."
  }

  Sofia is automatically the owner of the CraftMarket org.

  Now she defines the permission schema — what capabilities exist in a marketplace:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /permissions/registry/register                                          │
  │  Authorization: Bearer eyJ...  (Sofia's token)                                │
  └────────────────────────────────────────────────────────────────────────────────┘

  // Register the "store" service permissions
  {
    "service": "store",
    "description": "Seller store operations — inventory, orders, fulfillment",
    "actions": ["read", "write"],
    "resources": ["inventory", "orders", "analytics", "customers", "fulfillment", "delegations"]
  }

  // Register the "platform" service permissions
  {
    "service": "platform",
    "description": "Platform-wide operations — disputes, seller management",
    "actions": ["read", "write", "manage"],
    "resources": ["all_orders", "disputes", "sellers"]
  }

  What just happened?
  ─────────────────
  Sofia registered the platform org and defined every capability that will ever be granted
  anywhere in the system. This is the global schema — sellers get a subset, buyers get almost
  nothing (end_user), service accounts get exactly what they need.

---

## Step 2: Custom Roles for the Marketplace

  The default roles (owner/admin/member/guest) don't map cleanly to marketplace semantics. Sofia
  creates custom roles that match how her platform actually works:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /admin/roles                                                             │
  │  Authorization: Bearer eyJ...  (Sofia's token)                                │
  └────────────────────────────────────────────────────────────────────────────────┘

  // Seller owner — runs their store completely
  {
    "name": "seller_owner",
    "permissions": [
      "store.read.inventory",
      "store.write.inventory",
      "store.read.orders",
      "store.write.orders",
      "store.read.analytics",
      "store.read.customers",
      "store.write.fulfillment"
    ]
  }

  // Fulfillment manager — ships orders, can't change pricing
  {
    "name": "seller_fulfillment",
    "permissions": [
      "store.read.inventory",
      "store.read.orders",
      "store.write.fulfillment"
    ]
  }

  // Dispute agent — platform staff who mediates disputes
  {
    "name": "dispute_agent",
    "permissions": [
      "platform.read.all_orders",
      "platform.write.disputes",
      "platform.read.disputes"
    ]
  }

  What just happened?
  ─────────────────
  The "seller_fulfillment" role gives Rachel exactly what she needs to ship orders without being
  able to change Tom's pricing or see his revenue analytics. This is least-privilege at the role
  level — before you even get to Zanzibar checks.

  Buyers don't get a custom role. They register as "end_user" — the system's minimal role.
  end_user has zero marketplace permissions. The only thing they can do is read their own
  profile and tokens. Access to their orders comes through Zanzibar (Step 7), not org permissions.

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Buyer Role Summary                                                             │
  ├─────────────────────────────────┬───────────────────────────────────────────────┤
  │  end_user permissions           │  api.read (profile, tokens only)              │
  ├─────────────────────────────────┼───────────────────────────────────────────────┤
  │  Order access                   │  Via Zanzibar: order:ORD-xxx #buyer_party     │
  ├─────────────────────────────────┼───────────────────────────────────────────────┤
  │  Can see other buyers?          │  No — not in same org, no Zanzibar tuples     │
  ├─────────────────────────────────┼───────────────────────────────────────────────┤
  │  Can see seller inventory?      │  No — not in seller org, no Zanzibar tuples   │
  └─────────────────────────────────┴───────────────────────────────────────────────┘

---

## Step 3: Onboarding WoodCraft Studio (First Seller)

  Sellers get their own child org. Sofia's platform code creates it programmatically when a
  seller completes onboarding. Tom Baker fills in a form, clicks "Create My Store":

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /organizations                                                           │
  │  Authorization: Bearer eyJ...  (Sofia's platform token)                       │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "name": "WoodCraft Studio",
    "slug": "woodcraft-studio",
    "parent_id": "org_craftmarket",
    "settings": {
      "invitation_only": true
    }
  }

  Response:
  {
    "org": {
      "id": "org_woodcraft",
      "slug": "woodcraft-studio",
      "name": "WoodCraft Studio",
      "parent_id": "org_craftmarket"
    }
  }

  Now invite Tom as the seller_owner:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /organizations/org_woodcraft/invite                                      │
  │  Authorization: Bearer eyJ...  (Sofia's token)                                │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "email": "tom@woodcraftstudio.com",
    "role": "seller_owner"
  }

  Tom receives an invite email, clicks the link, sets his password. He's now the owner
  of WoodCraft Studio with full seller_owner permissions scoped to his org.

  Later, Tom invites Rachel to handle fulfillment:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /organizations/org_woodcraft/invite                                      │
  │  Authorization: Bearer eyJ...  (Tom's token)                                  │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "email": "rachel@woodcraftstudio.com",
    "role": "seller_fulfillment"
  }

  What just happened?
  ─────────────────
  WoodCraft Studio is a child org of CraftMarket. This means:
  - Tom can only see WoodCraft Studio data — no other seller orgs
  - Sofia (as platform owner with cross_tenant) can see everything
  - Rachel has the fulfillment-only role, can't change pricing
  - invitation_only means no one can self-register into WoodCraft Studio. Only Tom can add people.
    Buyers who self-register land in the platform org (end_user), not here.

  Repeat the same pattern for Ana Rivera → Pottery Plus (org_pottery).

---

## Step 4: Buyer Self-Registration

  Marcus wants to shop. He opens craftmarket.io and clicks "Create Account." The platform
  has self-registration enabled on the platform org, with default_role = "end_user":

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /organizations/craftmarket/auth/register                                 │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "email": "marcus@email.com",
    "password": "...",
    "name": "Marcus Kim"
  }

  Response:
  {
    "user": { "id": "usr_marcus", "email": "marcus@email.com" },
    "org":  { "id": "org_craftmarket", "slug": "craftmarket" },
    "role": "end_user",
    "token": "eyJ..."
  }

  Marcus is now a member of the CraftMarket platform org with role "end_user." His JWT contains:
  {
    "sub": "usr_marcus",
    "org_id": "org_craftmarket",
    "role": "end_user",
    "permissions": ["api.read"]
  }

  What just happened?
  ─────────────────
  Marcus joined the platform org, not any seller org. He has zero marketplace permissions from
  the org layer — no store.read.orders, nothing. He can authenticate (prove who he is), but
  can't see anything until Zanzibar grants him access to a specific order in Step 7.

  This is intentional. A buyer's access to their order history is not a role permission — it's
  a per-object relationship. "Marcus can see order ORD-001 because he is the buyer_party of
  that order" is a Zanzibar fact, not a permission bit.

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Situation: "But Marcus needs to see all his orders, not just one."            │
  │                                                                                 │
  │  Zanzibar has a list-objects query for this:                                    │
  │                                                                                 │
  │  POST /zanzibar/stores/org_craftmarket/list-objects                             │
  │  {                                                                              │
  │    "subject":     "user:usr_marcus",                                            │
  │    "permission":  "view_as_buyer",                                              │
  │    "object_type": "order"                                                       │
  │  }                                                                              │
  │                                                                                 │
  │  Returns: [order:ORD-001, order:ORD-047, order:ORD-103, ...]                   │
  │                                                                                 │
  │  The reverse ("who has access to this order?") uses list-users:                │
  │                                                                                 │
  │  POST /zanzibar/stores/org_craftmarket/list-users                               │
  │  { "object": "order:ord_cm_001847", "permission": "view_as_seller" }           │
  │                                                                                 │
  │  Marcus sees exactly his orders, no one else's.                                │
  └─────────────────────────────────────────────────────────────────────────────────┘

---

## Step 5: Zanzibar Marketplace Schema

  Before orders can exist as authorization objects, Sofia defines the Zanzibar namespaces.
  These are the "types" of objects that will have access control:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /zanzibar/stores/org_craftmarket/namespaces                               │
  │  Authorization: Bearer eyJ...  (Sofia's token)                                │
  └────────────────────────────────────────────────────────────────────────────────┘

  // The store namespace — who can do what in a seller's store
  {
    "name": "store",
    "relations": {
      "owner":   {},
      "manager": {},
      "staff":   {},
      "viewer":  { "union": ["owner", "manager", "staff"] }
    },
    "permissions": {
      "manage":  { "relation": "owner" },
      "edit":    { "union": ["owner", "manager"] },
      "view":    { "relation": "viewer" }
    }
  }

  // The product namespace — item-level access
  {
    "name": "product",
    "relations": {
      "store_owner": {},
      "viewer":      { "union": ["store_owner"] }
    },
    "permissions": {
      "edit":   { "relation": "store_owner" },
      "view":   { "relation": "viewer" }
    }
  }

  // The order namespace — THE key namespace for the marketplace
  {
    "name": "order",
    "relations": {
      "buyer_party":    {},
      "seller_party":   {},
      "platform_staff": {},
      "dispute_agent":  {},

      // computed: dispute_agent implies both buyer and seller view
      "can_view_buyer_data":  { "union": ["buyer_party",  "platform_staff", "dispute_agent"] },
      "can_view_seller_data": { "union": ["seller_party", "platform_staff", "dispute_agent"] },

      // computed: platform or dispute agent can do anything
      "full_access": { "union": ["platform_staff", "dispute_agent"] }
    },
    "permissions": {
      "view_as_buyer":    { "relation": "can_view_buyer_data" },
      "view_as_seller":   { "relation": "can_view_seller_data" },
      "write_fulfillment":{ "union": ["seller_party", "platform_staff"] },
      "manage":           { "relation": "full_access" }
    }
  }

  // The dispute namespace — dispute resolution objects
  {
    "name": "dispute",
    "relations": {
      "filer":           {},
      "respondent":      {},
      "assigned_agent":  {},
      "platform_admin":  {},
      "can_view":        { "union": ["filer", "respondent", "assigned_agent", "platform_admin"] }
    },
    "permissions": {
      "view":    { "relation": "can_view" },
      "resolve": { "union": ["assigned_agent", "platform_admin"] }
    }
  }

  What just happened?
  ─────────────────
  The "order" namespace is the centerpiece. It has two party relations (buyer_party, seller_party)
  plus computed relations:

    can_view_buyer_data  = buyer_party OR platform_staff OR dispute_agent
    can_view_seller_data = seller_party OR platform_staff OR dispute_agent

  This means:
  - Marcus (buyer_party) can see his shipping address and payment — not Tom's pricing
  - Tom (seller_party) can see the shipping address and item details — not Marcus's other orders
  - Diana (dispute_agent) can see BOTH sides — but only for orders she's assigned to

  The dispute_agent relation does NOT give Diana a blank pass into everything. It's placed on
  specific order objects when a dispute is filed. She has symmetric access to exactly one
  transaction, scoped by Zanzibar tuples.

---

## Step 6: Tom Lists a Product

  Tom logs into his WoodCraft Studio dashboard and lists a new item:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /store/products                                                          │
  │  Authorization: Bearer eyJ...  (Tom's token, org_id=org_woodcraft)            │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "name": "Oak Cutting Board — Large",
    "price": 8500,
    "sku": "WC-OCB-LG-001",
    "inventory": 12
  }

  Response:
  {
    "product_id": "prd_oak_board_001",
    "store_id": "org_woodcraft",
    "name": "Oak Cutting Board — Large",
    "price": 8500
  }

  The platform backend immediately writes Zanzibar tuples for this product:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /zanzibar/stores/org_woodcraft/relationships (internal, called by product service) │
  └────────────────────────────────────────────────────────────────────────────────┘

  [
    {
      "object":   "product:prd_oak_board_001",
      "relation": "store_owner",
      "subject":  "org:org_woodcraft#owner"
    }
  ]

  This says: "anyone who is an owner-relation of org_woodcraft can manage this product."

  What just happened?
  ─────────────────
  The product is now a Zanzibar object. Tom's ownership flows through org:org_woodcraft#owner —
  not by writing a tuple for Tom specifically. This means:
  - If Tom later adds a co-owner to WoodCraft Studio, they automatically get product access
  - Rachel (seller_fulfillment) does NOT have owner relation — she can read orders but not
    edit products. Correctly least-privilege.
  - Ana at Pottery Plus has zero Zanzibar tuples on prd_oak_board_001. The Zanzibar check
    fails before it even reaches application logic.

  Zanzibar check:
  Can user:usr_ana view product:prd_oak_board_001?
  → Look up tuples for product:prd_oak_board_001 → only org:org_woodcraft#owner → usr_ana
    is not in org_woodcraft → DENY

---

## Step 7: Marcus Places an Order — Cross-Org Zanzibar Tuples

  Marcus browses CraftMarket, adds the Oak Cutting Board to his cart, and checks out. The
  payment processor API key processes the payment, and the order service creates the order:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /store/orders  (called by Payment Processor service account)             │
  │  Authorization: Bearer <payment_processor_api_key>                            │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "buyer_user_id": "usr_marcus",
    "seller_org_id": "org_woodcraft",
    "product_id":    "prd_oak_board_001",
    "quantity":      1,
    "shipping_address": {
      "name":   "Marcus Kim",
      "line1":  "742 Evergreen Terrace",
      "city":   "Portland",
      "state":  "OR",
      "zip":    "97201"
    },
    "amount": 8500
  }

  Response:
  {
    "order_id": "ord_cm_001847",
    "status":   "confirmed",
    "buyer_id": "usr_marcus",
    "seller_org": "org_woodcraft"
  }

  The order service writes the Zanzibar tuples that create the cross-org link:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /zanzibar/stores/org_craftmarket/relationships (internal)                 │
  └────────────────────────────────────────────────────────────────────────────────┘

  [
    {
      "object":   "order:ord_cm_001847",
      "relation": "buyer_party",
      "subject":  "user:usr_marcus"
    },
    {
      "object":   "order:ord_cm_001847",
      "relation": "seller_party",
      "subject":  "org:org_woodcraft#owner"
    },
    {
      "object":   "order:ord_cm_001847",
      "relation": "seller_party",
      "subject":  "org:org_woodcraft#seller_fulfillment"
    }
  ]

  What just happened?
  ─────────────────
  Three tuples were written. Let's read them:

  1. "Marcus is the buyer_party of order ORD-001847"
     → Marcus can see his order (view_as_buyer permission) — his address, items, status

  2. "WoodCraft Studio owners are seller_party of order ORD-001847"
     → Tom (as org owner) can see this order from the seller's perspective — items to ship,
       but NOT Marcus's full profile or other orders

  3. "WoodCraft Studio fulfillment staff are seller_party of order ORD-001847"
     → Rachel can also see what needs to be shipped. She doesn't need to be Tom's co-owner.

  Critical: these tuples cross org boundaries. usr_marcus is in org_craftmarket. org_woodcraft
  is a separate child org. Zanzibar doesn't care — tuples are the authority. The org walls
  that normally prevent cross-org visibility are deliberately bypassed here, but ONLY for
  this specific order, and ONLY for the relations defined.

  Tom cannot see Marcus's other orders — there are no tuples for those.
  Marcus cannot see Tom's inventory — there are no tuples granting him store or product access.

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Zanzibar checks after order placement:                                         │
  │                                                                                 │
  │  Can usr_marcus view order:ord_cm_001847 as buyer?   → YES (buyer_party tuple) │
  │  Can usr_marcus view order:ord_cm_001847 as seller?  → NO  (no seller tuple)   │
  │  Can usr_tom view order:ord_cm_001847 as seller?     → YES (org#owner tuple)   │
  │  Can usr_tom view order:ord_cm_001847 as buyer?      → NO  (no buyer tuple)    │
  │  Can usr_ana view order:ord_cm_001847?               → NO  (no tuples at all)  │
  └─────────────────────────────────────────────────────────────────────────────────┘

---

## Step 8: Escrow-Style Delegation — Seller Gets Shipping Address

  Tom needs Marcus's shipping address to print the label and ship the order. But "give Tom
  access to Marcus's shipping address" is not a role permission — it's a scoped, temporary,
  purpose-specific grant for exactly this transaction.

  This is the escrow pattern: a trusted intermediary (the Escrow Service) issues a delegation
  token that grants narrow, time-limited access tied to the transaction lifecycle.

  The Escrow Service (a service account with store.write.delegations permission) runs this
  automatically when an order is confirmed. Delegation is a two-step flow:

  Step 1 — Grant delegation scope (Escrow Service creates the grant):

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /delegation/grant                                                       │
  │  Authorization: Bearer <escrow_service_api_key>                               │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "actor_id":          "usr_tom",
    "scope":             ["store.read.shipping_address", "store.read.buyer_contact"],
    "expires_in_hours":  168,
    "metadata": {
      "order_id":       "ord_cm_001847",
      "buyer_user_id":  "usr_marcus",
      "purpose":        "order_fulfillment"
    }
  }

  Response:
  {
    "success":     true,
    "message":     "Delegation granted",
    "expires_at":  "2026-03-04T08:00:00Z"
  }

  Step 2 — Exchange grant for a delegation token (Tom's app calls this):

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /auth/delegate                                                          │
  │  Authorization: Bearer eyJ...  (Tom's token)                                  │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "target_user_id": "usr_tom"
  }

  Response (TokenResponse):
  {
    "access_token":  "eyJ...",
    "refresh_token": "eyJ...",
    "token_type":    "bearer",
    "expires_in":    604800,
    "user":          {"id": "usr_tom", "email": "tom@woodcraft.com", "name": "Tom Baker", "is_delegated": true}
  }

  Note: For time-limited external access (auditors, guest reviewers, etc.), prefer writing
  Zanzibar relationships with an `expires_at` field instead of delegation tokens. Zanzibar
  expiry is evaluated on every check — no token to steal or revoke.

  Tom's dashboard receives this token. His app uses it to call the shipping address endpoint:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  GET /orders/ord_cm_001847/shipping-address                                   │
  │  Authorization: Bearer eyJ...  (delegated access_token)                        │
  └────────────────────────────────────────────────────────────────────────────────┘

  Response:
  {
    "name":  "Marcus Kim",
    "line1": "742 Evergreen Terrace",
    "city":  "Portland",
    "state": "OR",
    "zip":   "97201"
  }

  What just happened?
  ─────────────────
  This is NOT Tom accessing Marcus's user profile. The delegation token has two specific
  permissions (store.read.shipping_address, store.read.buyer_contact) and context binding
  (order_id: ord_cm_001847). The shipping address endpoint validates all three:

  1. Does the token have store.read.shipping_address? Yes.
  2. Does the token's context.order_id match the requested order? Yes.
  3. Is the token still valid (not expired, not revoked)? Yes.

  Tom gets Marcus's address for this order. He cannot use this token to get Marcus's address
  for a different order — the context binding fails. He cannot use it to read Marcus's payment
  details — the permissions don't include that. He cannot use it to read his own analytics —
  wrong permission scope entirely.

  The "granted_by_org" is org_craftmarket (the platform), not org_woodcraft. This is deliberate:
  the platform is the trusted escrow agent that holds the authority to grant this access.
  Tom's org doesn't have any standing access to buyer data — the platform grants it, transiently.

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Escrow Delegation Summary                                                      │
  ├─────────────────────────────────────┬───────────────────────────────────────────┤
  │  Granted by                         │  Escrow Service (platform service account)│
  ├─────────────────────────────────────┼───────────────────────────────────────────┤
  │  Granted to                         │  Tom Baker (usr_tom)                      │
  ├─────────────────────────────────────┼───────────────────────────────────────────┤
  │  Permissions                        │  shipping_address + buyer_contact only    │
  ├─────────────────────────────────────┼───────────────────────────────────────────┤
  │  Scope                              │  ord_cm_001847 only (context binding)     │
  ├─────────────────────────────────────┼───────────────────────────────────────────┤
  │  Expiry                             │  7 days (standard fulfillment window)     │
  ├─────────────────────────────────────┼───────────────────────────────────────────┤
  │  Auto-revoke trigger                │  order.delivered event                    │
  └─────────────────────────────────────┴───────────────────────────────────────────┘

---

## Step 9: Order Delivered — Automatic Revocation

  Tom ships the order. Rachel marks it as shipped in the fulfillment dashboard. The tracking
  system fires an order.delivered event when Marcus confirms receipt. The Escrow Service
  handles this event automatically:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  DELETE /delegation/revoke/usr_tom                                             │
  │  Authorization: Bearer <escrow_service_api_key>                               │
  └────────────────────────────────────────────────────────────────────────────────┘

  Response:
  {
    "message": "Delegation revoked successfully"
  }

  If Tom tries to use the revoked delegation token:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  GET /orders/ord_cm_001847/shipping-address                                   │
  │  Authorization: Bearer eyJ...  (revoked delegation)                            │
  └────────────────────────────────────────────────────────────────────────────────┘

  Response: 401 Unauthorized
  {
    "detail": "Delegation token has been revoked"
  }

  What just happened?
  ─────────────────
  The moment the order lifecycle ends, the escrow access ends with it. Tom had what he needed
  for exactly as long as he needed it — no more. There's no background job that "eventually"
  cleans up access. The revocation is immediate and irreversible.

  This is the full escrow cycle:
  order.confirmed  → delegation token ISSUED  → Tom gets shipping address
  order.delivered  → delegation token REVOKED → Tom loses shipping address

  Marcus's address is no longer accessible to Tom, even though the order record still exists
  in the database. The data doesn't disappear — the ACCESS disappears.

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Situation: "What if the order needs to be modified after delivery?"           │
  │                                                                                 │
  │  A new delegation token would need to be issued for the specific purpose.      │
  │  Example: customer reports wrong item → issue new dlg token with              │
  │  store.read.buyer_contact, context.order_id = same order, expires_in = 24h,  │
  │  purpose = "return_resolution". Each purpose is a separate, auditable grant.  │
  └─────────────────────────────────────────────────────────────────────────────────┘

---

## Step 10: Seller Isolation — Tom Can't See Ana's Store

  One week later, Tom is curious about Pottery Plus's pricing strategy. He tries to access
  their inventory using his seller_owner token:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  GET /store/org_pottery/products                                               │
  │  Authorization: Bearer eyJ...  (Tom's token, org_id=org_woodcraft)            │
  └────────────────────────────────────────────────────────────────────────────────┘

  Response: 403 Forbidden
  {
    "detail": "You do not have access to this organization's resources"
  }

  What happened behind the scenes:
  1. Server validates Tom's token: org_id = org_woodcraft ✓
  2. Server checks if org_woodcraft has access to org_pottery — different child orgs, no ancestry ✗
  3. Phase 2 check: resource.org_id (org_pottery) != token.org_id (org_woodcraft) → 403

  Tom can't even attempt a Zanzibar check — the org-level wall stops him first.

  What about the Zanzibar layer? The server could also run:
  Can user:usr_tom view store:org_pottery?
  → Check tuples for store:org_pottery → org:org_pottery#owner → usr_tom is not in org_pottery → DENY

  Two independent layers both say no. This redundancy is intentional: if application code
  ever has a bug that skips the Phase 2 org check, Zanzibar still blocks it.

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Isolation matrix:                                                              │
  │                                                                                 │
  │                    │ WoodCraft │ Pottery+ │ Marcus's orders │ Platform data    │
  │  ────────────────  │ ───────── │ ──────── │ ─────────────── │ ──────────────  │
  │  Tom (WoodCraft)   │    YES    │    NO    │  NO (except his) │      NO        │
  │  Ana (Pottery+)    │    NO     │    YES   │  NO (except his) │      NO        │
  │  Marcus (buyer)    │    NO     │    NO    │     YES          │      NO        │
  │  Sofia (platform)  │    YES    │    YES   │     YES          │      YES       │
  └─────────────────────────────────────────────────────────────────────────────────┘

---

## Step 11: A Dispute is Filed

  Marcus receives the wrong item — he got a Small cutting board instead of Large. He files
  a dispute through the CraftMarket platform:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /disputes                                                                │
  │  Authorization: Bearer eyJ...  (Marcus's end_user token)                      │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "order_id":  "ord_cm_001847",
    "reason":    "wrong_item",
    "description": "Received WC-OCB-SM-001 instead of WC-OCB-LG-001",
    "evidence_photo_url": "https://..."
  }

  Response:
  {
    "dispute_id":       "dsp_cm_00291",
    "status":           "open",
    "order_id":         "ord_cm_001847",
    "assigned_agent":   null,
    "created_at":       "2026-02-25T14:32:00Z"
  }

  The platform writes Zanzibar tuples for the dispute:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /zanzibar/stores/org_craftmarket/relationships                            │
  └────────────────────────────────────────────────────────────────────────────────┘

  [
    {
      "object":   "dispute:dsp_cm_00291",
      "relation": "filer",
      "subject":  "user:usr_marcus"
    },
    {
      "object":   "dispute:dsp_cm_00291",
      "relation": "respondent",
      "subject":  "org:org_woodcraft#owner"
    }
  ]

  Tom is notified. He's the respondent — he can see the dispute but can't resolve it.

---

## Step 12: Dispute Agent Gets Symmetric Access

  Sofia's platform assigns Diana Osei (dispute_agent role) to investigate. Diana needs to
  see both sides: Marcus's order confirmation, shipping details, and the evidence photo; and
  Tom's fulfillment record, the item that was shipped, and his inventory logs.

  Critically, Diana needs access to this one transaction — not to all of Marcus's orders, not
  to Tom's entire store, not to all ongoing disputes.

  The platform assigns Diana and writes the scoped Zanzibar tuples:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  PATCH /disputes/dsp_cm_00291/assign                                          │
  │  Authorization: Bearer eyJ...  (Sofia's platform token)                       │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "agent_user_id": "usr_diana"
  }

  The platform backend writes Zanzibar tuples:

  [
    // Diana is assigned_agent on the dispute object itself
    {
      "object":   "dispute:dsp_cm_00291",
      "relation": "assigned_agent",
      "subject":  "user:usr_diana"
    },
    // Diana gets dispute_agent relation on the ORDER — gives her both-sides view
    {
      "object":   "order:ord_cm_001847",
      "relation": "dispute_agent",
      "subject":  "user:usr_diana"
    }
  ]

  Now Diana can access both sides of this order:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  GET /orders/ord_cm_001847/buyer-view                                         │
  │  Authorization: Bearer eyJ...  (Diana's dispute_agent token)                  │
  └────────────────────────────────────────────────────────────────────────────────┘

  Response: Marcus's full order details, shipping address, payment confirmation

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  GET /orders/ord_cm_001847/seller-view                                        │
  │  Authorization: Bearer eyJ...  (Diana's token)                                │
  └────────────────────────────────────────────────────────────────────────────────┘

  Response: WoodCraft's fulfillment record, item picked, shipping label generated

  But Diana cannot see Tom's OTHER orders or inventory:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  GET /store/org_woodcraft/products                                             │
  │  Authorization: Bearer eyJ...  (Diana's token)                                │
  └────────────────────────────────────────────────────────────────────────────────┘

  Response: 403 Forbidden
  Diana's dispute_agent role doesn't include store.read.inventory. The dispute_agent Zanzibar
  relation is only on order:ord_cm_001847, not on store:org_woodcraft.

  What just happened?
  ─────────────────
  Diana has two things:
  1. Org permission "dispute_agent" role → can read/write disputes (platform-level)
  2. Zanzibar "dispute_agent" relation on order:ord_cm_001847 → can see both sides of this order

  These are independent. The Zanzibar relation grants order-specific access regardless of what
  org she's in. The org role grants dispute management capability. Together they give her
  exactly what she needs. Neither alone is sufficient.

  Zanzibar checks:
  Can usr_diana view_as_buyer order:ord_cm_001847?   → dispute_agent → can_view_buyer_data → YES
  Can usr_diana view_as_seller order:ord_cm_001847?  → dispute_agent → can_view_seller_data → YES
  Can usr_diana view store:org_woodcraft?            → no tuples on store → NO
  Can usr_diana view order:ord_cm_001900 (other)?    → no dispute_agent tuple there → NO

---

## Step 13: Dispute Resolved — Full Cleanup

  Diana reviews both sides. WoodCraft admits the picking error. The resolution: WoodCraft ships
  the correct item (Large) at no cost, Marcus keeps the Small as compensation. Diana resolves:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  PATCH /disputes/dsp_cm_00291/resolve                                         │
  │  Authorization: Bearer eyJ...  (Diana's token)                                │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "resolution":   "resend_and_keep",
    "resolution_note": "Seller error confirmed. Replacement shipped. Buyer keeps small item.",
    "actions": [
      { "type": "resend", "sku": "WC-OCB-LG-001" },
      { "type": "credit", "amount": 2500, "reason": "inconvenience" }
    ]
  }

  The platform then removes Diana's dispute-scoped Zanzibar tuples:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  DELETE /zanzibar/stores/org_craftmarket/relationships (bulk)                  │
  └────────────────────────────────────────────────────────────────────────────────┘

  [
    {
      "object":   "order:ord_cm_001847",
      "relation": "dispute_agent",
      "subject":  "user:usr_diana"
    },
    {
      "object":   "dispute:dsp_cm_00291",
      "relation": "assigned_agent",
      "subject":  "user:usr_diana"
    }
  ]

  Verify the cleanup:

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /zanzibar/stores/org_craftmarket/check                                   │
  └────────────────────────────────────────────────────────────────────────────────┘

  {
    "object":     "order:ord_cm_001847",
    "permission": "manage",
    "subject":    "user:usr_diana"
  }

  Response: { "allowed": false }

  Diana's access to the order is completely gone. The dispute record is closed and archived.
  Neither Tom nor Marcus can reopen it without platform action. The audit trail in the
  delegation and Zanzibar event logs shows exactly who had access to what, and for how long.

  What just happened?
  ─────────────────
  The full dispute lifecycle in auth terms:

  dispute filed     → Zanzibar tuples: dispute:X filer=Marcus, respondent=Tom
  agent assigned    → Zanzibar tuples: dispute:X assigned_agent=Diana, order:Y dispute_agent=Diana
  investigation     → Diana uses both-sides access to review the order
  resolved          → Zanzibar tuples deleted atomically → Diana loses order access immediately
  audit log         → Every tuple creation, check, and deletion is logged with timestamp + actor

---

## Step 14: Service API Keys — The Three Platform Services

  CraftMarket runs three automated services. Each gets a service API key with exactly the
  permissions it needs — nothing more.

  ┌────────────────────────────────────────────────────────────────────────────────┐
  │  POST /admin/users/create-service-account  (Sofia's token)                    │
  └────────────────────────────────────────────────────────────────────────────────┘

  // 1. Payment Processor — charges cards, creates orders
  {
    "email": "payment-processor@svc.craftmarket.internal",
    "name": "payment-processor",
    "permissions": [
      "store.write.orders",
      "store.read.inventory"
    ],
    "org_id": "org_craftmarket"
  }

  // 2. Escrow Service — manages delegation tokens for order access
  {
    "email": "escrow-service@svc.craftmarket.internal",
    "name": "escrow-service",
    "permissions": [
      "store.write.delegations",
      "store.read.orders"
    ],
    "org_id": "org_craftmarket"
  }

  // 3. Notification Service — sends order/dispute emails
  {
    "email": "notification-service@svc.craftmarket.internal",
    "name": "notification-service",
    "permissions": [
      "store.read.orders"
    ],
    "org_id": "org_craftmarket"
  }

  Each responds with an API key to store securely:
  {
    "id":          "svc_payment_01",
    "email":       "payment-processor@svc.craftmarket.internal",
    "api_key":     "sk_svc_8f2a9b...",
    "permissions": ["store.write.orders", "store.read.inventory"]
  }

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Service API Key Permission Matrix                                              │
  ├────────────────────────┬──────────────┬──────────────┬───────────────────────┤
  │  Permission            │ Payment Proc │ Escrow Svc   │ Notification Svc      │
  ├────────────────────────┼──────────────┼──────────────┼───────────────────────┤
  │  store.write.orders    │     YES      │     NO       │         NO            │
  ├────────────────────────┼──────────────┼──────────────┼───────────────────────┤
  │  store.read.inventory  │     YES      │     NO       │         NO            │
  ├────────────────────────┼──────────────┼──────────────┼───────────────────────┤
  │  store.write.delegations│     NO      │     YES      │         NO            │
  ├────────────────────────┼──────────────┼──────────────┼───────────────────────┤
  │  store.read.orders     │     NO       │     YES      │         YES           │
  └────────────────────────┴──────────────┴──────────────┴───────────────────────┘

  What just happened?
  ─────────────────
  The Notification Service can read orders (to send "your order shipped" emails) but cannot
  write anything. If an attacker compromises the notification service, they can read order
  statuses but cannot create orders, issue delegation tokens, or modify anything. The blast
  radius is bounded to what the key's permissions allow.

  The Escrow Service is the only one that can issue delegation tokens (store.write.delegations).
  The Payment Processor can't accidentally issue a delegation token because it simply doesn't
  have that permission. Service segmentation enforced at the credential layer.

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Situation: "Our recommendation engine needs to see all product listings       │
  │  to generate personalized results. How do we scope that?"                      │
  │                                                                                 │
  │  Create a service account "recommendation-engine" with store.read.inventory.   │
  │  It can list all products across all seller orgs (platform-level read). But:   │
  │  - It cannot write anything (no write permissions)                             │
  │  - It cannot see buyer order history (no store.read.orders)                   │
  │  - It cannot see seller financial analytics (no store.read.analytics)          │
  │  - If compromised, an attacker can read product listings — which are public    │
  │    anyway. No buyer data, no seller revenue data, no ability to create orders. │
  │                                                                                 │
  │  Least-privilege service keys make the blast radius of a compromised key       │
  │  match the minimal access needed for that key's job.                          │
  └─────────────────────────────────────────────────────────────────────────────────┘

---

## Step 15: Scaling the Seller Network — 50 Sellers, Same Pattern

  CraftMarket grows. Onboarding the 50th seller is identical to the first:

  1. POST /organizations — create child org of craftmarket
  2. POST /organizations/{new_org}/invite — invite seller as seller_owner
  3. Seller invites their own staff
  4. First product listing → Zanzibar product tuple with store_owner relation

  Each new seller org is automatically isolated from all others. Sofia never has to
  write isolation rules — the org hierarchy enforces it structurally.

  The Zanzibar schema defined in Step 5 applies to all sellers. A new seller's products,
  orders, and disputes use the same order/product/dispute namespaces. The system
  scales horizontally — each new order is just more tuples.

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Full System Summary: What auth solves for CraftMarket                         │
  ├──────────────────────────────┬────────────────────────────────────────────────┤
  │  Challenge                   │ Solution                                        │
  ├──────────────────────────────┼────────────────────────────────────────────────┤
  │  Sellers isolated from each  │ Separate child orgs — org layer hard wall      │
  │  other                       │                                                 │
  ├──────────────────────────────┼────────────────────────────────────────────────┤
  │  Buyers access only their    │ Zanzibar: buyer_party tuples per order         │
  │  own orders                  │                                                 │
  ├──────────────────────────────┼────────────────────────────────────────────────┤
  │  Seller sees buyer address   │ Escrow delegation token: scoped, time-limited  │
  │  only for active fulfillment │ context-bound, auto-revoked on delivery        │
  ├──────────────────────────────┼────────────────────────────────────────────────┤
  │  Dispute agent sees both     │ Zanzibar: dispute_agent on specific order only │
  │  sides, scoped to one order  │ Removed on dispute close                       │
  ├──────────────────────────────┼────────────────────────────────────────────────┤
  │  Services do minimal actions │ API keys: each key scoped to its exact needs   │
  ├──────────────────────────────┼────────────────────────────────────────────────┤
  │  New sellers auto-isolated   │ Child org model — no extra config per seller   │
  └──────────────────────────────┴────────────────────────────────────────────────┘

---

## Appendix: Complete Zanzibar Tuple Lifecycle for One Order

  Illustrating exactly which tuples exist at each stage of ord_cm_001847:

  ─── STAGE: Order Placed ─────────────────────────────────────────────────────────
  order:ord_cm_001847 #buyer_party           user:usr_marcus
  order:ord_cm_001847 #seller_party          org:org_woodcraft#owner
  order:ord_cm_001847 #seller_party          org:org_woodcraft#seller_fulfillment
  product:prd_oak_board_001 #store_owner     org:org_woodcraft#owner

  ─── STAGE: Escrow Delegation Issued (internal, not Zanzibar — delegation token) ─
  delegation token dlg_7f9e2b: usr_tom ← store.read.shipping_address, context=ord_cm_001847

  ─── STAGE: Dispute Filed ────────────────────────────────────────────────────────
  dispute:dsp_cm_00291 #filer                user:usr_marcus
  dispute:dsp_cm_00291 #respondent           org:org_woodcraft#owner

  ─── STAGE: Agent Assigned ───────────────────────────────────────────────────────
  dispute:dsp_cm_00291 #assigned_agent       user:usr_diana
  order:ord_cm_001847 #dispute_agent         user:usr_diana         ← symmetric access

  ─── STAGE: Dispute Resolved (cleanup) ───────────────────────────────────────────
  REMOVED: order:ord_cm_001847 #dispute_agent  user:usr_diana
  REMOVED: dispute:dsp_cm_00291 #assigned_agent user:usr_diana
  Delegation token dlg_7f9e2b: REVOKED (on delivery)

  ─── STAGE: Final state ──────────────────────────────────────────────────────────
  order:ord_cm_001847 #buyer_party           user:usr_marcus          ← permanent record
  order:ord_cm_001847 #seller_party          org:org_woodcraft#owner  ← permanent record
  dispute:dsp_cm_00291 #filer                user:usr_marcus          ← archived
  dispute:dsp_cm_00291 #respondent           org:org_woodcraft#owner  ← archived
  (delegation tokens: fully revoked)

  The permanent buyer/seller tuples on the order are kept for audit and history — Marcus
  can always see his order history. The dispute/agent tuples are archived. No one has
  operational access to the order data except the original parties.
