  ---                                                                                                                                                                                                              
  How Your Permission System Actually Works                                                                                                                                                                        
                                                                                                                                                                                                                   
  Having read permission_registry.py, permission_service.py, and api/permissions.py, here's the architecture:                                                                                                      
                                                                                                                                                                                                                   
  Two separate concerns, correctly separated:

  ┌───────────────────┬──────────────────────────┬─────────────────────────────────┬───────────────────────────────────────────────────────────┐
  │       Layer       │           What           │              Scope              │                        Storage Key                        │
  ├───────────────────┼──────────────────────────┼─────────────────────────────────┼───────────────────────────────────────────────────────────┤
  │ Schema registry   │ "What permissions exist" │ Global — shared across the mesh │ PK: PERM_SCHEMA#{service}, GSI: PERM_SCHEMAS              │
  ├───────────────────┼──────────────────────────┼─────────────────────────────────┼───────────────────────────────────────────────────────────┤
  │ Permission grants │ "Who has what"           │ Org-scoped                      │ PK: USER#{user_id}, SK: ORG#{org_id} with permissions: [] │
  └───────────────────┴──────────────────────────┴─────────────────────────────────┴───────────────────────────────────────────────────────────┘

  The registry defines the vocabulary — billing.read, api.write, myapp.deploy — and the grant system assigns those words to users within org contexts.

  Your Approach Is Valid — And It's the Industry Pattern

  This is exactly how the major systems work:

  Google Zanzibar / OpenFGA / SpiceDB: Type definitions (namespaces) are global. document, team, folder exist as shared types with shared relation definitions. The tuples (who has what on which object) are
  tenant-scoped. You don't define "document" per-org — the concept of a document with viewer, editor, owner relations is a shared schema. Different orgs just have different tuples.

  AWS IAM: Action namespaces are global — s3:GetObject, ec2:StartInstances — defined by the service, not the account. Every AWS account sees the same action vocabulary. What's account-scoped is the policies
  (grants). You can't create a custom s3:MySpecialAction, but you register your own service actions via CloudFormation custom resources.

  Auth0 / Okta: Scopes and permissions are defined at the API (resource server) level, which is effectively global for the tenant's auth domain. Multiple applications in the same domain share the same permission
   vocabulary.

  Istio / Consul: Authorization policies reference global service identities. The service mesh has a shared namespace of service names. Policies (who can call what) are namespace-scoped, but the service identity
   vocabulary is mesh-wide.

  Your format service.action.resource is the exact same pattern as AWS IAM's service:action/resource. The first segment is the service namespace, the rest is scoped within it. This is the correct approach.

  Why Global Schema Makes Sense for a Mesh

  The key insight: in a mesh, services need to discover each other's capabilities. If org A runs a billing service and org B wants to integrate, org B needs to know that billing.read exists and what it means.
  That's the whole point of a mesh — interconnection and discoverability.

  Making the schema public enables:
  - Service discovery: "What can I call? What permissions do I need?"
  - Cross-org delegation: Org A can delegate billing.read to an org B user because both understand the vocabulary
  - Validation at grant time: The grant endpoint (/permissions/grant) validates against the registry — it rejects unknown permission strings. This prevents typos and drift.
  - Consistent tooling: The dashboard, API keys page, and CLI can all show the same permission picker

  Your registry endpoints being public (/permissions/registry/services, /permissions/registry/valid-permissions) is correct — they're discovery endpoints, like OpenAPI specs or .well-known configs. The data is
  the vocabulary, not the access.

  What the Code Confirms

  From permission_registry.py:113-168:
  - register_service_permissions() writes to DynamoDB with PK: PERM_SCHEMA#{service} — keyed by service name, not org
  - No org_id anywhere in the schema storage — this is by design, not an omission

  From api/permissions.py:454-529:
  - Registration requires permissions.register permission (auth-gated)
  - API keys can be scoped to allowed_services via metadata — so a service can only update its own schema
  - But the resulting schema is globally visible — correct

  From permission_service.py:115-184:
  - get_user_permissions() joins global permissions + org membership permissions + role permissions + team permissions
  - Grants are stored at USER#{user_id} / ORG#{org_id} — fully org-scoped
  - The permission strings in grants reference the global vocabulary

  So What's Wrong with the API Keys Modal?

  Nothing about the global registry is wrong. The modal's problem is simpler: it has hardcoded template groups (read-only, write, admin, service) with permission strings that were guessed at UI-build time
  instead of being pulled from the actual registry.

  The fix for the modal should:
  1. Fetch /permissions/registry/services to show real service groups
  2. Let users pick from actual registered permissions
  3. Still show the predefined roles from /permissions/roles as quick templates (those are the real role bundles)
  4. Keep the free-text textarea for wildcard patterns (api.*, billing.*, *)

  The 978 permissions showing from 29 services — those are the correct global vocabulary for the mesh. A user creating an API key should be able to scope it to any of those permissions. The grant enforcement
  (whether the user has the right to create a key with billing.admin) happens server-side, not in the picker UI.

