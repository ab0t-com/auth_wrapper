---
name: auth-service-scenarios
description: Comprehensive scenario-based FAQ docs showing how to set up and use the ab0t auth/authz mesh for real-world business contexts. Use when explaining the auth service to customers, creating onboarding guides, answering "how do I set up X with the auth service" questions, writing integration walkthroughs, demonstrating org hierarchies, Zanzibar authorization patterns, hosted login portals, delegation, service accounts, or multi-tenant architectures. Covers 15+ industry verticals from simple SaaS companies to government clearance systems.
---

# Auth Service Scenario Guides

End-to-end FAQ walkthroughs showing how real companies integrate with the ab0t auth/authz mesh. Each guide is a self-contained narrative: a company type, their requirements, and a step-by-step build-out with working curl commands and code.

## File Index

### Foundation Guides (start here)

- **[faq_simple_company.md](faq_simple_company.md)** — SaaS founder setting up auth from scratch. Covers: register, create org, define permissions, integrate FastAPI app, onboard customers via invite, employees, frontend login, service-to-service API keys. 8 steps, simplest possible path.

- **[faq_simple_company_v2.md](faq_simple_company_v2.md)** — Same scenario, expanded. Adds: hosted login pages, OAuth client registration, self-registration, branded portals, social login providers (Google/Microsoft/GitHub), SAML SSO, login-as-join for multi-org users, BYOUI vs hosted vs widget integration options. 10 steps. **Superset of faq_simple_company.md.**

### Enterprise / Org Hierarchy

- **[faq_company_auth.md](faq_company_auth.md)** — 100-person company with departments, teams, nested child orgs. Covers: teams vs child orgs decision framework, hard walls (child orgs) vs soft walls (teams), cross-tenant support access.

- **[faq_company_auth_v2.md](faq_company_auth_v2.md)** — Same internal hierarchy, plus external customers who self-register through branded portals, SSO for employees. **Superset of faq_company_auth.md.**

- **[faq_20_person_company_v2.md](faq_20_person_company_v2.md)** — 20-person company (BillFlow) with customer onboarding, OAuth flows, hosted login, cross-tenant support.

### AI Agents

- **[faq_agent_company.md](faq_agent_company.md)** — Autonomous AI agent platform (AgentForge). Agents spawn, self-organize, create orgs, form teams, grab tools dynamically. Covers: agent-as-service-account, dynamic permission grants, agent org hierarchies, budget controls, human kill switch.

- **[faq_agent_company_v2.md](faq_agent_company_v2.md)** — Same agent platform, plus human collaborators joining agent-created orgs through hosted login portals. Agents can open their workspaces to external participants. **Superset of faq_agent_company.md.**

### Inter-Service / Service Mesh

- **[faq_storyboard_service_connection_v1.md](faq_storyboard_service_connection_v1.md)** — Screenplay app consuming Billing and Payment services on the same auth mesh. Covers: the anti-pattern (per-user sub-orgs), the correct pattern (shared customer org + customer references), backend API keys, frontend token forwarding, Zanzibar upgrade path.

- **[faq_storyboard_service_connection_v2.md](faq_storyboard_service_connection_v2.md)** — Same scenario but multi-tier: individual writers AND production studios (50+ writers). Adds: per-studio customer orgs, hosted login per studio, OAuth 2.1 with PKCE, org-scoped auth endpoints. **Superset of faq_storyboard_service_connection_v1.md.**

### Industry Verticals

- **[faq_fintech_banking_v3.md](faq_fintech_banking_v3.md)** — Digital bank (NovaPay). KYC tiers, transaction limits, fraud lockout, account deactivation, compliance audit trails.

- **[faq_finance_investment_bank_v2.md](faq_finance_investment_bank_v2.md)** — Investment bank (Apex Capital). Zanzibar namespaces for portfolios/accounts, information barriers between divisions, compliance officer cross-tenant access, risk engine service accounts.

- **[faq_healthcare_hospital_v2.md](faq_healthcare_hospital_v2.md)** — Hospital system (MedCore). HIPAA-style access: attending physician vs resident vs nurse, patient record Zanzibar tuples, break-glass emergency access, department transfers.

- **[faq_government_clearance_v1.md](faq_government_clearance_v1.md)** — Intelligence agency (ClearPath). Security clearances as permissions, compartmented access (SCI), need-to-know via Zanzibar, clearance upgrades/transfers, service accounts in regulated environments.

- **[faq_gaming_multiplayer_v1.md](faq_gaming_multiplayer_v1.md)** — Multiplayer game (DragonKeep). Guilds as orgs, Zanzibar for guild roles (leader/officer/member), item trading permissions, guild mergers, anti-cheat service accounts.

- **[faq_elearning_platform_v1.md](faq_elearning_platform_v1.md)** — E-learning platform (Learnly/Brightline Academy). Courses, cohorts, instructors, TAs, students. Zanzibar namespaces for course/cohort/lesson/assignment access. Enrollment as tuple, semester rollover.

- **[faq_marketplace_twosided_v1.md](faq_marketplace_twosided_v1.md)** — Two-sided marketplace (CraftMarket). Sellers and buyers isolated via seller child orgs. Escrow-style delegation for order fulfillment. Zanzibar for per-order access control.

- **[faq_law_firm_v1.md](faq_law_firm_v1.md)** — Law firm (CaseVault). Matter orgs, conflict-of-interest checks via permission queries, ethical walls, document ingestion service accounts, matter closure/suspension.

- **[faq_saas_reseller_whitelabel_v2.md](faq_saas_reseller_whitelabel_v2.md)** — SaaS reseller/whitelabel (FormFlow → NovaTech → end customers). Three-tier org hierarchy, reseller provisioning automation, customer suspension, cross-tenant support at each tier.

- **[faq_developer_tools_v1.md](faq_developer_tools_v1.md)** — Developer tools platform (FlowBase). API key lifecycle, personal access tokens, service accounts for webhooks/execution engines, key rotation, token introspection, connected apps.

- **[faq_devops_platform_engineering_v2.md](faq_devops_platform_engineering_v2.md)** — Platform engineering (Meridian). Environment orgs (dev/staging/prod), Zanzibar for cluster/database access, service-to-service identity per environment, promotion workflows.

- **[faq_msp_it_services_v1.md](faq_msp_it_services_v1.md)** — Managed service provider (Hendricks IT). Multi-client management, per-client child orgs, RMM agent service accounts, technician onboarding/offboarding, client isolation.

- **[faq_hosted_login.md](faq_hosted_login.md)** — Deep dive on hosted login specifically. BYOUI vs SDK vs hosted page patterns, login config API, OAuth client registration, org-scoped auth endpoints, login-as-join.

- **[faq_vaultdrive_v3.md](faq_vaultdrive_v3.md)** — Cloud file storage SaaS (VaultDrive) for regulated industries. Three founders scaling to thousands of customers. Covers: OAuth 2.1 with Google/GitHub (no passwords), hosted login, sub-orgs for customer teams, service accounts for background workers, delegation tokens, third-party API keys.

### Architecture Reference

- **[authz_layer_simple.md](authz_layer_simple.md)** — Explanation of the permission system architecture: schema registry (global) vs permission grants (org-scoped), comparison to Zanzibar/AWS IAM/Auth0/Istio.

## Version Pairs

Four topics have both an earlier and expanded version. In every case the v2 is a **strict superset** — same scenario foundation plus hosted login, self-registration, and multi-tenant portal features added later.

| Topic | Earlier version | Expanded version | What v2 adds |
|-------|----------------|-----------------|--------------|
| Simple SaaS company | `faq_simple_company.md` (16KB, 8 steps) | `faq_simple_company_v2.md` (39KB, 10 steps) | Hosted login pages, OAuth clients, self-registration, branded portals, social login (Google/MS/GitHub), SAML SSO, login-as-join, BYOUI/widget/hosted integration options |
| 100-person enterprise | `faq_company_auth.md` (20KB) | `faq_company_auth_v2.md` (31KB) | External customers with self-registration, branded portals, SSO for employees |
| AI agent platform | `faq_agent_company.md` (28KB) | `faq_agent_company_v2.md` (36KB) | Human collaborators joining agent-created orgs via hosted login portals |
| Inter-service wiring | `faq_storyboard_service_connection_v1.md` (47KB) | `faq_storyboard_service_connection_v2.md` (61KB) | Multi-tier customers (individuals + studios), per-studio hosted login, OAuth 2.1 PKCE |

Use the earlier version when the user needs a simpler introduction without hosted login complexity. Use the v2 when hosted login, self-registration, or multi-tenant portals are relevant.

## Choosing a Guide

Match the user's scenario to the closest guide:

| User says | Read |
|-----------|------|
| "I'm setting up auth for my SaaS" | `faq_simple_company_v2.md` |
| "We have departments and teams" | `faq_company_auth_v2.md` |
| "We need customer self-registration" | `faq_simple_company_v2.md` (step 7) |
| "We consume other services on the mesh" | `faq_storyboard_service_connection_v2.md` |
| "We deploy AI agents" | `faq_agent_company_v2.md` |
| "We need Zanzibar / fine-grained authz" | `faq_finance_investment_bank_v2.md` or `faq_healthcare_hospital_v2.md` |
| "We're a marketplace" | `faq_marketplace_twosided_v1.md` |
| "We resell / whitelabel" | `faq_saas_reseller_whitelabel_v2.md` |
| "We need compliance / clearances" | `faq_government_clearance_v1.md` |
| "We're building cloud storage / file sharing" | `faq_vaultdrive_v3.md` |
| "How does the permission system work?" | `authz_layer_simple.md` |
