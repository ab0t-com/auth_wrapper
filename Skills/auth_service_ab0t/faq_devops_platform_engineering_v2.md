question: We're a platform engineering team at a 60-person startup called "Meridian Tech." We build and run a SaaS product. We need proper environment isolation (dev, staging, prod),
  service accounts for each of our services in each environment, CI/CD pipeline keys that can only deploy to the right environment, and fine-grained access so engineers can touch
  dev freely but can't accidentally prod. We also want Zanzibar for infra — who can access which cluster, which database, which secret. And we need a break-glass procedure for
  emergencies. Walk us through the whole thing.

● This is the platform engineering setup. The problems you're describing — "engineer accidentally ran a migration against prod," "the CI key can deploy anywhere," "I don't know who
  SSHed into that box" — are all solved by the same underlying model: environments as hard-walled orgs, service accounts as first-class identities, and Zanzibar for resource-level
  access. Let's build it.

  By the end you'll have:
  - Dev, staging, and prod as isolated orgs — a key that works in dev physically cannot touch prod
  - Every service has its own identity per environment (API service in prod ≠ API service in dev)
  - CI/CD pipeline keys scoped by environment, with an approval gate before prod
  - Zanzibar tuples controlling who can access which cluster, database, namespace, and secret
  - A break-glass procedure: emergency prod access in 2 minutes, full audit trail, auto-expiry
  - Key rotation that doesn't break running services

  ---
  Concept: Why Environments as Orgs?

  The most common approach is to put dev/staging/prod access in a single org and use roles or tags to separate them. This fails in practice:

  Problem 1: Scope creep. Someone gets staging access, then someone grants them prod "just for this one thing," and nobody cleans it up.
  Problem 2: Misconfigured keys. A CI script uses the wrong environment variable. The key works everywhere so nothing stops it.
  Problem 3: Blast radius. A compromised staging service account can enumerate prod resources because they share an org.

  The fix: environments are separate orgs. Org isolation is structural, not policy. A token scoped to the dev org is cryptographically scoped to dev. It cannot make authenticated calls against the prod org. There is no misconfiguration that changes this.

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Meridian Platform (root org)                                                   │
  │  Zara and the platform team. Billing, settings, the rulebook. Not a runtime.   │
  └──────────────────────────────┬──────────────────────────────────────────────────┘
                                 │
          ┌──────────────────────┼─────────────────────────┐
          │                      │                         │
  ┌───────▼──────┐       ┌───────▼──────┐        ┌────────▼─────┐
  │   Dev Env    │       │ Staging Env  │        │   Prod Env   │
  │   (org)      │       │   (org)      │        │   (org)      │
  │              │       │              │        │              │
  │ All engineers│       │ Senior devs  │        │ SREs + CI    │
  │ full access  │       │ + CI only    │        │ only, humans │
  │              │       │              │        │ read-mostly  │
  └──────────────┘       └──────────────┘        └──────────────┘

  Each environment org contains:
  - Human members (who can access it)
  - Service accounts (the running services)
  - API keys (for CI/CD and automation)
  - Zanzibar store (for resource-level access within the environment)

  ---
  The Team

  - Zara Okonkwo     — Head of Platform Engineering, owns the root org
  - 5 junior/mid engineers  — full dev access, read-only staging, zero prod
  - 3 senior engineers       — full dev + staging access, read-only prod
  - Nate Rivera      — Senior SRE — full access everywhere (on-call primary)
  - Kai Thornton     — SRE — full access everywhere (on-call secondary)
  - CI/CD pipeline   — GitHub Actions, environment-scoped API keys
  - Services: api-service, worker-service, scheduler-service, data-pipeline

  ---
  Step 1: Zara Sets Up the Platform Root

  AUTH_URL="https://auth.service.ab0t.com"

  curl -X POST "$AUTH_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "zara@meridiantech.io",
      "password": "ZaraSecure2026!",
      "name": "Zara Okonkwo"
    }'

  ZARA_TOKEN=$(curl -s -X POST "$AUTH_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email": "zara@meridiantech.io", "password": "ZaraSecure2026!"}' \
    | jq -r '.access_token')

  # Root platform org — this is the control plane, not a runtime environment
  PLATFORM=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $ZARA_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Meridian Platform",
      "slug": "meridian",
      "domain": "meridiantech.io",
      "billing_type": "postpaid",
      "settings": {
        "type": "platform",
        "hierarchical": true
      },
      "metadata": {
        "product": "Meridian SaaS",
        "oncall_rotation": "pagerduty-meridian"
      }
    }')
  PLATFORM_ORG_ID=$(echo "$PLATFORM" | jq -r '.id')

  ZARA_TOKEN=$(curl -s -X POST "$AUTH_URL/auth/switch-organization" \
    -H "Authorization: Bearer $ZARA_TOKEN" \
    -d '{"org_id": "'$PLATFORM_ORG_ID'"}' \
    | jq -r '.access_token')

  ---
  Step 2: Define Platform Permissions

  {
    "service": "meridian",
    "description": "Meridian platform engineering permissions",
    "actions": [
      "read", "write", "create", "delete",
      "deploy", "execute", "rotate", "approve",
      "connect", "admin"
    ],
    "resources": [
      "clusters", "namespaces", "nodes",
      "databases", "secrets", "configs",
      "deployments", "pipelines", "logs",
      "metrics", "alerts", "infrastructure"
    ],
    "roles": {
      "meridian-viewer": {
        "description": "Read-only — logs, metrics, dashboards. Safe for all engineers.",
        "default_permissions": [
          "meridian.read.clusters",   "meridian.read.namespaces",
          "meridian.read.deployments","meridian.read.logs",
          "meridian.read.metrics",    "meridian.read.alerts",
          "meridian.read.configs"
        ]
      },
      "meridian-developer": {
        "description": "Can deploy to their environment, manage configs, view secrets",
        "implies": ["meridian-viewer"],
        "default_permissions": [
          "meridian.deploy.namespaces",
          "meridian.write.configs",
          "meridian.create.deployments",
          "meridian.write.deployments",
          "meridian.read.secrets"
        ]
      },
      "meridian-operator": {
        "description": "Can mutate infrastructure — restart pods, update nodes, rotate secrets",
        "implies": ["meridian-developer"],
        "default_permissions": [
          "meridian.execute.clusters",
          "meridian.write.namespaces",
          "meridian.rotate.secrets",
          "meridian.write.nodes",
          "meridian.delete.deployments"
        ]
      },
      "meridian-admin": {
        "description": "Full infrastructure admin — used by SREs and automation",
        "implies": ["meridian-operator"],
        "default_permissions": [
          "meridian.admin",
          "meridian.create.clusters",
          "meridian.delete.clusters",
          "meridian.write.infrastructure",
          "meridian.approve.deployments"
        ]
      }
    }
  }

  ./register-service-permissions.sh \
    --service-name "meridian" \
    --admin-email "svc+meridian@meridiantech.io" \
    --permissions-file meridian.permissions.json

  SERVICE_API_KEY="ab0t_sk_live_meridian_..."

  ---
  Step 3: Create the Environment Orgs

  3a: Dev environment

  DEV=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $ZARA_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Meridian Dev",
      "slug": "meridian-dev",
      "parent_id": "'"$PLATFORM_ORG_ID"'",
      "billing_type": "postpaid",
      "settings": {
        "type": "environment",
        "environment": "dev",
        "hierarchical": false
      },
      "metadata": {
        "aws_account_id": "111122223333",
        "k8s_cluster": "meridian-dev-eks",
        "region": "us-east-1",
        "auto_destroy_idle_hours": 72
      }
    }')
  DEV_ORG_ID=$(echo "$DEV" | jq -r '.id')

  3b: Staging environment

  STAGING=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $ZARA_TOKEN" \
    -d '{
      "name": "Meridian Staging",
      "slug": "meridian-staging",
      "parent_id": "'"$PLATFORM_ORG_ID"'",
      "settings": {"type": "environment", "environment": "staging"},
      "metadata": {
        "aws_account_id": "444455556666",
        "k8s_cluster": "meridian-staging-eks",
        "region": "us-east-1"
      }
    }')
  STAGING_ORG_ID=$(echo "$STAGING" | jq -r '.id')

  3c: Production environment

  PROD=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $ZARA_TOKEN" \
    -d '{
      "name": "Meridian Production",
      "slug": "meridian-prod",
      "parent_id": "'"$PLATFORM_ORG_ID"'",
      "settings": {
        "type": "environment",
        "environment": "prod",
        "require_mfa": true,
        "audit_all_access": true
      },
      "metadata": {
        "aws_account_id": "777788889999",
        "k8s_cluster": "meridian-prod-eks",
        "region": "us-east-1",
        "soc2_scope": true,
        "change_freeze_policy": "no-friday-deploys"
      }
    }')
  PROD_ORG_ID=$(echo "$PROD" | jq -r '.id')

  What just happened: three isolated orgs, each backed by a different AWS account. The AWS account IDs are stored in metadata — your automation reads them to know which account to operate in. A key scoped to DEV_ORG_ID will return 403 if it tries to do anything in PROD_ORG_ID. Different AWS accounts, different k8s clusters, different Zanzibar stores.

  ---
  Step 4: Set Up People Per Environment

  The key principle: you grant the minimum access per environment. Mistakes in dev are fine. Mistakes in prod cost customers.

  4a: Junior and mid engineers — dev only

  # Add all 5 junior/mid engineers to dev as operators (full freedom in dev)
  for eng in alice bob charlie dana evan; do
    curl -s -X POST "$AUTH_URL/organizations/$DEV_ORG_ID/invite" \
      -H "Authorization: Bearer $ZARA_TOKEN" \
      -d "{
        \"email\": \"${eng}@meridiantech.io\",
        \"role\": \"member\",
        \"permissions\": [
          \"meridian.admin\",
          \"meridian.deploy.namespaces\",
          \"meridian.write.configs\",
          \"meridian.rotate.secrets\",
          \"meridian.execute.clusters\",
          \"meridian.read.logs\",
          \"meridian.read.metrics\"
        ]
      }"
  done

  # Same engineers get READ-ONLY access to staging (for debugging)
  for eng in alice bob charlie dana evan; do
    curl -s -X POST "$AUTH_URL/organizations/$STAGING_ORG_ID/invite" \
      -H "Authorization: Bearer $ZARA_TOKEN" \
      -d "{
        \"email\": \"${eng}@meridiantech.io\",
        \"role\": \"member\",
        \"permissions\": [
          \"meridian.read.clusters\",
          \"meridian.read.namespaces\",
          \"meridian.read.deployments\",
          \"meridian.read.logs\",
          \"meridian.read.metrics\",
          \"meridian.read.configs\"
        ]
      }"
  done

  # Junior engineers get NO access to prod. Not even read. Nothing.
  # (They're simply not invited to the prod org.)

  4b: Senior engineers — full dev/staging, read-only prod

  for senior in felix grace hiro; do
    # Full operator in dev
    curl -s -X POST "$AUTH_URL/organizations/$DEV_ORG_ID/invite" \
      -H "Authorization: Bearer $ZARA_TOKEN" \
      -d "{\"email\": \"${senior}@meridiantech.io\", \"role\": \"member\",
           \"permissions\": [\"meridian.admin\"]}"

    # Full operator in staging
    curl -s -X POST "$AUTH_URL/organizations/$STAGING_ORG_ID/invite" \
      -H "Authorization: Bearer $ZARA_TOKEN" \
      -d "{\"email\": \"${senior}@meridiantech.io\", \"role\": \"member\",
           \"permissions\": [
             \"meridian.deploy.namespaces\", \"meridian.write.configs\",
             \"meridian.execute.clusters\", \"meridian.read.logs\",
             \"meridian.read.metrics\", \"meridian.read.secrets\"
           ]}"

    # Read-only prod
    curl -s -X POST "$AUTH_URL/organizations/$PROD_ORG_ID/invite" \
      -H "Authorization: Bearer $ZARA_TOKEN" \
      -d "{\"email\": \"${senior}@meridiantech.io\", \"role\": \"member\",
           \"permissions\": [
             \"meridian.read.clusters\", \"meridian.read.namespaces\",
             \"meridian.read.deployments\", \"meridian.read.logs\",
             \"meridian.read.metrics\"
           ]}"
  done

  4c: SREs — full access everywhere

  # Nate and Kai: admin across all three environments
  for sre in nate kai; do
    for ORG_ID in $DEV_ORG_ID $STAGING_ORG_ID $PROD_ORG_ID; do
      curl -s -X POST "$AUTH_URL/organizations/$ORG_ID/invite" \
        -H "Authorization: Bearer $ZARA_TOKEN" \
        -d "{\"email\": \"${sre}@meridiantech.io\", \"role\": \"admin\",
             \"permissions\": [\"meridian.admin\"]}"
    done
  done

  What this looks like:

  ┌────────────────────┬────────────────────────┬────────────────────────┬─────────────────────┐
  │       Person       │      Dev access        │    Staging access      │    Prod access      │
  ├────────────────────┼────────────────────────┼────────────────────────┼─────────────────────┤
  │ Alice (junior)     │ Full admin             │ Read-only              │ None (not a member) │
  ├────────────────────┼────────────────────────┼────────────────────────┼─────────────────────┤
  │ Felix (senior)     │ Full admin             │ Full operator          │ Read-only           │
  ├────────────────────┼────────────────────────┼────────────────────────┼─────────────────────┤
  │ Nate (SRE)         │ Full admin             │ Full admin             │ Full admin          │
  ├────────────────────┼────────────────────────┼────────────────────────┼─────────────────────┤
  │ Zara (head of PE)  │ Ancestor access (all)  │ Ancestor access (all)  │ Ancestor access     │
  └────────────────────┴────────────────────────┴────────────────────────┴─────────────────────┘

  Concept: Why "None" for junior prod access vs "read-only" for seniors?
  If Alice can't read prod logs, how does she debug production issues? Answer: she doesn't — that's what the on-call SRE is for. Junior engineers debug via staging. If they need prod logs, they ask an SRE to pull them. This isn't punitive; it's the blast-radius principle. The fewer people with any prod access, the smaller the surface area for mistakes.

  ---
  Step 5: Service Accounts — Every Service Gets Its Own Identity Per Environment

  Your API service running in prod needs to talk to the auth service (to validate user tokens). It needs an identity. That identity should be:
  - Not a human (it's a machine)
  - Scoped to prod only (the prod API service identity cannot touch staging)
  - Minimal permissions (can validate tokens, cannot modify users, cannot deploy)
  - Rotatable (you can generate a new key without downtime)

  Concept: Service Accounts
  A service account is a non-human identity in an org. It has an API key instead of a password. It gets exactly the permissions its service needs. It lives in the environment org that matches where the service runs. When the service makes an API call, it identifies itself and the auth service knows: "this is the API service in prod."

  5a: Create service accounts for each service in each environment

  # Function to create a service account for a service in an environment
  create_service_account() {
    local service_name=$1
    local env_name=$2
    local org_id=$3
    local permissions=$4

    # POST /api-keys/ — inherits org from bearer token's context (no org in path)
    KEY=$(curl -s -X POST "$AUTH_URL/api-keys/" \
      -H "Authorization: Bearer $ZARA_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{
        \"name\": \"${service_name}-${env_name}\",
        \"description\": \"Service account for ${service_name} in ${env_name}\",
        \"permissions\": $permissions,
        \"metadata\": {
          \"service\": \"${service_name}\",
          \"environment\": \"${env_name}\",
          \"managed_by\": \"terraform\",
          \"rotation_days\": 90
        }
      }")
    echo "$KEY" | jq -r '.key'
  }

  # api-service: validates tokens, reads configs
  API_DEV_KEY=$(create_service_account "api-service" "dev" "$DEV_ORG_ID" \
    '["meridian.read.configs", "meridian.read.secrets"]')

  API_STAGING_KEY=$(create_service_account "api-service" "staging" "$STAGING_ORG_ID" \
    '["meridian.read.configs", "meridian.read.secrets"]')

  API_PROD_KEY=$(create_service_account "api-service" "prod" "$PROD_ORG_ID" \
    '["meridian.read.configs", "meridian.read.secrets"]')

  # worker-service: reads configs, writes metrics
  WORKER_DEV_KEY=$(create_service_account "worker-service" "dev" "$DEV_ORG_ID" \
    '["meridian.read.configs", "meridian.read.secrets", "meridian.write.metrics"]')

  WORKER_STAGING_KEY=$(create_service_account "worker-service" "staging" "$STAGING_ORG_ID" \
    '["meridian.read.configs", "meridian.read.secrets", "meridian.write.metrics"]')

  WORKER_PROD_KEY=$(create_service_account "worker-service" "prod" "$PROD_ORG_ID" \
    '["meridian.read.configs", "meridian.read.secrets", "meridian.write.metrics"]')

  # data-pipeline: needs more — reads AND writes databases
  PIPELINE_DEV_KEY=$(create_service_account "data-pipeline" "dev" "$DEV_ORG_ID" \
    '["meridian.read.databases", "meridian.write.databases", "meridian.read.secrets"]')

  PIPELINE_PROD_KEY=$(create_service_account "data-pipeline" "prod" "$PROD_ORG_ID" \
    '["meridian.read.databases", "meridian.write.databases", "meridian.read.secrets"]')

  5b: Each service gets its key via environment variables

  These keys land in your secrets manager (AWS Secrets Manager, Vault, etc.) and are injected as environment variables at runtime:

  # In Terraform / Kubernetes secrets
  resource "kubernetes_secret" "api_service_creds" {
    metadata { name = "api-service-creds" }
    data = {
      MERIDIAN_API_KEY = var.api_service_key  # the key from above
      MERIDIAN_ORG_ID  = var.prod_org_id
    }
  }

  # The api-service reads this at startup:
  MERIDIAN_API_KEY=ab0t_sk_live_api_prod_...
  MERIDIAN_ORG_ID=prod-org-uuid

  # Every request the api-service makes to the auth platform:
  X-API-Key: ab0t_sk_live_api_prod_...

  The service account matrix:

  ┌────────────────────┬───────────────────────────────────────────────────────────────────────────────┐
  │     Service        │ Permissions (same across envs, but different KEY and different ORG_ID)        │
  ├────────────────────┼───────────────────────────────────────────────────────────────────────────────┤
  │ api-service        │ read.configs, read.secrets                                                    │
  ├────────────────────┼───────────────────────────────────────────────────────────────────────────────┤
  │ worker-service     │ read.configs, read.secrets, write.metrics                                     │
  ├────────────────────┼───────────────────────────────────────────────────────────────────────────────┤
  │ scheduler-service  │ read.configs, read.secrets, execute.pipelines                                 │
  ├────────────────────┼───────────────────────────────────────────────────────────────────────────────┤
  │ data-pipeline      │ read.databases, write.databases, read.secrets                                 │
  └────────────────────┴───────────────────────────────────────────────────────────────────────────────┘

  Three environments × four services = 12 service accounts. Each is isolated to its own environment org. The prod api-service key CANNOT read staging databases (wrong org). If someone steals the staging worker key, they get nothing in prod.

  ---
  Step 6: CI/CD API Keys — The Deploy Pipeline

  Your GitHub Actions pipeline deploys code. It needs credentials. Those credentials must be scoped to the target environment — and the prod deploy key should be harder to use than dev.

  6a: Dev deploy key — anyone can trigger

  CI_DEV_KEY=$(curl -s -X POST "$AUTH_URL/api-keys/" \
    -H "Authorization: Bearer $ZARA_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "github-actions-dev",
      "description": "GitHub Actions deploy to dev — triggered automatically on push to main",
      "permissions": [
        "meridian.deploy.namespaces",
        "meridian.write.deployments",
        "meridian.create.deployments",
        "meridian.read.clusters",
        "meridian.read.deployments",
        "meridian.write.configs"
      ],
      "metadata": {
        "ci_system": "github_actions",
        "repo": "meridiantech/api",
        "trigger": "push_to_main",
        "environment": "dev"
      }
    }' | jq -r '.key')

  # Store in GitHub Actions secrets as MERIDIAN_DEV_DEPLOY_KEY

  6b: Staging deploy key — triggered on merge to release branch

  CI_STAGING_KEY=$(curl -s -X POST "$AUTH_URL/api-keys/" \
    -H "Authorization: Bearer $ZARA_TOKEN" \
    -d '{
      "name": "github-actions-staging",
      "description": "GitHub Actions deploy to staging — triggered on release branch merge",
      "permissions": [
        "meridian.deploy.namespaces",
        "meridian.write.deployments",
        "meridian.create.deployments",
        "meridian.read.clusters",
        "meridian.read.deployments"
      ],
      "metadata": {
        "ci_system": "github_actions",
        "trigger": "release_branch_merge",
        "environment": "staging"
      }
    }' | jq -r '.key')

  6c: Prod deploy key — requires explicit approval before use

  CI_PROD_KEY=$(curl -s -X POST "$AUTH_URL/api-keys/" \
    -H "Authorization: Bearer $NATE_TOKEN" \
    -d '{
      "name": "github-actions-prod",
      "description": "GitHub Actions deploy to prod — gated by SRE approval in GitHub",
      "permissions": [
        "meridian.deploy.namespaces",
        "meridian.write.deployments",
        "meridian.read.clusters",
        "meridian.read.deployments",
        "meridian.approve.deployments"
      ],
      "metadata": {
        "ci_system": "github_actions",
        "trigger": "manual_approval",
        "environment": "prod",
        "required_approvers": ["nate", "kai", "zara"],
        "min_approvals": 1
      }
    }' | jq -r '.key')

  # Note: Nate (SRE) creates the prod key — not Zara's service account
  # The prod key is stored in a GitHub Environment with required reviewers set
  # GitHub won't pass the secret to the job until a reviewer approves

  Concept: The Prod Deploy Gate
  The prod CI key is stored as a GitHub Actions environment secret in the "production" environment, which has required reviewers configured. GitHub blocks the job from starting until an SRE approves it. The auth service key then scopes what the job can do after it starts. Two gates: GitHub (human approval) + the auth service (what operations are allowed). If someone bypasses GitHub's gate and somehow gets the key, they can only do what the key allows — and only in prod.

  6d: Your pipeline config (.github/workflows/deploy.yml)

  jobs:
    deploy-dev:
      environment: development
      runs-on: ubuntu-latest
      steps:
        - name: Deploy to dev
          env:
            MERIDIAN_API_KEY: ${{ secrets.MERIDIAN_DEV_DEPLOY_KEY }}
            MERIDIAN_ORG_ID:  ${{ secrets.MERIDIAN_DEV_ORG_ID }}
          run: ./scripts/deploy.sh dev

    deploy-staging:
      environment: staging
      needs: [test, deploy-dev]
      steps:
        - name: Deploy to staging
          env:
            MERIDIAN_API_KEY: ${{ secrets.MERIDIAN_STAGING_DEPLOY_KEY }}
            MERIDIAN_ORG_ID:  ${{ secrets.MERIDIAN_STAGING_ORG_ID }}
          run: ./scripts/deploy.sh staging

    deploy-prod:
      environment: production          # <-- has required reviewers in GitHub settings
      needs: [integration-tests]
      steps:
        - name: Deploy to production
          env:
            MERIDIAN_API_KEY: ${{ secrets.MERIDIAN_PROD_DEPLOY_KEY }}
            MERIDIAN_ORG_ID:  ${{ secrets.MERIDIAN_PROD_ORG_ID }}
          run: ./scripts/deploy.sh prod

  The deploy script itself:

  #!/bin/bash
  # scripts/deploy.sh
  ENV=$1

  # Validate the token is for the right environment
  ORG=$(curl -s -X GET "$AUTH_URL/organizations/me" \
    -H "X-API-Key: $MERIDIAN_API_KEY")
  ACTUAL_ENV=$(echo "$ORG" | jq -r '.settings.environment')

  if [ "$ACTUAL_ENV" != "$ENV" ]; then
    echo "FATAL: Key is for $ACTUAL_ENV but deploying to $ENV. Aborting."
    exit 1
  fi

  # Proceed with deploy — kubectl apply, helm upgrade, etc.

  This guard prevents the classic mistake: wrong key in the wrong pipeline step.

  ---
  Step 7: Zanzibar for Infrastructure Resources

  Org membership says Nate is in the prod org. That's Layer 1. But prod has 3 Kubernetes clusters, 8 databases, 40 namespaces, and 200 secrets. Zanzibar says exactly which ones Nate (or a service account) can touch.

  Concept: Infrastructure as Zanzibar Objects
  Just like the finance guide used portfolios and accounts as objects, here you use clusters, databases, namespaces, and secrets. A human or service account gets specific tuples — not "access to prod" but "access to prod-db-user-001 specifically."

  7a: Define the infra namespaces

  # Who can access which k8s cluster
  curl -X POST "$AUTH_URL/zanzibar/stores/$PLATFORM_ORG_ID/namespaces" \
    -H "Authorization: Bearer $ZARA_TOKEN" \
    -d '{
      "org_id": "'$PROD_ORG_ID'",
      "namespace": "cluster",
      "relations": {
        "admin":    {},
        "operator": {"union": ["admin"]},
        "deployer": {"union": ["operator"]},
        "viewer":   {"union": ["deployer"]}
      },
      "permissions": {
        "read":    {"union": ["viewer"]},
        "deploy":  {"union": ["deployer"]},
        "operate": {"union": ["operator"]},
        "admin":   {"union": ["admin"]}
      }
    }'

  # Who can access which database
  curl -X POST "$AUTH_URL/zanzibar/stores/$PLATFORM_ORG_ID/namespaces" \
    -H "Authorization: Bearer $ZARA_TOKEN" \
    -d '{
      "org_id": "'$PROD_ORG_ID'",
      "namespace": "database",
      "relations": {
        "owner":      {},
        "read_write": {"union": ["owner"]},
        "read_only":  {"union": ["read_write"]}
      },
      "permissions": {
        "read":  {"union": ["read_only"]},
        "write": {"union": ["read_write"]}
      }
    }'

  # Who can access which secret
  curl -X POST "$AUTH_URL/zanzibar/stores/$PLATFORM_ORG_ID/namespaces" \
    -H "Authorization: Bearer $ZARA_TOKEN" \
    -d '{
      "org_id": "'$PROD_ORG_ID'",
      "namespace": "secret",
      "relations": {
        "owner":  {},
        "reader": {"union": ["owner"]}
      },
      "permissions": {
        "read":   {"union": ["reader"]},
        "rotate": {"union": ["owner"]}
      }
    }'

  7b: Assign SREs to specific clusters

  # Nate and Kai are operators of all prod clusters
  curl -X POST "$AUTH_URL/zanzibar/stores/$PLATFORM_ORG_ID/relationships" \
    -H "Authorization: Bearer $ZARA_TOKEN" \
    -d '{
      "org_id": "'$PROD_ORG_ID'",
      "tuples": [
        {"object": "cluster:prod-eks-us-east-1", "relation": "operator", "subject": "user:'$NATE_USER_ID'"},
        {"object": "cluster:prod-eks-us-east-1", "relation": "operator", "subject": "user:'$KAI_USER_ID'"},
        {"object": "cluster:prod-eks-eu-west-1", "relation": "operator", "subject": "user:'$NATE_USER_ID'"},
        {"object": "cluster:prod-eks-eu-west-1", "relation": "operator", "subject": "user:'$KAI_USER_ID'"}
      ]
    }'

  # Senior engineers are viewers of prod clusters (read logs/metrics, no exec)
  curl -X POST "$AUTH_URL/zanzibar/stores/$PLATFORM_ORG_ID/relationships" \
    -H "Authorization: Bearer $ZARA_TOKEN" \
    -d '{
      "org_id": "'$PROD_ORG_ID'",
      "tuples": [
        {"object": "cluster:prod-eks-us-east-1", "relation": "viewer", "subject": "user:'$FELIX_USER_ID'"},
        {"object": "cluster:prod-eks-us-east-1", "relation": "viewer", "subject": "user:'$GRACE_USER_ID'"},
        {"object": "cluster:prod-eks-us-east-1", "relation": "viewer", "subject": "user:'$HIRO_USER_ID'"}
      ]
    }'

  7c: Assign service accounts to their specific databases

  # api-service can only read the users database (NOT billing, NOT analytics)
  curl -X POST "$AUTH_URL/zanzibar/stores/$PLATFORM_ORG_ID/relationships" \
    -H "Authorization: Bearer $ZARA_TOKEN" \
    -d '{
      "org_id": "'$PROD_ORG_ID'",
      "tuples": [
        {"object": "database:prod-users-db",    "relation": "read_only",  "subject": "service:api-service-prod"},
        {"object": "database:prod-sessions-db", "relation": "read_write", "subject": "service:api-service-prod"}
      ]
    }'

  # data-pipeline can read/write analytics, NOT users database
  curl -X POST "$AUTH_URL/zanzibar/stores/$PLATFORM_ORG_ID/relationships" \
    -H "Authorization: Bearer $ZARA_TOKEN" \
    -d '{
      "org_id": "'$PROD_ORG_ID'",
      "tuples": [
        {"object": "database:prod-analytics-db", "relation": "read_write", "subject": "service:data-pipeline-prod"},
        {"object": "database:prod-warehouse-db", "relation": "read_write", "subject": "service:data-pipeline-prod"}
      ]
    }'

  7d: Check access in your infrastructure tooling

  In your internal platform tooling (the thing engineers use to run kubectl, access databases, rotate secrets):

  # Engineer tries to exec into a prod pod
  async def kubectl_exec(cluster_id: str, user_id: str, command: str):
      allowed = await zanzibar.check(
          org_id=PROD_ORG_ID,
          subject=f"user:{user_id}",
          permission="operate",
          object=f"cluster:{cluster_id}"
      )
      if not allowed:
          raise PermissionError(
              f"You do not have operator access to {cluster_id}. "
              f"Ask an SRE or use the break-glass procedure if this is an emergency."
          )
      return await k8s_client.exec(cluster_id, command)

  # Service account reads a secret
  async def get_secret(secret_id: str, api_key: str):
      key_info = await auth.validate_api_key(api_key)  # identifies the service
      allowed = await zanzibar.check(
          org_id=PROD_ORG_ID,
          subject=f"service:{key_info.name}",
          permission="read",
          object=f"secret:{secret_id}"
      )
      if not allowed:
          raise PermissionError(f"Service {key_info.name} has no access to {secret_id}")
      return await secrets_manager.get(secret_id)

  Situation: Alice (junior engineer) tries to kubectl exec into a prod pod.
  Layer 1: Alice is in the prod org with read-only permissions (meridian.read.*). exec requires meridian.execute.clusters, which she doesn't have. Rejected at Layer 1.

  Situation: Felix (senior engineer) tries to kubectl exec into a prod pod.
  Layer 1: Felix has meridian.execute.clusters in the prod org. Passes.
  Layer 2: Zanzibar check — Felix has viewer on prod-eks-us-east-1, not operator. viewer doesn't grant operate permission. Rejected at Layer 2.
  Felix can read (view logs, describe pods) but cannot exec. Correct.

  Situation: Nate tries to kubectl exec.
  Layer 1: Nate has meridian.admin. Passes.
  Layer 2: Nate has operator on prod-eks-us-east-1. operator grants operate permission. Allowed.

  ---
  Step 8: Break-Glass — Emergency Prod Access

  At 2am, the prod API is throwing 500s. Nate is oncall. Felix gets paged as secondary. Felix normally has read-only prod access. He needs to exec into pods right now.

  Concept: Break-Glass
  Break-glass is a formal procedure for granting temporary elevated access in an emergency. Named after the literal glass-covered emergency switches in factories — you break the glass, take the action, the audit shows exactly what happened and when. Key properties:
  1. Fast: granted in under 2 minutes
  2. Time-limited: access expires automatically
  3. Audited: every single action is logged against the emergency access grant
  4. Revocable: on-call lead can cancel it before expiry

  8a: Nate grants Felix emergency operator access

  # Step 1: Nate (oncall primary) creates a delegation grant for Felix
  BREAKGLASS_GRANT=$(curl -s -X POST "$AUTH_URL/delegation/grant" \
    -H "Authorization: Bearer $NATE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "actor_id": "'$FELIX_USER_ID'",
      "scope": [
        "meridian.execute.clusters",
        "meridian.read.logs",
        "meridian.read.metrics",
        "meridian.read.secrets"
      ],
      "expires_in_hours": 4,
      "metadata": {
        "purpose": "Emergency oncall access — P0 incident #INC-4821, API 500s",
        "incident_id": "INC-4821",
        "granted_by_oncall": "nate@meridiantech.io",
        "pagerduty_incident": "https://meridian.pagerduty.com/incidents/INC-4821"
      }
    }')
  GRANT_ID=$(echo "$BREAKGLASS_GRANT" | jq -r '.id')

  # Nate also adds a Zanzibar tuple granting Felix operator on the affected cluster
  curl -X POST "$AUTH_URL/zanzibar/stores/$PLATFORM_ORG_ID/relationships" \
    -H "Authorization: Bearer $NATE_TOKEN" \
    -d '{
      "org_id": "'$PROD_ORG_ID'",
      "tuples": [
        {
          "object": "cluster:prod-eks-us-east-1",
          "relation": "operator",
          "subject": "user:'$FELIX_USER_ID'",
          "metadata": {
            "break_glass": true,
            "incident_id": "INC-4821",
            "grant_id": "'$GRANT_ID'",
            "expires_at": "2026-11-15T06:00:00Z"
          }
        }
      ]
    }'

  # Nate notifies Felix via PagerDuty chat that delegation is active

  8b: Felix uses the break-glass access

  # Step 2: Nate delegates to Felix — produces a scoped session token
  FELIX_EMERGENCY=$(curl -s -X POST "$AUTH_URL/auth/delegate" \
    -H "Authorization: Bearer $NATE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "target_user_id": "'$FELIX_USER_ID'"
    }')
  FELIX_EMERGENCY_TOKEN=$(echo "$FELIX_EMERGENCY" | jq -r '.access_token')

  # Felix execs into the crashing pod
  # Your internal tooling uses this token + Zanzibar check
  # Zanzibar: felix has operator on prod-eks-us-east-1 -> allowed
  kubectl exec -it api-service-prod-8f9d7c6b5-xk2m4 -- /bin/sh
  # AUDIT LOG: felix@meridiantech.io exec'd into pod, grant:INC-4821, 2026-11-15T02:17:44Z

  8c: Post-incident cleanup

  # Incident resolved. Nate revokes Felix's break-glass delegation grant immediately.
  curl -X DELETE "$AUTH_URL/delegation/grant/$FELIX_USER_ID" \
    -H "Authorization: Bearer $NATE_TOKEN"

  # Clean up the Zanzibar tuple
  curl -X DELETE "$AUTH_URL/zanzibar/stores/$PLATFORM_ORG_ID/relationships" \
    -H "Authorization: Bearer $NATE_TOKEN" \
    -d '{
      "org_id": "'$PROD_ORG_ID'",
      "filter": {
        "subject": "user:'$FELIX_USER_ID'",
        "metadata.incident_id": "INC-4821"
      }
    }'

  # Audit log preserved (even after deletion): who had access, when, what they did

  8d: Automatic expiry

  If Nate forgets to revoke (he's exhausted at 4am), the delegation grant expires after 4 hours automatically. Felix's emergency access self-destructs. The Zanzibar tuple metadata carries the expiry and your cleanup job removes it:

  # Runs every 15 minutes
  async def cleanup_expired_breakglass():
      tuples = await zanzibar.query(
          filter={"metadata.break_glass": True, "metadata.expires_at": {"$lt": now()}}
      )
      for t in tuples:
          await zanzibar.delete_tuple(t)
          await audit.log(f"Break-glass tuple auto-expired: {t}")

  ---
  Step 9: Key Rotation — Zero Downtime

  Service account keys should rotate every 90 days. Here's how to do it without dropping requests.

  Concept: Dual-Key Rotation
  The auth service supports multiple active keys per service account. During rotation you:
  1. Create new key (both old and new are valid)
  2. Deploy the new key to the service (rolling deploy — some pods use old, some use new)
  3. Verify all pods are using the new key
  4. Revoke the old key

  # Step 1: Create new key (old key still works)
  NEW_KEY=$(curl -s -X POST "$AUTH_URL/api-keys/" \
    -H "Authorization: Bearer $NATE_TOKEN" \
    -d '{
      "name": "api-service-prod-v2",
      "description": "Rotated key for api-service in prod (rotation cycle 2)",
      "permissions": ["meridian.read.configs", "meridian.read.secrets"],
      "metadata": {
        "service": "api-service",
        "environment": "prod",
        "rotation_date": "2026-11-01",
        "replaces": "api-service-prod-v1"
      }
    }' | jq -r '.key')

  # Step 2: Update the secret in AWS Secrets Manager
  aws secretsmanager update-secret \
    --secret-id "meridian/prod/api-service/new-key" \
    --secret-string "$NEW_KEY"

  # Step 3: Rolling deploy — new pods pick up the new key from the secret
  kubectl rollout restart deployment/api-service-prod
  kubectl rollout status deployment/api-service-prod
  # Wait for all pods to be running with the new key

  # Step 4: Verify old key is no longer in use (check metrics)
  # Your monitoring should show zero requests using the old key ID

  # Step 5: Revoke the old key
  curl -X DELETE "$AUTH_URL/api-keys/api-service-prod-v1" \
    -H "Authorization: Bearer $NATE_TOKEN"

  If a pod still using the old key tries to make a request after revocation: 401. The pod's readiness probe fails, Kubernetes restarts it, it picks up the new key. Self-healing rotation.

  ---
  Step 10: Promoting an Engineer — Alice Gets Staging Access

  Alice has been doing great. After 6 months she's ready for staging operator access.

  # Upgrade Alice's staging permissions from viewer to operator
  curl -X PUT "$AUTH_URL/organizations/$STAGING_ORG_ID/users/$ALICE_USER_ID/permissions" \
    -H "Authorization: Bearer $ZARA_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "permissions": [
        "meridian.deploy.namespaces",
        "meridian.write.configs",
        "meridian.execute.clusters",
        "meridian.read.logs",
        "meridian.read.metrics",
        "meridian.read.secrets",
        "meridian.rotate.secrets"
      ]
    }'

  # Also give Alice Zanzibar operator access to staging clusters
  curl -X POST "$AUTH_URL/zanzibar/stores/$PLATFORM_ORG_ID/relationships" \
    -H "Authorization: Bearer $ZARA_TOKEN" \
    -d '{
      "org_id": "'$STAGING_ORG_ID'",
      "tuples": [
        {"object": "cluster:staging-eks", "relation": "operator", "subject": "user:'$ALICE_USER_ID'"},
        {"object": "database:staging-users-db", "relation": "read_write", "subject": "user:'$ALICE_USER_ID'"}
      ]
    }'

  Alice's access:
  - Dev: unchanged (full admin)
  - Staging: upgraded from viewer to operator, can now deploy and exec
  - Prod: still no access

  ---
  Summary: The Complete Platform Picture

  Meridian Platform (root org)
  │  Zara (owner, ancestor access to all envs)
  │  SERVICE_API_KEY (manages all environments)
  │
  ├── Dev Environment (org — aws account 111122223333)
  │   ├── All 8 engineers: full admin
  │   ├── github-actions-dev key (auto-deploys on push to main)
  │   ├── Service accounts: api-dev, worker-dev, scheduler-dev, pipeline-dev
  │   └── Zanzibar: relaxed — engineers have operator on all dev resources
  │
  ├── Staging Environment (org — aws account 444455556666)
  │   ├── Junior engineers: read-only
  │   ├── Senior engineers + SREs: full operator
  │   ├── github-actions-staging key (deploys on release branch merge)
  │   ├── Service accounts: api-staging, worker-staging, scheduler-staging
  │   └── Zanzibar: seniors can operate staging clusters and databases
  │
  └── Prod Environment (org — aws account 777788889999)
      ├── Junior engineers: NOT MEMBERS (no access at all)
      ├── Senior engineers: read-only org membership
      │   └── Zanzibar: viewer on prod-eks (read logs, describe — no exec)
      ├── SREs (Nate, Kai): full admin
      │   └── Zanzibar: operator on all prod clusters and databases
      ├── github-actions-prod key (manual approval required)
      ├── Service accounts (12 total, least-privilege per service):
      │   ├── api-prod:       read.configs, read.secrets
      │   ├── worker-prod:    read.configs, read.secrets, write.metrics
      │   ├── scheduler-prod: read.configs, read.secrets, execute.pipelines
      │   └── pipeline-prod:  read.databases, write.databases, read.secrets
      └── Zanzibar tuples:
          ├── cluster:prod-eks-us-east-1 #operator -> nate, kai
          ├── cluster:prod-eks-us-east-1 #viewer   -> felix, grace, hiro
          ├── database:prod-users-db    #read_only  -> service:api-prod
          ├── database:prod-sessions-db #read_write -> service:api-prod
          ├── database:prod-analytics-db#read_write -> service:data-pipeline-prod
          └── (break-glass tuples created per incident, auto-expire)

  Security properties:
  - Mis-pointing a CI variable at the wrong environment = 403 before any deploy runs
  - Junior engineer in prod: impossible (not a member)
  - Senior engineer exec into prod pod: blocked by Zanzibar (viewer, not operator)
  - SRE emergency break-glass: granted in 60 seconds, auto-expires, full audit trail
  - Compromised service account key: scoped to one service + one environment + specific databases
  - Key rotation: zero-downtime dual-key swap, old key revoked after rollout confirmed
  - Every human prod action: logged with identity, delegation grant context if break-glass
