question: We are three founders building a cloud file storage SaaS called "VaultDrive" — think Google Drive but for regulated industries. We have 3 employees right now but
  we are planning for thousands of customers. We want users to sign up with Google or GitHub (no passwords), we need background workers that can access files on behalf of users,
  we want sub-orgs for when customers have separate teams or client projects, and API keys so third-party apps can integrate with us. Walk me through the whole thing.

● Great setup. You are planning correctly — start small, build the right primitives, scale without rewriting.

  By the end of this guide you will have:
  - Your 3-person company set up
  - VaultDrive's permissions registered (files, folders, sharing)
  - A hosted login page where users sign in with Google or GitHub — no passwords anywhere
  - A customer org with a sub-org for an isolated client project
  - A service account for your background sync worker
  - API keys so third-party desktop and mobile apps can call VaultDrive on behalf of users
  - Delegation tokens — your worker acting as a specific user, not as itself

  ---
  Concept: Why "No Passwords"?

  OAuth 2.1 is the current standard for delegated authorization. When a user clicks "Continue with Google," they authenticate with Google (who already knows their password, MFA, and
  device history), and Google tells your system "yes, this is them." You never handle a password. You never store a password hash. You can never leak one.

  The auth service implements OAuth 2.1 throughout:
  - PKCE (Proof Key for Code Exchange) is mandatory on every flow — no exceptions
  - Implicit flow is gone (tokens never appear in URLs)
  - Refresh tokens rotate on every use — a stolen refresh token can only be used once
  - Every authorization code is single-use and expires in 60 seconds

  Your users sign in with Google or GitHub. Your enterprise customers' employees sign in with Okta SAML. Nobody types a password into VaultDrive. That is the goal.

  ---
  The Architecture You Are Building

  Auth Service
  ├── VaultDrive Inc        ← your 3 founders (internal)
  ├── VaultDrive Service    ← your app's permission rulebook + API keys
  ├── Spark Creative        ← customer org (marketing agency)
  │   └── Spark / Nike Project  ← sub-org (isolated client project)
  └── ... thousands more customers, each isolated

  ---
  Step 1: Register the Three Founders

  AUTH_URL="https://auth.service.ab0t.com"

  # Maya — CEO
  curl -X POST "$AUTH_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d '{"email": "maya@vaultdrive.io", "password": "BootstrapOnly2026!", "name": "Maya Osei"}'

  # Priya — CTO
  curl -X POST "$AUTH_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d '{"email": "priya@vaultdrive.io", "password": "BootstrapOnly2026!", "name": "Priya Nair"}'

  # Tom — Head of Growth
  curl -X POST "$AUTH_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d '{"email": "tom@vaultdrive.io", "password": "BootstrapOnly2026!", "name": "Tom Ribeiro"}'

  What just happened: Three identities exist. Nobody has a company yet. Nobody has permissions yet.

  Note: you are using email/password here for your own internal accounts — founders need a reliable fallback. Your customers will use OAuth 2.1 (Google, GitHub). We will lock that down per-org in Step 7.

  Login and create a company org:

  TOKEN=$(curl -s -X POST "$AUTH_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email": "maya@vaultdrive.io", "password": "BootstrapOnly2026!"}' \
    | jq -r '.access_token')

  curl -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "VaultDrive Inc",
      "slug": "vaultdrive",
      "domain": "vaultdrive.io",
      "billing_type": "postpaid",
      "settings": {"type": "company", "hierarchical": true},
      "metadata": {"stage": "seed", "founded": "2026"}
    }'

  VAULTDRIVE_ORG_ID="the-uuid-from-response"

  # Switch into the org context
  MAYA_TOKEN=$(curl -s -X POST "$AUTH_URL/auth/switch-organization" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"org_id": "'"$VAULTDRIVE_ORG_ID"'"}' \
    | jq -r '.access_token')

  # Invite Priya and Tom as admins
  curl -X POST "$AUTH_URL/organizations/$VAULTDRIVE_ORG_ID/invite" \
    -H "Authorization: Bearer $MAYA_TOKEN" \
    -d '{"email": "priya@vaultdrive.io", "role": "admin", "permissions": ["vaultdrive.admin"]}'

  curl -X POST "$AUTH_URL/organizations/$VAULTDRIVE_ORG_ID/invite" \
    -H "Authorization: Bearer $MAYA_TOKEN" \
    -d '{"email": "tom@vaultdrive.io", "role": "member", "permissions": ["vaultdrive.read.files", "vaultdrive.read.reports"]}'

  ---
  Step 2: Define VaultDrive's Permissions

  Your app is a file storage system. Define what actions exist.

  Create vaultdrive.permissions.json:

  {
    "service": "vaultdrive",
    "description": "Cloud file storage for regulated industries",
    "actions": ["read", "write", "create", "delete", "share", "download", "restore", "admin"],
    "resources": ["files", "folders", "shares", "versions", "trash", "members", "settings", "audit"],
    "roles": {
      "vaultdrive-viewer": {
        "description": "Can view and download files, cannot modify",
        "default_permissions": [
          "vaultdrive.read.files",
          "vaultdrive.read.folders",
          "vaultdrive.download.files",
          "vaultdrive.read.shares"
        ]
      },
      "vaultdrive-editor": {
        "description": "Can upload, edit, organize files",
        "default_permissions": [
          "vaultdrive.read.files", "vaultdrive.write.files", "vaultdrive.create.files",
          "vaultdrive.read.folders", "vaultdrive.write.folders", "vaultdrive.create.folders",
          "vaultdrive.download.files", "vaultdrive.share.files",
          "vaultdrive.restore.versions"
        ]
      },
      "vaultdrive-admin": {
        "description": "Full access — manage members, settings, audit logs",
        "implies": ["vaultdrive-editor"],
        "default_permissions": [
          "vaultdrive.admin",
          "vaultdrive.delete.files",
          "vaultdrive.delete.folders",
          "vaultdrive.write.settings",
          "vaultdrive.read.audit",
          "vaultdrive.write.members",
          "vaultdrive.delete.trash"
        ]
      }
    }
  }

  Run the registration script:

  ./register-service-permissions.sh \
    --auth-url "$AUTH_URL" \
    --service-name "vaultdrive" \
    --admin-email "priya+svc@vaultdrive.io" \
    --permissions-file vaultdrive.permissions.json

  Save the output:

  SERVICE_ORG_ID="vaultdrive-service-org-uuid"
  SERVICE_API_KEY="ab0t_sk_live_..."

  What just happened: A second org was created — "VaultDrive Service." This holds your permission definitions and API keys. It is separate from VaultDrive Inc (your employees). If someone compromises your internal Slack, they reach employee data. They do not reach the service API keys. Separate blast radius.

  ---
  Step 3: Integrate VaultDrive (app/auth.py)

  from typing import Annotated
  from fastapi import Depends, HTTPException
  from ab0t_auth import AuthGuard, AuthenticatedUser, require_permission, require_any_permission
  from ab0t_auth.errors import PermissionDeniedError

  auth = AuthGuard(
      auth_url="https://auth.service.ab0t.com",
      audience="vaultdrive",  # Matches service_audience from registration
      permission_check_mode="server",
  )

  def belongs_to_org(user: AuthenticatedUser, **kwargs) -> bool:
      resource_org_id = kwargs.get("org_id")
      return resource_org_id is None or user.org_id == resource_org_id

  # Badges — these go in your route signatures
  FileViewer  = Annotated[AuthenticatedUser, Depends(require_permission(auth, "vaultdrive.read.files",   check=belongs_to_org))]
  FileEditor  = Annotated[AuthenticatedUser, Depends(require_permission(auth, "vaultdrive.write.files",  check=belongs_to_org))]
  FileDeleter = Annotated[AuthenticatedUser, Depends(require_permission(auth, "vaultdrive.delete.files", check=belongs_to_org))]
  DriveAdmin  = Annotated[AuthenticatedUser, Depends(require_permission(auth, "vaultdrive.admin",        check=belongs_to_org))]

  Protected routes:

  @router.get("/folders/{folder_id}/files")
  async def list_files(folder_id: str, user: FileViewer):
      folder = await db.get_folder(folder_id)
      if folder.org_id != user.org_id:          # Phase 2: is this folder theirs?
          raise PermissionDeniedError("Access denied")
      return await db.list_files(folder_id=folder_id, org_id=user.org_id)

  @router.post("/folders/{folder_id}/files")
  async def upload_file(folder_id: str, file: UploadFile, user: FileEditor):
      folder = await db.get_folder(folder_id)
      if folder.org_id != user.org_id:
          raise PermissionDeniedError("Access denied")
      return await storage.upload(file, folder_id=folder_id, org_id=user.org_id, uploaded_by=user.user_id)

  Concept: Phase 1 vs Phase 2
  Phase 1 is the badge check: does this user have vaultdrive.read.files? The auth library handles this.
  Phase 2 is the resource check: does THIS folder belong to THIS user's org? Your code handles this.
  Both are required. Phase 1 without Phase 2 means a user at Spark Creative could read Nike's files if they guessed the folder_id. Never skip Phase 2.

  ---
  Step 4: Your First Customer — Spark Creative Agency

  Spark Creative is a marketing agency with 15 employees. Their clients (Nike, Apple, Adidas) each have projects. Some projects have NDAs — Spark's Nike team cannot see Adidas files.

  4a: Create Spark's org

  SPARK=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "X-API-Key: $SERVICE_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Spark Creative",
      "slug": "spark-creative",
      "domain": "sparkcreative.com",
      "billing_type": "postpaid",
      "settings": {"type": "customer", "hierarchical": true},
      "metadata": {"plan": "pro", "industry": "marketing"}
    }')
  SPARK_ORG_ID=$(echo "$SPARK" | jq -r '.id')

  4b: Jordan (Spark's admin) invites the team

  # Jordan is Spark's owner — she was first to sign up
  JORDAN_TOKEN="..."

  # Senior designers — can upload and share
  curl -X POST "$AUTH_URL/organizations/$SPARK_ORG_ID/invite" \
    -H "Authorization: Bearer $JORDAN_TOKEN" \
    -d '{"email": "leo@sparkcreative.com", "role": "vaultdrive-editor"}'

  curl -X POST "$AUTH_URL/organizations/$SPARK_ORG_ID/invite" \
    -H "Authorization: Bearer $JORDAN_TOKEN" \
    -d '{"email": "anais@sparkcreative.com", "role": "vaultdrive-editor"}'

  # Account manager — reads files for client meetings, can't edit
  curl -X POST "$AUTH_URL/organizations/$SPARK_ORG_ID/invite" \
    -H "Authorization: Bearer $JORDAN_TOKEN" \
    -d '{"email": "ben@sparkcreative.com", "role": "vaultdrive-viewer"}'

  ---
  Step 5: Sub-Orgs — Isolating the Nike Project

  Situation: Spark wins a Nike campaign. The contract has an NDA — the Adidas team at Spark cannot see Nike files. Jordan needs hard walls between client projects.

  Concept: Teams vs Sub-Orgs
  - Teams are soft grouping. Everyone in the parent org can still technically be given access. Good for internal organisation.
  - Sub-orgs are hard walls. A person in the Nike sub-org cannot see the Adidas sub-org even if an admin tries to grant it accidentally. The isolation is structural.

  Use a sub-org whenever a customer says "compliance," "NDA," "separate billing," or "isolated." Use a team when they say "group these people."

  5a: Jordan creates the Nike project sub-org

  NIKE=$(curl -s -X POST "$AUTH_URL/organizations/" \
    -H "Authorization: Bearer $JORDAN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Spark — Nike Campaign",
      "slug": "spark-nike",
      "parent_id": "'"$SPARK_ORG_ID"'",
      "billing_type": "enterprise",
      "settings": {"type": "project", "hierarchical": false},
      "metadata": {"client": "Nike", "nda": true, "project_code": "NK-2026-Q1"}
    }')
  NIKE_ORG_ID=$(echo "$NIKE" | jq -r '.id')

  What just happened: A child org was created inside Spark Creative. Jordan (in the parent) has ancestor access — she can see into it. Leo and Anais (in the parent Spark org) cannot see inside unless they are explicitly added to the Nike sub-org.

  Concept: Ancestor Access
  Parent org members with admin role can look into child orgs. Child org members cannot look up into the parent or sideways into sibling orgs. The information flows one way: down.

  Jordan sees:    Spark Creative (parent) + Spark Nike (child)
  Leo sees:       Spark Creative only (he is not in the Nike sub-org)
  Nike sub-org member sees: Nike sub-org only (cannot see parent or Adidas)

  5b: Add the Nike team to the sub-org

  # Leo is on the Nike campaign — move him in
  curl -X POST "$AUTH_URL/organizations/$NIKE_ORG_ID/invite" \
    -H "Authorization: Bearer $JORDAN_TOKEN" \
    -d '{
      "email": "leo@sparkcreative.com",
      "role": "vaultdrive-editor",
      "message": "You are on the Nike campaign. Files here are NDA."
    }'

  # Invite the Nike-side reviewer (external — a Nike employee who reviews proofs)
  curl -X POST "$AUTH_URL/organizations/$NIKE_ORG_ID/invite" \
    -H "Authorization: Bearer $JORDAN_TOKEN" \
    -d '{
      "email": "creative-review@nike.com",
      "role": "vaultdrive-viewer",
      "message": "Welcome to the Spark x Nike proof review portal"
    }'

  What the structure looks like now:

  Spark Creative (parent org)
  ├── Jordan (owner) ← sees everything via ancestor access
  ├── Leo (editor)   ← also in Nike sub-org
  ├── Anais (editor) ← NOT in Nike sub-org, cannot see Nike files
  ├── Ben (viewer)   ← NOT in Nike sub-org
  │
  └── [SUB-ORG] Spark — Nike Campaign
      ├── Jordan (ancestor access — reads from parent)
      ├── Leo (editor — full upload/share on Nike files)
      └── Nike Reviewer (viewer — reads proofs, cannot edit)

  5c: Move a user between orgs

  Situation: Anais finishes the Adidas project and is reassigned to Nike. She needs to move.

  Moving a user means: remove from old org (or sub-org), invite to new one. Permissions update instantly.

  # Remove Anais from Adidas sub-org (she is done there)
  curl -X DELETE "$AUTH_URL/organizations/$ADIDAS_ORG_ID/members/$ANAIS_USER_ID" \
    -H "Authorization: Bearer $JORDAN_TOKEN"

  # Invite her to the Nike sub-org
  curl -X POST "$AUTH_URL/organizations/$NIKE_ORG_ID/invite" \
    -H "Authorization: Bearer $JORDAN_TOKEN" \
    -d '{
      "email": "anais@sparkcreative.com",
      "role": "vaultdrive-editor"
    }'

  What just happened: The moment Anais is removed from the Adidas sub-org, her token (on next validation) no longer grants access to Adidas files. She cannot read, download, or list anything there. She is now in Nike — full editor access there. No "forgot to revoke" — removal is immediate and total.

  Concept: Instant Revocation
  When using permission_check_mode: "server", the auth library validates permissions on every request against the live auth service. Remove a user from an org and they lose access on their very next API call — before their token expires. There is no grace period, no caching lag.

  If you use permission_check_mode: "token" (for high-throughput apps), revocation takes effect when the token expires (up to 15 minutes). Most apps use "server" for safety until they need the performance optimisation.

  ---
  Step 6: OAuth 2.1 — No Passwords for Your Customers

  You want your customers to sign in with Google or GitHub. No VaultDrive passwords. No password reset flows to build. No password breach risk.

  6a: Configure Spark's login page — OAuth 2.1 only

  curl -X PUT "$AUTH_URL/organizations/$SPARK_ORG_ID/login-config" \
    -H "Authorization: Bearer $JORDAN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "branding": {
        "primary_color": "#F97316",
        "page_title": "Spark Creative — VaultDrive",
        "logo_url": "https://sparkcreative.com/logo.png",
        "login_template": "dark"
      },
      "content": {
        "welcome_message": "Spark Creative Files",
        "signup_message": "Use your work Google or GitHub account"
      },
      "auth_methods": {
        "email_password": false,
        "signup_enabled": true,
        "invitation_only": false
      },
      "registration": {
        "default_role": "end_user"
      }
    }'

  Notice email_password: false. The login page renders no email/password form at all. Users must use a social provider. If they try to call the org-scoped login endpoint directly with a password, they get 403 — email/password is disabled for this org.

  6b: Configure Google and GitHub providers

  # Google — for @sparkcreative.com GSuite accounts
  curl -X POST "$AUTH_URL/providers/" \
    -H "Authorization: Bearer $JORDAN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "org_id": "'$SPARK_ORG_ID'",
      "provider_type": "google",
      "name": "Continue with Google",
      "config": {
        "client_id": "GOOGLE_CLIENT_ID.apps.googleusercontent.com",
        "client_secret": "GOOGLE_SECRET",
        "hd": "sparkcreative.com"
      },
      "priority": 1
    }'

  # GitHub — for developers who connect external repos
  curl -X POST "$AUTH_URL/providers/" \
    -H "Authorization: Bearer $JORDAN_TOKEN" \
    -d '{
      "org_id": "'$SPARK_ORG_ID'",
      "provider_type": "github",
      "name": "Continue with GitHub",
      "config": {"client_id": "GH_CLIENT_ID", "client_secret": "GH_SECRET"},
      "priority": 2
    }'

  Concept: hd (Hosted Domain) Restriction
  The hd field on Google restricts sign-in to accounts in the sparkcreative.com Google Workspace. If someone tries to log in with their personal gmail.com account, Google rejects it before they even land on your app. This is how you enforce "only Spark employees can join Spark's org" without invitation lists.

  6c: Register an OAuth 2.1 client for Spark's web app

  CLIENT=$(curl -s -X POST "$AUTH_URL/auth/oauth/register" \
    -H "Authorization: Bearer $JORDAN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "client_name": "Spark Creative Web App",
      "redirect_uris": ["https://app.vaultdrive.io/callback"],
      "response_types": ["code"],
      "grant_types": ["authorization_code", "refresh_token"],
      "token_endpoint_auth_method": "none"
    }')
  CLIENT_ID=$(echo "$CLIENT" | jq -r '.client_id')

  6d: The complete OAuth 2.1 login flow

  Here is what happens when Leo clicks "Sign In" in VaultDrive:

  Step 1 — Your app generates PKCE:
  code_verifier  = random 64-byte string (base64url encoded)
  code_challenge = SHA-256(code_verifier), base64url encoded
  state          = random 16-byte CSRF token

  Step 2 — Redirect Leo to the hosted login page:
  https://auth.service.ab0t.com/login/spark-creative
    ?client_id=CLIENT_ID
    &redirect_uri=https://app.vaultdrive.io/callback
    &response_type=code
    &code_challenge=HASH
    &code_challenge_method=S256
    &state=CSRF_TOKEN

  Step 3 — Leo sees Spark's branded page (orange, dark, Spark logo):
  Only two buttons: "Continue with Google" and "Continue with GitHub"
  No email/password form (email_password: false)

  Step 4 — Leo clicks "Continue with Google":
  -> Auth service redirects to Google with its own OAuth flow
  -> Google authenticates Leo (password, MFA — all Google's problem)
  -> Google verifies @sparkcreative.com domain (hd restriction)
  -> Google returns to auth service with Leo's profile
  -> Auth service creates Leo's VaultDrive session
  -> Auth service generates a one-time authorization code (expires in 60 seconds)
  -> Auth service redirects to:
     https://app.vaultdrive.io/callback?code=ONE_TIME_CODE&state=CSRF_TOKEN

  Step 5 — Your app's callback handler:
  1. Verify state matches what you sent (CSRF protection)
  2. Exchange code for tokens:

  curl -X POST "$AUTH_URL/organizations/spark-creative/auth/token" \
    -H "Content-Type: application/json" \
    -d '{
      "grant_type": "authorization_code",
      "code": "ONE_TIME_CODE",
      "client_id": "CLIENT_ID",
      "code_verifier": "ORIGINAL_64_BYTE_VERIFIER",
      "redirect_uri": "https://app.vaultdrive.io/callback"
    }'

  Returns:
  {
    "access_token": "eyJ...",      // 15 minutes, send as Authorization: Bearer
    "refresh_token": "rt_...",     // 30 days, single-use, rotates on refresh
    "token_type": "bearer",
    "expires_in": 900
  }

  Concept: Why PKCE Is Mandatory in OAuth 2.1
  Without PKCE, anyone who intercepts the authorization code (browser history, server logs, a malicious redirect) can exchange it for tokens. With PKCE, the code is useless without the code_verifier that only your app generated. The auth service verifies: SHA-256(code_verifier) == code_challenge_you_sent. If they do not match, the exchange is rejected. The code_verifier never travels over a network during the login redirect — only the hash does.

  Concept: Refresh Token Rotation (OAuth 2.1)
  Every time you use a refresh token, it is invalidated and a new one is issued. If a refresh token is stolen and used by an attacker, the next time your real app tries to refresh, it fails (token already used). The auth service detects this and revokes the entire session. The user has to log in again — a mild inconvenience that catches token theft.

  Step 6 — Refresh when the access token expires:

  NEW_TOKENS=$(curl -s -X POST "$AUTH_URL/organizations/spark-creative/auth/refresh" \
    -H "Content-Type: application/json" \
    -d '{"refresh_token": "rt_..."}')

  NEW_ACCESS_TOKEN=$(echo "$NEW_TOKENS" | jq -r '.access_token')
  NEW_REFRESH_TOKEN=$(echo "$NEW_TOKENS" | jq -r '.refresh_token')  # Store this, old one is dead

  ---
  Step 7: Service Accounts — Background Workers

  VaultDrive runs background jobs: a virus scanner checks every uploaded file, a thumbnail generator creates previews, a sync worker replicates files to cold storage.

  These jobs need to access files. But they are not humans. They do not log in with Google. They need machine identities.

  Concept: Service Account
  A service account is an identity for a program, not a person. It has an email-style identifier, an API key (instead of a password), and permissions granted like any other user. The key difference: service accounts never do OAuth flows. They authenticate with a long-lived API key sent as X-API-Key: header.

  You grant service accounts exactly the permissions they need — nothing more. A virus scanner needs to read files. It does not need to delete, share, or manage members. If the scanner is compromised, the attacker can read files but cannot delete them or exfiltrate member lists.

  7a: Create the virus scanner service account

  # Create under VaultDrive Service org (not the customer org — this is a platform worker)
  curl -X POST "$AUTH_URL/admin/users/create-service-account" \
    -H "Authorization: Bearer $MAYA_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "virus-scanner@workers.vaultdrive.io",
      "name": "VaultDrive Virus Scanner",
      "description": "Scans uploaded files for malware using ClamAV",
      "org_id": "'"$SERVICE_ORG_ID"'",
      "permissions": [
        "vaultdrive.read.files",
        "vaultdrive.write.files"
      ],
      "metadata": {
        "worker_type": "virus_scanner",
        "created_by": "priya@vaultdrive.io",
        "version": "1.0"
      }
    }'

  Save the response:

  SCANNER_USER_ID="svc_abc123"
  SCANNER_API_KEY="ab0t_sk_live_scanner_..."

  7b: Create the thumbnail generator

  curl -X POST "$AUTH_URL/admin/users/create-service-account" \
    -H "Authorization: Bearer $MAYA_TOKEN" \
    -d '{
      "email": "thumbnailer@workers.vaultdrive.io",
      "name": "VaultDrive Thumbnail Generator",
      "description": "Creates image and PDF previews",
      "org_id": "'"$SERVICE_ORG_ID"'",
      "permissions": [
        "vaultdrive.read.files",
        "vaultdrive.write.files"
      ],
      "metadata": {"worker_type": "thumbnailer"}
    }'

  THUMBNAILER_API_KEY="ab0t_sk_live_thumb_..."

  7c: Use the service account in your worker code

  # Your virus scanner Docker container runs this
  import httpx

  SCANNER_API_KEY = os.environ["SCANNER_API_KEY"]  # injected via Kubernetes secret

  async def scan_uploaded_file(file_id: str, org_id: str):
      # Authenticate as the scanner service account
      headers = {"X-API-Key": SCANNER_API_KEY}

      # Fetch the file
      file_response = await httpx.get(
          f"{AUTH_URL}/files/{file_id}",
          headers=headers
      )

      # Run the scan
      result = await clam_av.scan(file_response.content)

      # Update file metadata (scanner has vaultdrive.write.files)
      await httpx.patch(
          f"{VAULTDRIVE_API}/files/{file_id}/scan-result",
          headers=headers,
          json={"clean": result.clean, "scanned_at": datetime.utcnow().isoformat()}
      )

  What just happened: The scanner authenticates with a static API key (no OAuth, no token refresh). The API key is long-lived but scope-limited — read files, write files, nothing else. If someone leaks the scanner's API key, they cannot delete files, cannot manage users, cannot see billing. Least privilege in practice.

  Concept: API Keys vs Tokens
  - API keys: Long-lived, static, for machine-to-machine. Sent as X-API-Key: header. Created in an org, scoped to that org's permissions. Revoke by deleting the key.
  - Tokens: Short-lived (15 min), for user sessions. Sent as Authorization: Bearer. Created by logging in or refreshing. Revoke by invalidating the session.

  Service accounts use API keys. Users use tokens. Never swap them.

  7d: Rotate service account API keys (good practice)

  # Create a new key for the scanner
  NEW_KEY=$(curl -s -X POST "$AUTH_URL/api-keys/" \
    -H "Authorization: Bearer $MAYA_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "virus-scanner-v2",
      "user_id": "'"$SCANNER_USER_ID"'",
      "org_id": "'"$SERVICE_ORG_ID"'",
      "permissions": ["vaultdrive.read.files", "vaultdrive.write.files"]
    }')
  NEW_SCANNER_KEY=$(echo "$NEW_KEY" | jq -r '.key')

  # Deploy new key to Kubernetes secret, confirm workers are using it
  # Then revoke the old key
  curl -X DELETE "$AUTH_URL/api-keys/$OLD_KEY_ID" \
    -H "Authorization: Bearer $MAYA_TOKEN"

  Rotate keys every 90 days or whenever someone who had access leaves the company.

  ---
  Step 8: Delegation Tokens — Worker Acting as a User

  Here is the problem: VaultDrive has a "Smart Sync" worker that syncs files to a user's local machine. The sync worker needs to access files on behalf of Leo specifically — not as a generic platform worker. Why? Because Leo might have files in Spark Creative that he can access but the platform worker cannot (e.g., a file shared specifically with Leo's user_id, not with the whole org).

  You need the sync worker to act as Leo, with Leo's permissions, but controlled by your backend — not by Leo's browser session.

  Concept: Delegation Token
  A delegation token is a short-lived token that says "this service account is acting on behalf of this user." The service account must have the vaultdrive.delegate permission. The resulting token has the user's identity but is controlled programmatically.

  This is different from the service account's own API key: the API key says "I am the scanner." The delegation token says "I am the scanner, acting as Leo."

  8a: Grant the sync worker delegation permission

  # The sync worker needs permission to act on behalf of users
  # NOTE: permissions/grant takes query parameters, not a JSON body
  curl -X POST "$AUTH_URL/permissions/grant?user_id=$SYNC_WORKER_USER_ID&org_id=$SERVICE_ORG_ID&permission=vaultdrive.delegate" \
    -H "Authorization: Bearer $MAYA_TOKEN"

  8b: The sync worker requests a delegation token for Leo

  When Leo connects his desktop client, he authorises the sync worker to act on his behalf.
  POST /auth/delegate creates a JWT where the caller acts AS the target user.
  NOTE: Only accepts {"target_user_id"} — permission scoping is application-layer.

  # Your sync worker backend calls this
  DELEGATION=$(curl -s -X POST "$AUTH_URL/auth/delegate" \
    -H "X-API-Key: $SYNC_WORKER_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{
      "target_user_id": "'"$LEO_USER_ID"'"
    }')
  DELEGATION_TOKEN=$(echo "$DELEGATION" | jq -r '.access_token')
  # The token is a JWT acting as Leo — your application enforces which files it can access.

  What the delegation token contains:
  {
    "sub": "leo-user-id",            // the user's identity
    "org_id": "spark-creative-uuid", // Leo's org
    "delegated_by": "sync-worker-svc-id",  // who created this token
    "permissions": ["vaultdrive.read.files", "vaultdrive.download.files"],
    "exp": 1740000000                // 1 hour from now
  }

  8c: The sync worker uses the delegation token

  # Worker calls VaultDrive API as Leo (not as itself)
  async def sync_user_files(leo_delegation_token: str, local_path: str):
      headers = {"Authorization": f"Bearer {leo_delegation_token}"}

      # This call runs as Leo — gets only files Leo can see
      files = await httpx.get(
          f"{VAULTDRIVE_API}/organizations/spark-creative/files",
          headers=headers
      )

      for file in files.json():
          await sync_to_local(file, local_path)

  What VaultDrive's route sees:

  @router.get("/organizations/{org_slug}/files")
  async def list_user_files(org_slug: str, user: FileViewer):
      # user.user_id  = "leo-user-id"      ← Leo's identity, not the worker's
      # user.org_id   = "spark-creative"   ← Leo's org
      # user.delegated_by = "sync-worker"  ← can audit who created this token
      return await db.list_files(user_id=user.user_id, org_id=user.org_id)

  The route does not need to know or care that a worker is making the call. It sees Leo's identity and Leo's permissions. It returns Leo's files.

  Concept: Why Not Just Give the Worker Leo's Token?
  Three reasons:
  1. Leo's token expires every 15 minutes. You would need Leo's refresh token to keep syncing. Storing refresh tokens in a background worker is a security nightmare.
  2. Leo's token has ALL of Leo's permissions (write, delete, share). The delegation token has only what you specify (read, download). Least privilege.
  3. Audit trail. The delegation token records delegated_by: sync-worker. Every file access shows "Leo's sync worker downloaded this file." Not just "Leo did something."

  ---
  Step 9: API Keys for Third-Party Integrations

  VaultDrive wants to let third-party desktop apps, Figma plugins, and Zapier integrations access files on behalf of users.

  Concept: These integrations are not your backend workers. They are external code you do not control. You cannot give them a service account API key (too powerful, cannot revoke per user). You need per-user, scope-limited API keys that users can create and revoke themselves.

  9a: A user creates an API key for a Figma plugin

  Leo wants to install the VaultDrive Figma plugin. He goes to VaultDrive settings and generates an API key:

  # Leo (authenticated in VaultDrive) creates a personal API key
  KEY=$(curl -s -X POST "$AUTH_URL/api-keys/" \
    -H "Authorization: Bearer $LEO_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Figma Plugin — Leo",
      "org_id": "'"$SPARK_ORG_ID"'",
      "permissions": [
        "vaultdrive.read.files",
        "vaultdrive.read.folders",
        "vaultdrive.download.files"
      ],
      "expires_at": "2027-01-01T00:00:00Z",
      "metadata": {"integration": "figma", "created_from": "settings_page"}
    }')
  FIGMA_API_KEY=$(echo "$KEY" | jq -r '.key')

  Leo pastes this key into the Figma plugin settings. The plugin uses it:

  # Figma plugin code
  headers = {"X-API-Key": FIGMA_API_KEY}
  response = requests.get(f"{VAULTDRIVE_API}/files", headers=headers)

  What VaultDrive sees: a request from Leo's identity, scoped to read/download only, in Spark Creative's org. The plugin cannot write, delete, share, or see other members. If Leo leaves Spark Creative, his key stops working (it was scoped to his org membership).

  9b: Difference between an OAuth flow and an API key for third parties

  The right choice depends on the integration:

  ┌─────────────────────────┬───────────────────────────────────────┬─────────────────────────────────────────────────────────┐
  │      Integration        │           Use OAuth 2.1               │              Use API Key                                │
  ├─────────────────────────┼───────────────────────────────────────┼─────────────────────────────────────────────────────────┤
  │ Web app (Figma, Notion) │ Yes — user clicks "Connect VaultDrive"│ No — OAuth is smoother for web apps                     │
  ├─────────────────────────┼───────────────────────────────────────┼─────────────────────────────────────────────────────────┤
  │ CLI tool                │ Possible but annoying (browser pops up│ Yes — developer pastes key in ~/.config/vaultdrive       │
  ├─────────────────────────┼───────────────────────────────────────┼─────────────────────────────────────────────────────────┤
  │ Zapier / webhook        │ No — no browser session available     │ Yes — paste key in Zapier's settings field               │
  ├─────────────────────────┼───────────────────────────────────────┼─────────────────────────────────────────────────────────┤
  │ Mobile SDK              │ Yes — PKCE works great on mobile      │ No — storing API keys in mobile apps is unsafe           │
  ├─────────────────────────┼───────────────────────────────────────┼─────────────────────────────────────────────────────────┤
  │ Server-to-server        │ No — no user involved                 │ Yes — service account key                               │
  └─────────────────────────┴───────────────────────────────────────┴─────────────────────────────────────────────────────────┘

  For the VaultDrive mobile app, you use OAuth 2.1 with PKCE — same flow as the web app, just with a custom URI scheme as redirect:

  redirect_uri: "vaultdrive://callback"

  The mobile OS intercepts this URL, passes the code to your app, and you exchange it for tokens. Tokens are stored in the device keychain (never plain text).

  ---
  The Full Picture — Planning for Scale

  Auth Service
  │
  ├── VaultDrive Inc (3 founders)
  │   ├── Maya (owner), Priya (admin), Tom (member)
  │   └── No hosted login — founders use internal email/password
  │
  ├── VaultDrive Service (the rulebook)
  │   ├── Permissions: vaultdrive.read.files, vaultdrive.create.files, ...
  │   ├── Roles: vaultdrive-viewer, vaultdrive-editor, vaultdrive-admin
  │   │
  │   ├── [Service Account] virus-scanner
  │   │   Key: ab0t_sk_live_scanner_...
  │   │   Perms: read.files, write.files (scan results only)
  │   │
  │   ├── [Service Account] thumbnailer
  │   │   Key: ab0t_sk_live_thumb_...
  │   │   Perms: read.files, write.files (preview writes only)
  │   │
  │   └── [Service Account] sync-worker
  │       Key: ab0t_sk_live_sync_...
  │       Perms: read.files, download.files, vaultdrive.delegate
  │
  ├── Spark Creative (customer)
  │   ├── Login: /login/spark-creative
  │   │   Providers: Google (hd:sparkcreative.com), GitHub
  │   │   Auth: OAuth 2.1 only (no email/password)
  │   │   OAuth client: spark_web_app (scoped to this org)
  │   │
  │   ├── Jordan (owner), Leo (editor), Anais (editor), Ben (viewer)
  │   │   Leo's API key: figma-plugin (read + download only)
  │   │
  │   └── [SUB-ORG] Spark — Nike Campaign
  │       ├── Jordan (ancestor access)
  │       ├── Leo (editor — NDA project)
  │       └── Nike Reviewer (viewer — external, review only)
  │
  └── ... thousands more customers at scale
      ├── Small studios: flat org, GitHub login, no sub-orgs
      ├── Agencies: parent org + sub-org per client, Google + GitHub
      └── Enterprises: SAML SSO + sub-orgs per department + API key integrations

  What scales automatically:
  - New customers get their own isolated org — no config changes in your app
  - Sub-orgs are created by customers, not by you — Spark creates as many as they need
  - Service accounts are in the service org — they do not multiply with customers
  - Delegation tokens are generated on demand — one sync worker serves all users
  - API keys are created by users — you do not manage them per integration

  What you never build:
  - Password reset flow (Google handles it)
  - MFA (Google/GitHub handle it)
  - Session management UI (tokens handle it)
  - Permission assignment per customer (the role system handles it)
  - Org isolation logic (the auth library handles it)

  Three founders. Regulated industries. Thousands of customers. The auth service scales with you — each new customer is a new org, each org is isolated, each org configures its own login experience. Your code stays the same.
