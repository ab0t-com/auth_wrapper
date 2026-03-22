#!/bin/bash
#
# register-service-permissions.sh
# ================================
# Registers the service with the Auth Service.
# Loads all permissions dynamically from .permissions.json
#
# IDEMPOTENT: Safe to run multiple times
#   - Step 1: Uses existing credentials OR creates admin account
#   - Step 2: Creates organization, or finds existing one
#   - Step 3: Logs in with org context (always succeeds if steps 1-2 passed)
#   - Step 4: Re-registers permissions (updates existing, no duplicates)
#   - Step 5: Creates new API key (old keys remain valid)
#   - Step 6: Registers with proxy controller (create_only flag prevents duplicates)
#
# SAFE: No destructive operations
#   - Does NOT delete any accounts, orgs, or permissions
#   - Does NOT revoke existing API keys
#   - Credentials file is overwritten with latest values
#
# USAGE:
#   ./register-service-permissions.sh
#   AUTH_SERVICE_URL=http://localhost:8001 ./register-service-permissions.sh
#
# REQUIRES: jq, curl
# READS: .permissions.json (service info + permissions to register)
# READS: ./credentials/{service-id}.json (if exists, for existing account)
# WRITES: ./credentials/{service-id}.json
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERMISSIONS_FILE="$SCRIPT_DIR/.permissions.json"

# Check permissions file exists
if [ ! -f "$PERMISSIONS_FILE" ]; then
    echo "ERROR: .permissions.json not found at $PERMISSIONS_FILE"
    exit 1
fi

# Configuration
AUTH_SERVICE_URL="${AUTH_SERVICE_URL:-https://auth.service.ab0t.com}"
SERVICE_PORT="${SERVICE_PORT:-8007}"  # Default to resource-service port

# Load service info from .permissions.json
SERVICE_ID=$(jq -r '.service.id' "$PERMISSIONS_FILE")
SERVICE_NAME=$(jq -r '.service.name' "$PERMISSIONS_FILE")
SERVICE_DESC=$(jq -r '.service.description' "$PERMISSIONS_FILE")
SERVICE_AUDIENCE=$(jq -r '.service.audience' "$PERMISSIONS_FILE")

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${MAGENTA}=== $SERVICE_NAME Registration ===${NC}"
echo "Service ID: $SERVICE_ID"
echo "Description: $SERVICE_DESC"
echo "Loading permissions from: $PERMISSIONS_FILE"
echo ""

# Create credentials directory
mkdir -p "$SCRIPT_DIR/credentials"

# Check for existing credentials
CREDS_FILE="$SCRIPT_DIR/credentials/${SERVICE_ID}.json"
if [ -f "$CREDS_FILE" ]; then
    echo -e "${CYAN}Found existing credentials at $CREDS_FILE${NC}"
    ADMIN_EMAIL=$(jq -r '.admin.email' "$CREDS_FILE")
    ADMIN_PASSWORD=$(jq -r '.admin.password' "$CREDS_FILE")
    EXISTING_ORG_ID=$(jq -r '.organization.id' "$CREDS_FILE")
    EXISTING_API_KEY=$(jq -r '.api_key.key' "$CREDS_FILE")
    EXISTING_USER_ID=$(jq -r '.admin.user_id' "$CREDS_FILE")
    echo "  Using admin: $ADMIN_EMAIL"
    echo "  Existing org: $EXISTING_ORG_ID"
    echo "  Existing API key: ${EXISTING_API_KEY:+yes (will keep)}"
    echo ""
fi

# Step 1: Create Service Admin Account
echo -e "${BLUE}Step 1: Setting up Admin Account${NC}"

# Use existing credentials or derive from service ID
if [ -z "$ADMIN_EMAIL" ]; then
    # Derive admin email from service ID: resource-service -> mike+resource-service@ab0t.com
    ADMIN_EMAIL="mike+${SERVICE_ID}@ab0t.com"
    # Derive password from service name: Resource Service -> ResourceServiceAdmin2024!Secure
    SERVICE_NAME_NO_SPACES=$(echo "$SERVICE_NAME" | tr -d ' ')
    ADMIN_PASSWORD="${SERVICE_NAME_NO_SPACES}Admin2024!Secure"
    echo "  Derived admin: $ADMIN_EMAIL"
fi

REGISTER_RESPONSE=$(curl -s -X POST "$AUTH_SERVICE_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d '{
        "email": "'"$ADMIN_EMAIL"'",
        "password": "'"$ADMIN_PASSWORD"'",
        "name": "'"$SERVICE_NAME"' Admin"
    }' 2>&1)

if echo "$REGISTER_RESPONSE" | grep -q "access_token"; then
    echo -e "${GREEN}✓ Admin account created${NC}"
    ACCESS_TOKEN=$(echo "$REGISTER_RESPONSE" | jq -r '.access_token')
    REFRESH_TOKEN=$(echo "$REGISTER_RESPONSE" | jq -r '.refresh_token')
    USER_ID=$(echo "$REGISTER_RESPONSE" | jq -r '.user.id // .user_info.id // .user_id // empty')
else
    echo -e "${YELLOW}⚠ Admin may already exist, logging in...${NC}"

    LOGIN_RESPONSE=$(curl -s -X POST "$AUTH_SERVICE_URL/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"email\": \"$ADMIN_EMAIL\", \"password\": \"$ADMIN_PASSWORD\"}" 2>&1)

    if echo "$LOGIN_RESPONSE" | grep -q "access_token"; then
        echo -e "${GREEN}✓ Login successful${NC}"
        ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token')
        REFRESH_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.refresh_token')
        USER_ID=$(echo "$LOGIN_RESPONSE" | jq -r '.user.id // .user_info.id // .user_id // empty')
    else
        echo -e "${RED}✗ Login failed${NC}"
        echo "Registration response: $REGISTER_RESPONSE"
        echo "Login response: $LOGIN_RESPONSE"
        exit 1
    fi
fi

echo ""

# Step 2: Create Service Organization
echo -e "${BLUE}Step 2: Finding/Creating $SERVICE_NAME Organization${NC}"

# Use existing org ID if we have it from credentials
if [ -n "$EXISTING_ORG_ID" ] && [ "$EXISTING_ORG_ID" != "null" ]; then
    echo -e "${GREEN}✓ Using existing organization from credentials${NC}"
    ORG_ID="$EXISTING_ORG_ID"
else
    CREATE_ORG_RESPONSE=$(curl -s -X POST "$AUTH_SERVICE_URL/organizations/" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "'"$SERVICE_NAME"'",
            "slug": "'"$SERVICE_ID"'",
            "service_audience": "'"$SERVICE_AUDIENCE"'",
            "domain": "'"$SERVICE_ID"'.service.ab0t.com",
            "billing_type": "enterprise",
            "settings": {
                "type": "platform_service",
                "service": "'"$SERVICE_ID"'",
                "hierarchical": false,
                "internal_service": false
            },
            "metadata": {
                "description": "'"$SERVICE_DESC"'",
                "service_type": "resource_management",
                "data_classification": "standard"
            }
        }' 2>&1)

    if echo "$CREATE_ORG_RESPONSE" | grep -q '"id"'; then
        echo -e "${GREEN}✓ Organization created${NC}"
        ORG_ID=$(echo "$CREATE_ORG_RESPONSE" | jq -r '.id')
    else
        echo -e "${YELLOW}⚠ Organization may already exist${NC}"
        USER_ORGS=$(curl -s -X GET "$AUTH_SERVICE_URL/users/me/organizations" \
            -H "Authorization: Bearer $ACCESS_TOKEN")
        ORG_ID=$(echo "$USER_ORGS" | jq -r '.[] | select(.name=="'"$SERVICE_NAME"'") | .id' 2>/dev/null || echo "")

        if [ -z "$ORG_ID" ] || [ "$ORG_ID" == "null" ]; then
            echo -e "${RED}✗ Could not find organization${NC}"
            exit 1
        fi
    fi
fi

echo "Organization ID: $ORG_ID"
echo ""

# Step 3: Login with org context
echo -e "${BLUE}Step 3: Logging in with Organization Context${NC}"

ORG_LOGIN=$(curl -s -X POST "$AUTH_SERVICE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"$ADMIN_EMAIL\", \"password\": \"$ADMIN_PASSWORD\", \"org_id\": \"$ORG_ID\"}")

ORG_TOKEN=$(echo "$ORG_LOGIN" | jq -r '.access_token')

if [ -z "$ORG_TOKEN" ] || [ "$ORG_TOKEN" == "null" ]; then
    echo -e "${RED}✗ Failed to login with org context${NC}"
    echo "Response: $ORG_LOGIN"
    exit 1
fi

echo -e "${GREEN}✓ Logged in as organization owner${NC}"
echo ""

# Step 4: Register Permissions from .permissions.json
echo -e "${BLUE}Step 4: Registering Permissions from .permissions.json${NC}"

# Extract registration block from .permissions.json (v2 schema)
# Format: { "service": "resource", "actions": [...], "resources": [...] }
REG_SERVICE=$(jq -r '.registration.service // .service.id' "$PERMISSIONS_FILE")
REG_ACTIONS=$(jq -c '.registration.actions // []' "$PERMISSIONS_FILE")
REG_RESOURCES=$(jq -c '.registration.resources // []' "$PERMISSIONS_FILE")

if [ -z "$REG_SERVICE" ] || [ "$REG_SERVICE" = "null" ]; then
    echo -e "${RED}    ✗ No registration.service found in .permissions.json${NC}"
    echo "      Ensure .permissions.json has a 'registration' block with 'service', 'actions', 'resources'"
    exit 1
fi

echo -e "${CYAN}  Registering service '$REG_SERVICE'...${NC}"
echo "    Actions: $REG_ACTIONS"
echo "    Resources: $REG_RESOURCES"

# Single registration call with service, actions, and resources
PERM_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$AUTH_SERVICE_URL/permissions/registry/register" \
    -H "Authorization: Bearer $ORG_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "service": "'"$REG_SERVICE"'",
        "description": "'"$SERVICE_NAME"'",
        "actions": '"$REG_ACTIONS"',
        "resources": '"$REG_RESOURCES"'
    }')

HTTP_CODE=$(echo "$PERM_RESPONSE" | grep "HTTP_CODE" | cut -d: -f2)
RESPONSE_BODY=$(echo "$PERM_RESPONSE" | grep -v "HTTP_CODE")

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
    echo -e "${GREEN}    ✓ Service '$REG_SERVICE' registered${NC}"
    echo "    Generated permissions: $REG_SERVICE.{action}.{resource}"
elif [ "$HTTP_CODE" = "500" ]; then
    echo -e "${RED}    ✗ Registration failed (HTTP 500)${NC}"
    echo "      $RESPONSE_BODY"
else
    echo -e "${YELLOW}    ⚠ Unexpected response: HTTP $HTTP_CODE${NC}"
    echo "      $RESPONSE_BODY"
fi

echo ""

# Step 4b: Grant Admin User Implied Permissions
# If resource.admin has "implies", grant all those permissions to the admin user
echo -e "${BLUE}Step 4b: Granting Admin Implied Permissions${NC}"

# Get user_id from token if not already set
if [ -z "$USER_ID" ] || [ "$USER_ID" = "null" ]; then
    USER_ID=$(echo "$ORG_TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq -r '.sub // empty')
fi

if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
    # Find permissions with "implies" and grant them + their implied permissions
    ADMIN_PERMS=$(jq -r '.permissions[] | select(.implies != null) | .id' "$PERMISSIONS_FILE")

    for ADMIN_PERM in $ADMIN_PERMS; do
        echo -e "${CYAN}  Processing $ADMIN_PERM...${NC}"

        # Grant the admin permission itself
        curl -s -X POST "$AUTH_SERVICE_URL/permissions/grant?user_id=$USER_ID&org_id=$ORG_ID&permission=$ADMIN_PERM" \
            -H "Authorization: Bearer $ORG_TOKEN" > /dev/null 2>&1
        echo "    ✓ Granted: $ADMIN_PERM"

        # Get all implied permissions and grant each one
        IMPLIED_PERMS=$(jq -r --arg perm "$ADMIN_PERM" '.permissions[] | select(.id == $perm) | .implies[]?' "$PERMISSIONS_FILE")

        for IMPLIED in $IMPLIED_PERMS; do
            GRANT_RESP=$(curl -s -X POST "$AUTH_SERVICE_URL/permissions/grant?user_id=$USER_ID&org_id=$ORG_ID&permission=$IMPLIED" \
                -H "Authorization: Bearer $ORG_TOKEN")

            if echo "$GRANT_RESP" | grep -qi "success\|granted\|message"; then
                echo "    ✓ Granted (implied): $IMPLIED"
            else
                echo "    • $IMPLIED (may already exist)"
            fi
        done
    done

    echo -e "${GREEN}✓ Admin permissions configured${NC}"
else
    echo -e "${YELLOW}⚠ Could not determine user_id, skipping admin permission grants${NC}"
fi

echo ""

# Step 5: Create Service API Key (skip if already exists)
echo -e "${BLUE}Step 5: Service API Key${NC}"

if [ -n "$EXISTING_API_KEY" ] && [ "$EXISTING_API_KEY" != "null" ]; then
    echo -e "${GREEN}✓ Using existing API key (not creating new one)${NC}"
    API_KEY="$EXISTING_API_KEY"
    API_KEY_ID=$(jq -r '.api_key.id' "$CREDS_FILE")
else
    echo "Creating new API key..."
    # Build permissions list from .permissions.json
    ALL_PERMISSIONS=$(jq -r '[.permissions[].id] | map(gsub(":"; ".")) | .[]' "$PERMISSIONS_FILE" | jq -R . | jq -s .)

    API_KEY_RESPONSE=$(curl -s -X POST "$AUTH_SERVICE_URL/api-keys/" \
        -H "Authorization: Bearer $ORG_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "'"$SERVICE_ID"'-internal",
            "permissions": '"$ALL_PERMISSIONS"',
            "rate_limit": 100000,
            "metadata": {
                "purpose": "Internal '"$SERVICE_NAME"' operations",
                "service_type": "'"$SERVICE_ID"'"
            }
        }' 2>&1)

    if echo "$API_KEY_RESPONSE" | grep -q '"key"'; then
        echo -e "${GREEN}✓ API key created${NC}"
        API_KEY=$(echo "$API_KEY_RESPONSE" | jq -r '.key')
        API_KEY_ID=$(echo "$API_KEY_RESPONSE" | jq -r '.id')
    else
        echo -e "${YELLOW}⚠ Could not create API key${NC}"
        echo "Response: $API_KEY_RESPONSE"
        API_KEY=""
        API_KEY_ID=""
    fi
fi

# Backup existing credentials before overwriting
if [ -f "$CREDS_FILE" ]; then
    BACKUP_FILE="$CREDS_FILE.bak.$(date +%Y%m%d_%H%M%S)"
    cp "$CREDS_FILE" "$BACKUP_FILE"
    echo -e "${CYAN}Backed up existing credentials to: $BACKUP_FILE${NC}"
fi

# Save credentials
cat > "$SCRIPT_DIR/credentials/$SERVICE_ID.json" <<EOF
{
    "service": "$SERVICE_ID",
    "organization": {
        "id": "$ORG_ID",
        "name": "$SERVICE_NAME",
        "slug": "$SERVICE_ID"
    },
    "admin": {
        "email": "$ADMIN_EMAIL",
        "password": "$ADMIN_PASSWORD",
        "user_id": "$USER_ID",
        "access_token": "$ACCESS_TOKEN",
        "refresh_token": "$REFRESH_TOKEN"
    },
    "api_key": {
        "id": "$API_KEY_ID",
        "key": "$API_KEY"
    },
    "permissions_source": ".permissions.json",
    "created_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF

echo -e "${GREEN}✓ Credentials saved to $SCRIPT_DIR/credentials/$SERVICE_ID.json${NC}"
echo ""

# Step 6: Register with Proxy Controller (DISABLED by default)
# This is for production routing to *.service.ab0t.com
# For dev environments, use *.dev.ab0t.com instead
# Enable with: REGISTER_PROXY=1 ./register-service-permissions.sh
if [ "${REGISTER_PROXY:-0}" != "1" ]; then
    echo -e "${BLUE}Step 6: Proxy Registration${NC}"
    echo -e "${YELLOW}⚠ Skipped (dev environment). Set REGISTER_PROXY=1 to enable.${NC}"
    echo ""
else
    echo -e "${BLUE}Step 6: Registering with Proxy Controller${NC}"

    PUBLIC_IP=$(curl -s http://checkip.amazonaws.com)

    if [ -z "$PUBLIC_IP" ]; then
        echo -e "${YELLOW}⚠ Could not determine public IP, using localhost${NC}"
        PUBLIC_IP="127.0.0.1"
    fi

    echo "Public IP: $PUBLIC_IP"

    PROXY_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "https://controller.proxy.ab0t.com/v1/service/services" \
        -H "Content-Type: application/json" \
        -d "{
            \"service_id\": \"$SERVICE_ID\",
            \"ip\": \"$PUBLIC_IP\",
            \"port\": $SERVICE_PORT,
            \"ttl_seconds\": 2592000,
            \"description\": \"$SERVICE_DESC\",
            \"weight\": 100,
            \"create_only\": true
        }")

    HTTP_CODE=$(echo "$PROXY_RESPONSE" | tail -n1)
    BODY=$(echo "$PROXY_RESPONSE" | sed '$d')

    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
        echo -e "${GREEN}✓ Successfully registered with proxy controller${NC}"
        echo "Service accessible at: https://$SERVICE_ID.service.ab0t.com"
    else
        echo -e "${YELLOW}⚠ Proxy registration may have failed${NC}"
        echo "HTTP Status: $HTTP_CODE"
        echo "Response: $BODY"
    fi

    echo ""
fi

# Summary
echo -e "${CYAN}=== $SERVICE_NAME Registration Complete ===${NC}"
echo ""
echo "Service Details:"
echo "  • Service ID: $SERVICE_ID"
echo "  • Organization ID: $ORG_ID"
echo "  • Admin Email: $ADMIN_EMAIL"
echo ""
echo "Permissions Registered (from .permissions.json):"
jq -r '.permissions[] | "  • \(.id) - \(.name)"' "$PERMISSIONS_FILE"
echo ""
echo "Roles Defined:"
jq -r '.roles[] | "  • \(.id) - \(.description)"' "$PERMISSIONS_FILE"
echo ""
echo "Access URLs:"
echo "  • Internal: http://$SERVICE_ID:$SERVICE_PORT"
echo "  • External: https://$SERVICE_ID.service.ab0t.com"
echo ""
echo "Credentials saved in:"
echo "  • $SCRIPT_DIR/credentials/$SERVICE_ID.json"
echo ""
echo -e "${GREEN}Next Steps:${NC}"
echo "1. Configure users with appropriate roles"
echo "2. Test auth flow with security tests"
echo "3. Deploy service to production"
