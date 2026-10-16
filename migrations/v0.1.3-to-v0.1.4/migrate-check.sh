#!/usr/bin/env bash
# migrate-check.sh — find the places in your service affected by ab0t-auth 0.1.3 -> 0.1.4.
#
# 0.1.4 has NO source-breaking change. It changes cache DEFAULTS (a security property: revocation latency):
#   - permission decisions (server mode): 30 s -> 15 s for allowed, 5 s for denied
#   - API-key validation: not cached -> 60 s for a valid key, 10 s for a rejected key
#   - unknown-kid JWKS refetch: at most once per 30 s -> once per 60 s
# So this checker looks for code/config that RELIES on the old 30 s permission TTL or on API keys being validated
# on every request, and prints, per finding: file:line, the rule, and the fix.
#
# Read-only: it NEVER edits your code. Only bash + grep + find.
#
# Two kinds of finding:
#   ACTION  likely relies on the old behaviour -> review and change (or mark reviewed). These set the exit code.
#   REVIEW  advisory: where the new defaults apply to you. Do not affect the exit code (unless --strict).
# Findings are CANDIDATES (textual matches): prefer a false positive to a missed site. When a finding needs no
# change, append a comment containing   ab0t-auth-0.1.4: reviewed   to that line and it is skipped next time.
#
# Usage:   ./migrate-check.sh [--strict] [path-to-your-repo]      (default path: current dir)
# Exit:    0 = no ACTION findings (CI-gateable), 1 = ACTION findings remain, 2 = usage error
# See MIGRATION.md (same directory) for the before -> after of every change and how to opt out.

set -u
set -o pipefail

STRICT=0
TARGET="."
for arg in "$@"; do
  case "$arg" in
    --strict) STRICT=1 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    -*) echo "unknown option: $arg" >&2; exit 2 ;;
    *) TARGET="$arg" ;;
  esac
done
if [ ! -d "$TARGET" ]; then echo "not a directory: $TARGET" >&2; exit 2; fi

if [ -t 1 ]; then
  GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
else
  GREEN=''; RED=''; YELLOW=''; CYAN=''; BOLD=''; NC=''
fi
REVIEWED_MARK='ab0t-auth-0.1.4: reviewed'
ACTION=0
REVIEW=0

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ---- file sets ------------------------------------------------------------------------------------------------
# Skip VCS/env/build dirs, a vendored copy of the library itself, and this kit.
list_files() {
  find "$TARGET" \( -name .git -o -name .venv -o -name venv -o -name env -o -name node_modules \
       -o -name site-packages -o -name __pycache__ -o -name dist -o -name build -o -name .tox -o -name .mypy_cache \) \
       -prune -o -type f \( "$@" \) -print 2>/dev/null \
    | grep -v '/ab0t_auth/' | grep -v '/migrations/v0.1.3-to-v0.1.4/' || true
}
# Python files that use the library (mention ab0t_auth).
list_files -name '*.py' | while IFS= read -r f; do
  grep -q 'ab0t_auth' "$f" 2>/dev/null && printf '%s\n' "$f"
done > "$TMP/sdk_py"
# Deployment / settings files.
list_files -name '*.env' -o -name '.env*' -o -name '*.yml' -o -name '*.yaml' -o -name '*.toml' -o -name '*.ini' \
  -o -name '*.cfg' -o -name 'Dockerfile*' -o -name '*.json' -o -name '*.tf' -o -name '*.sh' -o -name '*.service' \
  -o -name '*.template' > "$TMP/cfg"
# Python files that use the library AND talk about API-key validation (for the call-count rule).
while IFS= read -r f; do
  grep -qE 'validate[-_]api[-_]key' "$f" 2>/dev/null && printf '%s\n' "$f"
done < "$TMP/sdk_py" > "$TMP/apikey_py"

SDK_N="$(grep -c . "$TMP/sdk_py" || true)"
CFG_N="$(grep -c . "$TMP/cfg" || true)"
echo -e "${BOLD}ab0t-auth 0.1.3 -> 0.1.4 migration check${NC}"
echo    "target: $TARGET   python files using ab0t_auth: $SDK_N   config files: $CFG_N"
if [ "$SDK_N" -eq 0 ] && [ "$CFG_N" -eq 0 ]; then
  echo "nothing to check under $TARGET."; exit 0
fi

# check <ACTION|REVIEW> <rule-id> <label> <fix> <file-list> <extended-regex> [grep flags] [exclude-regex]
check() {
  local level="$1" id="$2" label="$3" fix="$4" list="$5" pat="$6" flags="${7:-}" exclude="${8:-}"
  local hits=""
  if [ -s "$list" ]; then
    # shellcheck disable=SC2086  # $flags is intentionally word-split (empty or e.g. -i)
    hits="$(while IFS= read -r f; do grep -nHE $flags -- "$pat" "$f" 2>/dev/null; done < "$list" \
            | grep -vF "$REVIEWED_MARK" || true)"
    if [ -n "$exclude" ] && [ -n "$hits" ]; then
      hits="$(printf '%s\n' "$hits" | grep -vE -- "$exclude" || true)"
    fi
  fi
  [ -n "$hits" ] || return 0
  local n; n="$(printf '%s\n' "$hits" | grep -c .)"
  if [ "$level" = "ACTION" ]; then
    ACTION=$((ACTION + n)); echo -e "\n${YELLOW}● ACTION [$id] ${label}${NC}  ($n)"
  else
    REVIEW=$((REVIEW + n)); echo -e "\n${CYAN}○ REVIEW [$id] ${label}${NC}  ($n)"
  fi
  echo -e "  ${BOLD}fix:${NC} ${fix}"
  printf '%s\n' "$hits" | sed 's/^/    /'
}

# ==== ACTION: relies on the old 30 s permission TTL ==============================================================
check ACTION perm-cache-default \
  "PermissionCache() built without ttl= (class default 30 s -> 15 s allowed / 5 s denied)" \
  "accept 15/5, or pin the old value explicitly: PermissionCache(ttl=30, negative_ttl=30). Prefer config: AB0T_AUTH_PERMISSION_CACHE_TTL / _NEGATIVE_TTL." \
  "$TMP/sdk_py" 'PermissionCache\(' '' '[^_a-z]ttl[[:space:]]*=|import|^[^:]*:[0-9]+:[[:space:]]*#'
check ACTION perm-ttl-30-literal \
  "code/tests that assume or pin a 30 s permission cache (a denied answer now lives 5 s unless negative_ttl is set)" \
  "update assumptions to 15 s (allowed) / 5 s (denied). An explicit PermissionCache(ttl=30) keeps 30 s for allowed only — add negative_ttl=30 for the old denial behaviour. Config: AB0T_AUTH_PERMISSION_CACHE_TTL=30 + AB0T_AUTH_PERMISSION_CACHE_NEGATIVE_TTL=30." \
  "$TMP/sdk_py" '(permission_cache|PermissionCache|perm(ission)?_ttl).*\b30\b|\b30\b.*(permission_cache|PermissionCache)'

# ==== ACTION: relies on API keys being validated on every request ================================================
check ACTION apikey-call-count \
  "tests/mocks that count or sequence auth-service API-key validations (answers are now cached 60 s / 10 s)" \
  "in that test: set api_key_cache_ttl=0 (AB0T_AUTH_API_KEY_CACHE_TTL=0), or call auth.clear_caches() / auth.invalidate_api_key(key) between steps, or pass fresh=True, or update the expected count." \
  "$TMP/apikey_py" '(\.call_count|\.await_count|assert_(awaited|called)|called_once|side_effect[[:space:]]*=[[:space:]]*\[)'
check ACTION apikey-wrapper \
  "service-side override/wrapper of the guard's auth methods (0.1.4 caches API keys itself)" \
  "remove a wrapper that only adds API-key caching (0.1.4 does it; a wrapper written to stand down when upstream caches will do so). If you keep an override, accept a keyword-only 'fresh: bool = False' before using fresh=True." \
  "$TMP/sdk_py" '\._authenticate_(api_key|jwt)[[:space:]]*=[^=]|def _authenticate_(api_key|jwt)\('
check ACTION apikey-token-cache-invalidate \
  "API-key answers invalidated through the token cache (they now live in the API-key cache)" \
  "use auth.invalidate_api_key(raw_key) (AuthGuard or Ab0tAuth); _token_cache.invalidate(api_key) no longer drops an API-key answer." \
  "$TMP/sdk_py" '_token_cache.*api_key|\.invalidate\([[:space:]]*api_key'

# ==== REVIEW: where the new defaults apply ========================================================================
check REVIEW server-permission-mode \
  "server permission mode: allowed answers now cached 15 s (was 30 s), denied 5 s (was 30 s)" \
  "nothing to change. Revocation is now visible within 15 s; a new grant within 5 s. Expect up to ~2x /permissions/check calls on hot paths. Opt out: AB0T_AUTH_PERMISSION_CACHE_TTL (0 = no cache)." \
  "$TMP/sdk_py" 'permission_check_mode[[:space:]]*=[[:space:]]*["'"'"']server'
check REVIEW server-permission-mode-config \
  "server permission mode set in config" \
  "as above (15 s allowed / 5 s denied)." \
  "$TMP/cfg" 'AB0T_AUTH_PERMISSION_CHECK_MODE[^A-Za-z0-9_]*["'"'"']?server'
check REVIEW apikey-cache-on \
  "guard built here: API-key auth is on by default, and API keys are now cached (valid 60 s, rejected 10 s)" \
  "a revoked key can keep working on this service for up to 60 s. If that is too long: AB0T_AUTH_API_KEY_CACHE_TTL=<seconds> (0 = no cache), fresh=True on sensitive routes, or auth.invalidate_api_key(key) when you revoke." \
  "$TMP/sdk_py" '(AuthGuard|Ab0tAuth)\('
check REVIEW cache-ttl-config \
  "existing cache TTL settings (new TTLs derive from token_cache_ttl when not set)" \
  "token_cache_ttl=0 still disables EVERY cache (strict). Otherwise permission = min(token_cache_ttl//2, 15), API key = min(token_cache_ttl, 60). Set the new AB0T_AUTH_PERMISSION_CACHE_TTL / AB0T_AUTH_API_KEY_CACHE_TTL to override." \
  "$TMP/cfg" 'AB0T_AUTH_(TOKEN|PERMISSION|API_KEY)_CACHE'
check REVIEW cache-ttl-code \
  "cache TTL set in code" \
  "same as above." \
  "$TMP/sdk_py" '(token_cache_ttl|permission_cache_ttl|api_key_cache_ttl)[[:space:]]*='
check REVIEW sensitive-route \
  "permission dependency on what looks like a sensitive operation" \
  "consider fresh=True on this dependency: it skips every decision cache for that route (server mode asks /permissions/check on every request)." \
  "$TMP/sdk_py" 'require_(permission|any_permission|all_permissions|auth_and_permission)\(.*(admin|delete|payout|payment|refund|transfer|withdraw|owner|grant|revoke|secret|role|billing)' -i
check REVIEW logout-local-jwt \
  "logout / session revocation near local JWT auth" \
  "local JWT verification does not see a logout until the token's exp (~15 min). Where a logged-out session must be refused at once: permission_check_mode='server' + fresh=True, or ab0t_auth.client.introspect_token()." \
  "$TMP/sdk_py" '(logout|log_out|revoke_session|session.*revok)' -i
check REVIEW jwks-kid-cooldown \
  "unknown-kid JWKS refetch cooldown referenced (30 s -> 60 s)" \
  "at most one forced refetch per 60 s now. To change it set ab0t_auth.jwt.JWKS_UNKNOWN_KID_REFRESH_COOLDOWN_SECONDS before the guard initializes, or pass refresh_cooldown=." \
  "$TMP/sdk_py" '(JWKS_UNKNOWN_KID_REFRESH_COOLDOWN_SECONDS|refresh_cooldown)'

echo
echo "======================================================"
COUNTED=$ACTION
[ "$STRICT" -eq 1 ] && COUNTED=$((ACTION + REVIEW))
if [ "$COUNTED" -eq 0 ]; then
  echo -e "${GREEN}No ACTION findings.${NC} ($REVIEW advisory REVIEW finding(s) above — read them; they do not fail the check.)"
  echo "Then: bump to ab0t-auth 0.1.4 and run your test suite."
  exit 0
fi
echo -e "${RED}${ACTION} ACTION finding(s)${NC} to review/change for 0.1.4 (plus $REVIEW advisory REVIEW finding(s))."
[ "$STRICT" -eq 1 ] && echo "(--strict: REVIEW findings also fail the check.)"
echo "Each block shows the fix. Matches are textual CANDIDATES: change only where the value is the ab0t_auth object"
echo "the rule names; where no change is needed, add the comment '$REVIEWED_MARK' to that line."
echo "Re-run until it exits 0, then run your test suite. Rollback at any time: pin ab0t-auth back to 0.1.3."
exit 1
