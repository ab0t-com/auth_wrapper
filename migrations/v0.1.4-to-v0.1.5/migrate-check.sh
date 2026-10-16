#!/usr/bin/env bash
# migrate-check.sh — find the places in your service affected by ab0t-auth 0.1.4 -> 0.1.5.
#
# 0.1.5 is a PATCH with NO breaking change to the documented API. It fixes four defects:
#   - permission cache: resource_type is now part of the key (an allow for one resource type was served for another)
#   - permission cache: the key is a tuple (a ':' in a permission name could collide with permission + resource)
#   - a lower-case 'bearer' scheme is forwarded to the auth service as 'Bearer <t>' (was 'Bearer bearer <t>')
#   - a decision-cache TTL SET IN CODE outside 0-300 s is clamped into range with a WARNING (it was honoured as-is)
# None of them stops a service that ran on 0.1.4. This checker looks first for TTLs set in code outside 0-300 (not
# honoured any more; a later minor release may refuse them) and for code that reads permission-cache keys as strings,
# and prints, per finding: file:line, the rule, the fix.
#
# Read-only: it NEVER edits your code. Only bash + grep + find.
#
# Two kinds of finding:
#   ACTION  will fail or misbehave on 0.1.5 -> change it (or mark reviewed). These set the exit code.
#   REVIEW  advisory: where the fixes change what you observe. Do not affect the exit code (unless --strict).
# Findings are CANDIDATES (textual matches): prefer a false positive to a missed site. When a finding needs no
# change, append a comment containing   ab0t-auth-0.1.5: reviewed   to that line and it is skipped next time.
#
# Usage:   ./migrate-check.sh [--strict] [path-to-your-repo]      (default path: current dir)
# Exit:    0 = no ACTION findings (CI-gateable), 1 = ACTION findings remain, 2 = usage error
# See MIGRATION.md (same directory) for the before -> after of every change.

set -u
set -o pipefail

STRICT=0
TARGET="."
for arg in "$@"; do
  case "$arg" in
    --strict) STRICT=1 ;;
    -h|--help) sed -n '2,23p' "$0"; exit 0 ;;
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
REVIEWED_MARK='ab0t-auth-0.1.5: reviewed'
ACTION=0
REVIEW=0

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ---- file sets ------------------------------------------------------------------------------------------------
# Skip VCS/env/build dirs, a vendored copy of the library itself, and the migration kits.
list_files() {
  find "$TARGET" \( -name .git -o -name .venv -o -name venv -o -name env -o -name node_modules \
       -o -name site-packages -o -name __pycache__ -o -name dist -o -name build -o -name .tox -o -name .mypy_cache \) \
       -prune -o -type f \( "$@" \) -print 2>/dev/null \
    | grep -v '/ab0t_auth/' | grep -v '/migrations/v0\.1\.[0-9]*-to-v0\.1\.[0-9]*/' || true
}
# Python files that use the library (mention ab0t_auth).
list_files -name '*.py' | while IFS= read -r f; do
  grep -q 'ab0t_auth' "$f" 2>/dev/null && printf '%s\n' "$f"
done > "$TMP/sdk_py"

SDK_N="$(grep -c . "$TMP/sdk_py" || true)"
echo -e "${BOLD}ab0t-auth 0.1.4 -> 0.1.5 migration check${NC}"
echo    "target: $TARGET   python files using ab0t_auth: $SDK_N"
if [ "$SDK_N" -eq 0 ]; then
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

TTL_NAMES='(permission_cache_ttl|permission_cache_negative_ttl|api_key_cache_ttl|api_key_cache_negative_ttl)'
# name = value  |  "name": value  |  name=value inside a call. Value: a negative int, or an int > 300.
OUT_OF_RANGE='(-[[:space:]]*[0-9]+|30[1-9]|3[1-9][0-9]|[4-9][0-9][0-9]|[1-9][0-9]{3,}|[1-9][0-9]{0,2}(_[0-9]{3})+)'

# ==== ACTION: not honoured on 0.1.5 (clamped + warned); a later minor may refuse it ================================
check ACTION ttl-out-of-range-code \
  "decision-cache TTL set in code outside 0-300 s (0.1.5 clamps it into range and logs a WARNING naming the field; a later minor release may refuse it)" \
  "use 0 to turn that cache off (what a negative value did) or a value <= 300. Need faster revocation? keep the TTL short and use fresh=True / auth.invalidate_api_key(key)." \
  "$TMP/sdk_py" "${TTL_NAMES}[\"']?[[:space:]]*[=:][[:space:]]*${OUT_OF_RANGE}([^0-9_]|\$)" '' '^[^:]*:[0-9]+:[[:space:]]*#'

# ==== ACTION: relies on the string cache key =======================================================================
check ACTION cache-key-internal \
  "code that builds permission-cache keys itself or reads PermissionCache._cache keys (they are tuples now, not ':'-joined strings)" \
  "treat keys as tuples (user_id, credential, org, permission, resource_type, resource_id); in tests use ' '.join(repr(k) for k in cache._cache.keys()) or go through PermissionCache.get(...). Seeding with PermissionCache.set(...) is unchanged." \
  "$TMP/sdk_py" '(create_permission_cache_key|_permission_cache\._cache|PermissionCache\(\)\._cache|permission_cache\._cache)'

# ==== REVIEW: where the fixes change what you observe ==============================================================
check REVIEW resource-type-direct \
  "direct permission check with resource_type= (0.1.4 could serve one type's cached answer for another type with the same id)" \
  "nothing to change: each (type, id) is now asked separately, so /permissions/check calls (and call-count tests) may rise where types share an id. verify_any_permission / verify_all_permissions now accept resource_type= too. (Single-line match: also look at multi-line verify_permission(...) calls that pass resource_type=.)" \
  "$TMP/sdk_py" '(verify_(any_|all_)?permission|_permission_cache\.(get|set)|PermissionCheckRequest)\(.*resource_type' '' 'def |^[^:]*:[0-9]+:[[:space:]]*#'
check REVIEW bearer-case-workaround \
  "code that rewrites the 'bearer' scheme to 'Bearer' before calling the SDK, or expects 'Bearer bearer' (0.1.5 forwards any case as 'Bearer <t>')" \
  "optional cleanup: the rewrite is no longer needed and is harmless to keep. A test that expected the forwarded value 'Bearer bearer <t>' must now expect 'Bearer <t>'." \
  "$TMP/sdk_py" "(replace\([[:space:]]*[\"']bearer[[:space:]]|[\"'][Bb]earer [Bb]earer[[:space:]])" ''
check REVIEW ttl-code-expression \
  "decision-cache TTL set in code from a variable/expression (0.1.5 clamps it into 0-300 s with a warning if it is outside)" \
  "make sure the value is an int 0-300 in every environment (e.g. a config file or env var you parse yourself)." \
  "$TMP/sdk_py" "${TTL_NAMES}[\"']?[[:space:]]*[=:][[:space:]]*[A-Za-z_(]" '' '^[^:]*:[0-9]+:[[:space:]]*#|[=:][[:space:]]*None\b|self\.'

echo
echo "======================================================"
COUNTED=$ACTION
[ "$STRICT" -eq 1 ] && COUNTED=$((ACTION + REVIEW))
if [ "$COUNTED" -eq 0 ]; then
  echo -e "${GREEN}No ACTION findings.${NC} ($REVIEW advisory REVIEW finding(s) above — read them; they do not fail the check.)"
  echo "Then: bump to ab0t-auth 0.1.5 and run your test suite."
  exit 0
fi
echo -e "${RED}${ACTION} ACTION finding(s)${NC} to review/change for 0.1.5 (plus $REVIEW advisory REVIEW finding(s))."
[ "$STRICT" -eq 1 ] && echo "(--strict: REVIEW findings also fail the check.)"
echo "Each block shows the fix. Matches are textual CANDIDATES: change only where the value is the ab0t_auth object"
echo "the rule names; where no change is needed, add the comment '$REVIEWED_MARK' to that line."
echo "Re-run until it exits 0, then run your test suite. Rollback at any time: pin ab0t-auth back to 0.1.4."
exit 1
