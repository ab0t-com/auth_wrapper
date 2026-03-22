#!/usr/bin/env bash
set -euo pipefail

REPO="ab0t-com/auth_wrapper"
BRANCH="main"
ARCHIVE_URL="https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz"
ARCHIVE_PREFIX="auth_wrapper-${BRANCH}/Skills"

SKILLS=(auth_fastapi_skill auth_service_ab0t)

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Install ab0t auth skills for Claude Code.

  curl -sSL https://raw.githubusercontent.com/${REPO}/${BRANCH}/install_skills.sh | bash
  curl -sSL https://raw.githubusercontent.com/${REPO}/${BRANCH}/install_skills.sh | bash -s -- --project

Options:
  --project    Install to .claude/skills/ in the current directory instead of user-wide
  --uninstall  Remove installed skills
  -h, --help   Show this help

Default: installs user-wide to ~/.claude/skills/
EOF
    exit 0
}

MODE="user"
UNINSTALL=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project)   MODE="project"; shift ;;
        --uninstall) UNINSTALL=true; shift ;;
        -h|--help)   usage ;;
        *)           echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [[ "$MODE" == "user" ]]; then
    DEST="${HOME}/.claude/skills"
else
    DEST="${PWD}/.claude/skills"
fi

# Guard against empty/dangerous DEST
if [[ -z "$DEST" || "$DEST" == "/" ]]; then
    echo "Error: refusing to operate on root or empty path" >&2
    exit 1
fi

if [[ "$UNINSTALL" == true ]]; then
    for skill in "${SKILLS[@]}"; do
        target="${DEST}/${skill}"
        if [[ -d "$target" ]]; then
            rm -rf -- "$target"
            echo "Removed ${target}"
        else
            echo "Already absent: ${skill}"
        fi
    done
    exit 0
fi

# Check for curl or wget
if command -v curl &>/dev/null; then
    fetch() { curl -fsSL "$1"; }
elif command -v wget &>/dev/null; then
    fetch() { wget -qO- "$1"; }
else
    echo "Error: curl or wget required" >&2
    exit 1
fi

mkdir -p "$DEST"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf -- "$WORK_DIR"' EXIT

echo "Downloading skills from ${REPO}@${BRANCH}..."
fetch "$ARCHIVE_URL" | tar xz -C "$WORK_DIR"

for skill in "${SKILLS[@]}"; do
    src="${WORK_DIR}/${ARCHIVE_PREFIX}/${skill}"
    if [[ ! -d "$src" ]]; then
        echo "Warning: ${skill} not found in archive, skipping" >&2
        continue
    fi
    rm -rf -- "${DEST}/${skill}"
    mv -- "$src" "${DEST}/${skill}"
    echo "Installed ${skill} -> ${DEST}/${skill}"
done

echo "Done. Skills installed to ${DEST}"
