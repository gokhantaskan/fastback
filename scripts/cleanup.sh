#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

DRY_RUN=false
AUTO_YES=false

usage() {
  cat <<'EOF'
Usage: scripts/cleanup.sh [options]

Removes common Python/FastAPI cache + temp files from the repo.
Prompts y/N before deleting .venv (unless --yes).

Options:
  -n, --dry-run   Show what would be removed
  -y, --yes       Do not prompt (also removes .venv)
  -h, --help      Show help
EOF
}

while [[ "${#}" -gt 0 ]]; do
  case "${1}" in
    -n|--dry-run) DRY_RUN=true; shift ;;
    -y|--yes) AUTO_YES=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: ${1}" >&2; usage; exit 2 ;;
  esac
done

cd -- "${ROOT_DIR}"

run_rm() {
  # Usage: run_rm <path>
  local p="${1}"
  if [[ ! -e "${p}" ]]; then
    return 0
  fi
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "Would remove: ${p}"
  else
    rm -rf -- "${p}"
    echo "Removed: ${p}"
  fi
}

echo "Cleaning cache/temp files in: ${ROOT_DIR}"

#
# Cleanup targets (edit these lists as needed)
#
# NOTE:
# - This script intentionally does NOT parse or depend on .gitignore.
# - Add/remove items here to control what gets deleted.
#
CLEANUP_PATHS=(
  "app.db"
  ".ruff_cache"
  ".pytest_cache"
  ".coverage"
  "htmlcov"
  ".mypy_cache"
  ".tox"
  ".hypothesis"
  "__pycache__"
)

FIND_DIR_NAMES=(
  "__pycache__"
)

FIND_FILE_GLOBS=(
  "*.pyc"
  "*.pyo"
  ".DS_Store"
)

for p in "${CLEANUP_PATHS[@]}"; do
  run_rm "${p}"
done

# Common Python bytecode / caches
if [[ "${DRY_RUN}" == "true" ]]; then
  for dname in "${FIND_DIR_NAMES[@]}"; do
    {
      find . \( -path "./.git" -o -path "./.venv" \) -prune -o -type d -name "${dname}" -prune -print 2>/dev/null \
        | sed 's|^\./||' \
        | while IFS= read -r d; do echo "Would remove: ${d}"; done
    } || true
  done

  for glob in "${FIND_FILE_GLOBS[@]}"; do
    {
      find . \( -path "./.git" -o -path "./.venv" \) -prune -o -type f -name "${glob}" -print 2>/dev/null \
        | sed 's|^\./||' \
        | while IFS= read -r f; do echo "Would remove: ${f}"; done
    } || true
  done
else
  for dname in "${FIND_DIR_NAMES[@]}"; do
    find . \( -path "./.git" -o -path "./.venv" \) -prune -o -type d -name "${dname}" -prune -exec rm -rf {} + 2>/dev/null || true
  done

  for glob in "${FIND_FILE_GLOBS[@]}"; do
    if [[ "${glob}" == ".DS_Store" ]]; then
      find . \( -path "./.git" -o -path "./.venv" \) -prune -o -type f -name "${glob}" -delete 2>/dev/null || true
    else
      find . \( -path "./.git" -o -path "./.venv" \) -prune -o -type f -name "${glob}" -delete 2>/dev/null || true
    fi
  done

  echo "Removed: ${FIND_DIR_NAMES[*]} and ${FIND_FILE_GLOBS[*]} (where found)"
fi

# Optional: venv (prompt y/N)
if [[ -d ".venv" ]]; then
  if [[ "${AUTO_YES}" == "true" ]]; then
    run_rm ".venv"
  else
    ans=""
    if [[ -t 0 ]]; then
      # Interactive prompt; default is "No"
      read -r -p "Remove .venv? [y/N] " ans || true
    fi
    case "${ans}" in
      y|Y|yes|YES|Yes) run_rm ".venv" ;;
      *) echo "Keeping: .venv" ;;
    esac
  fi
fi

echo "Done."
