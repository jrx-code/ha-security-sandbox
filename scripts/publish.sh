#!/bin/bash
# Publish clean version to the 'publish' branch.
#
# Strategy: merge main into publish, verify no secrets leak.
# The publish branch has extra public files (README, LICENSE, etc.)
# that are NOT on main. This script preserves them.
#
# Usage:
#   ./scripts/publish.sh          # dry run (verify only)
#   ./scripts/publish.sh --push   # verify + force-push to origin/publish
set -euo pipefail

PUBLISH_BRANCH="publish"
MAIN_BRANCH="main"
DO_PUSH=false

if [[ "${1:-}" == "--push" ]]; then
    DO_PUSH=true
fi

# --- Secret patterns to check (broad enough to catch leaks) ---
# Patterns that indicate actual secrets (not env var references like ${VAR:-})
SECRET_PATTERNS='\.iwanus\.eu|Service001|8GZiT|adm-nas|192\.168\.(18|19)\.[0-9]+'

# --- Files that must NOT appear on publish ---
EXCLUDED_FILES=(
    "docker-compose.override.yml"
    "data/settings.json"
)

# --- Preflight checks ---
current_branch=$(git rev-parse --abbrev-ref HEAD)
if [[ "$current_branch" != "$MAIN_BRANCH" ]]; then
    echo "ERROR: Must be on $MAIN_BRANCH branch (currently on $current_branch)"
    exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "ERROR: Working tree not clean. Commit or stash changes first."
    exit 1
fi

echo "=== Publish script ==="
echo "Main:    $(git rev-parse --short HEAD)"
echo "Publish: $(git rev-parse --short $PUBLISH_BRANCH 2>/dev/null || echo 'not found')"

# --- Step 1: Check tracked files on main for secrets ---
echo ""
echo "--- Step 1: Verify main branch has no secrets ---"
matches=$(git ls-files -z | xargs -0 grep -lE "$SECRET_PATTERNS" 2>/dev/null || true)
if [[ -n "$matches" ]]; then
    echo "ERROR: Secret patterns found in tracked files:"
    echo "$matches"
    echo ""
    echo "Matches:"
    git ls-files -z | xargs -0 grep -nE "$SECRET_PATTERNS" 2>/dev/null || true
    exit 1
fi
echo "OK: No secrets in tracked files."

# --- Step 2: Merge main into publish ---
echo ""
echo "--- Step 2: Merge main into publish ---"
git checkout "$PUBLISH_BRANCH"

# Merge main, preferring main's version for conflicts
git merge "$MAIN_BRANCH" -m "Merge main into publish" --no-edit -X theirs --allow-unrelated-histories || {
    echo "ERROR: Merge failed. Aborting."
    git merge --abort 2>/dev/null || true
    git checkout "$MAIN_BRANCH"
    exit 1
}

# --- Step 3: Verify no excluded files leaked ---
echo ""
echo "--- Step 3: Verify excluded files ---"
leak_found=false
for f in "${EXCLUDED_FILES[@]}"; do
    if git ls-files --error-unmatch "$f" &>/dev/null; then
        echo "ERROR: Excluded file tracked on publish: $f"
        leak_found=true
    fi
done
if $leak_found; then
    git checkout "$MAIN_BRANCH"
    exit 1
fi
echo "OK: No excluded files."

# --- Step 4: Full secret scan on publish ---
echo ""
echo "--- Step 4: Full secret scan on publish branch ---"
matches=$(git ls-files -z | xargs -0 grep -lE "$SECRET_PATTERNS" 2>/dev/null || true)
if [[ -n "$matches" ]]; then
    echo "ERROR: Secret patterns found on publish branch:"
    echo "$matches"
    git ls-files -z | xargs -0 grep -nE "$SECRET_PATTERNS" 2>/dev/null || true
    git checkout "$MAIN_BRANCH"
    exit 1
fi
echo "OK: No secrets on publish branch."

# --- Step 5: Push or report ---
echo ""
if $DO_PUSH; then
    echo "--- Step 5: Pushing to origin/$PUBLISH_BRANCH ---"
    git push origin "$PUBLISH_BRANCH"
    echo "OK: Pushed to origin/$PUBLISH_BRANCH"
else
    echo "--- Dry run complete ---"
    echo "Publish branch updated locally. Run with --push to push."
fi

# Return to main
git checkout "$MAIN_BRANCH"
echo ""
echo "=== Done ==="
