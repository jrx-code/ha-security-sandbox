#!/usr/bin/env bash
# Sync GitHub issues to GitLab (runs from GitLab CI scheduled pipeline).
#
# Required env vars:
#   GITHUB_TOKEN       — GitHub PAT with repo scope (read issues)
#   GITLAB_TOKEN_SYNC  — GitLab PAT with api scope (create issues)
#   GITHUB_REPO        — e.g. "jrx-code/ha-security-sandbox"
#   GITLAB_PROJECT_ID  — numeric GitLab project ID
#
# Optional:
#   GITLAB_API_URL     — defaults to $CI_API_V4_URL or https://gitlab.iwanus.eu/api/v4
#   SYNC_STATE_FILE    — path to persist last sync timestamp (default: /tmp/github-sync-state)

set -euo pipefail

GITLAB_API_URL="${GITLAB_API_URL:-${CI_API_V4_URL:-https://gitlab.iwanus.eu/api/v4}}"
SYNC_STATE_FILE="${SYNC_STATE_FILE:-/tmp/github-sync-state}"

# Read last sync timestamp (ISO 8601)
SINCE=""
if [ -f "$SYNC_STATE_FILE" ]; then
    SINCE=$(cat "$SYNC_STATE_FILE")
    echo "Last sync: $SINCE"
fi

# Fetch open issues from GitHub (created since last sync)
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}/issues"
PARAMS="state=open&sort=created&direction=asc&per_page=100"
if [ -n "$SINCE" ]; then
    PARAMS+="&since=${SINCE}"
fi

echo "Fetching GitHub issues from ${GITHUB_REPO}..."
ISSUES=$(curl -sf \
    -H "Authorization: token ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github.v3+json" \
    "${GITHUB_API}?${PARAMS}")

# Filter: only issues (not PRs), skip issues already synced (check GitLab for existing)
COUNT=$(echo "$ISSUES" | jq '[.[] | select(.pull_request == null)] | length')
echo "Found ${COUNT} open issues"

SYNCED=0
SKIPPED=0

echo "$ISSUES" | jq -c '.[] | select(.pull_request == null)' | while read -r issue; do
    TITLE=$(echo "$issue" | jq -r '.title')
    NUMBER=$(echo "$issue" | jq -r '.number')
    BODY=$(echo "$issue" | jq -r '.body // ""')
    AUTHOR=$(echo "$issue" | jq -r '.user.login')
    URL=$(echo "$issue" | jq -r '.html_url')
    CREATED=$(echo "$issue" | jq -r '.created_at')

    # Check if already synced — search GitLab for issue with same title
    EXISTING=$(curl -sf \
        -H "PRIVATE-TOKEN: ${GITLAB_TOKEN_SYNC}" \
        "${GITLAB_API_URL}/projects/${GITLAB_PROJECT_ID}/issues?search=$(echo "$TITLE" | jq -sRr @uri)&in=title" \
        | jq --arg title "$TITLE" '[.[] | select(.title == $title)] | length')

    if [ "$EXISTING" -gt 0 ]; then
        echo "  [skip] #${NUMBER}: ${TITLE} (already exists in GitLab)"
        continue
    fi

    # Build description
    DESCRIPTION="**Synced from GitHub** — [#${NUMBER}](${URL})\n\n"
    DESCRIPTION+="**Author:** @${AUTHOR}\n\n---\n\n"
    if [ -n "$BODY" ] && [ "$BODY" != "null" ]; then
        DESCRIPTION+="$BODY"
    else
        DESCRIPTION+="*No description provided.*"
    fi

    # Create GitLab issue
    PAYLOAD=$(jq -n \
        --arg title "$TITLE" \
        --arg description "$DESCRIPTION" \
        --arg labels "github" \
        '{title: $title, description: $description, labels: $labels}')

    RESPONSE=$(curl -sf -w "\n%{http_code}" \
        -X POST \
        "${GITLAB_API_URL}/projects/${GITLAB_PROJECT_ID}/issues" \
        -H "PRIVATE-TOKEN: ${GITLAB_TOKEN_SYNC}" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD")

    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    RESP_BODY=$(echo "$RESPONSE" | sed '$d')

    if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
        GL_URL=$(echo "$RESP_BODY" | jq -r '.web_url')
        echo "  [synced] #${NUMBER}: ${TITLE} → ${GL_URL}"
    else
        echo "  [ERROR] #${NUMBER}: HTTP ${HTTP_CODE}"
        echo "$RESP_BODY" | jq . 2>/dev/null || echo "$RESP_BODY"
    fi
done

# Save current timestamp for next run
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$SYNC_STATE_FILE"
echo "Sync complete"
