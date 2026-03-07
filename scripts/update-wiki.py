#!/usr/bin/env python3
"""Update BookStack wiki pages after publish.

Updates:
  - Architecture page (id=425): version, changelog
  - Roadmap page (id=417): current version, milestones

Requires env vars: BOOKSTACK_TOKEN_ID, BOOKSTACK_TOKEN_SECRET
Runs inside gitlab-runner container which has access to bookstack via docker exec.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

# BookStack API via docker exec (runner shares docker socket with bookstack)
TOKEN_ID = os.environ.get("BOOKSTACK_TOKEN_ID", "")
TOKEN_SECRET = os.environ.get("BOOKSTACK_TOKEN_SECRET", "")
ARCH_PAGE_ID = 425
ROADMAP_PAGE_ID = 417


def bookstack_api(method: str, endpoint: str, data: dict | None = None) -> dict:
    """Call BookStack API via docker exec bookstack curl."""
    cmd = [
        "docker", "exec", "bookstack", "curl", "-s",
        "-X", method,
        f"http://localhost/api/{endpoint}",
        "-H", f"Authorization: Token {TOKEN_ID}:{TOKEN_SECRET}",
        "-H", "Content-Type: application/json",
    ]
    if data:
        cmd.extend(["-d", json.dumps(data)])
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"ERROR: docker exec failed: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    return json.loads(result.stdout)


def read_version() -> str:
    """Read version from config.yaml."""
    config = Path("ha-sandbox/config.yaml").read_text()
    match = re.search(r'version:\s*"(.+?)"', config)
    return match.group(1) if match else "unknown"


def read_changelog() -> str:
    """Read latest changelog entry."""
    changelog = Path("ha-sandbox/CHANGELOG.md").read_text()
    # Extract first version block (## [x.y.z] ... until next ## or EOF)
    match = re.search(r'(## \[.+?\].*?)(?=\n## \[|\Z)', changelog, re.DOTALL)
    return match.group(1).strip() if match else ""


def update_architecture(version: str, changelog: str):
    """Update Architecture page with current version."""
    page = bookstack_api("GET", f"pages/{ARCH_PAGE_ID}")
    md = page.get("markdown", "")
    if not md:
        print("WARN: Architecture page has no markdown content")
        return

    # Update title
    md = re.sub(
        r'# HA Add-on Architecture — v[\d.]+',
        f'# HA Add-on Architecture — v{version}',
        md
    )
    # Update version in versioning section
    md = re.sub(
        r'`config\.yaml` → `version: "[\d.]+"',
        f'`config.yaml` → `version: "{version}"',
        md
    )
    # Update image tag in deployment section
    md = re.sub(
        r'Image: `ha-sandbox:[\d.]+`',
        f'Image: `ha-sandbox:{version}`',
        md
    )
    # Update "pending rebuild" note
    md = re.sub(
        r'ha-sandbox:[\d.]+ \(pending rebuild to [\d.]+\)',
        f'ha-sandbox:{version}',
        md
    )

    bookstack_api("PUT", f"pages/{ARCH_PAGE_ID}", {
        "markdown": md,
        "tags": [
            {"name": "typ", "value": "architecture"},
            {"name": "project", "value": "ha-security-sandbox"},
            {"name": "version", "value": version},
        ]
    })
    print(f"  Architecture page updated to v{version}")


def update_roadmap(version: str, changelog: str):
    """Update Roadmap page with current version and milestone."""
    page = bookstack_api("GET", f"pages/{ROADMAP_PAGE_ID}")
    md = page.get("markdown", "")
    if not md:
        print("WARN: Roadmap page has no markdown content")
        return

    # Update "Current State" header
    md = re.sub(
        r'## Current State — v[\d.]+',
        f'## Current State — v{version}',
        md
    )

    # Check if this version is already in milestones
    if f'v{version}' not in md.split('### Completed milestones')[1].split('---')[0] if '### Completed milestones' in md else '':
        # Extract changelog summary for milestone line
        lines = changelog.split('\n')
        summary_parts = []
        for line in lines:
            if line.startswith('### '):
                continue
            if line.startswith('- '):
                summary_parts.append(line[2:].strip())
        summary = '; '.join(summary_parts[:3])
        if summary:
            milestone = f'- **v{version}**: {summary}'
            # Insert before the last milestone line (before ---)
            md = re.sub(
                r'(\n---\n\n## Phase 1)',
                f'\n{milestone}\n---\n\n## Phase 1',
                md,
                count=1
            )

    bookstack_api("PUT", f"pages/{ROADMAP_PAGE_ID}", {"markdown": md})
    print(f"  Roadmap page updated to v{version}")


def main():
    if not TOKEN_ID or not TOKEN_SECRET:
        print("WARN: BOOKSTACK_TOKEN_ID/SECRET not set, skipping wiki update")
        sys.exit(0)

    version = read_version()
    changelog = read_changelog()
    print(f"Updating wiki for v{version}...")

    try:
        update_architecture(version, changelog)
    except Exception as e:
        print(f"WARN: Architecture update failed: {e}")

    try:
        update_roadmap(version, changelog)
    except Exception as e:
        print(f"WARN: Roadmap update failed: {e}")

    print("Wiki update complete")


if __name__ == "__main__":
    main()
