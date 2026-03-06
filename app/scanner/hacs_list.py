"""Fetch lists of HACS components from default repository and installed list."""

import json
import logging

import httpx

from app.config import settings

log = logging.getLogger(__name__)

# HACS default repo raw URLs
HACS_LISTS = {
    "integration": "https://raw.githubusercontent.com/hacs/default/master/integration",
    "plugin": "https://raw.githubusercontent.com/hacs/default/master/plugin",
    "theme": "https://raw.githubusercontent.com/hacs/default/master/theme",
    "python_script": "https://raw.githubusercontent.com/hacs/default/master/python_script",
}


async def fetch_hacs_defaults(category: str = "integration") -> list[str]:
    """Fetch list of repos from HACS default repository."""
    url = HACS_LISTS.get(category)
    if not url:
        return []
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        log.error("Failed to fetch HACS %s list: %s", category, e)
        return []


async def fetch_installed_hacs(ha_url: str | None = None, ha_token: str | None = None) -> list[dict]:
    """Fetch installed HACS components from Home Assistant.

    Returns list of dicts with keys: repository, category, installed_version, name.
    """
    url = ha_url or settings.ha_url
    token = ha_token or settings.ha_token
    if not token:
        log.warning("No HA token configured, cannot fetch installed HACS")
        return []

    try:
        async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
            # HACS stores its data via websocket, but we can try the HACS API
            resp = await client.get(
                f"{url}/api/hacs/repositories",
                headers={"Authorization": f"Bearer {token}"},
            )
            if resp.status_code == 200:
                repos = resp.json()
                return [
                    {
                        "repository": r.get("full_name", ""),
                        "category": r.get("category", ""),
                        "installed_version": r.get("installed_version", ""),
                        "name": r.get("name", r.get("full_name", "")),
                        "installed": r.get("installed", False),
                    }
                    for r in repos
                    if r.get("installed", False)
                ]
            else:
                log.warning("HACS API returned %d", resp.status_code)
                return []
    except Exception as e:
        log.error("Failed to fetch installed HACS: %s", e)
        return []


def repo_to_url(repo_full_name: str) -> str:
    """Convert GitHub repo full name to clone URL."""
    if repo_full_name.startswith("http"):
        return repo_full_name
    return f"https://github.com/{repo_full_name}.git"
