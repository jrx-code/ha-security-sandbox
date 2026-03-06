"""Fetch lists of HACS components from HA via WebSocket API."""

import json
import logging
import ssl

import httpx

from app.config import settings

log = logging.getLogger(__name__)


async def fetch_installed_hacs(ha_url: str | None = None, ha_token: str | None = None) -> list[dict]:
    """Fetch installed HACS components from Home Assistant via WebSocket.

    Returns list of dicts with keys: repository, category, installed_version, name.
    """
    url = ha_url or settings.ha_url
    token = ha_token or settings.ha_token
    if not token:
        log.warning("No HA token configured, cannot fetch installed HACS")
        return []

    # Convert http(s) URL to ws(s) URL
    ws_url = url.replace("https://", "wss://").replace("http://", "ws://")
    ws_url = f"{ws_url}/api/websocket"

    try:
        import websockets
        ssl_ctx = None
        if ws_url.startswith("wss://"):
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        async with websockets.connect(ws_url, ssl=ssl_ctx, max_size=20 * 1024 * 1024) as ws:
            # Receive auth_required
            await ws.recv()

            # Authenticate
            await ws.send(json.dumps({"type": "auth", "access_token": token}))
            auth_resp = json.loads(await ws.recv())
            if auth_resp.get("type") != "auth_ok":
                log.error("HA auth failed: %s", auth_resp)
                return []

            # Request HACS repos
            await ws.send(json.dumps({"id": 1, "type": "hacs/repositories/list"}))
            resp = json.loads(await ws.recv())

            if not resp.get("success"):
                log.error("HACS repos request failed: %s", resp)
                return []

            repos = resp.get("result", [])
            installed = [
                {
                    "repository": r.get("full_name", ""),
                    "category": r.get("category", ""),
                    "installed_version": r.get("installed_version", ""),
                    "name": r.get("name", r.get("full_name", "")),
                }
                for r in repos
                if r.get("installed")
            ]
            log.info("Fetched %d installed HACS components", len(installed))
            return installed

    except ImportError:
        log.error("websockets package not installed")
        return []
    except Exception as e:
        log.error("Failed to fetch installed HACS: %s", e)
        return []


async def fetch_hacs_defaults(category: str = "integration") -> list[str]:
    """Fetch list of repos from HACS default repository."""
    urls = {
        "integration": "https://raw.githubusercontent.com/hacs/default/master/integration",
        "plugin": "https://raw.githubusercontent.com/hacs/default/master/plugin",
        "theme": "https://raw.githubusercontent.com/hacs/default/master/theme",
    }
    url = urls.get(category)
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


def repo_to_url(repo_full_name: str) -> str:
    """Convert GitHub repo full name to clone URL."""
    if repo_full_name.startswith("http"):
        return repo_full_name
    return f"https://github.com/{repo_full_name}.git"
