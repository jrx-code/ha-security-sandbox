"""HACS install/update auto-scan watcher over the HA WebSocket API.

HACS does not fire events on the HA event bus: it uses the dispatcher
(async_dispatcher_send) and exposes it over WebSocket as
``{"type": "hacs/subscribe", "signal": "hacs_dispatch_repository"}``. After a
download it sends ``{"action": "install", "repository": "<owner/repo>", ...}``
(hacs/integration, repositories/base.py). That payload carries no version, so
an install signal only brings the next snapshot of installed repositories
forward; the snapshot diff decides what changed and to which version. The
periodic snapshot stays as the fallback for anything the signal misses.
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
import time
from collections.abc import Awaitable, Callable
from typing import Any

log = logging.getLogger(__name__)

HACS_REPOSITORY_SIGNAL = "hacs_dispatch_repository"

# Actions on that signal that mean new code landed on disk. An update is a
# download too, and HACS reports it as "install".
_INSTALL_ACTIONS = frozenset({"install"})

# How long after an install signal to take the snapshot, so HACS has written
# the new installed_version.
SIGNAL_SNAPSHOT_DELAY_SECONDS = 5

COOLDOWN_SECONDS = 600  # 10 minutes
SNAPSHOT_INTERVAL_SECONDS = 120
_RECONNECT_BASE = 2.0
_RECONNECT_MAX = 60.0

_task: asyncio.Task | None = None
_enabled: bool = False
_last_scanned: dict[str, float] = {}  # "full_name@version" -> monotonic ts
_snapshot: dict[str, str] = {}  # full_name -> installed_version
_scan_cb: Callable[[str, str, str], Awaitable[None]] | None = None
_msg_id: int = 1
_scan_tasks: set[asyncio.Task] = set()


def _next_id() -> int:
    global _msg_id
    _msg_id += 1
    return _msg_id


def cooldown_key(full_name: str, version: str) -> str:
    return f"{full_name}@{version or 'unknown'}"


def in_cooldown(
    full_name: str,
    version: str,
    last_scanned: dict[str, float] | None = None,
    *,
    now: float | None = None,
    cooldown: float = COOLDOWN_SECONDS,
) -> bool:
    """Return True if this repo+version was scanned within the cooldown window."""
    store = last_scanned if last_scanned is not None else _last_scanned
    key = cooldown_key(full_name, version)
    ts = store.get(key)
    if ts is None:
        return False
    t = now if now is not None else time.monotonic()
    return (t - ts) < cooldown


def mark_scanned(
    full_name: str,
    version: str,
    last_scanned: dict[str, float] | None = None,
    *,
    now: float | None = None,
) -> None:
    store = last_scanned if last_scanned is not None else _last_scanned
    store[cooldown_key(full_name, version)] = now if now is not None else time.monotonic()


def parse_hacs_signal(data: Any) -> str | None:
    """Return the repository full_name if a hacs_dispatch_repository payload is
    an install, else None. Other actions (uninstall, registration, the empty
    refresh payload) are ignored."""
    if not isinstance(data, dict):
        return None
    action = str(data.get("action") or "").lower()
    if action not in _INSTALL_ACTIONS:
        return None
    repo = data.get("repository")
    return repo if isinstance(repo, str) and repo else None


def snapshot_from_installed(installed: list[dict]) -> dict[str, str]:
    """Build full_name -> version map from fetch_installed_hacs result."""
    out: dict[str, str] = {}
    for comp in installed:
        name = comp.get("full_name") or comp.get("repository") or ""
        if not name:
            continue
        out[name] = str(comp.get("installed_version") or "")
    return out


def snapshot_diff(
    old: dict[str, str],
    new: dict[str, str],
) -> list[dict[str, str]]:
    """Detect new installs and version bumps between snapshots.

    Returns list of {full_name, version, action} where action is
    'install' or 'update'.
    """
    changes: list[dict[str, str]] = []
    for name, version in new.items():
        if name not in old:
            changes.append({"full_name": name, "version": version, "action": "install"})
        elif old[name] != version:
            changes.append({"full_name": name, "version": version, "action": "update"})
    return changes


def _ws_url_and_ssl(ha_url: str) -> tuple[str, ssl.SSLContext | None]:
    ws_url = ha_url.replace("https://", "wss://").replace("http://", "ws://")
    ws_url = f"{ws_url.rstrip('/')}/api/websocket"
    ssl_ctx = None
    if ws_url.startswith("wss://"):
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
    return ws_url, ssl_ctx


async def _default_scan(url: str, name: str, version: str) -> None:
    """Scan through the same runner as the UI: it holds the concurrency limit,
    records the job, and run_scan() already sends the finding alerts."""
    from app.main import _run_scan_background

    await _run_scan_background(url, name, batch_id="hacs_autoscan")


async def _trigger_scan(full_name: str, version: str, action: str) -> None:
    """Dedup + enqueue a scan for one component."""
    if not _enabled:
        return
    if in_cooldown(full_name, version):
        log.info("HACS auto-scan cooldown skip: %s@%s", full_name, version)
        return

    from app.scanner.hacs_list import repo_to_url

    url = repo_to_url(full_name)
    if not url:
        return

    mark_scanned(full_name, version)
    log.info("HACS auto-scan (%s): %s@%s", action, full_name, version)
    cb = _scan_cb or _default_scan
    try:
        await cb(url, full_name, version)
    except Exception as e:
        log.exception("HACS auto-scan callback error for %s: %s", full_name, e)


def _spawn_scan(full_name: str, version: str, action: str) -> None:
    """Run a scan without holding up the WebSocket loop (a scan takes minutes)."""
    task = asyncio.create_task(_trigger_scan(full_name, version, action))
    _scan_tasks.add(task)
    task.add_done_callback(_scan_tasks.discard)


async def _apply_snapshot_changes(installed: list[dict]) -> None:
    global _snapshot
    new_snap = snapshot_from_installed(installed)
    if _snapshot:
        for change in snapshot_diff(_snapshot, new_snap):
            _spawn_scan(change["full_name"], change["version"], change["action"])
    _snapshot = new_snap


async def _watch_session(ha_url: str, token: str) -> None:
    """One authenticated WebSocket session with event subscribe + snapshot fallback."""
    import websockets

    from app.scanner.hacs_list import fetch_installed_hacs

    ws_url, ssl_ctx = _ws_url_and_ssl(ha_url)
    async with websockets.connect(ws_url, ssl=ssl_ctx, max_size=20 * 1024 * 1024) as ws:
        await ws.recv()  # auth_required
        await ws.send(json.dumps({"type": "auth", "access_token": token}))
        auth_resp = json.loads(await ws.recv())
        if auth_resp.get("type") != "auth_ok":
            raise RuntimeError(f"HA auth failed: {auth_resp}")

        sub_id = _next_id()
        await ws.send(json.dumps({
            "id": sub_id,
            "type": "hacs/subscribe",
            "signal": HACS_REPOSITORY_SIGNAL,
        }))
        sub_resp = json.loads(await ws.recv())
        if not sub_resp.get("success", False):
            # Older HACS or HACS missing: the snapshot poll still works.
            log.warning("hacs/subscribe failed, polling only: %s", sub_resp)

        # Seed snapshot
        try:
            installed = await fetch_installed_hacs(ha_url, token)
            await _apply_snapshot_changes(installed)
        except Exception as e:
            log.warning("HACS autoscan initial snapshot failed: %s", e)

        log.info("HACS autoscan watcher connected")

        last_poll = time.monotonic()
        while _enabled:
            timeout = max(1.0, SNAPSHOT_INTERVAL_SECONDS - (time.monotonic() - last_poll))
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
            except asyncio.TimeoutError:
                raw = None

            if raw is not None:
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if msg.get("type") == "event" and msg.get("id") == sub_id:
                    repo = parse_hacs_signal(msg.get("event"))
                    if repo:
                        log.info("HACS install signal for %s", repo)
                        # Snapshot in SIGNAL_SNAPSHOT_DELAY_SECONDS, not now.
                        last_poll = min(
                            last_poll,
                            time.monotonic()
                            - SNAPSHOT_INTERVAL_SECONDS
                            + SIGNAL_SNAPSHOT_DELAY_SECONDS,
                        )

            if time.monotonic() - last_poll >= SNAPSHOT_INTERVAL_SECONDS:
                last_poll = time.monotonic()
                try:
                    installed = await fetch_installed_hacs(ha_url, token)
                    await _apply_snapshot_changes(installed)
                except Exception as e:
                    log.warning("HACS autoscan snapshot poll failed: %s", e)


async def _watcher_loop() -> None:
    """Reconnect loop with exponential backoff."""
    from app.config import settings

    backoff = _RECONNECT_BASE
    while _enabled:
        token = settings.ha_token
        if not token:
            log.warning("HACS autoscan: no HA token configured - idling")
            await asyncio.sleep(60)
            continue

        try:
            await _watch_session(settings.ha_url, token)
            backoff = _RECONNECT_BASE
        except asyncio.CancelledError:
            raise
        except Exception as e:
            if not _enabled:
                break
            log.warning("HACS autoscan WS disconnected: %s - retry in %.0fs", e, backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, _RECONNECT_MAX)


def start(scan_callback: Callable[[str, str, str], Awaitable[None]] | None = None) -> None:
    """Start the HACS install/update watcher."""
    global _task, _enabled, _scan_cb
    _enabled = True
    if scan_callback is not None:
        _scan_cb = scan_callback

    if _task and not _task.done():
        log.info("HACS autoscan watcher already running")
        return

    _task = asyncio.create_task(_watcher_loop())
    log.info("HACS autoscan watcher enabled")


def stop() -> None:
    """Stop the HACS watcher."""
    global _task, _enabled
    _enabled = False
    if _task and not _task.done():
        _task.cancel()
        _task = None
    log.info("HACS autoscan watcher disabled")


def status() -> dict:
    """Return watcher status."""
    return {
        "enabled": _enabled,
        "running": _task is not None and not _task.done() if _task else False,
        "snapshot_size": len(_snapshot),
        "cooldown_entries": len(_last_scanned),
        "cooldown_seconds": COOLDOWN_SECONDS,
        "snapshot_interval_seconds": SNAPSHOT_INTERVAL_SECONDS,
    }
