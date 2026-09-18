"""HACS install/update auto-scan watcher via HA WebSocket events."""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
import time
from collections.abc import Awaitable, Callable
from typing import Any

log = logging.getLogger(__name__)

# Event types HACS may fire on install/update
HACS_EVENT_TYPES = ("hacs/repository", "hacs_repository")

# Actions that should trigger a scan
_SCAN_ACTIONS = frozenset({
    "download", "install", "installed", "update", "updated",
    "upgrade", "register",
})

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


def parse_hacs_event(event: dict[str, Any]) -> dict[str, str] | None:
    """Parse a HA WebSocket event into a scan decision.

    Returns dict with keys: full_name, version, action - or None if not actionable.
    """
    event_type = event.get("event_type") or event.get("type") or ""
    if event_type not in HACS_EVENT_TYPES and not str(event_type).startswith("hacs"):
        # Still allow if nested under "event" envelope from subscribe_events
        pass

    data = event.get("data") or event.get("event") or event
    if isinstance(data, dict) and "data" in data and "event_type" in data:
        # unwrap {event_type, data} nested once
        event_type = data.get("event_type", event_type)
        data = data.get("data") or data

    if not isinstance(data, dict):
        return None

    action = str(
        data.get("action")
        or data.get("type")
        or data.get("event")
        or ""
    ).lower()

    # Repository identity - HACS payloads vary
    repo = data.get("repository") or data.get("repo") or {}
    if isinstance(repo, dict):
        full_name = (
            repo.get("full_name")
            or repo.get("repository")
            or repo.get("full_name")
            or ""
        )
        version = str(
            repo.get("installed_version")
            or repo.get("version")
            or repo.get("available_version")
            or data.get("installed_version")
            or data.get("version")
            or ""
        )
    else:
        full_name = str(repo or data.get("full_name") or "")
        version = str(
            data.get("installed_version")
            or data.get("version")
            or ""
        )

    if not full_name:
        return None

    # Thin payloads without an action still warrant a scan if we got a repo name
    # from a known HACS event type; otherwise require an install/update action.
    if action and action not in _SCAN_ACTIONS:
        return None
    if not action and event_type not in HACS_EVENT_TYPES:
        return None
    if not action:
        action = "update"

    return {
        "full_name": full_name,
        "version": version,
        "action": action,
    }


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
    """Create storage job, run scan, MQTT-alert on critical/DANGER findings."""
    from app import storage
    from app.models import Severity
    from app.report.mqtt import publish_critical_alert, publish_status
    from app.scanner.pipeline import run_scan

    job_id = f"hacs:{name}"
    storage.create_job(job_id, name, url, batch_id="hacs_autoscan")
    publish_status(f"hacs_autoscan:{name}")
    try:
        job = await run_scan(url, name)
        storage.complete_job(job_id)

        critical = [f for f in job.findings if f.severity == Severity.CRITICAL]
        is_danger = job.ai_score is not None and job.ai_score < 5
        if critical or is_danger:
            parts = [
                f"[{f.severity.value}] {f.category}: {f.description[:120]}"
                for f in critical[:5]
            ]
            if is_danger and job.ai_score is not None:
                parts.insert(0, f"AI score {job.ai_score}/10 (DANGER)")
            if not parts:
                parts.append(f"{job.critical_count} critical / score={job.ai_score}")
            summary = f"{name}@{version}: " + "; ".join(parts)
            publish_critical_alert(name, summary)
    except Exception as e:
        storage.fail_job(job_id, str(e))
        log.warning("HACS auto-scan failed for %s: %s", name, e)
    finally:
        publish_status("idle")
        storage.cleanup_repo_cache()


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


async def _apply_snapshot_changes(installed: list[dict]) -> None:
    global _snapshot
    new_snap = snapshot_from_installed(installed)
    if _snapshot:
        for change in snapshot_diff(_snapshot, new_snap):
            await _trigger_scan(change["full_name"], change["version"], change["action"])
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

        for etype in HACS_EVENT_TYPES:
            await ws.send(json.dumps({
                "id": _next_id(),
                "type": "subscribe_events",
                "event_type": etype,
            }))
            sub_resp = json.loads(await ws.recv())
            if not sub_resp.get("success", True) and sub_resp.get("type") == "result":
                log.warning("subscribe_events %s failed: %s", etype, sub_resp)

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
                if msg.get("type") == "event":
                    event = msg.get("event") or {}
                    parsed = parse_hacs_event(event)
                    if parsed:
                        await _trigger_scan(
                            parsed["full_name"], parsed["version"], parsed["action"],
                        )
                    else:
                        # Thin payload - refresh snapshot soon
                        last_poll = 0

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
