"""Scheduled periodic scans of installed HACS components."""

import asyncio
import logging
from datetime import datetime

log = logging.getLogger(__name__)

_task: asyncio.Task | None = None
_interval_hours: float = 0
_enabled: bool = False


async def _scheduled_loop():
    """Run periodic scan of installed HACS components."""
    from app.scanner.hacs_list import fetch_installed_hacs, repo_to_url
    from app.scanner.pipeline import run_scan
    from app import storage
    from app.report.mqtt import publish_status

    while True:
        await asyncio.sleep(_interval_hours * 3600)
        if not _enabled:
            continue

        log.info("Scheduled scan starting (interval=%gh)", _interval_hours)
        publish_status("scheduled_scan")

        try:
            installed = await fetch_installed_hacs()
            if not installed:
                log.warning("Scheduled scan: no HACS components found")
                continue

            scanned = 0
            for comp in installed:
                url = repo_to_url(comp.get("full_name", ""))
                if not url:
                    continue
                name = comp.get("name", comp.get("full_name", ""))
                job_id = f"sched:{name}"
                storage.create_job(job_id, name, url, batch_id="scheduled")
                try:
                    await run_scan(url, name)
                    storage.complete_job(job_id)
                    scanned += 1
                except Exception as e:
                    storage.fail_job(job_id, str(e))
                    log.warning("Scheduled scan failed for %s: %s", name, e)

            log.info("Scheduled scan done: %d/%d components scanned", scanned, len(installed))
            publish_status("idle")
            storage.cleanup_repo_cache()

        except Exception as e:
            log.exception("Scheduled scan loop error: %s", e)
            publish_status("idle")


def start(interval_hours: float = 24):
    """Start the scheduled scan loop."""
    global _task, _interval_hours, _enabled
    if interval_hours <= 0:
        log.info("Scheduled scans disabled (interval=0)")
        return

    _interval_hours = interval_hours
    _enabled = True

    if _task and not _task.done():
        log.info("Scheduler already running, updating interval to %gh", interval_hours)
        return

    _task = asyncio.create_task(_scheduled_loop())
    log.info("Scheduled scans enabled: every %gh", interval_hours)


def stop():
    """Stop the scheduled scan loop."""
    global _task, _enabled
    _enabled = False
    if _task and not _task.done():
        _task.cancel()
        _task = None
    log.info("Scheduled scans disabled")


def status() -> dict:
    """Return scheduler status."""
    return {
        "enabled": _enabled,
        "interval_hours": _interval_hours,
        "running": _task is not None and not _task.done() if _task else False,
    }
