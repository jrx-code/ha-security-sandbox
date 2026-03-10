"""Scheduled periodic scans and CVE watch for installed HACS components."""

import asyncio
import logging
from datetime import datetime

log = logging.getLogger(__name__)

_task: asyncio.Task | None = None
_cve_task: asyncio.Task | None = None
_interval_hours: float = 0
_cve_interval_hours: float = 6
_enabled: bool = False
_cve_enabled: bool = False
_last_cve_alerts: dict[str, list[str]] = {}


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


async def _cve_watch_loop():
    """Lightweight CVE-only check — queries OSV.dev for known deps without full scan."""
    from app.scanner.hacs_list import fetch_installed_hacs, repo_to_url
    from app.scanner.fetch import fetch_and_parse
    from app.scanner.cve_lookup import check_cve, check_cve_repo
    from app.report.mqtt import publish_status
    from app.models import ScanJob

    global _last_cve_alerts

    while True:
        await asyncio.sleep(_cve_interval_hours * 3600)
        if not _cve_enabled:
            continue

        log.info("CVE watch check starting (interval=%gh)", _cve_interval_hours)

        try:
            installed = await fetch_installed_hacs()
            if not installed:
                continue

            new_alerts: dict[str, list[str]] = {}
            for comp in installed:
                url = repo_to_url(comp.get("full_name", ""))
                if not url:
                    continue
                name = comp.get("name", comp.get("full_name", ""))

                try:
                    job = ScanJob(id=f"cve:{name[:8]}", repo_url=url, name=name)
                    repo_path = fetch_and_parse(job)

                    findings = []
                    if job.manifest and job.manifest.requirements:
                        cve_findings = await check_cve(job.manifest)
                        findings.extend(cve_findings)
                    repo_cve = await check_cve_repo(repo_path)
                    findings.extend(repo_cve)

                    if findings:
                        cve_ids = [f.description[:80] for f in findings]
                        prev = _last_cve_alerts.get(name, [])
                        new_cves = [c for c in cve_ids if c not in prev]
                        if new_cves:
                            new_alerts[name] = new_cves
                            log.warning("CVE watch: %s has %d new vulnerabilities", name, len(new_cves))
                        _last_cve_alerts[name] = cve_ids

                except Exception as e:
                    log.warning("CVE watch failed for %s: %s", name, e)

            if new_alerts:
                total = sum(len(v) for v in new_alerts.values())
                publish_status(f"cve_alert:{total}_new")
                log.warning("CVE watch: %d new vulnerabilities across %d components",
                            total, len(new_alerts))
            else:
                log.info("CVE watch: no new vulnerabilities found")

        except Exception as e:
            log.exception("CVE watch loop error: %s", e)


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


def start_cve_watch(interval_hours: float = 6):
    """Start the CVE watch loop (lightweight, CVE-only checks)."""
    global _cve_task, _cve_interval_hours, _cve_enabled
    if interval_hours <= 0:
        log.info("CVE watch disabled (interval=0)")
        return

    _cve_interval_hours = interval_hours
    _cve_enabled = True

    if _cve_task and not _cve_task.done():
        log.info("CVE watch already running, updating interval to %gh", interval_hours)
        return

    _cve_task = asyncio.create_task(_cve_watch_loop())
    log.info("CVE watch enabled: every %gh", interval_hours)


def stop():
    """Stop all scheduled tasks."""
    global _task, _cve_task, _enabled, _cve_enabled
    _enabled = False
    _cve_enabled = False
    if _task and not _task.done():
        _task.cancel()
        _task = None
    if _cve_task and not _cve_task.done():
        _cve_task.cancel()
        _cve_task = None
    log.info("All scheduled tasks disabled")


def status() -> dict:
    """Return scheduler status."""
    return {
        "enabled": _enabled,
        "interval_hours": _interval_hours,
        "running": _task is not None and not _task.done() if _task else False,
        "cve_watch": {
            "enabled": _cve_enabled,
            "interval_hours": _cve_interval_hours,
            "running": _cve_task is not None and not _cve_task.done() if _cve_task else False,
            "active_alerts": len(_last_cve_alerts),
        },
    }


def get_cve_alerts() -> dict[str, list[str]]:
    """Return current CVE alerts from last watch run."""
    return _last_cve_alerts
