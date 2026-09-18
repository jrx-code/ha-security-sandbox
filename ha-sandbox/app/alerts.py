"""Notification alerts for critical/high scan findings.

Sends HA persistent notifications, MQTT alerts, and optional mobile push
when findings meet the configured severity threshold. Failures never fail
the scan pipeline.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from app import settings as app_settings
from app.models import Finding, ScanJob, ScanStatus, Severity

log = logging.getLogger(__name__)

SEVERITY_RANK: dict[str, int] = {
    Severity.CRITICAL.value: 4,
    Severity.HIGH.value: 3,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 1,
    Severity.INFO.value: 0,
}

VALID_THRESHOLDS = ("critical", "high", "medium")

_cooldown_until: dict[str, float] = {}


def reset_rate_limits() -> None:
    """Clear in-memory cooldowns (for tests)."""
    _cooldown_until.clear()


def _sev_value(severity: Severity | str) -> str:
    return severity.value if isinstance(severity, Severity) else str(severity).lower()


def severity_meets_threshold(severity: Severity | str, threshold: str) -> bool:
    """True if finding severity is at or above threshold."""
    sev = _sev_value(severity)
    thr = (threshold or "critical").lower()
    return SEVERITY_RANK.get(sev, -1) >= SEVERITY_RANK.get(thr, 4)


def filter_alertable_findings(findings: list[Finding], threshold: str) -> list[Finding]:
    """Return findings at or above the severity threshold, highest first."""
    matched = [f for f in findings if severity_meets_threshold(f.severity, threshold)]
    matched.sort(key=lambda f: SEVERITY_RANK.get(_sev_value(f.severity), 0), reverse=True)
    return matched


def component_key(job: ScanJob) -> str:
    """Stable id for notification_id and rate-limit bucket."""
    if job.manifest and job.manifest.domain:
        return job.manifest.domain
    if job.name:
        return job.name
    return job.id or "unknown"


def format_alert_message(
    job: ScanJob, findings: list[Finding], *, max_items: int = 5,
) -> tuple[str, str]:
    """Build (title, message) for HA notifications / MQTT."""
    component = component_key(job)
    counts: dict[str, int] = {}
    for f in findings:
        key = _sev_value(f.severity)
        counts[key] = counts.get(key, 0) + 1
    parts = [
        f"{counts[s]} {s}"
        for s in ("critical", "high", "medium", "low", "info")
        if s in counts
    ]
    summary = ", ".join(parts) if parts else f"{len(findings)} findings"
    title = f"HA Sandbox: {component} — {summary}"

    lines = [
        f"Scan of '{component}' found {len(findings)} finding(s) at/above alert threshold.",
    ]
    if job.repo_url:
        lines.append(f"Repo: {job.repo_url}")
    for f in findings[:max_items]:
        loc = f.file + (f":{f.line}" if f.line else "")
        desc = (f.description or "")[:120]
        lines.append(f"- [{_sev_value(f.severity)}] {f.category} @ {loc}: {desc}")
    if len(findings) > max_items:
        lines.append(f"...and {len(findings) - max_items} more")
    return title, "\n".join(lines)


def _rate_limit_key(component: str, threshold: str) -> str:
    return f"{component}|{threshold}"


def is_rate_limited(component: str, threshold: str, cooldown_seconds: int) -> bool:
    key = _rate_limit_key(component, threshold)
    return _cooldown_until.get(key, 0.0) > time.monotonic()


def mark_alerted(component: str, threshold: str, cooldown_seconds: int) -> None:
    key = _rate_limit_key(component, threshold)
    _cooldown_until[key] = time.monotonic() + max(0, int(cooldown_seconds))


def notification_id_for(component: str) -> str:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in component)[:48]
    return f"ha_sandbox_{safe or 'unknown'}"


async def create_persistent_notification(
    ha_url: str,
    ha_token: str,
    notification_id: str,
    title: str,
    message: str,
    *,
    client: httpx.AsyncClient | None = None,
) -> bool:
    """POST /api/services/persistent_notification/create."""
    if not ha_url or not ha_token:
        log.debug("Skipping persistent_notification: missing ha_url/ha_token")
        return False
    url = f"{ha_url.rstrip('/')}/api/services/persistent_notification/create"
    headers = {"Authorization": f"Bearer {ha_token}", "Content-Type": "application/json"}
    payload = {
        "notification_id": notification_id,
        "title": title,
        "message": message,
    }
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=15.0, verify=False)
    assert client is not None
    try:
        resp = await client.post(url, headers=headers, json=payload)
        resp.raise_for_status()
        return True
    finally:
        if own_client:
            await client.aclose()


async def call_notify_service(
    ha_url: str,
    ha_token: str,
    service: str,
    title: str,
    message: str,
    *,
    client: httpx.AsyncClient | None = None,
) -> bool:
    """POST /api/services/{domain}/{service} for optional mobile push."""
    if not service or not ha_url or not ha_token:
        return False
    parts = service.strip().split(".", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        log.warning("Invalid alert_notify_service %r (expected domain.service)", service)
        return False
    domain, svc = parts
    url = f"{ha_url.rstrip('/')}/api/services/{domain}/{svc}"
    headers = {"Authorization": f"Bearer {ha_token}", "Content-Type": "application/json"}
    payload = {"title": title, "message": message}
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=15.0, verify=False)
    assert client is not None
    try:
        resp = await client.post(url, headers=headers, json=payload)
        resp.raise_for_status()
        return True
    finally:
        if own_client:
            await client.aclose()


def _alert_config() -> dict[str, Any]:
    cfg = app_settings.load()
    threshold = str(cfg.get("alert_severity_threshold", "critical")).lower()
    if threshold not in VALID_THRESHOLDS:
        threshold = "critical"
    try:
        cooldown = int(cfg.get("alert_cooldown_seconds", 3600))
    except (TypeError, ValueError):
        cooldown = 3600
    return {
        "enabled": bool(cfg.get("alerts_enabled", True)),
        "threshold": threshold,
        "cooldown_seconds": max(0, cooldown),
        "notify_service": str(cfg.get("alert_notify_service", "") or "").strip(),
        "ha_url": str(cfg.get("ha_url", "") or ""),
        "ha_token": str(cfg.get("ha_token", "") or ""),
        "mqtt_enabled": bool(cfg.get("mqtt_enabled", True)),
    }


async def maybe_alert(job: ScanJob) -> dict[str, Any] | None:
    """Send alerts after a successful scan if findings meet threshold.

    Returns a status dict. Never raises — MQTT/HA failures are logged only.
    """
    try:
        if job.status != ScanStatus.DONE:
            return {"skipped": "not_done"}

        cfg = _alert_config()
        if not cfg["enabled"]:
            return {"skipped": "disabled"}

        alertable = filter_alertable_findings(job.findings, cfg["threshold"])
        if not alertable:
            return {"skipped": "no_findings"}

        component = component_key(job)
        if is_rate_limited(component, cfg["threshold"], cfg["cooldown_seconds"]):
            log.info(
                "Alert rate-limited for %s (threshold=%s, cooldown=%ss)",
                component, cfg["threshold"], cfg["cooldown_seconds"],
            )
            return {"skipped": "rate_limited", "component": component}

        title, message = format_alert_message(job, alertable)
        nid = notification_id_for(component)
        result: dict[str, Any] = {
            "component": component,
            "threshold": cfg["threshold"],
            "count": len(alertable),
            "notification_id": nid,
            "title": title,
            "persistent_notification": False,
            "mqtt": False,
            "notify_service": False,
        }

        try:
            result["persistent_notification"] = await create_persistent_notification(
                cfg["ha_url"], cfg["ha_token"], nid, title, message,
            )
        except Exception as e:
            log.warning("HA persistent_notification failed: %s", e)

        if cfg["mqtt_enabled"]:
            try:
                from app.report.mqtt import publish_finding_alert
                publish_finding_alert(job, alertable, title=title, message=message)
                result["mqtt"] = True
            except Exception as e:
                log.warning("MQTT finding alert failed: %s", e)

        if cfg["notify_service"]:
            try:
                result["notify_service"] = await call_notify_service(
                    cfg["ha_url"], cfg["ha_token"], cfg["notify_service"], title, message,
                )
            except Exception as e:
                log.warning("HA notify service failed: %s", e)

        mark_alerted(component, cfg["threshold"], cfg["cooldown_seconds"])
        log.info(
            "Alert sent for %s (%d findings >= %s)",
            component, len(alertable), cfg["threshold"],
        )
        return result
    except Exception as e:
        log.warning("maybe_alert failed (non-fatal): %s", e)
        return {"error": str(e)}
