"""HTTP API for notification alert settings (GET/POST /api/alerts)."""

from __future__ import annotations

import logging

from fastapi import Request
from fastapi.responses import JSONResponse

from app import alerts
from app import settings as app_settings

log = logging.getLogger(__name__)

_registered = False


def _public_alerts_config() -> dict:
    cfg = app_settings.load()
    threshold = str(cfg.get("alert_severity_threshold", "critical")).lower()
    if threshold not in alerts.VALID_THRESHOLDS:
        threshold = "critical"
    try:
        cooldown = int(cfg.get("alert_cooldown_seconds", 3600))
    except (TypeError, ValueError):
        cooldown = 3600
    return {
        "alerts_enabled": bool(cfg.get("alerts_enabled", True)),
        "alert_severity_threshold": threshold,
        "alert_cooldown_seconds": max(0, cooldown),
        "alert_notify_service": str(cfg.get("alert_notify_service", "") or ""),
        "valid_thresholds": list(alerts.VALID_THRESHOLDS),
    }


def register_routes(app) -> None:
    """Idempotently attach /api/alerts to the FastAPI app."""
    global _registered
    if _registered:
        return

    @app.get("/api/alerts")
    async def api_alerts_get():
        return JSONResponse(content=_public_alerts_config())

    @app.post("/api/alerts")
    async def api_alerts_update(request: Request):
        """Update alert settings.

        Body keys (all optional):
          alerts_enabled: bool
          alert_severity_threshold: critical|high|medium
          alert_cooldown_seconds: int
          alert_notify_service: str (e.g. notify.mobile_app_xxx)
        """
        data = await request.json()
        updates: dict = {}

        if "alerts_enabled" in data:
            updates["alerts_enabled"] = bool(data["alerts_enabled"])

        if "alert_severity_threshold" in data:
            thr = str(data["alert_severity_threshold"]).lower()
            if thr not in alerts.VALID_THRESHOLDS:
                return JSONResponse(
                    content={
                        "error": (
                            f"invalid threshold {thr!r}; "
                            f"expected one of {list(alerts.VALID_THRESHOLDS)}"
                        )
                    },
                    status_code=400,
                )
            updates["alert_severity_threshold"] = thr

        if "alert_cooldown_seconds" in data:
            try:
                updates["alert_cooldown_seconds"] = max(0, int(data["alert_cooldown_seconds"]))
            except (TypeError, ValueError):
                return JSONResponse(
                    content={"error": "alert_cooldown_seconds must be an integer"},
                    status_code=400,
                )

        if "alert_notify_service" in data:
            updates["alert_notify_service"] = str(data["alert_notify_service"] or "").strip()

        if updates:
            app_settings.save(updates)

        return JSONResponse(content={"ok": True, **_public_alerts_config()})

    _registered = True
    log.info("Alerts API routes registered")
