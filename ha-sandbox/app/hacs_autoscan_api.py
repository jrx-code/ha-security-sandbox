"""HTTP API for the HACS auto-scan watcher. Routes are attached in app.main."""

from __future__ import annotations

import logging

from fastapi import Request
from fastapi.responses import JSONResponse

from app import hacs_watcher
from app import settings as app_settings

log = logging.getLogger(__name__)
_registered = False


def register_routes(app) -> None:
    """Idempotently attach /api/hacs-autoscan to the FastAPI app."""
    global _registered
    if _registered:
        return

    @app.get("/api/hacs-autoscan")
    async def api_hacs_autoscan_status():
        return JSONResponse(content=hacs_watcher.status())

    @app.post("/api/hacs-autoscan")
    async def api_hacs_autoscan_update(request: Request):
        """Enable/disable HACS install/update auto-scan.

        Body: {"enabled": true/false}
        """
        data = await request.json()
        enabled = bool(data.get("enabled", False))
        app_settings.save({"hacs_autoscan_enabled": enabled})
        if enabled:
            hacs_watcher.start()
        else:
            hacs_watcher.stop()
        return JSONResponse(content={"ok": True, **hacs_watcher.status()})

    _registered = True
    log.info("HACS autoscan API routes registered")

