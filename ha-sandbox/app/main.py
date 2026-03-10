"""HA Sandbox Analyzer — FastAPI application (HA Add-on)."""

import asyncio
import logging
import os
import shutil
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from app import settings as app_settings
from app import storage
from app.ai.ollama import list_ollama_models, test_ollama, test_public_api
from app.report.generator import export_csv, export_html, export_pdf, load_all_reports, load_report
from app.report.mqtt import disconnect, publish_discovery, publish_status
from app.scanner.hacs_list import fetch_installed_hacs, repo_to_url, test_ha_connection
from app.scanner.pipeline import run_scan
from app import scheduler

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


def _read_version() -> str:
    """Read version from config.yaml (HA add-on single source of truth)."""
    for p in (Path("/config.yaml"), Path(__file__).parents[1] / "config.yaml"):
        if p.exists():
            for line in p.read_text().splitlines():
                if line.startswith("version:"):
                    return line.split(":", 1)[1].strip().strip('"').strip("'")
    return os.environ.get("BUILD_VERSION", "dev")


__version__ = _read_version()


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("HA Sandbox Analyzer v%s starting", __version__)
    app_settings.init_from_env()
    storage.init()
    storage.cleanup_old()
    storage.cleanup_repo_cache()
    try:
        publish_discovery()
        publish_status("idle")
    except Exception as e:
        log.warning("MQTT init failed (non-fatal): %s", e)
    # Start scheduled scans if enabled
    cfg = app_settings.load()
    if cfg.get("schedule_enabled"):
        scheduler.start(cfg.get("schedule_interval_hours", 24))
    yield
    scheduler.stop()
    storage.close()
    disconnect()


app = FastAPI(title="HA Sandbox Analyzer", version=__version__, lifespan=lifespan)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "web" / "templates"))

# Rate limiting: max 3 concurrent scans
_scan_semaphore = asyncio.Semaphore(3)


@app.middleware("http")
async def ingress_middleware(request: Request, call_next):
    """Support HA ingress by reading X-Ingress-Path header."""
    ingress_path = request.headers.get("X-Ingress-Path", "")
    request.state.ingress_path = ingress_path
    # Normalize double-slash from ingress proxy (GET // → redirect to /)
    if request.url.path != "/" and request.url.path.startswith("//"):
        return RedirectResponse(request.url.path.replace("//", "/", 1), status_code=301)
    response = await call_next(request)
    return response


async def _run_scan_background(repo_url: str, name: str, batch_id: str = ""):
    job_id = f"{name or repo_url}"
    storage.create_job(job_id, name, repo_url, batch_id=batch_id)
    async with _scan_semaphore:
        try:
            job = await run_scan(repo_url, name)
            storage.complete_job(job_id)
            if batch_id:
                storage.batch_job_done(batch_id, success=True)
        except Exception as e:
            storage.fail_job(job_id, str(e))
            if batch_id:
                storage.batch_job_done(batch_id, success=False)
    storage.cleanup_repo_cache()


async def _run_batch_background(batch_id: str, repos: list[dict]):
    """Process a batch of repos sequentially."""
    for item in repos:
        url = item["url"]
        name = item.get("name", "")
        await _run_scan_background(url, name, batch_id=batch_id)


# --- Pages ---

def _ctx(request: Request, extra: dict | None = None) -> dict:
    """Build template context with ingress base path."""
    ctx = {"request": request, "base": getattr(request.state, "ingress_path", ""), "version": __version__}
    if extra:
        ctx.update(extra)
    return ctx


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    reports = load_all_reports()
    return templates.TemplateResponse("index.html", _ctx(request, {
        "reports": reports, "active_jobs": storage.get_active_jobs(),
    }))


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    cfg = app_settings.load()
    return templates.TemplateResponse("settings.html", _ctx(request, {
        "cfg": cfg, "provider_presets": app_settings.PROVIDER_PRESETS,
    }))


# --- Scan API ---

@app.post("/scan/url")
async def scan_url(request: Request, background_tasks: BackgroundTasks, url: str = Form(...), name: str = Form("")):
    if not url.startswith("http"):
        url = f"https://github.com/{url}.git"
    background_tasks.add_task(_run_scan_background, url, name)
    base = getattr(request.state, "ingress_path", "")
    return RedirectResponse(f"{base}/#results", status_code=303)


@app.post("/scan/repo")
async def scan_repo(request: Request, background_tasks: BackgroundTasks, repo: str = Form(...), name: str = Form("")):
    url = repo_to_url(repo)
    background_tasks.add_task(_run_scan_background, url, name)
    base = getattr(request.state, "ingress_path", "")
    return RedirectResponse(f"{base}/#results", status_code=303)


# --- Data API ---

@app.get("/api/installed")
async def api_installed():
    return JSONResponse(content=await fetch_installed_hacs())


@app.get("/api/reports")
async def api_reports():
    return JSONResponse(content=load_all_reports())


@app.get("/api/report/{report_id}")
async def api_report(report_id: str):
    report = load_report(report_id)
    if report:
        return JSONResponse(content=report)
    return JSONResponse(content={"error": "not found"}, status_code=404)


@app.get("/api/report/{report_id}/csv")
async def api_report_csv(report_id: str):
    report = load_report(report_id)
    if not report:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    csv_data = export_csv(report)
    return Response(
        content=csv_data, media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{report_id}.csv"'},
    )


@app.get("/api/report/{report_id}/html")
async def api_report_html(report_id: str):
    report = load_report(report_id)
    if not report:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    html = export_html(report)
    return HTMLResponse(content=html)


@app.get("/api/report/{report_id}/pdf")
async def api_report_pdf(report_id: str):
    report = load_report(report_id)
    if not report:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    pdf_bytes = bytes(export_pdf(report))
    return Response(
        content=pdf_bytes, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{report_id}.pdf"'},
    )


@app.get("/api/status")
async def api_status():
    return JSONResponse(content={"active_jobs": storage.get_active_jobs()})


# --- Settings API ---

@app.get("/api/settings")
async def api_settings_get():
    cfg = app_settings.load()
    # Mask secrets
    safe = {**cfg}
    for key in ("ha_token", "public_api_key", "mqtt_pass"):
        if safe.get(key):
            safe[key] = safe[key][:8] + "..." + safe[key][-4:]
    return JSONResponse(content=safe)


@app.post("/api/settings")
async def api_settings_save(request: Request):
    data = await request.json()
    app_settings.save(data)
    return JSONResponse(content={"ok": True})


@app.get("/api/ollama/models")
async def api_ollama_models(url: str = ""):
    cfg = app_settings.load()
    ollama_url = url or cfg.get("ollama_url", "http://ollama:11434")
    models = await list_ollama_models(ollama_url)
    return JSONResponse(content={"models": models})


@app.post("/api/test/ollama")
async def api_test_ollama(request: Request):
    data = await request.json()
    result = await test_ollama(data.get("url", ""), data.get("model", ""))
    return JSONResponse(content=result)


@app.post("/api/test/public")
async def api_test_public(request: Request):
    data = await request.json()
    result = await test_public_api(data.get("url", ""), data.get("api_key", ""), data.get("model", ""))
    return JSONResponse(content=result)


@app.post("/api/test/ha")
async def api_test_ha(request: Request):
    data = await request.json()
    result = await test_ha_connection(data.get("url", ""), data.get("token", ""))
    return JSONResponse(content=result)


@app.post("/api/test/mqtt")
async def api_test_mqtt(request: Request):
    from app.report.mqtt import test_mqtt_connection
    data = await request.json()
    result = test_mqtt_connection(
        data.get("host", ""), int(data.get("port", 8883)),
        data.get("user", ""), data.get("pass", ""), data.get("tls", True),
    )
    return JSONResponse(content=result)


@app.post("/api/cache/clear")
async def api_clear_cache():
    repos_dir = Path(app_settings.get("repos_dir", "/data/repos"))
    if repos_dir.exists():
        shutil.rmtree(repos_dir)
        repos_dir.mkdir(parents=True)
    return JSONResponse(content={"ok": True})


@app.post("/api/reports/clear")
async def api_clear_reports():
    reports_dir = Path(app_settings.get("reports_dir", "/data/reports"))
    if reports_dir.exists():
        shutil.rmtree(reports_dir)
        reports_dir.mkdir(parents=True)
    return JSONResponse(content={"ok": True})


@app.post("/api/scan/batch")
async def api_scan_batch(request: Request, background_tasks: BackgroundTasks):
    """Start a batch scan of multiple repos.

    Body: {"repos": [{"url": "...", "name": "..."}, ...]}
    Returns: {"batch_id": "...", "total": N}
    """
    data = await request.json()
    repos = data.get("repos", [])
    if not repos:
        return JSONResponse(content={"error": "No repos provided"}, status_code=400)

    # Normalize: accept both ["url", ...] and [{"url": "...", "name": "..."}, ...]
    normalized = []
    for item in repos:
        if isinstance(item, str):
            item = {"url": item, "name": ""}
        url = item.get("url", "")
        if not url.startswith("http"):
            item["url"] = f"https://github.com/{url}.git"
        normalized.append(item)
    repos = normalized

    batch_id = uuid.uuid4().hex[:12]
    storage.create_batch(batch_id, len(repos))
    background_tasks.add_task(_run_batch_background, batch_id, repos)
    return JSONResponse(content={"batch_id": batch_id, "total": len(repos)})


@app.get("/api/scan/batch/{batch_id}")
async def api_batch_status(batch_id: str):
    """Get batch scan progress."""
    batch = storage.get_batch(batch_id)
    if not batch:
        return JSONResponse(content={"error": "Batch not found"}, status_code=404)
    return JSONResponse(content=batch)


@app.post("/api/scan/installed")
async def api_scan_installed(request: Request, background_tasks: BackgroundTasks):
    """Scan all installed HACS components (batch mode)."""
    installed = await fetch_installed_hacs()
    if not installed:
        return JSONResponse(content={"error": "No HACS components found or HA unreachable"}, status_code=404)

    repos = []
    for comp in installed:
        url = repo_to_url(comp.get("full_name", ""))
        if url:
            repos.append({"url": url, "name": comp.get("name", comp.get("full_name", ""))})

    if not repos:
        return JSONResponse(content={"error": "No scannable repos found"}, status_code=404)

    batch_id = uuid.uuid4().hex[:12]
    storage.create_batch(batch_id, len(repos))
    background_tasks.add_task(_run_batch_background, batch_id, repos)
    return JSONResponse(content={"batch_id": batch_id, "total": len(repos)})


# --- Whitelist API (L.3) ---

@app.post("/api/whitelist")
async def api_whitelist_add(request: Request):
    """Add a finding to the whitelist (mark as false positive)."""
    data = await request.json()
    category = data.get("category", "")
    file_pattern = data.get("file_pattern", "")
    description = data.get("description", "")
    reason = data.get("reason", "")
    if not category:
        return JSONResponse(content={"error": "category required"}, status_code=400)
    ph = storage.add_whitelist(category, file_pattern, description, reason)
    return JSONResponse(content={"ok": True, "pattern_hash": ph})


@app.delete("/api/whitelist/{pattern_hash}")
async def api_whitelist_remove(pattern_hash: str):
    ok = storage.remove_whitelist(pattern_hash)
    if not ok:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    return JSONResponse(content={"ok": True})


@app.get("/api/whitelist")
async def api_whitelist_list():
    return JSONResponse(content=storage.get_whitelist())


# --- Reputation API (L.4) ---

@app.get("/api/reputation/{domain}")
async def api_reputation(domain: str):
    from app.learning.reputation import get_reputation
    conn = storage.get_conn()
    rep = get_reputation(conn, domain=domain)
    if not rep:
        return JSONResponse(content={"error": "no history"}, status_code=404)
    return JSONResponse(content=rep)


@app.get("/api/reputation")
async def api_reputation_all():
    from app.learning.reputation import get_all_reputations
    conn = storage.get_conn()
    return JSONResponse(content=get_all_reputations(conn))


# --- Scheduler API ---

@app.get("/api/scheduler")
async def api_scheduler_status():
    return JSONResponse(content=scheduler.status())


@app.post("/api/scheduler")
async def api_scheduler_update(request: Request):
    """Enable/disable scheduled scans.

    Body: {"enabled": true/false, "interval_hours": 24}
    """
    data = await request.json()
    enabled = data.get("enabled", False)
    interval = float(data.get("interval_hours", 24))

    app_settings.save({"schedule_enabled": enabled, "schedule_interval_hours": interval})

    if enabled and interval > 0:
        scheduler.start(interval)
    else:
        scheduler.stop()

    return JSONResponse(content={"ok": True, **scheduler.status()})


@app.get("/api/system")
async def api_system_info():
    repos_dir = Path(app_settings.get("repos_dir", "/data/repos"))
    reports_dir = Path(app_settings.get("reports_dir", "/data/reports"))
    repo_count = len(list(repos_dir.iterdir())) if repos_dir.exists() else 0
    repo_size = sum(f.stat().st_size for f in repos_dir.rglob("*") if f.is_file()) if repos_dir.exists() else 0
    report_count = len(list(reports_dir.glob("*.json"))) if reports_dir.exists() else 0
    return JSONResponse(content={
        "version": __version__,
        "reports": report_count,
        "repos_cached": repo_count,
        "cache_size_mb": round(repo_size / 1024 / 1024, 1),
        "scheduler": scheduler.status(),
    })
