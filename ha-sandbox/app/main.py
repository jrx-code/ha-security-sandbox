"""HA Sandbox Analyzer — FastAPI application (HA Add-on)."""

import logging
import os
import shutil
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app import settings as app_settings
from app import storage
from app.ai.ollama import list_ollama_models, test_ollama, test_public_api
from app.report.generator import load_all_reports
from app.report.mqtt import disconnect, publish_discovery, publish_status
from app.scanner.hacs_list import fetch_installed_hacs, repo_to_url, test_ha_connection
from app.scanner.pipeline import run_scan

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
    try:
        publish_discovery()
        publish_status("idle")
    except Exception as e:
        log.warning("MQTT init failed (non-fatal): %s", e)
    yield
    storage.close()
    disconnect()


app = FastAPI(title="HA Sandbox Analyzer", version=__version__, lifespan=lifespan)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "web" / "templates"))


@app.middleware("http")
async def ingress_middleware(request: Request, call_next):
    """Support HA ingress by reading X-Ingress-Path header."""
    ingress_path = request.headers.get("X-Ingress-Path", "")
    request.state.ingress_path = ingress_path
    response = await call_next(request)
    return response


async def _run_scan_background(repo_url: str, name: str, batch_id: str = ""):
    job_id = f"{name or repo_url}"
    storage.create_job(job_id, name, repo_url, batch_id=batch_id)
    try:
        job = await run_scan(repo_url, name)
        storage.complete_job(job_id)
        if batch_id:
            storage.batch_job_done(batch_id, success=True)
    except Exception as e:
        storage.fail_job(job_id, str(e))
        if batch_id:
            storage.batch_job_done(batch_id, success=False)


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
    for r in load_all_reports():
        if r.get("id") == report_id:
            return JSONResponse(content=r)
    return JSONResponse(content={"error": "not found"}, status_code=404)


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

    # Normalize URLs
    for item in repos:
        url = item.get("url", "")
        if not url.startswith("http"):
            item["url"] = f"https://github.com/{url}.git"

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
    })
