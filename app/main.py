"""HA Sandbox Analyzer — FastAPI application."""

import logging
import shutil
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app import settings as app_settings
from app.ai.ollama import list_ollama_models, test_ollama, test_public_api
from app.report.generator import load_all_reports
from app.report.mqtt import disconnect, publish_discovery, publish_status
from app.scanner.hacs_list import fetch_installed_hacs, repo_to_url, test_ha_connection
from app.scanner.pipeline import run_scan

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

_active_jobs: dict[str, dict] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("HA Sandbox Analyzer starting")
    app_settings.init_from_env()
    try:
        publish_discovery()
        publish_status("idle")
    except Exception as e:
        log.warning("MQTT init failed (non-fatal): %s", e)
    yield
    disconnect()


__version__ = "0.4.0"

app = FastAPI(title="HA Sandbox Analyzer", version=__version__, lifespan=lifespan)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "web" / "templates"))


async def _run_scan_background(repo_url: str, name: str):
    job_id = f"{name or repo_url}"
    _active_jobs[job_id] = {"status": "running", "name": name, "url": repo_url}
    try:
        job = await run_scan(repo_url, name)
        _active_jobs[job_id] = {
            "status": job.status.value, "name": job.name,
            "score": job.ai_score, "findings": len(job.findings),
        }
    except Exception as e:
        _active_jobs[job_id] = {"status": "failed", "error": str(e)}


# --- Pages ---

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    reports = load_all_reports()
    return templates.TemplateResponse("index.html", {
        "request": request, "reports": reports, "active_jobs": _active_jobs,
    })


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    cfg = app_settings.load()
    return templates.TemplateResponse("settings.html", {
        "request": request, "cfg": cfg,
        "provider_presets": app_settings.PROVIDER_PRESETS,
    })


# --- Scan API ---

@app.post("/scan/url")
async def scan_url(background_tasks: BackgroundTasks, url: str = Form(...), name: str = Form("")):
    if not url.startswith("http"):
        url = f"https://github.com/{url}.git"
    background_tasks.add_task(_run_scan_background, url, name)
    return RedirectResponse("/#results", status_code=303)


@app.post("/scan/repo")
async def scan_repo(background_tasks: BackgroundTasks, repo: str = Form(...), name: str = Form("")):
    url = repo_to_url(repo)
    background_tasks.add_task(_run_scan_background, url, name)
    return RedirectResponse("/#results", status_code=303)


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
    return JSONResponse(content={"active_jobs": _active_jobs})


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
