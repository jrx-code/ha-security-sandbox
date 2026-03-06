"""HA Sandbox Analyzer — FastAPI application."""

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.report.generator import load_all_reports
from app.report.mqtt import disconnect, publish_discovery, publish_status
from app.scanner.hacs_list import fetch_installed_hacs, repo_to_url
from app.scanner.pipeline import run_scan

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# In-memory scan tracking
_active_jobs: dict[str, dict] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("HA Sandbox Analyzer starting")
    try:
        publish_discovery()
        publish_status("idle")
    except Exception as e:
        log.warning("MQTT init failed (non-fatal): %s", e)
    yield
    disconnect()


app = FastAPI(title="HA Sandbox Analyzer", version="1.0.0", lifespan=lifespan)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "web" / "templates"))


async def _run_scan_background(repo_url: str, name: str):
    """Background task wrapper for scan pipeline."""
    job_id = f"{name or repo_url}"
    _active_jobs[job_id] = {"status": "running", "name": name, "url": repo_url}
    try:
        job = await run_scan(repo_url, name)
        _active_jobs[job_id] = {
            "status": job.status.value,
            "name": job.name,
            "score": job.ai_score,
            "findings": len(job.findings),
        }
    except Exception as e:
        _active_jobs[job_id] = {"status": "failed", "error": str(e)}


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    reports = load_all_reports()
    return templates.TemplateResponse("index.html", {
        "request": request,
        "reports": reports,
        "active_jobs": _active_jobs,
    })


@app.post("/scan/url")
async def scan_url(background_tasks: BackgroundTasks, url: str = Form(...), name: str = Form("")):
    """Start scan from custom URL."""
    if not url.startswith("http"):
        url = f"https://github.com/{url}.git"
    background_tasks.add_task(_run_scan_background, url, name)
    return RedirectResponse("/", status_code=303)


@app.post("/scan/repo")
async def scan_repo(background_tasks: BackgroundTasks, repo: str = Form(...), name: str = Form("")):
    """Start scan from HACS repo full name."""
    url = repo_to_url(repo)
    background_tasks.add_task(_run_scan_background, url, name)
    return RedirectResponse("/", status_code=303)


@app.get("/api/installed")
async def api_installed():
    """Get list of installed HACS components from HA."""
    components = await fetch_installed_hacs()
    return JSONResponse(content=components)


@app.get("/api/reports")
async def api_reports():
    """Get all scan reports."""
    return JSONResponse(content=load_all_reports())


@app.get("/api/report/{report_id}")
async def api_report(report_id: str):
    """Get single report by ID."""
    reports = load_all_reports()
    for r in reports:
        if r.get("id") == report_id:
            return JSONResponse(content=r)
    return JSONResponse(content={"error": "not found"}, status_code=404)


@app.get("/api/status")
async def api_status():
    """Current scan status."""
    return JSONResponse(content={"active_jobs": _active_jobs})
