"""Scan pipeline: orchestrates fetch -> static analysis -> AI review -> report."""

import logging
import uuid
from pathlib import Path

from app.models import ComponentType, ScanJob, ScanStatus
from app.scanner.fetch import fetch_and_parse
from app.scanner.static_js import scan_js_repo
from app.scanner.static_python import scan_python_repo
from app.ai.ollama import ai_review
from app.report.generator import generate_report
from app.report.mqtt import publish_scan_result, publish_status

log = logging.getLogger(__name__)


async def run_scan(repo_url: str, name: str = "") -> ScanJob:
    """Run the full scan pipeline on a repository URL."""
    job = ScanJob(
        id=uuid.uuid4().hex[:12],
        repo_url=repo_url,
        name=name,
    )

    try:
        # Phase 1: Clone and parse
        publish_status(f"cloning:{job.name or repo_url}")
        repo_path = fetch_and_parse(job)

        # Phase 2: Static analysis
        job.status = ScanStatus.SCANNING
        publish_status(f"scanning:{job.name}")

        comp_type = job.manifest.component_type if job.manifest else ComponentType.UNKNOWN
        if comp_type in (ComponentType.INTEGRATION, ComponentType.PYTHON_SCRIPT, ComponentType.UNKNOWN):
            job.findings.extend(scan_python_repo(repo_path))
        if comp_type in (ComponentType.CARD, ComponentType.UNKNOWN):
            job.findings.extend(scan_js_repo(repo_path))

        # Phase 4: AI review
        job.status = ScanStatus.AI_REVIEW
        publish_status(f"ai_review:{job.name}")
        await ai_review(job, repo_path)

        # Phase 5: Report
        job.status = ScanStatus.DONE
        generate_report(job)
        publish_scan_result(job)

    except Exception as e:
        log.exception("Scan failed for %s", repo_url)
        job.status = ScanStatus.FAILED
        job.error = str(e)
        publish_status(f"failed:{job.name}")

    return job
