"""Scan pipeline: orchestrates fetch -> static analysis -> AI review -> report."""

import logging
import uuid
from pathlib import Path

from app.models import ComponentType, ScanJob, ScanStatus
from app.scanner.fetch import fetch_and_parse
from app.scanner.static_js import scan_js_repo
from app.scanner.static_python import scan_python_repo
from app.scanner.static_yaml import scan_yaml_repo
from app.scanner.static_ha import scan_ha_repo
from app.scanner.cve_lookup import check_cve
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
        log.info("[%s] Phase 1: cloning %s", job.id, repo_url)
        publish_status(f"cloning:{job.name or repo_url}")
        repo_path = fetch_and_parse(job)
        log.info("[%s] Phase 1 done: type=%s, name=%s", job.id,
                 job.manifest.component_type.value if job.manifest else "?", job.name)

        # Phase 1b: CVE lookup for dependencies
        if job.manifest and job.manifest.requirements:
            log.info("[%s] Phase 1b: CVE lookup for %d dependencies", job.id, len(job.manifest.requirements))
            cve_findings = await check_cve(job.manifest)
            if cve_findings:
                log.info("[%s] CVE lookup: %d vulnerabilities found", job.id, len(cve_findings))
                job.findings.extend(cve_findings)

        # Phase 2: Static analysis
        job.status = ScanStatus.SCANNING
        log.info("[%s] Phase 2: static analysis", job.id)
        publish_status(f"scanning:{job.name}")

        comp_type = job.manifest.component_type if job.manifest else ComponentType.UNKNOWN
        if comp_type in (ComponentType.INTEGRATION, ComponentType.PYTHON_SCRIPT, ComponentType.UNKNOWN):
            py_findings = scan_python_repo(repo_path)
            log.info("[%s] Python scanner: %d findings", job.id, len(py_findings))
            job.findings.extend(py_findings)
        if comp_type in (ComponentType.CARD, ComponentType.UNKNOWN):
            js_findings = scan_js_repo(repo_path)
            log.info("[%s] JS scanner: %d findings", job.id, len(js_findings))
            job.findings.extend(js_findings)

        # YAML/Jinja2 scan (all component types)
        yaml_findings = scan_yaml_repo(repo_path)
        if yaml_findings:
            log.info("[%s] YAML scanner: %d findings", job.id, len(yaml_findings))
            job.findings.extend(yaml_findings)

        # HA API pattern scan (integrations only)
        if comp_type in (ComponentType.INTEGRATION, ComponentType.PYTHON_SCRIPT, ComponentType.UNKNOWN):
            ha_findings = scan_ha_repo(repo_path)
            if ha_findings:
                log.info("[%s] HA API scanner: %d findings", job.id, len(ha_findings))
                job.findings.extend(ha_findings)

        # Phase 4: AI review
        job.status = ScanStatus.AI_REVIEW
        log.info("[%s] Phase 4: AI review (%d static findings)", job.id, len(job.findings))
        publish_status(f"ai_review:{job.name}")
        await ai_review(job, repo_path)
        log.info("[%s] Phase 4 done: score=%s", job.id, job.ai_score)

        # Phase 5: Report
        job.status = ScanStatus.DONE
        report_path = generate_report(job)
        publish_scan_result(job)
        log.info("[%s] Done: %d findings, score=%s", job.id, len(job.findings), job.ai_score)

    except Exception as e:
        log.exception("Scan failed for %s", repo_url)
        job.status = ScanStatus.FAILED
        job.error = str(e)
        publish_status(f"failed:{job.name}")

    return job
