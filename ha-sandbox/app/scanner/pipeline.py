"""Scan pipeline: orchestrates fetch -> static analysis -> AI review -> report."""

import asyncio
import logging
import uuid
from pathlib import Path

from app import storage
from app.models import ComponentType, Finding, ScanJob, ScanStatus, Severity
from app.scanner.fetch import fetch_and_parse
from app.scanner.static_js import scan_js_repo
from app.scanner.static_python import scan_python_repo
from app.scanner.static_yaml import scan_yaml_repo
from app.scanner.static_ha import scan_ha_repo
from app.scanner.cve_lookup import check_cve, check_cve_repo
from app.ai.ollama import ai_review
from app.report.generator import generate_report
from app.report.mqtt import publish_scan_result, publish_status
from app.learning.fingerprint import extract_fingerprint, fingerprint_diff
from app.learning.baseline import compute_baseline, check_deviations
from app.learning.reputation import record_scan

log = logging.getLogger(__name__)

# Severity rank for keeping the highest severity on merge
_SEV_RANK = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0}

# Category aliases — different scanners may use different names for the same issue
_CATEGORY_ALIASES: dict[str, str] = {
    "taint_code_injection": "code_injection",
    "taint_command_injection": "command_execution",
    "taint_deserialization": "deserialization",
    "taint_path_traversal": "path_traversal",
    "ha_dynamic_service": "ha_api_risk",
    "script_injection": "xss",
}


def _normalize_category(cat: str) -> str:
    """Normalize category name for dedup comparison."""
    return _CATEGORY_ALIASES.get(cat, cat)


def _dedup_key(f: Finding) -> str:
    """Generate a dedup key from a finding. Same file+category+line = duplicate."""
    norm_cat = _normalize_category(f.category)
    # For AI findings without line numbers, use file+category only
    if f.line:
        return f"{f.file}:{f.line}:{norm_cat}"
    return f"{f.file}::{norm_cat}"


def _aggregate_info_findings(findings: list[Finding], max_network: int = 5) -> list[Finding]:
    """Aggregate high-volume INFO findings to reduce noise.

    Network findings (e.g. 'import requests') are capped to max_network
    per repo, with a summary finding appended when excess are dropped.
    """
    network_findings = [f for f in findings if f.category == "network"]
    other_findings = [f for f in findings if f.category != "network"]

    if len(network_findings) <= max_network:
        return findings

    # Keep first max_network, aggregate the rest into a summary
    kept = network_findings[:max_network]
    dropped = len(network_findings) - max_network
    kept.append(Finding(
        severity=Severity.INFO,
        category="network",
        file="(aggregated)",
        description=f"...and {dropped} more network findings (total {len(network_findings)} across repo)",
    ))
    return other_findings + kept


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Merge duplicate findings, keeping the highest severity and best description.

    Two findings are considered duplicates if they have the same file, line
    (or both lack a line), and normalized category. When merged, the higher
    severity is kept and descriptions are combined if meaningfully different.
    """
    by_key: dict[str, Finding] = {}

    for f in findings:
        key = _dedup_key(f)
        if key not in by_key:
            by_key[key] = f
            continue

        existing = by_key[key]
        # Keep higher severity
        if _SEV_RANK.get(f.severity, 0) > _SEV_RANK.get(existing.severity, 0):
            merged = Finding(
                severity=f.severity,
                category=f.category,
                file=f.file,
                line=f.line or existing.line,
                code=f.code or existing.code,
                description=f.description,
            )
        else:
            merged = Finding(
                severity=existing.severity,
                category=existing.category,
                file=existing.file,
                line=existing.line or f.line,
                code=existing.code or f.code,
                description=existing.description,
            )

        # Append AI insight if different and meaningful
        other_desc = f.description if merged.description == existing.description else existing.description
        if other_desc and other_desc != merged.description:
            # Only append if substantively different (not just a prefix)
            if not merged.description.startswith(other_desc[:30]) and not other_desc.startswith(merged.description[:30]):
                merged = Finding(
                    severity=merged.severity,
                    category=merged.category,
                    file=merged.file,
                    line=merged.line,
                    code=merged.code,
                    description=f"{merged.description} | {other_desc}",
                )

        by_key[key] = merged

    return list(by_key.values())


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

        # Phase 1c: Repo-wide dependency scanning (requirements.txt, package.json, pyproject.toml)
        repo_cve = await check_cve_repo(repo_path)
        if repo_cve:
            log.info("[%s] Repo dependency scan: %d findings", job.id, len(repo_cve))
            job.findings.extend(repo_cve)

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

        # Normalize file paths to relative (strip repo_path prefix)
        repo_prefix = str(repo_path) + "/"
        for f in job.findings:
            if f.file and f.file.startswith(repo_prefix):
                f.file = f.file[len(repo_prefix):]

        # Aggregate high-volume info findings before AI review
        before_agg = len(job.findings)
        job.findings = _aggregate_info_findings(job.findings)
        if before_agg != len(job.findings):
            log.info("[%s] Aggregation: %d → %d findings", job.id, before_agg, len(job.findings))

        # Phase 4: AI review (with timeout)
        job.status = ScanStatus.AI_REVIEW
        log.info("[%s] Phase 4: AI review (%d static findings)", job.id, len(job.findings))
        publish_status(f"ai_review:{job.name}")
        from app.config import settings as cfg
        try:
            await asyncio.wait_for(ai_review(job, repo_path), timeout=cfg.scan_timeout_seconds)
        except asyncio.TimeoutError:
            log.warning("[%s] AI review timed out after %ds — continuing with static findings only",
                        job.id, cfg.scan_timeout_seconds)
            job.ai_score = None
        log.info("[%s] Phase 4 done: score=%s", job.id, job.ai_score)

        # Deduplication: merge static + AI findings
        before_dedup = len(job.findings)
        job.findings = deduplicate_findings(job.findings)
        if before_dedup != len(job.findings):
            log.info("[%s] Dedup: %d → %d findings", job.id, before_dedup, len(job.findings))

        # Filter whitelisted findings (L.3)
        before_wl = len(job.findings)
        job.findings = [
            f for f in job.findings
            if not storage.is_whitelisted(f.category, f.file, f.description)
        ]
        if before_wl != len(job.findings):
            log.info("[%s] Whitelist: %d → %d findings", job.id, before_wl, len(job.findings))

        # Learning phase (L.1, L.2, L.4)
        domain = job.manifest.domain if job.manifest else ""
        version = job.manifest.version if job.manifest else ""
        learning_data: dict = {}
        try:
            # L.1: Extract and store fingerprint
            fp = extract_fingerprint(repo_path, domain=domain, repo_url=job.repo_url)
            storage.save_fingerprint(job.id, fp)
            learning_data["fingerprint"] = {
                "total_lines": fp.get("total_lines", 0),
                "py_files": fp.get("py_files", 0),
                "js_files": fp.get("js_files", 0),
                "network_domains": fp.get("network_domains", []),
                "imports_count": len(fp.get("imports", [])),
                "ha_apis_count": len(fp.get("ha_apis", [])),
            }

            # Check for fingerprint changes vs previous scan
            prev_fp = storage.get_last_fingerprint(domain=domain, repo_url=job.repo_url)
            if prev_fp and prev_fp["fingerprint_hash"] != fp["fingerprint_hash"]:
                changes = fingerprint_diff(prev_fp, fp)
                if changes:
                    log.info("[%s] Fingerprint changed: %s", job.id, changes)
                    learning_data["fingerprint_changes"] = changes

            # L.2: Check deviations from baseline
            conn = storage.get_conn()
            deviations = check_deviations(conn, fp, job.ai_score, len(job.findings))
            if deviations:
                log.info("[%s] Baseline deviations: %s", job.id,
                         [f"{d['label']} ({d['direction']} by {d['z_score']}σ)" for d in deviations])
                learning_data["deviations"] = deviations

            # L.4: Record in scan history for reputation tracking
            record_scan(conn, domain, job.repo_url, version,
                        job.ai_score, len(job.findings),
                        fingerprint_hash=fp.get("fingerprint_hash", ""),
                        total_lines=fp.get("total_lines", 0),
                        py_files=fp.get("py_files", 0),
                        js_files=fp.get("js_files", 0),
                        network_domain_count=len(fp.get("network_domains", [])))

            # L.2: Recompute baseline periodically
            compute_baseline(conn)
        except Exception as e:
            log.warning("[%s] Learning phase error (non-fatal): %s", job.id, e)

        # Phase 5: Report
        job.status = ScanStatus.DONE
        report_path = generate_report(job, learning_data=learning_data or None)
        try:
            publish_scan_result(job)
        except Exception as e:
            log.warning("[%s] MQTT publish failed (non-fatal): %s", job.id, e)
        log.info("[%s] Done: %d findings, score=%s", job.id, len(job.findings), job.ai_score)

    except Exception as e:
        log.exception("Scan failed for %s", repo_url)
        job.status = ScanStatus.FAILED
        job.error = str(e)
        publish_status(f"failed:{job.name}")

    return job
