"""CVE lookup via OSV.dev API for Python dependencies."""

import logging
import re

import httpx

from app.models import Finding, ManifestInfo, Severity

log = logging.getLogger(__name__)

OSV_API = "https://api.osv.dev/v1/query"
TIMEOUT = 15

# Parse requirement string: "package==1.2.3" or "package>=1.0,<2.0"
_REQ_RE = re.compile(r"^([a-zA-Z0-9_.-]+)\s*[=<>!~]+\s*([\d.]+)")


def _parse_requirements(manifest: ManifestInfo) -> list[tuple[str, str]]:
    """Extract (package, version) pairs from manifest requirements."""
    results = []
    for req in manifest.requirements:
        m = _REQ_RE.match(req)
        if m:
            results.append((m.group(1), m.group(2)))
    return results


async def check_cve(manifest: ManifestInfo) -> list[Finding]:
    """Check manifest requirements against OSV.dev for known vulnerabilities."""
    if not manifest or not manifest.requirements:
        return []

    deps = _parse_requirements(manifest)
    if not deps:
        return []

    findings = []
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        for pkg, version in deps:
            try:
                resp = await client.post(OSV_API, json={
                    "package": {"name": pkg, "ecosystem": "PyPI"},
                    "version": version,
                })
                if resp.status_code != 200:
                    continue

                data = resp.json()
                vulns = data.get("vulns", [])
                for vuln in vulns:
                    vuln_id = vuln.get("id", "UNKNOWN")
                    summary = vuln.get("summary", "No description")
                    severity = _map_severity(vuln)
                    findings.append(Finding(
                        severity=severity,
                        category="known_vulnerability",
                        file="manifest.json",
                        code=f"{pkg}=={version}",
                        description=f"{vuln_id}: {summary}",
                    ))
            except httpx.HTTPError as e:
                log.warning("OSV lookup failed for %s: %s", pkg, e)
            except Exception as e:
                log.warning("CVE check error for %s: %s", pkg, e)

    if findings:
        log.info("CVE lookup: %d vulnerabilities found in %d dependencies", len(findings), len(deps))
    return findings


def _map_severity(vuln: dict) -> Severity:
    """Map OSV severity to our Severity enum."""
    # Check database_specific or severity field
    for sev_entry in vuln.get("severity", []):
        score = sev_entry.get("score", "")
        # CVSS score string like "CVSS:3.1/AV:N/AC:L/..."
        if "CVSS" in str(score):
            try:
                # Extract base score from vector
                parts = str(score).split("/")
                for p in parts:
                    if p.replace(".", "").isdigit():
                        base = float(p)
                        if base >= 9.0:
                            return Severity.CRITICAL
                        if base >= 7.0:
                            return Severity.HIGH
                        if base >= 4.0:
                            return Severity.MEDIUM
                        return Severity.LOW
            except (ValueError, IndexError):
                pass

    # Fallback: check aliases for CVE severity hints
    aliases = vuln.get("aliases", [])
    # Default to HIGH for any known vulnerability
    return Severity.HIGH
