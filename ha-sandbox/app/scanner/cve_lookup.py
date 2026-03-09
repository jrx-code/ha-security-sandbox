"""CVE lookup via OSV.dev API for Python and npm dependencies.

Checks:
- PyPI packages from manifest.json requirements
- npm packages from package.json dependencies
- Auto-discovered requirements.txt / pyproject.toml
- Known malicious packages (typosquatting, dependency confusion)
- Batch queries for efficiency
"""

import json
import logging
import re
from pathlib import Path

import httpx

from app.models import Finding, ManifestInfo, Severity

log = logging.getLogger(__name__)

OSV_API = "https://api.osv.dev/v1/query"
OSV_BATCH_API = "https://api.osv.dev/v1/querybatch"
TIMEOUT = 15

# Parse requirement string: "package==1.2.3" or "package>=1.0,<2.0"
_REQ_RE = re.compile(r"^([a-zA-Z0-9_.-]+)\s*[=<>!~]+\s*([\d.]+)")

# ──────────────────────────────────────────────────────────────────────
# Known malicious / typosquatting packages
# ──────────────────────────────────────────────────────────────────────

# PyPI packages known to be malicious or typosquatting on popular ones
_MALICIOUS_PYPI: set[str] = {
    # Common typosquats
    "python-dateutil".replace("-", ""),  # "pythondateutil"
    "colourama", "clorama", "coloramma",  # colorama typos
    "requesrs", "reequests", "requestes",  # requests typos
    "urlib3", "urrlib3",  # urllib3 typos
    "python3-dateutil",
    "jeIlyfish",  # homoglyph: l→I
    "python-binance",  # known supply chain attack
    "ctx",  # known malicious
    "noblesse", "noblesse2",  # known malicious
    "pytagora", "pytagoras",
    "importlib-metadata",  # known supply chain
    "setup-tools",  # setuptools typo
    "pip-install",  # pip typo
}

# npm packages known to be malicious
_MALICIOUS_NPM: set[str] = {
    "event-stream",  # famous supply chain attack (v3.3.6)
    "flatmap-stream",  # malicious dep of event-stream
    "ua-parser-js",  # compromised (v0.7.29)
    "coa",  # compromised
    "rc",  # compromised (v1.2.9, 1.3.9, 2.3.9)
    "colors",  # sabotaged (v1.4.1+)
    "faker",  # sabotaged (v6.6.6)
    "is-promise",  # broke npm ecosystem
    "crossenv",  # typosquat of cross-env
    "babelcli",  # typosquat of babel-cli
    "mongose",  # typosquat of mongoose
    "d3.js",  # typosquat of d3
    "gruntcli",  # typosquat of grunt-cli
    "http-proxy.js",  # typosquat
    "jquery.js",  # typosquat
    "node-fabric",  # typosquat of fabric
    "node-opencv",  # typosquat
    "node-opensl",  # typosquat of openssl
    "node-openssl",  # typosquat
    "nodecaffe",  # typosquat
    "nodefabric",  # typosquat
    "nodemailer-js",  # typosquat
    "nodesass",  # typosquat of node-sass
    "noderequest",  # typosquat
    "shadowsock",  # typosquat of shadowsocks
    "smb",  # malicious
    "sqliter",  # typosquat of sqlite3
    "proxy.js",  # typosquat
}


# ──────────────────────────────────────────────────────────────────────
# Dependency parsing
# ──────────────────────────────────────────────────────────────────────

def _parse_requirements(manifest: ManifestInfo) -> list[tuple[str, str]]:
    """Extract (package, version) pairs from manifest requirements."""
    results = []
    for req in manifest.requirements:
        m = _REQ_RE.match(req)
        if m:
            results.append((m.group(1), m.group(2)))
    return results


def _parse_requirements_txt(filepath: Path) -> list[tuple[str, str]]:
    """Parse requirements.txt file for (package, version) pairs."""
    results = []
    try:
        for line in filepath.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = _REQ_RE.match(line)
            if m:
                results.append((m.group(1), m.group(2)))
    except OSError:
        pass
    return results


def _parse_pyproject_toml(filepath: Path) -> list[tuple[str, str]]:
    """Parse pyproject.toml [project.dependencies] for (package, version) pairs."""
    results = []
    try:
        content = filepath.read_text(errors="replace")
        # Simple regex-based parsing (no toml lib required)
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped in ("[project.dependencies]", "dependencies = ["):
                in_deps = True
                continue
            if in_deps:
                if stripped.startswith("[") and not stripped.startswith('"'):
                    break  # New section
                if stripped == "]":
                    break
                # Parse "package>=1.0" style entries
                clean = stripped.strip('",\' ')
                m = _REQ_RE.match(clean)
                if m:
                    results.append((m.group(1), m.group(2)))
    except OSError:
        pass
    return results


def _parse_package_json(filepath: Path) -> list[tuple[str, str]]:
    """Parse package.json for npm (package, version) pairs."""
    results = []
    try:
        data = json.loads(filepath.read_text(errors="replace"))
    except (OSError, json.JSONDecodeError):
        return results

    for dep_key in ("dependencies", "devDependencies"):
        deps = data.get(dep_key, {})
        if not isinstance(deps, dict):
            continue
        for pkg, ver_spec in deps.items():
            if not isinstance(ver_spec, str):
                continue
            # Extract version from "^1.2.3", "~1.2.0", ">=1.0.0", "1.2.3"
            ver_match = re.search(r"(\d+\.\d+[\d.]*)", ver_spec)
            if ver_match:
                results.append((pkg, ver_match.group(1)))
    return results


def _discover_deps(repo_path: Path) -> tuple[list[tuple[str, str, str]], list[tuple[str, str, str]]]:
    """Discover all dependency files in repo.

    Returns (pypi_deps, npm_deps) where each is [(package, version, source_file)].
    """
    pypi_deps: list[tuple[str, str, str]] = []
    npm_deps: list[tuple[str, str, str]] = []

    # requirements*.txt files
    for req_file in repo_path.rglob("requirements*.txt"):
        rel = str(req_file.relative_to(repo_path))
        if any(skip in rel.split("/") for skip in [".venv", "node_modules", ".git"]):
            continue
        for pkg, ver in _parse_requirements_txt(req_file):
            pypi_deps.append((pkg, ver, rel))

    # pyproject.toml
    for pyproj in repo_path.rglob("pyproject.toml"):
        rel = str(pyproj.relative_to(repo_path))
        if any(skip in rel.split("/") for skip in [".venv", "node_modules", ".git"]):
            continue
        for pkg, ver in _parse_pyproject_toml(pyproj):
            pypi_deps.append((pkg, ver, rel))

    # package.json (skip node_modules)
    for pkg_json in repo_path.rglob("package.json"):
        rel = str(pkg_json.relative_to(repo_path))
        if "node_modules" in rel.split("/"):
            continue
        for pkg, ver in _parse_package_json(pkg_json):
            npm_deps.append((pkg, ver, rel))

    return pypi_deps, npm_deps


# ──────────────────────────────────────────────────────────────────────
# Malicious package check
# ──────────────────────────────────────────────────────────────────────

def _check_malicious(deps: list[tuple[str, str, str]], ecosystem: str) -> list[Finding]:
    """Check dependency list against known malicious packages."""
    findings = []
    malicious_set = _MALICIOUS_PYPI if ecosystem == "PyPI" else _MALICIOUS_NPM

    for pkg, ver, source in deps:
        pkg_lower = pkg.lower()
        if pkg_lower in {m.lower() for m in malicious_set}:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                category="malicious_package",
                file=source,
                code=f"{pkg}=={ver}" if ver else pkg,
                description=f"Known malicious {ecosystem} package: {pkg} — possible typosquatting or supply chain attack",
            ))
    return findings


# ──────────────────────────────────────────────────────────────────────
# OSV.dev batch query
# ──────────────────────────────────────────────────────────────────────

async def _batch_query_osv(
    deps: list[tuple[str, str, str]], ecosystem: str
) -> list[Finding]:
    """Query OSV.dev in batches for known vulnerabilities."""
    if not deps:
        return []

    # Deduplicate by (pkg, version)
    seen: set[tuple[str, str]] = set()
    unique_deps: list[tuple[str, str, str]] = []
    for pkg, ver, source in deps:
        key = (pkg.lower(), ver)
        if key not in seen:
            seen.add(key)
            unique_deps.append((pkg, ver, source))

    findings = []
    # OSV batch API accepts up to 1000 queries
    batch_size = 100
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        for i in range(0, len(unique_deps), batch_size):
            chunk = unique_deps[i:i + batch_size]
            queries = [
                {"package": {"name": pkg, "ecosystem": ecosystem}, "version": ver}
                for pkg, ver, _ in chunk
            ]

            try:
                resp = await client.post(OSV_BATCH_API, json={"queries": queries})
                if resp.status_code != 200:
                    # Fallback to individual queries
                    for pkg, ver, source in chunk:
                        findings.extend(await _single_query(client, pkg, ver, source, ecosystem))
                    continue

                results = resp.json().get("results", [])
                for j, result in enumerate(results):
                    if j >= len(chunk):
                        break
                    pkg, ver, source = chunk[j]
                    vulns = result.get("vulns", [])
                    for vuln in vulns:
                        vuln_id = vuln.get("id", "UNKNOWN")
                        summary = vuln.get("summary", "No description")
                        severity = _map_severity(vuln)
                        findings.append(Finding(
                            severity=severity,
                            category="known_vulnerability",
                            file=source,
                            code=f"{pkg}=={ver}",
                            description=f"{vuln_id}: {summary}",
                        ))
            except httpx.HTTPError as e:
                log.warning("OSV batch query failed: %s", e)
                # Fallback to individual queries
                for pkg, ver, source in chunk:
                    findings.extend(await _single_query(client, pkg, ver, source, ecosystem))
            except Exception as e:
                log.warning("CVE batch check error: %s", e)

    return findings


async def _single_query(
    client: httpx.AsyncClient, pkg: str, ver: str, source: str, ecosystem: str
) -> list[Finding]:
    """Single OSV.dev query as fallback."""
    findings = []
    try:
        resp = await client.post(OSV_API, json={
            "package": {"name": pkg, "ecosystem": ecosystem},
            "version": ver,
        })
        if resp.status_code != 200:
            return findings
        data = resp.json()
        for vuln in data.get("vulns", []):
            vuln_id = vuln.get("id", "UNKNOWN")
            summary = vuln.get("summary", "No description")
            severity = _map_severity(vuln)
            findings.append(Finding(
                severity=severity,
                category="known_vulnerability",
                file=source,
                code=f"{pkg}=={ver}",
                description=f"{vuln_id}: {summary}",
            ))
    except (httpx.HTTPError, Exception) as e:
        log.warning("OSV lookup failed for %s: %s", pkg, e)
    return findings


# ──────────────────────────────────────────────────────────────────────
# Main entry points
# ──────────────────────────────────────────────────────────────────────

async def check_cve(manifest: ManifestInfo) -> list[Finding]:
    """Check manifest requirements against OSV.dev for known vulnerabilities.

    This is the original entry point — checks only manifest.json requirements (PyPI).
    """
    if not manifest or not manifest.requirements:
        return []

    deps = _parse_requirements(manifest)
    if not deps:
        return []

    # Convert to (pkg, ver, source) format
    deps_with_source = [(pkg, ver, "manifest.json") for pkg, ver in deps]

    # Check malicious packages
    findings = _check_malicious(deps_with_source, "PyPI")

    # Query OSV.dev
    findings.extend(await _batch_query_osv(deps_with_source, "PyPI"))

    if findings:
        log.info("CVE lookup: %d vulnerabilities found in %d dependencies", len(findings), len(deps))
    return findings


async def check_cve_repo(repo_path: Path) -> list[Finding]:
    """Discover and check all dependencies in a repository.

    Auto-discovers requirements.txt, pyproject.toml, package.json
    in addition to the manifest requirements.
    """
    pypi_deps, npm_deps = _discover_deps(repo_path)
    findings: list[Finding] = []

    # Check malicious packages first (no network needed)
    findings.extend(_check_malicious(pypi_deps, "PyPI"))
    findings.extend(_check_malicious(npm_deps, "npm"))

    # Batch query OSV.dev for both ecosystems
    if pypi_deps:
        log.info("Checking %d PyPI dependencies from repo files", len(pypi_deps))
        findings.extend(await _batch_query_osv(pypi_deps, "PyPI"))

    if npm_deps:
        log.info("Checking %d npm dependencies from package.json", len(npm_deps))
        findings.extend(await _batch_query_osv(npm_deps, "npm"))

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
