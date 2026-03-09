"""L.1 — Pattern Fingerprinting.

Extract a component's structural fingerprint: imports used, HA APIs called,
network domains contacted, file types present, and code size metrics.
Fingerprints are stored per-scan so we can track how a component evolves.
"""

import ast
import hashlib
import json
import logging
import re
from pathlib import Path

log = logging.getLogger(__name__)

# Patterns for extracting network domains from source code
_URL_RE = re.compile(r'https?://([a-zA-Z0-9._-]+)')
_DOMAIN_RE = re.compile(r'["\']([a-zA-Z0-9._-]+\.[a-z]{2,})["\']')

# HA-specific API patterns
_HA_API_RE = re.compile(r'hass\.(async_)?(add_job|create_task|services|states|bus|config_entries|helpers)')
_HA_IMPORT_RE = re.compile(r'from\s+homeassistant\.(\w+(?:\.\w+)*)\s+import')


def extract_fingerprint(repo_path: Path, domain: str = "", repo_url: str = "") -> dict:
    """Extract a structural fingerprint from a component's source code.

    Returns a dict with keys:
        domain, repo_url, imports, ha_apis, network_domains,
        file_types, py_files, js_files, total_lines, avg_complexity
    """
    imports: set[str] = set()
    ha_apis: set[str] = set()
    network_domains: set[str] = set()
    file_types: dict[str, int] = {}
    total_lines = 0
    py_files = 0
    js_files = 0

    for f in repo_path.rglob("*"):
        if not f.is_file():
            continue
        # Skip hidden dirs, __pycache__, node_modules
        parts = f.relative_to(repo_path).parts
        if any(p.startswith(".") or p in ("__pycache__", "node_modules", ".git") for p in parts):
            continue

        ext = f.suffix.lower()
        file_types[ext] = file_types.get(ext, 0) + 1

        if ext == ".py":
            py_files += 1
            _extract_python(f, imports, ha_apis, network_domains)
            try:
                total_lines += len(f.read_text(errors="replace").splitlines())
            except OSError:
                pass
        elif ext in (".js", ".ts"):
            js_files += 1
            _extract_js(f, network_domains)
            try:
                total_lines += len(f.read_text(errors="replace").splitlines())
            except OSError:
                pass

    # Build fingerprint hash for quick comparison
    sig = json.dumps(sorted(imports) + sorted(ha_apis) + sorted(network_domains), sort_keys=True)
    fp_hash = hashlib.sha256(sig.encode()).hexdigest()[:16]

    return {
        "domain": domain,
        "repo_url": repo_url,
        "fingerprint_hash": fp_hash,
        "imports": sorted(imports),
        "ha_apis": sorted(ha_apis),
        "network_domains": sorted(network_domains),
        "file_types": file_types,
        "py_files": py_files,
        "js_files": js_files,
        "total_lines": total_lines,
    }


def _extract_python(filepath: Path, imports: set, ha_apis: set, domains: set) -> None:
    """Extract imports, HA APIs, and network domains from a Python file."""
    try:
        source = filepath.read_text(errors="replace")
    except OSError:
        return

    # AST-based import extraction
    try:
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split(".")[0])
    except SyntaxError:
        # Fallback: regex for imports
        for m in re.finditer(r'^(?:from|import)\s+([\w.]+)', source, re.MULTILINE):
            imports.add(m.group(1).split(".")[0])

    # HA API usage
    for m in _HA_API_RE.finditer(source):
        ha_apis.add(m.group(0))
    for m in _HA_IMPORT_RE.finditer(source):
        ha_apis.add(f"homeassistant.{m.group(1)}")

    # Network domains
    for m in _URL_RE.finditer(source):
        domain = m.group(1).lower()
        if domain not in ("localhost", "127.0.0.1", "0.0.0.0"):
            domains.add(domain)


def _extract_js(filepath: Path, domains: set) -> None:
    """Extract network domains from JavaScript/TypeScript."""
    try:
        source = filepath.read_text(errors="replace")
    except OSError:
        return
    for m in _URL_RE.finditer(source):
        domain = m.group(1).lower()
        if domain not in ("localhost", "127.0.0.1", "0.0.0.0"):
            domains.add(domain)


def fingerprint_diff(old: dict, new: dict) -> dict:
    """Compare two fingerprints and return what changed.

    Returns dict with added/removed sets for imports, ha_apis, network_domains.
    """
    changes = {}
    for key in ("imports", "ha_apis", "network_domains"):
        old_set = set(old.get(key, []))
        new_set = set(new.get(key, []))
        added = new_set - old_set
        removed = old_set - new_set
        if added or removed:
            changes[key] = {"added": sorted(added), "removed": sorted(removed)}

    # Size change
    old_lines = old.get("total_lines", 0)
    new_lines = new.get("total_lines", 0)
    if old_lines and new_lines:
        pct = round((new_lines - old_lines) / old_lines * 100, 1) if old_lines else 0
        if abs(pct) > 10:
            changes["size"] = {"old_lines": old_lines, "new_lines": new_lines, "change_pct": pct}

    return changes
