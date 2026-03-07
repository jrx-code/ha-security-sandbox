"""Phase 1: Clone repository and parse manifest."""

import json
import logging
import os
import shutil
from pathlib import Path

from git import Repo

from app.config import settings
from app.models import ComponentType, ManifestInfo, ScanJob, ScanStatus

log = logging.getLogger(__name__)


def clone_repo(job: ScanJob) -> Path:
    """Clone a git repo into data/repos/<job.id>. Returns repo path."""
    job.status = ScanStatus.CLONING
    dest = Path(settings.repos_dir) / job.id
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    log.info("Cloning %s -> %s", job.repo_url, dest)
    Repo.clone_from(job.repo_url, str(dest), depth=1)
    return dest


def detect_type(repo_path: Path) -> ComponentType:
    """Detect component type from repo contents."""
    # Integration: has custom_components/<domain>/manifest.json
    for manifest in repo_path.rglob("manifest.json"):
        if "custom_components" in str(manifest):
            return ComponentType.INTEGRATION

    # Card: has *.js in dist/ or root, or hacs.json type=plugin
    hacs_json = repo_path / "hacs.json"
    if hacs_json.exists():
        try:
            data = json.loads(hacs_json.read_text())
            render = data.get("render_readme", False)
            cat = data.get("category", "")
            if cat == "plugin" or cat == "lovelace":
                return ComponentType.CARD
            if cat == "theme":
                return ComponentType.THEME
            if cat == "python_script":
                return ComponentType.PYTHON_SCRIPT
            if cat == "integration":
                return ComponentType.INTEGRATION
        except (json.JSONDecodeError, OSError):
            pass

    # Fallback: check for JS files
    js_files = list(repo_path.rglob("*.js"))
    py_files = list(repo_path.rglob("*.py"))
    if js_files and not py_files:
        return ComponentType.CARD
    if py_files and not js_files:
        return ComponentType.INTEGRATION

    return ComponentType.UNKNOWN


def parse_manifest(repo_path: Path) -> ManifestInfo:
    """Parse manifest.json from integration or hacs.json from card."""
    info = ManifestInfo()

    # Try integration manifest first
    for manifest_path in repo_path.rglob("manifest.json"):
        if "custom_components" in str(manifest_path):
            try:
                data = json.loads(manifest_path.read_text())
                info.domain = data.get("domain", "")
                info.name = data.get("name", "")
                info.version = data.get("version", "")
                info.documentation = data.get("documentation", "")
                info.dependencies = data.get("dependencies", [])
                info.requirements = data.get("requirements", [])
                info.iot_class = data.get("iot_class", "")
                return info
            except (json.JSONDecodeError, OSError):
                pass

    # Try hacs.json
    hacs_json = repo_path / "hacs.json"
    if hacs_json.exists():
        try:
            data = json.loads(hacs_json.read_text())
            info.name = data.get("name", "")
        except (json.JSONDecodeError, OSError):
            pass

    # Fallback name from directory
    if not info.name:
        info.name = repo_path.name

    return info


def fetch_and_parse(job: ScanJob) -> Path:
    """Clone repo, detect type, parse manifest. Updates job in place."""
    repo_path = clone_repo(job)
    comp_type = detect_type(repo_path)
    manifest = parse_manifest(repo_path)
    manifest.component_type = comp_type
    job.manifest = manifest
    if not job.name:
        job.name = manifest.name or repo_path.name
    return repo_path
