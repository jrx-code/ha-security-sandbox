"""Tests for enhanced dependency scanner (v0.11.0): npm, requirements.txt, pyproject.toml, malicious packages, batch."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models import ManifestInfo, Severity
from app.scanner.cve_lookup import (
    _check_malicious,
    _discover_deps,
    _parse_package_json,
    _parse_pyproject_toml,
    _parse_requirements,
    _parse_requirements_txt,
    check_cve,
    check_cve_repo,
)


class TestParseRequirementsTxt:
    """Test requirements.txt parsing (D.2)."""

    def test_basic(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("aiohttp==3.9.1\npyyaml>=6.0\n")
        result = _parse_requirements_txt(f)
        assert ("aiohttp", "3.9.1") in result
        assert ("pyyaml", "6.0") in result

    def test_comments_and_empty(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("# comment\n\naiohttp==3.9.1\n-r base.txt\n")
        result = _parse_requirements_txt(f)
        assert len(result) == 1
        assert result[0] == ("aiohttp", "3.9.1")

    def test_no_version_skipped(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("requests\nsomelib\n")
        result = _parse_requirements_txt(f)
        assert len(result) == 0


class TestParsePyprojectToml:
    """Test pyproject.toml parsing (D.2)."""

    def test_project_dependencies(self, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text(
            "[project]\n"
            "name = \"myproject\"\n"
            "dependencies = [\n"
            '    "aiohttp>=3.9.0",\n'
            '    "pyyaml==6.0",\n'
            "]\n"
        )
        result = _parse_pyproject_toml(f)
        assert ("aiohttp", "3.9.0") in result
        assert ("pyyaml", "6.0") in result

    def test_empty_dependencies(self, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text("[project]\nname = \"test\"\n")
        result = _parse_pyproject_toml(f)
        assert len(result) == 0


class TestParsePackageJson:
    """Test package.json parsing (D.1)."""

    def test_dependencies(self, tmp_path):
        f = tmp_path / "package.json"
        f.write_text(json.dumps({
            "dependencies": {
                "lit": "^3.1.0",
                "home-assistant-js-websocket": "~9.0.0",
            }
        }))
        result = _parse_package_json(f)
        assert ("lit", "3.1.0") in result
        assert ("home-assistant-js-websocket", "9.0.0") in result

    def test_dev_dependencies(self, tmp_path):
        f = tmp_path / "package.json"
        f.write_text(json.dumps({
            "devDependencies": {
                "rollup": "^4.9.0",
                "typescript": "5.3.3",
            }
        }))
        result = _parse_package_json(f)
        assert ("rollup", "4.9.0") in result
        assert ("typescript", "5.3.3") in result

    def test_no_version_skipped(self, tmp_path):
        f = tmp_path / "package.json"
        f.write_text(json.dumps({
            "dependencies": {
                "lit": "*",
                "something": "latest",
            }
        }))
        result = _parse_package_json(f)
        assert len(result) == 0

    def test_invalid_json(self, tmp_path):
        f = tmp_path / "package.json"
        f.write_text("{invalid json")
        result = _parse_package_json(f)
        assert result == []


class TestDiscoverDeps:
    """Test repo-wide dependency discovery (D.2)."""

    def test_discovers_all(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "requirements.txt").write_text("aiohttp==3.9.1\n")
        (repo / "package.json").write_text(json.dumps({
            "dependencies": {"lit": "^3.1.0"}
        }))
        pypi, npm = _discover_deps(repo)
        assert len(pypi) >= 1
        assert len(npm) >= 1
        assert any(pkg == "aiohttp" for pkg, _, _ in pypi)
        assert any(pkg == "lit" for pkg, _, _ in npm)

    def test_skips_node_modules(self, tmp_path):
        repo = tmp_path / "repo"
        nm = repo / "node_modules" / "some-pkg"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(json.dumps({
            "dependencies": {"evil": "1.0.0"}
        }))
        (repo / "package.json").write_text(json.dumps({
            "dependencies": {"safe": "^2.0.0"}
        }))
        _, npm = _discover_deps(repo)
        assert not any(pkg == "evil" for pkg, _, _ in npm)
        assert any(pkg == "safe" for pkg, _, _ in npm)

    def test_skips_venv(self, tmp_path):
        repo = tmp_path / "repo"
        venv = repo / ".venv" / "lib"
        venv.mkdir(parents=True)
        (venv / "requirements.txt").write_text("internal==1.0.0\n")
        (repo / "requirements.txt").write_text("real==2.0.0\n")
        pypi, _ = _discover_deps(repo)
        assert not any(pkg == "internal" for pkg, _, _ in pypi)
        assert any(pkg == "real" for pkg, _, _ in pypi)


class TestMaliciousPackages:
    """Test known malicious package detection (D.5)."""

    def test_pypi_malicious(self):
        deps = [("colourama", "0.4.0", "requirements.txt")]
        findings = _check_malicious(deps, "PyPI")
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].category == "malicious_package"

    def test_npm_malicious(self):
        deps = [("event-stream", "3.3.6", "package.json")]
        findings = _check_malicious(deps, "npm")
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_safe_package_not_flagged(self):
        deps = [("requests", "2.31.0", "requirements.txt")]
        findings = _check_malicious(deps, "PyPI")
        assert len(findings) == 0

    def test_npm_typosquat(self):
        deps = [("crossenv", "1.0.0", "package.json")]
        findings = _check_malicious(deps, "npm")
        assert len(findings) == 1
        assert "typosquatting" in findings[0].description


class TestBatchQuery:
    """Test batch CVE query (D.7)."""

    @pytest.mark.asyncio
    async def test_batch_query_success(self):
        m = ManifestInfo(requirements=["aiohttp==3.9.1", "pyyaml==6.0"])

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "results": [
                {"vulns": [{"id": "GHSA-1234", "summary": "Test vuln", "severity": []}]},
                {"vulns": []},
            ]
        }

        with patch("app.scanner.cve_lookup.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            findings = await check_cve(m)

        assert len(findings) == 1
        assert "GHSA-1234" in findings[0].description

    @pytest.mark.asyncio
    async def test_check_cve_repo(self, tmp_path):
        """Test repo-wide scanning discovers and checks dependencies."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "requirements.txt").write_text("aiohttp==3.9.1\n")
        (repo / "package.json").write_text(json.dumps({
            "dependencies": {"lit": "^3.1.0"}
        }))

        # Mock batch responses for both PyPI and npm
        call_count = 0

        async def mock_post(url, json=None):
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"results": [{"vulns": []}]}
            return resp

        with patch("app.scanner.cve_lookup.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = mock_post
            mock_client_cls.return_value = mock_client

            findings = await check_cve_repo(repo)

        # Should have made at least 2 batch calls (PyPI + npm)
        assert call_count >= 2


class TestExistingCVE:
    """Backward compatibility with original check_cve."""

    @pytest.mark.asyncio
    async def test_no_manifest(self):
        findings = await check_cve(None)
        assert findings == []

    @pytest.mark.asyncio
    async def test_no_requirements(self):
        m = ManifestInfo(requirements=[])
        findings = await check_cve(m)
        assert findings == []

    @pytest.mark.asyncio
    async def test_api_error_handled(self):
        m = ManifestInfo(requirements=["aiohttp==3.9.1"])

        import httpx
        with patch("app.scanner.cve_lookup.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(side_effect=httpx.ConnectError("timeout"))
            mock_client_cls.return_value = mock_client

            findings = await check_cve(m)

        assert len(findings) == 0
