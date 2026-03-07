"""Tests for CVE lookup via OSV.dev API."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models import ManifestInfo, Severity
from app.scanner.cve_lookup import check_cve, _parse_requirements


class TestParseRequirements:
    def test_pinned_version(self):
        m = ManifestInfo(requirements=["aiohttp==3.9.1", "pyyaml==6.0"])
        result = _parse_requirements(m)
        assert ("aiohttp", "3.9.1") in result
        assert ("pyyaml", "6.0") in result

    def test_gte_version(self):
        m = ManifestInfo(requirements=["requests>=2.28.0"])
        result = _parse_requirements(m)
        assert ("requests", "2.28.0") in result

    def test_no_version(self):
        m = ManifestInfo(requirements=["somelib"])
        result = _parse_requirements(m)
        assert len(result) == 0

    def test_empty_requirements(self):
        m = ManifestInfo(requirements=[])
        result = _parse_requirements(m)
        assert result == []


class TestCheckCVE:
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
    async def test_vulnerability_found(self):
        m = ManifestInfo(requirements=["aiohttp==3.9.1"])

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "vulns": [
                {
                    "id": "GHSA-1234-5678",
                    "summary": "Test vulnerability in aiohttp",
                    "severity": [],
                }
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
        assert findings[0].category == "known_vulnerability"
        assert "GHSA-1234-5678" in findings[0].description

    @pytest.mark.asyncio
    async def test_no_vulnerabilities(self):
        m = ManifestInfo(requirements=["safelib==1.0.0"])

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"vulns": []}

        with patch("app.scanner.cve_lookup.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            findings = await check_cve(m)

        assert len(findings) == 0

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

        assert len(findings) == 0  # graceful failure
