"""Phase 6 tests: Web UI & API endpoints."""

import json
from unittest.mock import patch, AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path):
    """Create test client with mocked MQTT and temp settings."""
    settings_file = tmp_path / "settings.json"
    with patch("app.settings.SETTINGS_FILE", settings_file), \
         patch("app.report.mqtt.publish_discovery"), \
         patch("app.report.mqtt.publish_status"), \
         patch("app.report.mqtt.disconnect"):
        from app.main import app
        with TestClient(app) as c:
            yield c


class TestPages:
    def test_index_page(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "HA Sandbox Analyzer" in resp.text

    def test_settings_page(self, client):
        resp = client.get("/settings")
        assert resp.status_code == 200
        assert "Settings" in resp.text


class TestDataAPI:
    def test_api_reports_empty(self, client):
        resp = client.get("/api/reports")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_api_report_not_found(self, client):
        resp = client.get("/api/report/nonexistent")
        assert resp.status_code == 404
        assert resp.json()["error"] == "not found"

    def test_api_status(self, client):
        resp = client.get("/api/status")
        assert resp.status_code == 200
        assert "active_jobs" in resp.json()

    def test_api_system(self, client):
        resp = client.get("/api/system")
        assert resp.status_code == 200
        data = resp.json()
        assert "version" in data
        assert "reports" in data
        assert "repos_cached" in data
        assert "cache_size_mb" in data


class TestSettingsAPI:
    def test_get_settings(self, client):
        resp = client.get("/api/settings")
        assert resp.status_code == 200
        data = resp.json()
        assert "ai_provider" in data

    def test_get_settings_masks_secrets(self, client, tmp_path):
        # Save settings with a long token, then verify it gets masked
        settings_file = tmp_path / "settings_mask.json"
        settings_file.write_text(json.dumps({"ha_token": "abcdefghij1234567890"}))
        with patch("app.settings.SETTINGS_FILE", settings_file):
            resp = client.get("/api/settings")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ha_token"] != "abcdefghij1234567890"
        assert "..." in data["ha_token"]

    def test_save_settings(self, client, tmp_path):
        settings_file = tmp_path / "settings.json"
        with patch("app.settings.SETTINGS_FILE", settings_file):
            resp = client.post("/api/settings", json={
                "ai_provider": "public",
                "ollama_url": "http://test:11434",
            })
        assert resp.status_code == 200
        assert resp.json()["ok"] is True


class TestScanAPI:
    def test_scan_url_redirect(self, client):
        with patch("app.main._run_scan_background"):
            resp = client.post("/scan/url",
                               data={"url": "https://github.com/test/repo", "name": "Test"},
                               follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"] == "/#results"

    def test_scan_url_auto_prefix(self, client):
        with patch("app.main._run_scan_background"):
            resp = client.post("/scan/url",
                               data={"url": "user/repo", "name": ""},
                               follow_redirects=False)
        assert resp.status_code == 303

    def test_scan_repo_redirect(self, client):
        with patch("app.main._run_scan_background"):
            resp = client.post("/scan/repo",
                               data={"repo": "custom-components/test", "name": "Test"},
                               follow_redirects=False)
        assert resp.status_code == 303


class TestCacheAPI:
    def test_clear_cache(self, client, _test_dirs):
        cache_dir = _test_dirs["repos"]
        (cache_dir / "some_repo").mkdir()

        with patch("app.settings.get", return_value=str(cache_dir)):
            resp = client.post("/api/cache/clear")
        assert resp.status_code == 200

    def test_clear_reports(self, client, _test_dirs):
        reports_dir = _test_dirs["reports"]
        (reports_dir / "test.json").write_text("{}")

        with patch("app.settings.get", return_value=str(reports_dir)):
            resp = client.post("/api/reports/clear")
        assert resp.status_code == 200
