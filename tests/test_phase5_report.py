"""Phase 5 tests: Report generation + MQTT discovery."""

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from app.models import Finding, ManifestInfo, ScanJob, ScanStatus, Severity, ComponentType
from app.report.generator import generate_report, load_all_reports


def _make_job(**kwargs) -> ScanJob:
    defaults = {
        "id": "rpt001",
        "repo_url": "https://github.com/test/repo",
        "name": "Test Component",
        "status": ScanStatus.DONE,
        "manifest": ManifestInfo(component_type=ComponentType.INTEGRATION, domain="test"),
        "ai_score": 8.5,
        "ai_summary": "Looks safe",
        "findings": [
            Finding(severity=Severity.HIGH, category="command_execution",
                    file="sensor.py", line=10, code="import subprocess",
                    description="subprocess usage"),
            Finding(severity=Severity.LOW, category="network",
                    file="api.py", line=5, code="import requests",
                    description="network module"),
        ],
    }
    defaults.update(kwargs)
    return ScanJob(**defaults)


class TestGenerateReport:
    def test_creates_json_file(self, _test_dirs):
        job = _make_job()
        filepath = generate_report(job)
        assert filepath.exists()
        assert filepath.suffix == ".json"
        assert filepath.name == "rpt001.json"

    def test_report_structure(self, _test_dirs):
        job = _make_job()
        filepath = generate_report(job)
        report = json.loads(filepath.read_text())

        assert report["id"] == "rpt001"
        assert report["name"] == "Test Component"
        assert report["status"] == "done"
        assert report["component_type"] == "integration"
        assert report["ai_score"] == 8.5
        assert report["ai_summary"] == "Looks safe"
        assert report["score_label"] == "SAFE"

    def test_report_stats(self, _test_dirs):
        job = _make_job()
        filepath = generate_report(job)
        report = json.loads(filepath.read_text())

        assert report["stats"]["critical"] == 0
        assert report["stats"]["high"] == 1
        assert report["stats"]["total_findings"] == 2

    def test_report_findings_serialized(self, _test_dirs):
        job = _make_job()
        filepath = generate_report(job)
        report = json.loads(filepath.read_text())

        assert len(report["findings"]) == 2
        assert report["findings"][0]["severity"] == "high"
        assert report["findings"][0]["file"] == "sensor.py"

    def test_timestamps(self, _test_dirs):
        job = _make_job()
        filepath = generate_report(job)
        report = json.loads(filepath.read_text())

        assert "created_at" in report
        assert "completed_at" in report
        # Should be valid ISO format
        datetime.fromisoformat(report["created_at"])
        datetime.fromisoformat(report["completed_at"])


class TestLoadAllReports:
    def test_empty_dir(self, _test_dirs):
        reports = load_all_reports()
        assert reports == []

    def test_loads_reports(self, _test_dirs):
        job1 = _make_job(id="rpt001", name="First")
        job2 = _make_job(id="rpt002", name="Second")
        generate_report(job1)
        generate_report(job2)

        reports = load_all_reports()
        assert len(reports) == 2

    def test_ignores_broken_json(self, _test_dirs):
        job = _make_job()
        generate_report(job)

        # Add a broken JSON file
        broken = Path(_test_dirs["reports"]) / "broken.json"
        broken.write_text("{invalid}")

        reports = load_all_reports()
        assert len(reports) == 1  # Only the valid one

    def test_sorted_reverse(self, _test_dirs):
        for i in range(3):
            job = _make_job(id=f"rpt{i:03d}")
            generate_report(job)

        reports = load_all_reports()
        ids = [r["id"] for r in reports]
        assert ids == ["rpt002", "rpt001", "rpt000"]

    def test_nonexistent_dir(self, tmp_path):
        with patch("app.config.settings.reports_dir", str(tmp_path / "nonexistent")):
            reports = load_all_reports()
        assert reports == []


class TestMQTTDiscovery:
    def test_publish_discovery(self):
        from app.report.mqtt import publish_discovery

        mock_client = MagicMock()
        mock_client.is_connected.return_value = True

        with patch("app.report.mqtt._client", mock_client), \
             patch("app.report.mqtt._get_client", return_value=mock_client):
            publish_discovery()

        # Should publish 4 sensor configs (status, last_scan, last_score, scans_total)
        assert mock_client.publish.call_count == 4
        calls = mock_client.publish.call_args_list
        topics = [c[0][0] for c in calls]
        assert all("homeassistant/sensor/ha_sandbox/" in t for t in topics)

        # Verify retain flag
        for call in calls:
            assert call[1].get("retain", call[0][2] if len(call[0]) > 2 else False) is True

    def test_publish_scan_result(self):
        from app.report.mqtt import publish_scan_result

        mock_client = MagicMock()
        mock_client.is_connected.return_value = True
        job = _make_job()

        with patch("app.report.mqtt._client", mock_client), \
             patch("app.report.mqtt._get_client", return_value=mock_client):
            publish_scan_result(job)

        assert mock_client.publish.call_count == 4  # status, last_scan, last_score, scans_total

    def test_publish_status(self):
        from app.report.mqtt import publish_status

        mock_client = MagicMock()
        mock_client.is_connected.return_value = True

        with patch("app.report.mqtt._client", mock_client), \
             patch("app.report.mqtt._get_client", return_value=mock_client):
            publish_status("scanning:test")

        mock_client.publish.assert_called_once()
        args = mock_client.publish.call_args[0]
        assert args[0] == "ha_sandbox/status"
        assert args[1] == "scanning:test"

    def test_publish_status_handles_error(self):
        from app.report.mqtt import publish_status

        with patch("app.report.mqtt._get_client", side_effect=Exception("No MQTT")):
            # Should not raise
            publish_status("test")

    def test_test_mqtt_connection_timeout(self):
        from app.report.mqtt import test_mqtt_connection

        result = test_mqtt_connection("192.0.2.1", 1883, "user", "pass", False)
        assert result["ok"] is False
        assert result["error"] != ""
