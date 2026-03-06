"""Phase 7 tests: Pipeline integration — end-to-end run_scan."""

from unittest.mock import patch, AsyncMock, MagicMock

import pytest

from app.models import ScanJob, ScanStatus, ComponentType
from app.scanner.pipeline import run_scan


class TestRunScan:
    @pytest.mark.asyncio
    async def test_full_pipeline_success(self, fixture_integration):
        """End-to-end scan with mocked clone and AI."""
        ai_response = {
            "text": '{"score": 8.0, "summary": "Good", "findings": []}',
            "analysis": "Clean",
        }
        cfg = {"ai_provider": "ollama", "max_code_context": 5000, "ai_timeout": 30}

        with patch("app.scanner.pipeline.fetch_and_parse") as mock_fetch, \
             patch("app.scanner.pipeline.publish_status"), \
             patch("app.scanner.pipeline.publish_scan_result"), \
             patch("app.ai.ollama._get_ai_config", return_value=cfg), \
             patch("app.ai.ollama._review_ollama", new_callable=AsyncMock, return_value=ai_response):

            # Setup mock fetch
            def _fake_fetch(job):
                from app.models import ManifestInfo
                job.manifest = ManifestInfo(
                    component_type=ComponentType.INTEGRATION,
                    domain="test_domain", name="Test Integration",
                )
                job.name = "Test Integration"
                return fixture_integration

            mock_fetch.side_effect = _fake_fetch

            job = await run_scan("https://github.com/test/repo", "Test Integration")

        assert job.status == ScanStatus.DONE
        assert job.ai_score == 8.0
        assert job.manifest.component_type == ComponentType.INTEGRATION
        assert len(job.findings) > 0  # static findings from subprocess in fixture

    @pytest.mark.asyncio
    async def test_pipeline_clone_failure(self):
        """Pipeline should handle clone failure gracefully."""
        with patch("app.scanner.pipeline.fetch_and_parse", side_effect=Exception("Clone failed")), \
             patch("app.scanner.pipeline.publish_status"):

            job = await run_scan("https://github.com/nonexistent/repo", "Bad Repo")

        assert job.status == ScanStatus.FAILED
        assert "Clone failed" in job.error

    @pytest.mark.asyncio
    async def test_pipeline_ai_failure_still_completes(self, fixture_safe_py):
        """If AI fails, scan should still complete — ai_review catches errors internally."""
        import httpx
        cfg = {"ai_provider": "ollama", "max_code_context": 5000, "ai_timeout": 30}

        with patch("app.scanner.pipeline.fetch_and_parse") as mock_fetch, \
             patch("app.scanner.pipeline.publish_status"), \
             patch("app.scanner.pipeline.publish_scan_result"), \
             patch("app.ai.ollama._get_ai_config", return_value=cfg), \
             patch("app.ai.ollama._review_ollama", new_callable=AsyncMock,
                   side_effect=httpx.HTTPError("AI down")):

            def _fake_fetch(job):
                from app.models import ManifestInfo
                job.manifest = ManifestInfo(component_type=ComponentType.INTEGRATION, name="Safe")
                job.name = "Safe"
                return fixture_safe_py

            mock_fetch.side_effect = _fake_fetch

            job = await run_scan("https://github.com/test/safe", "Safe")

        # ai_review catches HTTPError internally, pipeline continues to DONE
        assert job.status == ScanStatus.DONE
        assert "failed" in (job.ai_summary or "").lower()
        assert job.ai_score is None

    @pytest.mark.asyncio
    async def test_pipeline_publishes_mqtt(self, fixture_safe_py):
        """Verify MQTT status updates are published during scan."""
        ai_response = {"text": '{"score": 9, "summary": "OK", "findings": []}', "analysis": ""}
        cfg = {"ai_provider": "ollama", "max_code_context": 5000, "ai_timeout": 30}

        mock_publish_status = MagicMock()
        mock_publish_result = MagicMock()

        with patch("app.scanner.pipeline.fetch_and_parse") as mock_fetch, \
             patch("app.scanner.pipeline.publish_status", mock_publish_status), \
             patch("app.scanner.pipeline.publish_scan_result", mock_publish_result), \
             patch("app.ai.ollama._get_ai_config", return_value=cfg), \
             patch("app.ai.ollama._review_ollama", new_callable=AsyncMock, return_value=ai_response):

            def _fake_fetch(job):
                from app.models import ManifestInfo
                job.manifest = ManifestInfo(component_type=ComponentType.INTEGRATION, name="Test")
                job.name = "Test"
                return fixture_safe_py

            mock_fetch.side_effect = _fake_fetch

            job = await run_scan("https://github.com/test/repo", "Test")

        # Should publish: cloning, scanning, ai_review statuses
        assert mock_publish_status.call_count >= 3
        mock_publish_result.assert_called_once()
