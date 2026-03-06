"""Phase 4 tests: AI review — code context building, JSON parsing, provider calls."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from app.ai.ollama import (
    _build_code_context,
    _format_static_findings,
    _parse_json_response,
    ai_review,
)
from app.models import Finding, ScanJob, Severity, ManifestInfo, ComponentType


class TestBuildCodeContext:
    def test_respects_max_chars(self, fixture_integration):
        # With max_chars=100, at least the first file chunk is included but total stays bounded
        ctx_small = _build_code_context(fixture_integration, max_chars=100)
        ctx_large = _build_code_context(fixture_integration, max_chars=50000)
        assert len(ctx_small) < len(ctx_large)

    def test_includes_priority_files(self, fixture_integration):
        ctx = _build_code_context(fixture_integration, max_chars=50000)
        assert "manifest.json" in ctx
        assert "__init__" in ctx

    def test_skips_git_dir(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        git_dir = repo / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("secret")
        (repo / "main.py").write_text("x = 1")
        ctx = _build_code_context(repo, max_chars=50000)
        assert "secret" not in ctx
        assert "main.py" in ctx

    def test_skips_node_modules(self, tmp_path):
        repo = tmp_path / "repo"
        nm = repo / "node_modules" / "lib"
        nm.mkdir(parents=True)
        (nm / "dep.js").write_text("eval('evil')")
        (repo / "card.js").write_text("var x = 1;")
        ctx = _build_code_context(repo, max_chars=50000)
        assert "evil" not in ctx

    def test_empty_repo(self, tmp_path):
        repo = tmp_path / "empty"
        repo.mkdir()
        ctx = _build_code_context(repo, max_chars=50000)
        assert ctx == ""


class TestFormatStaticFindings:
    def test_empty_findings(self):
        result = _format_static_findings([])
        assert result == "No static analysis findings."

    def test_formats_findings(self):
        findings = [
            Finding(severity=Severity.CRITICAL, category="code_injection",
                    file="evil.py", line=5, description="eval() detected"),
        ]
        result = _format_static_findings(findings)
        assert "[critical]" in result
        assert "code_injection" in result
        assert "evil.py:5" in result

    def test_truncates_at_20(self):
        findings = [
            Finding(severity=Severity.LOW, category=f"cat{i}",
                    file=f"file{i}.py", line=i, description=f"Finding {i}")
            for i in range(30)
        ]
        result = _format_static_findings(findings)
        lines = result.strip().split("\n")
        assert len(lines) == 21  # header + 20 findings


class TestParseJsonResponse:
    def test_clean_json(self):
        text = '{"score": 8, "summary": "Safe", "findings": []}'
        result = _parse_json_response(text)
        assert result["score"] == 8
        assert result["summary"] == "Safe"

    def test_json_with_markdown(self):
        text = '```json\n{"score": 7, "summary": "OK", "findings": []}\n```'
        result = _parse_json_response(text)
        assert result["score"] == 7

    def test_json_with_extra_text(self):
        text = 'Here is the result: {"score": 5, "summary": "Issues found", "findings": []} Extra text'
        result = _parse_json_response(text)
        assert result["score"] == 5

    def test_invalid_json_raises(self):
        with pytest.raises(json.JSONDecodeError):
            _parse_json_response("not json at all")

    def test_nested_json(self):
        text = '{"score": 9, "summary": "Clean", "findings": [{"severity": "low", "description": "minor"}]}'
        result = _parse_json_response(text)
        assert len(result["findings"]) == 1


class TestAiReview:
    @pytest.mark.asyncio
    async def test_ollama_provider(self, fixture_safe_py):
        job = ScanJob(id="ai001", repo_url="https://test.com", name="Test")
        job.manifest = ManifestInfo(component_type=ComponentType.INTEGRATION)

        mock_response = {
            "text": '{"score": 9.5, "summary": "Very safe", "findings": []}',
            "analysis": "Looks clean",
        }
        cfg = {"ai_provider": "ollama", "max_code_context": 5000, "ai_timeout": 30}

        with patch("app.ai.ollama._get_ai_config", return_value=cfg), \
             patch("app.ai.ollama._review_ollama", new_callable=AsyncMock, return_value=mock_response):
            await ai_review(job, fixture_safe_py)

        assert job.ai_score == 9.5
        assert job.ai_summary == "Very safe"

    @pytest.mark.asyncio
    async def test_public_provider(self, fixture_safe_py):
        job = ScanJob(id="ai002", repo_url="https://test.com", name="Test")
        job.manifest = ManifestInfo(component_type=ComponentType.INTEGRATION)

        mock_response = {
            "text": '{"score": 8.0, "summary": "Good", "findings": [{"severity": "low", "category": "info", "description": "Minor", "file": "x.py"}]}',
            "analysis": "",
        }
        cfg = {"ai_provider": "public", "public_api_key": "sk-test", "max_code_context": 5000, "ai_timeout": 30}

        with patch("app.ai.ollama._get_ai_config", return_value=cfg), \
             patch("app.ai.ollama._review_public_api", new_callable=AsyncMock, return_value=mock_response):
            await ai_review(job, fixture_safe_py)

        assert job.ai_score == 8.0
        # AI findings should be appended
        ai_findings = [f for f in job.findings if f.code == "[AI finding]"]
        assert len(ai_findings) == 1

    @pytest.mark.asyncio
    async def test_score_clamped(self, fixture_safe_py):
        job = ScanJob(id="ai003", repo_url="https://test.com", name="Test")
        job.manifest = ManifestInfo(component_type=ComponentType.INTEGRATION)

        mock_response = {"text": '{"score": 15, "summary": "Over", "findings": []}', "analysis": ""}
        cfg = {"ai_provider": "ollama", "max_code_context": 5000, "ai_timeout": 30}

        with patch("app.ai.ollama._get_ai_config", return_value=cfg), \
             patch("app.ai.ollama._review_ollama", new_callable=AsyncMock, return_value=mock_response):
            await ai_review(job, fixture_safe_py)

        assert job.ai_score == 10.0

    @pytest.mark.asyncio
    async def test_negative_score_clamped(self, fixture_safe_py):
        job = ScanJob(id="ai004", repo_url="https://test.com", name="Test")
        job.manifest = ManifestInfo(component_type=ComponentType.INTEGRATION)

        mock_response = {"text": '{"score": -5, "summary": "Bad", "findings": []}', "analysis": ""}
        cfg = {"ai_provider": "ollama", "max_code_context": 5000, "ai_timeout": 30}

        with patch("app.ai.ollama._get_ai_config", return_value=cfg), \
             patch("app.ai.ollama._review_ollama", new_callable=AsyncMock, return_value=mock_response):
            await ai_review(job, fixture_safe_py)

        assert job.ai_score == 0.0

    @pytest.mark.asyncio
    async def test_http_error_handled(self, fixture_safe_py):
        import httpx
        job = ScanJob(id="ai005", repo_url="https://test.com", name="Test")
        job.manifest = ManifestInfo(component_type=ComponentType.INTEGRATION)

        cfg = {"ai_provider": "ollama", "max_code_context": 5000, "ai_timeout": 30}

        with patch("app.ai.ollama._get_ai_config", return_value=cfg), \
             patch("app.ai.ollama._review_ollama", new_callable=AsyncMock,
                   side_effect=httpx.HTTPError("Connection refused")):
            await ai_review(job, fixture_safe_py)

        assert "failed" in job.ai_summary.lower()
        assert job.ai_score is None

    @pytest.mark.asyncio
    async def test_invalid_json_handled(self, fixture_safe_py):
        job = ScanJob(id="ai006", repo_url="https://test.com", name="Test")
        job.manifest = ManifestInfo(component_type=ComponentType.INTEGRATION)

        mock_response = {"text": "not valid json", "analysis": ""}
        cfg = {"ai_provider": "ollama", "max_code_context": 5000, "ai_timeout": 30}

        with patch("app.ai.ollama._get_ai_config", return_value=cfg), \
             patch("app.ai.ollama._review_ollama", new_callable=AsyncMock, return_value=mock_response):
            await ai_review(job, fixture_safe_py)

        assert "error" in job.ai_summary.lower() or "parse" in job.ai_summary.lower()

    @pytest.mark.asyncio
    async def test_invalid_severity_defaults_to_medium(self, fixture_safe_py):
        job = ScanJob(id="ai007", repo_url="https://test.com", name="Test")
        job.manifest = ManifestInfo(component_type=ComponentType.INTEGRATION)

        mock_response = {
            "text": '{"score": 7, "summary": "OK", "findings": [{"severity": "unknown_sev", "category": "test", "description": "test", "file": "x.py"}]}',
            "analysis": "",
        }
        cfg = {"ai_provider": "ollama", "max_code_context": 5000, "ai_timeout": 30}

        with patch("app.ai.ollama._get_ai_config", return_value=cfg), \
             patch("app.ai.ollama._review_ollama", new_callable=AsyncMock, return_value=mock_response):
            await ai_review(job, fixture_safe_py)

        ai_findings = [f for f in job.findings if f.code == "[AI finding]"]
        assert ai_findings[0].severity == Severity.MEDIUM
