"""Phase 1 tests: Clone & Parse — detect_type, parse_manifest, fetch_and_parse."""

import json
from pathlib import Path

import pytest

from app.models import ComponentType, ScanJob, ScanStatus
from app.scanner.fetch import detect_type, parse_manifest, fetch_and_parse


class TestDetectType:
    def test_integration(self, fixture_integration):
        assert detect_type(fixture_integration) == ComponentType.INTEGRATION

    def test_card_from_hacs_json(self, fixture_card):
        assert detect_type(fixture_card) == ComponentType.CARD

    def test_theme_from_hacs_json(self, tmp_path):
        repo = tmp_path / "theme-repo"
        repo.mkdir()
        (repo / "hacs.json").write_text(json.dumps({"category": "theme"}))
        (repo / "themes").mkdir()
        assert detect_type(repo) == ComponentType.THEME

    def test_python_script_from_hacs_json(self, tmp_path):
        repo = tmp_path / "pyscript-repo"
        repo.mkdir()
        (repo / "hacs.json").write_text(json.dumps({"category": "python_script"}))
        assert detect_type(repo) == ComponentType.PYTHON_SCRIPT

    def test_integration_from_hacs_json(self, tmp_path):
        repo = tmp_path / "int-repo"
        repo.mkdir()
        (repo / "hacs.json").write_text(json.dumps({"category": "integration"}))
        assert detect_type(repo) == ComponentType.INTEGRATION

    def test_fallback_js_only(self, tmp_path):
        repo = tmp_path / "js-repo"
        repo.mkdir()
        (repo / "card.js").write_text("class Card {}")
        assert detect_type(repo) == ComponentType.CARD

    def test_fallback_py_only(self, tmp_path):
        repo = tmp_path / "py-repo"
        repo.mkdir()
        (repo / "script.py").write_text("print(1)")
        assert detect_type(repo) == ComponentType.INTEGRATION

    def test_unknown_empty(self, tmp_path):
        repo = tmp_path / "empty-repo"
        repo.mkdir()
        assert detect_type(repo) == ComponentType.UNKNOWN

    def test_unknown_mixed(self, tmp_path):
        repo = tmp_path / "mixed-repo"
        repo.mkdir()
        (repo / "code.py").write_text("x=1")
        (repo / "card.js").write_text("x=1")
        assert detect_type(repo) == ComponentType.UNKNOWN

    def test_broken_hacs_json(self, tmp_path):
        repo = tmp_path / "broken-repo"
        repo.mkdir()
        (repo / "hacs.json").write_text("{invalid json")
        (repo / "code.py").write_text("x=1")
        # Should fallback to file-based detection
        assert detect_type(repo) == ComponentType.INTEGRATION


class TestParseManifest:
    def test_integration_manifest(self, fixture_integration):
        info = parse_manifest(fixture_integration)
        assert info.domain == "test_domain"
        assert info.name == "Test Integration"
        assert info.version == "1.2.3"
        assert info.iot_class == "local_push"
        assert "mqtt" in info.dependencies
        assert "somelib==1.0" in info.requirements

    def test_card_hacs_json(self, fixture_card):
        info = parse_manifest(fixture_card)
        assert info.name == "Test Card"

    def test_fallback_name_from_dir(self, tmp_path):
        repo = tmp_path / "my-cool-repo"
        repo.mkdir()
        info = parse_manifest(repo)
        assert info.name == "my-cool-repo"

    def test_broken_manifest_fallback(self, tmp_path):
        repo = tmp_path / "broken"
        cc = repo / "custom_components" / "broken"
        cc.mkdir(parents=True)
        (cc / "manifest.json").write_text("{bad json!")
        info = parse_manifest(repo)
        assert info.name == "broken"


class TestFetchAndParse:
    def test_local_integration(self, fixture_integration):
        """Test fetch_and_parse with a local repo (bypassing git clone)."""
        from unittest.mock import patch

        job = ScanJob(id="test001", repo_url="https://github.com/test/repo")

        with patch("app.scanner.fetch.clone_repo", return_value=fixture_integration):
            result = fetch_and_parse(job)

        assert result == fixture_integration
        assert job.manifest is not None
        assert job.manifest.component_type == ComponentType.INTEGRATION
        assert job.manifest.domain == "test_domain"
        assert job.name == "Test Integration"

    def test_local_card(self, fixture_card):
        from unittest.mock import patch

        job = ScanJob(id="test002", repo_url="https://github.com/test/card")

        with patch("app.scanner.fetch.clone_repo", return_value=fixture_card):
            result = fetch_and_parse(job)

        assert job.manifest.component_type == ComponentType.CARD
        assert job.name == "Test Card"

    def test_name_preserved_if_set(self, fixture_integration):
        from unittest.mock import patch

        job = ScanJob(id="test003", repo_url="https://github.com/test/repo", name="Custom Name")

        with patch("app.scanner.fetch.clone_repo", return_value=fixture_integration):
            fetch_and_parse(job)

        assert job.name == "Custom Name"
