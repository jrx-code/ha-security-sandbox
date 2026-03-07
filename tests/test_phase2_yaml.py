"""Phase 2 tests: YAML/Jinja2 static analysis."""

from pathlib import Path

import pytest

from app.models import Severity
from app.scanner.static_yaml import scan_yaml_file, scan_yaml_repo


class TestYAMLScanner:
    def test_shell_command_detected(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            "shell_command:\n"
            "  restart_service: systemctl restart nginx\n"
        )
        findings = scan_yaml_file(f)
        assert any(f.category == "command_execution" for f in findings)

    def test_command_line_detected(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            "command_line:\n"
            "  - sensor:\n"
            "      command: cat /proc/uptime\n"
        )
        findings = scan_yaml_file(f)
        assert any(f.category == "command_execution" for f in findings)

    def test_hardcoded_password_detected(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            "mqtt:\n"
            "  broker: 192.168.1.1\n"
            '  password: "SuperSecretPassword123"\n'
        )
        findings = scan_yaml_file(f)
        assert any(f.category == "hardcoded_secret" for f in findings)

    def test_secret_reference_not_flagged(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            "mqtt:\n"
            "  broker: 192.168.1.1\n"
            "  password: !secret mqtt_password\n"
        )
        findings = scan_yaml_file(f)
        assert not any(f.category == "hardcoded_secret" for f in findings)

    def test_insecure_http_detected(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            "rest:\n"
            "  url: http://external-api.example.com/data\n"
        )
        findings = scan_yaml_file(f)
        assert any(f.category == "insecure_transport" for f in findings)

    def test_local_http_not_flagged(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            "rest:\n"
            "  url: http://192.168.1.100/api\n"
        )
        findings = scan_yaml_file(f)
        assert not any(f.category == "insecure_transport" for f in findings)

    def test_jinja2_eval_detected(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            "template:\n"
            '  value: "{{ eval(user_input) }}"\n'
        )
        findings = scan_yaml_file(f)
        assert any(f.category == "code_injection" and f.severity == Severity.CRITICAL for f in findings)

    def test_template_injection_detected(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            "shell_command:\n"
            '  run_cmd: "echo {{ states(\"sensor.temp\") }}"\n'
        )
        findings = scan_yaml_file(f)
        assert any(f.category == "template_injection" for f in findings)

    def test_safe_yaml(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            "sensor:\n"
            "  - platform: mqtt\n"
            "    name: Temperature\n"
            "    state_topic: home/temp\n"
        )
        findings = scan_yaml_file(f)
        high_or_above = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(high_or_above) == 0

    def test_repo_scan_finds_yaml(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "configuration.yaml").write_text(
            "shell_command:\n"
            "  test: echo hello\n"
        )
        (repo / "README.md").write_text("# Test\n")
        findings = scan_yaml_repo(repo)
        assert len(findings) > 0

    def test_repo_skips_git_dir(self, tmp_path):
        repo = tmp_path / "repo"
        git_dir = repo / ".git" / "hooks"
        git_dir.mkdir(parents=True)
        (git_dir / "pre-commit.yml").write_text("shell_command:\n  bad: rm -rf /\n")
        (repo / "safe.yaml").write_text("sensor:\n  name: test\n")
        findings = scan_yaml_repo(repo)
        assert not any(".git" in f.file for f in findings)
