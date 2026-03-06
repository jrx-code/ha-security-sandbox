"""Phase 2 tests: Static analysis — Python AST + JS regex scanners."""

from pathlib import Path

import pytest

from app.models import Severity
from app.scanner.static_python import scan_python_file, scan_python_repo
from app.scanner.static_js import scan_js_file, scan_js_repo


class TestPythonScanner:
    def test_dangerous_file(self, fixture_dangerous_py):
        """Dangerous patterns should be detected."""
        init_file = fixture_dangerous_py / "custom_components" / "evil" / "__init__.py"
        findings = scan_python_file(init_file)

        categories = {f.category for f in findings}
        severities = {f.severity for f in findings}

        assert "code_injection" in categories  # eval, exec
        assert "command_execution" in categories  # subprocess, os.system
        assert "deserialization" in categories  # pickle
        assert "native_code" in categories  # ctypes
        assert Severity.CRITICAL in severities

    def test_safe_file(self, fixture_safe_py):
        """Safe code should produce no findings (or only info)."""
        init_file = fixture_safe_py / "custom_components" / "safe" / "__init__.py"
        findings = scan_python_file(init_file)

        high_or_above = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(high_or_above) == 0

    def test_eval_detected(self, tmp_path):
        f = tmp_path / "code.py"
        f.write_text('result = eval(user_input)\n')
        findings = scan_python_file(f)
        assert any(f.category == "code_injection" and f.severity == Severity.CRITICAL for f in findings)

    def test_exec_detected(self, tmp_path):
        f = tmp_path / "code.py"
        f.write_text('exec(some_code)\n')
        findings = scan_python_file(f)
        assert any(f.category == "code_injection" and f.severity == Severity.CRITICAL for f in findings)

    def test_subprocess_detected(self, tmp_path):
        f = tmp_path / "code.py"
        f.write_text('import subprocess\nsubprocess.run(["ls"])\n')
        findings = scan_python_file(f)
        assert any(f.category == "command_execution" for f in findings)

    def test_network_module_detected(self, tmp_path):
        f = tmp_path / "code.py"
        f.write_text('import requests\nrequests.get("http://example.com")\n')
        findings = scan_python_file(f)
        assert any(f.category == "network" for f in findings)

    def test_syntax_error_handled(self, tmp_path):
        f = tmp_path / "broken.py"
        f.write_text('def broken(\n')
        findings = scan_python_file(f)
        # Should not raise, just skip AST
        assert isinstance(findings, list)

    def test_large_file_skipped(self, tmp_path):
        from unittest.mock import patch
        f = tmp_path / "big.py"
        f.write_text('x = 1\n' * 200000)  # >500KB
        with patch("app.config.settings.max_file_size_kb", 500):
            findings = scan_python_file(f)
        assert any(f.category == "size" for f in findings)

    def test_repo_skips_tests_dir(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        tests_dir = repo / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_evil.py").write_text('eval("1+1")\n')
        (repo / "main.py").write_text('x = 1\n')
        findings = scan_python_repo(repo)
        assert not any("test_evil" in f.file for f in findings)

    def test_repo_skips_venv(self, tmp_path):
        repo = tmp_path / "repo"
        venv = repo / ".venv" / "lib"
        venv.mkdir(parents=True)
        (venv / "evil.py").write_text('eval("1")\n')
        (repo / "main.py").write_text('x = 1\n')
        findings = scan_python_repo(repo)
        assert not any(".venv" in f.file for f in findings)


class TestJSScanner:
    def test_dangerous_file(self, fixture_dangerous_js):
        js_file = fixture_dangerous_js / "evil-card.js"
        findings = scan_js_file(js_file)

        categories = {f.category for f in findings}
        assert "code_injection" in categories  # eval, Function
        assert "xss" in categories  # document.write
        assert "data_exfiltration" in categories  # sendBeacon
        assert "data_access" in categories  # document.cookie
        assert "telemetry" in categories  # gtag

    def test_safe_file(self, fixture_safe_js):
        js_file = fixture_safe_js / "safe-card.js"
        findings = scan_js_file(js_file)

        high_or_above = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(high_or_above) == 0

    def test_eval_detected(self, tmp_path):
        f = tmp_path / "code.js"
        f.write_text('var x = eval("1+1");\n')
        findings = scan_js_file(f)
        assert any(f.severity == Severity.CRITICAL and f.category == "code_injection" for f in findings)

    def test_innerhtml_detected(self, tmp_path):
        f = tmp_path / "code.js"
        f.write_text('el.innerHTML = userInput;\n')
        findings = scan_js_file(f)
        assert any(f.category == "xss" for f in findings)

    def test_websocket_detected(self, tmp_path):
        f = tmp_path / "code.js"
        f.write_text('const ws = new WebSocket("wss://example.com");\n')
        findings = scan_js_file(f)
        assert any(f.category == "network" for f in findings)

    def test_repo_skips_node_modules(self, tmp_path):
        repo = tmp_path / "repo"
        nm = repo / "node_modules" / "lib"
        nm.mkdir(parents=True)
        (nm / "evil.js").write_text('eval("1");\n')
        (repo / "card.js").write_text('var x = 1;\n')
        findings = scan_js_repo(repo)
        assert not any("node_modules" in f.file for f in findings)

    def test_multiple_extensions(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "comp.ts").write_text('eval("bad");\n')
        (repo / "comp.tsx").write_text('var y = 1;\n')
        (repo / "readme.txt").write_text('eval("ignored")\n')
        findings = scan_js_repo(repo)
        assert any("comp.ts" in f.file for f in findings)
        assert not any("readme.txt" in f.file for f in findings)
