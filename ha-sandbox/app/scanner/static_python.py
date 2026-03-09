"""Phase 2: Python static analysis using AST + data flow analysis."""

import ast
import logging
from pathlib import Path

from app.config import settings
from app.models import Finding, Severity

log = logging.getLogger(__name__)

# Dangerous function calls
DANGEROUS_CALLS = {
    "eval": ("code_injection", Severity.CRITICAL, "eval() can execute arbitrary code"),
    "exec": ("code_injection", Severity.CRITICAL, "exec() can execute arbitrary code"),
    "compile": ("code_injection", Severity.HIGH, "compile() can create executable code"),
    "__import__": ("code_injection", Severity.HIGH, "Dynamic import can load arbitrary modules"),
}

# Dangerous module usage
DANGEROUS_IMPORTS = {
    "subprocess": ("command_execution", Severity.HIGH, "subprocess can execute system commands"),
    "os.system": ("command_execution", Severity.CRITICAL, "os.system executes shell commands"),
    "os.popen": ("command_execution", Severity.HIGH, "os.popen executes shell commands"),
    "pickle": ("deserialization", Severity.HIGH, "pickle can execute arbitrary code during deserialization"),
    "shelve": ("deserialization", Severity.MEDIUM, "shelve uses pickle internally"),
    "marshal": ("deserialization", Severity.MEDIUM, "marshal can deserialize code objects"),
    "ctypes": ("native_code", Severity.HIGH, "ctypes allows calling native code"),
    "webbrowser": ("data_exfiltration", Severity.MEDIUM, "Can open URLs in browser"),
}

# Network-related modules
NETWORK_MODULES = {
    "requests", "httpx", "urllib", "urllib3", "aiohttp",
    "socket", "http.client", "ftplib", "smtplib", "telnetlib",
}

# Suspicious string patterns in code
SUSPICIOUS_PATTERNS = [
    ("base64.b64decode", Severity.MEDIUM, "obfuscation", "Base64 decode may hide payloads"),
    ("codecs.decode", Severity.MEDIUM, "obfuscation", "Codec decode may hide payloads"),
    ("analytics", Severity.LOW, "telemetry", "Possible analytics/telemetry"),
    ("google-analytics", Severity.MEDIUM, "telemetry", "Google Analytics tracking"),
    ("sentry", Severity.LOW, "telemetry", "Sentry error tracking"),
    ("tracking", Severity.LOW, "telemetry", "Possible tracking code"),
]

# ──────────────────────────────────────────────────────────────────────
# Taint sources: attribute access patterns that introduce user-controlled data
# ──────────────────────────────────────────────────────────────────────
_TAINT_ATTRS: set[str] = {
    # HA config entry data (user-supplied configuration)
    "data", "options",
    # HTTP request attributes
    "query", "form", "json", "body", "params", "args",
    "query_string", "cookies", "headers",
    # Generic input
    "user_input", "input",
}

# Attribute chains that mark a variable as tainted (obj.attr patterns)
_TAINT_MEMBER_CHAINS: set[tuple[str, str]] = {
    ("config_entry", "data"),
    ("config_entry", "options"),
    ("entry", "data"),
    ("entry", "options"),
    ("hass", "data"),
    ("request", "query"),
    ("request", "json"),
    ("request", "form"),
    ("request", "body"),
}

# Function calls whose return value is tainted
_TAINT_CALLS: set[str] = {
    "input", "raw_input",
}

# ──────────────────────────────────────────────────────────────────────
# Dangerous sinks: functions where tainted data causes vulnerabilities
# ──────────────────────────────────────────────────────────────────────
_DANGEROUS_SINKS: dict[str, tuple[Severity, str, str]] = {
    "eval": (Severity.CRITICAL, "taint_code_injection",
             "User-controlled data flows into eval()"),
    "exec": (Severity.CRITICAL, "taint_code_injection",
             "User-controlled data flows into exec()"),
    "system": (Severity.CRITICAL, "taint_command_injection",
               "User-controlled data flows into os.system()"),
    "popen": (Severity.HIGH, "taint_command_injection",
              "User-controlled data flows into os.popen()"),
    "run": (Severity.HIGH, "taint_command_injection",
            "User-controlled data in subprocess.run() (check shell=True)"),
    "call": (Severity.HIGH, "taint_command_injection",
             "User-controlled data in subprocess.call() (check shell=True)"),
    "check_output": (Severity.HIGH, "taint_command_injection",
                     "User-controlled data in subprocess.check_output()"),
    "Popen": (Severity.HIGH, "taint_command_injection",
              "User-controlled data in subprocess.Popen()"),
    "loads": (Severity.HIGH, "taint_deserialization",
              "User-controlled data in pickle.loads()"),
    "load": (Severity.MEDIUM, "taint_deserialization",
             "User-controlled data in deserialization (pickle/yaml)"),
}

# File operations where tainted path = path traversal
_FILE_SINKS: set[str] = {"open", "read_text", "read_bytes", "write_text", "write_bytes"}


class PythonASTVisitor(ast.NodeVisitor):
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.findings: list[Finding] = []
        self._imports: set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self._imports.add(alias.name)
            self._check_import(alias.name, node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            self._imports.add(node.module)
            self._check_import(node.module, node.lineno)
            for alias in node.names:
                full = f"{node.module}.{alias.name}"
                self._check_import(full, node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        name = self._get_call_name(node)
        if name in DANGEROUS_CALLS:
            cat, sev, desc = DANGEROUS_CALLS[name]
            self.findings.append(Finding(
                severity=sev, category=cat, file=self.filepath,
                line=node.lineno, code=name, description=desc,
            ))
        self.generic_visit(node)

    def _check_import(self, module: str, lineno: int):
        for pattern, (cat, sev, desc) in DANGEROUS_IMPORTS.items():
            if module == pattern or module.startswith(pattern + "."):
                self.findings.append(Finding(
                    severity=sev, category=cat, file=self.filepath,
                    line=lineno, code=f"import {module}", description=desc,
                ))
        base = module.split(".")[0]
        if base in NETWORK_MODULES:
            self.findings.append(Finding(
                severity=Severity.INFO, category="network",
                file=self.filepath, line=lineno,
                code=f"import {module}",
                description=f"Network module '{base}' imported",
            ))

    def _get_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""


# ──────────────────────────────────────────────────────────────────────
# Taint tracker — lightweight intraprocedural data flow analysis
# ──────────────────────────────────────────────────────────────────────

def _is_taint_source(node: ast.expr) -> bool:
    """Check if an expression introduces tainted (user-controlled) data."""
    # Direct taint call: input()
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in _TAINT_CALLS:
            return True
    # Subscript on tainted container: config_entry.data["key"], hass.data[DOMAIN]
    if isinstance(node, ast.Subscript):
        return _is_taint_source(node.value)
    # Attribute access: config_entry.data, request.json
    if isinstance(node, ast.Attribute):
        if node.attr in _TAINT_ATTRS:
            return True
        if isinstance(node.value, ast.Name):
            if (node.value.id, node.attr) in _TAINT_MEMBER_CHAINS:
                return True
    # .get() on tainted container: config_entry.data.get("key")
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "get":
            return _is_taint_source(node.func.value)
    return False


def _expr_uses_var(node: ast.expr, tainted: set[str]) -> bool:
    """Check if an expression references any tainted variable."""
    if isinstance(node, ast.Name):
        return node.id in tainted
    if isinstance(node, ast.BinOp):
        return _expr_uses_var(node.left, tainted) or _expr_uses_var(node.right, tainted)
    if isinstance(node, ast.JoinedStr):  # f-string
        for val in node.values:
            if isinstance(val, ast.FormattedValue):
                if _expr_uses_var(val.value, tainted):
                    return True
    if isinstance(node, ast.Call):
        # str.format() with tainted arg
        for arg in node.args:
            if _expr_uses_var(arg, tainted):
                return True
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            if _expr_uses_var(node.func.value, tainted):
                return True
    if isinstance(node, ast.Subscript):
        return _expr_uses_var(node.value, tainted)
    if isinstance(node, ast.Attribute):
        return _expr_uses_var(node.value, tainted)
    if isinstance(node, ast.Starred):
        return _expr_uses_var(node.value, tainted)
    return False


def _has_shell_true(node: ast.Call) -> bool:
    """Check if a Call node has shell=True keyword argument."""
    for kw in node.keywords:
        if kw.arg == "shell":
            if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
            if isinstance(kw.value, ast.NameConstant) and getattr(kw.value, "value", None) is True:
                return True
    return False


def _get_code_snippet(source: str, lineno: int) -> str:
    """Get a trimmed code snippet for a given line."""
    lines = source.splitlines()
    if 0 < lineno <= len(lines):
        return lines[lineno - 1].strip()[:120]
    return ""


def _scan_taint_flow(tree: ast.Module, filepath: str, source: str) -> list[Finding]:
    """Scan for tainted data flowing into dangerous sinks.

    Walks each function body tracking which local variables hold
    user-controlled data (taint sources), then flags when those
    variables reach dangerous sinks like eval(), subprocess, open().
    """
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    def add(sev: Severity, cat: str, desc: str, lineno: int):
        key = (cat, lineno)
        if key not in seen:
            seen.add(key)
            findings.append(Finding(
                severity=sev, category=cat, file=filepath,
                line=lineno, code=_get_code_snippet(source, lineno),
                description=desc,
            ))

    def scan_body(stmts: list[ast.stmt]):
        """Scan a sequence of statements tracking taint."""
        tainted: set[str] = set()

        for stmt in stmts:
            # Track assignments: x = config_entry.data["key"]
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        if _is_taint_source(stmt.value) or _expr_uses_var(stmt.value, tainted):
                            tainted.add(target.id)
                        elif target.id in tainted:
                            tainted.discard(target.id)  # Overwritten with safe value
            elif isinstance(stmt, ast.AnnAssign) and stmt.value and isinstance(stmt.target, ast.Name):
                if _is_taint_source(stmt.value) or _expr_uses_var(stmt.value, tainted):
                    tainted.add(stmt.target.id)
                elif stmt.target.id in tainted:
                    tainted.discard(stmt.target.id)

            # Check calls for tainted args flowing to sinks
            for node in ast.walk(stmt):
                if not isinstance(node, ast.Call):
                    continue

                call_name = ""
                if isinstance(node.func, ast.Name):
                    call_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    call_name = node.func.attr

                if not call_name:
                    continue

                # Check if any argument is tainted
                args_tainted = any(_expr_uses_var(a, tainted) for a in node.args)
                if not args_tainted:
                    continue

                # Sink: dangerous function calls
                if call_name in _DANGEROUS_SINKS:
                    sev, cat, desc = _DANGEROUS_SINKS[call_name]
                    # subprocess with shell=True is CRITICAL
                    if call_name in ("run", "call", "check_output", "Popen") and _has_shell_true(node):
                        sev = Severity.CRITICAL
                        desc += " with shell=True"
                    add(sev, cat, desc, node.lineno)

                # Sink: file operations with tainted path
                if call_name in _FILE_SINKS:
                    add(Severity.HIGH, "taint_path_traversal",
                        "User-controlled data in file path — potential path traversal",
                        node.lineno)

            # Recurse into nested blocks (if/for/while/with/try)
            if isinstance(stmt, (ast.If, ast.For, ast.While, ast.With)):
                scan_body(stmt.body)
                if hasattr(stmt, "orelse") and stmt.orelse:
                    scan_body(stmt.orelse)
            elif isinstance(stmt, ast.Try):
                scan_body(stmt.body)
                for handler in stmt.handlers:
                    scan_body(handler.body)
                if stmt.orelse:
                    scan_body(stmt.orelse)
                if stmt.finalbody:
                    scan_body(stmt.finalbody)

    # Scan module-level statements
    scan_body(tree.body)

    # Scan each function/method body independently
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scan_body(node.body)

    return findings


def scan_python_file(filepath: Path) -> list[Finding]:
    """Scan a single Python file using AST analysis."""
    findings = []
    try:
        source = filepath.read_text(errors="replace")
    except OSError as e:
        log.warning("Cannot read %s: %s", filepath, e)
        return findings

    if len(source) > settings.max_file_size_kb * 1024:
        findings.append(Finding(
            severity=Severity.INFO, category="size",
            file=str(filepath), description=f"File exceeds {settings.max_file_size_kb}KB, skipped AST",
        ))
        return findings

    # AST analysis
    try:
        tree = ast.parse(source, filename=str(filepath))
        visitor = PythonASTVisitor(str(filepath))
        visitor.visit(tree)
        findings.extend(visitor.findings)

        # Taint flow analysis
        taint_findings = _scan_taint_flow(tree, str(filepath), source)
        findings.extend(taint_findings)
    except SyntaxError:
        log.debug("Syntax error in %s, skipping AST", filepath)

    # String pattern matching
    for pattern, sev, cat, desc in SUSPICIOUS_PATTERNS:
        if pattern in source.lower():
            # Find line number
            for i, line in enumerate(source.splitlines(), 1):
                if pattern in line.lower():
                    findings.append(Finding(
                        severity=sev, category=cat, file=str(filepath),
                        line=i, code=line.strip()[:120], description=desc,
                    ))
                    break

    return findings


def scan_python_repo(repo_path: Path) -> list[Finding]:
    """Scan all Python files in a repository."""
    findings = []
    for pyfile in repo_path.rglob("*.py"):
        # Skip test files and venvs
        rel = str(pyfile.relative_to(repo_path))
        if any(skip in rel.split("/") for skip in ["tests", ".venv", "node_modules", "__pycache__"]):
            continue
        findings.extend(scan_python_file(pyfile))
    return findings
