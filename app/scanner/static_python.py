"""Phase 2: Python static analysis using AST."""

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
