"""Phase 2: YAML and Jinja2 template static analysis."""

import logging
import re
from pathlib import Path

from app.config import settings
from app.models import Finding, Severity

log = logging.getLogger(__name__)

# Dangerous shell/command patterns in YAML values
DANGEROUS_SERVICES = re.compile(
    r"^\s*(shell_command|command_line)\s*:", re.MULTILINE
)

# Hardcoded secrets (not using !secret)
HARDCODED_SECRET_PATTERNS = [
    re.compile(r"^\s*(password|api_key|token|secret|client_secret)\s*:\s*[\"']?[^\s!][^\s#\"']{8,}", re.MULTILINE | re.IGNORECASE),
]

# Insecure HTTP URLs (not HTTPS) in url: fields
INSECURE_URL = re.compile(
    r"^\s*url\s*:\s*[\"']?http://(?!localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)",
    re.MULTILINE | re.IGNORECASE,
)

# Jinja2 template patterns
JINJA_EVAL = re.compile(r"\{[%{].*?\b(eval|exec|import|__import__|compile)\b.*?[%}]\}")
JINJA_SHELL_TEMPLATE = re.compile(r"\{[{%].*?states\s*\(.*?\).*?[%}]\}")

# External URL loading in templates
EXTERNAL_URL_TEMPLATE = re.compile(r"\{[{%].*?(https?://[^\s}%]+).*?[%}]\}")


def _find_line(content: str, pattern: re.Pattern) -> tuple[int | None, str]:
    """Find line number and matched text for a pattern."""
    for i, line in enumerate(content.splitlines(), 1):
        m = pattern.search(line)
        if m:
            return i, line.strip()[:120]
    return None, ""


def scan_yaml_file(filepath: Path) -> list[Finding]:
    """Scan a single YAML file for security issues."""
    findings = []
    try:
        content = filepath.read_text(errors="replace")
    except OSError as e:
        log.warning("Cannot read %s: %s", filepath, e)
        return findings

    if len(content) > settings.max_file_size_kb * 1024:
        return findings

    fpath = str(filepath)

    # Check for shell_command / command_line services
    for m in DANGEROUS_SERVICES.finditer(content):
        line_num = content[:m.start()].count("\n") + 1
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category="command_execution",
            file=fpath,
            line=line_num,
            code=m.group().strip()[:120],
            description="shell_command/command_line can execute arbitrary system commands",
        ))

    # Check for hardcoded secrets
    for pattern in HARDCODED_SECRET_PATTERNS:
        line, code = _find_line(content, pattern)
        if line:
            findings.append(Finding(
                severity=Severity.HIGH,
                category="hardcoded_secret",
                file=fpath,
                line=line,
                code=code,
                description="Possible hardcoded secret — use !secret instead",
            ))

    # Check for insecure HTTP URLs
    line, code = _find_line(content, INSECURE_URL)
    if line:
        findings.append(Finding(
            severity=Severity.LOW,
            category="insecure_transport",
            file=fpath,
            line=line,
            code=code,
            description="HTTP URL used instead of HTTPS (unencrypted)",
        ))

    # Check Jinja2 templates for dangerous patterns
    line, code = _find_line(content, JINJA_EVAL)
    if line:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            category="code_injection",
            file=fpath,
            line=line,
            code=code,
            description="Jinja2 template uses eval/exec/import — possible code injection",
        ))

    # Check for shell_command that uses template values (injection risk)
    if DANGEROUS_SERVICES.search(content) and JINJA_SHELL_TEMPLATE.search(content):
        line, code = _find_line(content, JINJA_SHELL_TEMPLATE)
        if line:
            findings.append(Finding(
                severity=Severity.HIGH,
                category="template_injection",
                file=fpath,
                line=line,
                code=code,
                description="Template value used in shell_command context — possible command injection",
            ))

    return findings


def scan_yaml_repo(repo_path: Path) -> list[Finding]:
    """Scan all YAML files in a repository."""
    findings = []
    for yamlfile in repo_path.rglob("*.y*ml"):
        if yamlfile.suffix not in (".yaml", ".yml"):
            continue
        rel = str(yamlfile.relative_to(repo_path))
        if any(skip in rel.split("/") for skip in ["tests", ".venv", "node_modules", "__pycache__", ".git"]):
            continue
        findings.extend(scan_yaml_file(yamlfile))
    return findings
