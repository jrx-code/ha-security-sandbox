"""Phase 2: YAML and Jinja2 template static analysis.

Detects security issues in HA YAML configuration files:
- shell_command / command_line services
- Hardcoded secrets (should use !secret)
- Insecure HTTP URLs
- Jinja2 template injection (eval/exec/import)
- Shell+template combo (command injection)
- Automation flow injection (dynamic service calls, template entity_ids)
- Unsafe !include from external/user-controlled paths
- rest_command / rest with HTTP (not HTTPS)
- Secrets in comments
"""

import logging
import re
from pathlib import Path

import yaml

from app.config import settings
from app.models import Finding, Severity

log = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────
# Regex patterns (used for line-level scanning)
# ──────────────────────────────────────────────────────────────────────

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

# Secret value leaked in YAML comments
SECRET_IN_COMMENT = re.compile(
    r"#.*\b(password|api_key|token|secret|client_secret)\s*[:=]\s*\S{8,}",
    re.IGNORECASE,
)

# Template patterns for dynamic values in automations
_TEMPLATE_VALUE = re.compile(r"\{\{.*?\}\}|\{%.*?%\}")

# ──────────────────────────────────────────────────────────────────────
# Structural YAML analysis
# ──────────────────────────────────────────────────────────────────────

# Keys whose values are service domains/names — dynamic values are risky
_SERVICE_KEYS = {"service", "service_template"}
# Keys whose values are entity IDs — dynamic values may be risky
_ENTITY_KEYS = {"entity_id", "target"}


def _find_line(content: str, pattern: re.Pattern) -> tuple[int | None, str]:
    """Find line number and matched text for a pattern."""
    for i, line in enumerate(content.splitlines(), 1):
        m = pattern.search(line)
        if m:
            return i, line.strip()[:120]
    return None, ""


def _find_all_lines(content: str, pattern: re.Pattern) -> list[tuple[int, str]]:
    """Find all matching lines."""
    results = []
    for i, line in enumerate(content.splitlines(), 1):
        if pattern.search(line):
            results.append((i, line.strip()[:120]))
    return results


def _has_template(value) -> bool:
    """Check if a YAML value contains Jinja2 templates."""
    if isinstance(value, str):
        return bool(_TEMPLATE_VALUE.search(value))
    return False


def _scan_automation_actions(actions: list, filepath: str, findings: list[Finding]):
    """Scan automation action list for risky patterns."""
    if not isinstance(actions, list):
        return
    for action in actions:
        if not isinstance(action, dict):
            continue

        # service_template is inherently dynamic — flag it
        if "service_template" in action:
            findings.append(Finding(
                severity=Severity.HIGH,
                category="automation_injection",
                file=filepath,
                description="service_template in automation — service name is dynamic, verify not user-controlled",
            ))

        # service with template value
        service = action.get("service", "")
        if isinstance(service, str) and _has_template(service):
            findings.append(Finding(
                severity=Severity.HIGH,
                category="automation_injection",
                file=filepath,
                description=f"Dynamic service call in automation: {service[:80]}",
            ))

        # data_template or data with templates that could reach dangerous sinks
        data = action.get("data_template") or action.get("data", {})
        if isinstance(data, dict):
            for key, val in data.items():
                if isinstance(val, str) and _has_template(val):
                    # Template in service data — check if it flows to a dangerous sink
                    if action.get("service", "").startswith(("shell_command", "script")):
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            category="template_injection",
                            file=filepath,
                            description=f"Template value in {key} flows to {action.get('service', '?')} — command injection risk",
                        ))

        # Nested sequences (choose, repeat, if/then)
        for nested_key in ("sequence", "then", "else", "default"):
            nested = action.get(nested_key)
            if isinstance(nested, list):
                _scan_automation_actions(nested, filepath, findings)

        # choose: list of {conditions, sequence} dicts
        choose = action.get("choose")
        if isinstance(choose, list):
            for option in choose:
                if isinstance(option, dict):
                    seq = option.get("sequence", [])
                    if isinstance(seq, list):
                        _scan_automation_actions(seq, filepath, findings)


def _scan_structured_yaml(data: dict | list, filepath: str) -> list[Finding]:
    """Analyze parsed YAML structure for HA-specific security issues."""
    findings: list[Finding] = []
    if not isinstance(data, dict):
        return findings

    # Scan automation triggers/actions
    automations = []
    if "automation" in data:
        auto = data["automation"]
        if isinstance(auto, list):
            automations = auto
        elif isinstance(auto, dict):
            automations = [auto]

    # Also handle standalone automation files (list at root level)
    # This is handled by scan_yaml_file when data is a list

    for auto in automations:
        if not isinstance(auto, dict):
            continue
        actions = auto.get("action") or auto.get("actions") or auto.get("sequence", [])
        if isinstance(actions, dict):
            actions = [actions]
        _scan_automation_actions(actions, filepath, findings)

    # rest_command with HTTP
    rest_cmds = data.get("rest_command", {})
    if isinstance(rest_cmds, dict):
        for name, cfg in rest_cmds.items():
            url = ""
            if isinstance(cfg, str):
                url = cfg
            elif isinstance(cfg, dict):
                url = cfg.get("url", "")
            if isinstance(url, str) and url.startswith("http://"):
                # Skip local URLs
                if not re.match(r"http://(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)", url):
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        category="insecure_transport",
                        file=filepath,
                        description=f"rest_command '{name}' uses HTTP — should use HTTPS",
                    ))

    # rest sensor/binary_sensor with HTTP
    rest_entries = data.get("rest", [])
    if isinstance(rest_entries, list):
        for entry in rest_entries:
            if isinstance(entry, dict):
                url = entry.get("resource", "") or entry.get("url", "")
                if isinstance(url, str) and url.startswith("http://"):
                    if not re.match(r"http://(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)", url):
                        findings.append(Finding(
                            severity=Severity.MEDIUM,
                            category="insecure_transport",
                            file=filepath,
                            description=f"REST resource uses HTTP — should use HTTPS: {url[:60]}",
                        ))

    return findings


def _scan_include_patterns(content: str, filepath: str) -> list[Finding]:
    """Detect potentially unsafe !include patterns."""
    findings: list[Finding] = []
    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        # !include with template or variable path
        if "!include" in stripped:
            # Check for template in the include path
            path_part = stripped.split("!include", 1)[1].strip() if "!include" in stripped else ""
            if _has_template(path_part):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category="unsafe_include",
                    file=filepath,
                    line=i,
                    code=stripped[:120],
                    description="!include with template path — dynamic file loading risk",
                ))
            # Check for absolute or parent paths
            elif path_part.startswith("/") or ".." in path_part:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category="unsafe_include",
                    file=filepath,
                    line=i,
                    code=stripped[:120],
                    description="!include with absolute/parent path — potential path traversal",
                ))
    return findings


def _scan_secret_comments(content: str, filepath: str) -> list[Finding]:
    """Detect secrets accidentally left in YAML comments."""
    findings: list[Finding] = []
    matches = _find_all_lines(content, SECRET_IN_COMMENT)
    for line_num, code in matches[:3]:  # Cap at 3 per file
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category="hardcoded_secret",
            file=filepath,
            line=line_num,
            code=code,
            description="Possible secret value in YAML comment — remove or use !secret",
        ))
    return findings


# ──────────────────────────────────────────────────────────────────────
# Main scan functions
# ──────────────────────────────────────────────────────────────────────

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

    # ── Regex-based scanning (original patterns) ──

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

    # ── New: include pattern scanning ──
    findings.extend(_scan_include_patterns(content, fpath))

    # ── New: secret-in-comment scanning ──
    findings.extend(_scan_secret_comments(content, fpath))

    # ── Structural YAML parsing ──
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            findings.extend(_scan_structured_yaml(data, fpath))
        elif isinstance(data, list):
            # Standalone automation files are lists of automations
            for item in data:
                if isinstance(item, dict):
                    actions = item.get("action") or item.get("actions") or item.get("sequence", [])
                    if isinstance(actions, dict):
                        actions = [actions]
                    if isinstance(actions, list):
                        _scan_automation_actions(actions, fpath, findings)
    except yaml.YAMLError:
        pass  # File may use HA-specific YAML tags (!secret, !include) — regex scanning still covers it

    return findings


def _cap_findings_per_file(findings: list[Finding], max_per_cat: int = 3) -> list[Finding]:
    """Cap findings to max_per_cat per category per file to reduce noise."""
    counts: dict[tuple[str, str], int] = {}
    capped: list[Finding] = []
    for f in findings:
        key = (f.file, f.category)
        counts[key] = counts.get(key, 0) + 1
        if counts[key] <= max_per_cat:
            capped.append(f)
    return capped


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
    return _cap_findings_per_file(findings)
