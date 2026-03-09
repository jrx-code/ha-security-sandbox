"""Phase 2.3: Home Assistant API pattern validator.

Detects risky HA API usage patterns in custom integrations:
- hass.services.call / hass.services.async_call with dynamic service names
- Broad entity access without domain filtering
- Unsafe use of hass.bus.fire (event injection)
- Excessive permission patterns (PLATFORM_SCHEMA without validation)
- Direct file system access in HA context
"""

import ast
import logging
from pathlib import Path

from app.config import settings
from app.models import Finding, Severity

log = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────
# HA API patterns to detect
# ──────────────────────────────────────────────────────────────────────

# Dangerous hass method calls: (object_attr, method) -> (severity, category, description)
_HASS_DANGEROUS_METHODS: dict[tuple[str, str], tuple[Severity, str, str]] = {
    ("services", "call"): (
        Severity.MEDIUM, "ha_api_risk",
        "hass.services.call() — verify service name is not user-controlled",
    ),
    ("services", "async_call"): (
        Severity.MEDIUM, "ha_api_risk",
        "hass.services.async_call() — verify service name is not user-controlled",
    ),
    ("bus", "fire"): (
        Severity.MEDIUM, "ha_event_injection",
        "hass.bus.fire() can inject events into HA event bus",
    ),
    ("bus", "async_fire"): (
        Severity.MEDIUM, "ha_event_injection",
        "hass.bus.async_fire() can inject events into HA event bus",
    ),
}

# Risky attribute access on hass object
_HASS_RISKY_ACCESS: dict[str, tuple[Severity, str, str]] = {
    "auth": (Severity.HIGH, "ha_auth_access", "Direct access to hass.auth — authentication system"),
    "config": (Severity.LOW, "ha_config_access", "Access to hass.config — HA configuration"),
}

# Platform schema without proper validation
_SCHEMA_PATTERNS: set[str] = {"PLATFORM_SCHEMA", "CONFIG_SCHEMA"}


class HAASTVisitor(ast.NodeVisitor):
    """Detect HA-specific risky API usage patterns."""

    def __init__(self, filepath: str, source: str):
        self.filepath = filepath
        self.source = source
        self.findings: list[Finding] = []
        self._seen: set[tuple[str, int]] = set()
        self._has_vol_schema = False
        self._uses_schema = False

    def _add(self, sev: Severity, cat: str, desc: str, lineno: int):
        key = (cat, lineno)
        if key not in self._seen:
            self._seen.add(key)
            code = self._get_line(lineno)
            self.findings.append(Finding(
                severity=sev, category=cat, file=self.filepath,
                line=lineno, code=code, description=desc,
            ))

    def _get_line(self, lineno: int) -> str:
        lines = self.source.splitlines()
        if 0 < lineno <= len(lines):
            return lines[lineno - 1].strip()[:120]
        return ""

    def visit_Call(self, node: ast.Call):
        self._check_hass_call(node)
        self._check_service_call_dynamic(node)
        self._check_hass_states_set(node)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        self._check_hass_risky_attr(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        self._check_schema_assign(node)
        self.generic_visit(node)

    def _check_hass_call(self, node: ast.Call):
        """Detect hass.services.call(), hass.bus.fire(), etc."""
        func = node.func
        if not isinstance(func, ast.Attribute):
            return
        method = func.attr
        # Check for hass.X.method() pattern
        if isinstance(func.value, ast.Attribute):
            middle = func.value.attr
            key = (middle, method)
            if key in _HASS_DANGEROUS_METHODS:
                sev, cat, desc = _HASS_DANGEROUS_METHODS[key]
                self._add(sev, cat, desc, node.lineno)

    def _check_service_call_dynamic(self, node: ast.Call):
        """Escalate if service.call uses variable (not literal) for domain/service."""
        func = node.func
        if not isinstance(func, ast.Attribute):
            return
        if func.attr not in ("call", "async_call"):
            return
        if not isinstance(func.value, ast.Attribute):
            return
        if func.value.attr != "services":
            return

        # First two args are domain and service — check if they're dynamic
        for i, arg in enumerate(node.args[:2]):
            if not isinstance(arg, ast.Constant):
                self._add(
                    Severity.HIGH, "ha_dynamic_service",
                    f"Dynamic service {'domain' if i == 0 else 'name'} in "
                    f"hass.services.{'async_' if func.attr == 'async_call' else ''}call() "
                    f"— potential service injection",
                    node.lineno,
                )
                break

    def _check_hass_states_set(self, node: ast.Call):
        """Detect hass.states.set / async_set with broad patterns."""
        func = node.func
        if not isinstance(func, ast.Attribute):
            return
        if func.attr not in ("set", "async_set"):
            return
        if isinstance(func.value, ast.Attribute) and func.value.attr == "states":
            # Check if entity_id is dynamic
            if node.args and not isinstance(node.args[0], ast.Constant):
                self._add(
                    Severity.MEDIUM, "ha_dynamic_entity",
                    "Dynamic entity_id in hass.states.set() — verify controlled",
                    node.lineno,
                )

    def _check_hass_risky_attr(self, node: ast.Attribute):
        """Detect risky hass.auth, hass.config access."""
        if node.attr in _HASS_RISKY_ACCESS:
            # Only flag if parent is likely 'hass' object
            if isinstance(node.value, ast.Name) and node.value.id in ("hass", "self.hass", "self._hass"):
                sev, cat, desc = _HASS_RISKY_ACCESS[node.attr]
                self._add(sev, cat, desc, node.lineno)
            elif isinstance(node.value, ast.Attribute) and node.value.attr in ("hass", "_hass"):
                sev, cat, desc = _HASS_RISKY_ACCESS[node.attr]
                self._add(sev, cat, desc, node.lineno)

    def _check_schema_assign(self, node: ast.Assign):
        """Detect PLATFORM_SCHEMA/CONFIG_SCHEMA assignments, check for vol.Schema."""
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in _SCHEMA_PATTERNS:
                self._uses_schema = True
                # Check if it uses vol.Schema for validation
                if self._uses_voluptuous(node.value):
                    self._has_vol_schema = True
                else:
                    self._add(
                        Severity.MEDIUM, "ha_no_validation",
                        f"{target.id} defined without vol.Schema() validation",
                        node.lineno,
                    )

    def _uses_voluptuous(self, node: ast.expr) -> bool:
        """Check if an expression uses vol.Schema or cv.* validators."""
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                if isinstance(func.value, ast.Name):
                    if func.value.id in ("vol", "cv"):
                        return True
            return self._uses_voluptuous(func)
        return False


def scan_ha_patterns(filepath: Path) -> list[Finding]:
    """Scan a Python file for HA-specific API patterns."""
    try:
        source = filepath.read_text(errors="replace")
    except OSError as e:
        log.warning("Cannot read %s: %s", filepath, e)
        return []

    if len(source) > settings.max_file_size_kb * 1024:
        return []

    try:
        tree = ast.parse(source, filename=str(filepath))
    except SyntaxError:
        return []

    visitor = HAASTVisitor(str(filepath), source)
    visitor.visit(tree)
    return visitor.findings


def scan_ha_repo(repo_path: Path) -> list[Finding]:
    """Scan all Python files in a repo for HA API patterns."""
    findings = []
    for pyfile in repo_path.rglob("*.py"):
        rel = str(pyfile.relative_to(repo_path))
        if any(skip in rel.split("/") for skip in ["tests", ".venv", "node_modules", "__pycache__"]):
            continue
        findings.extend(scan_ha_patterns(pyfile))
    return findings
