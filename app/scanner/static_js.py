"""Phase 2: JavaScript/TypeScript static pattern analysis."""

import logging
import re
from pathlib import Path

from app.config import settings
from app.models import Finding, Severity

log = logging.getLogger(__name__)

# Patterns: (regex, severity, category, description)
JS_PATTERNS: list[tuple[str, Severity, str, str]] = [
    # Code injection
    (r'\beval\s*\(', Severity.CRITICAL, "code_injection", "eval() can execute arbitrary code"),
    (r'\bFunction\s*\(', Severity.CRITICAL, "code_injection", "Function() constructor creates executable code"),
    (r'setTimeout\s*\(\s*["\']', Severity.HIGH, "code_injection", "setTimeout with string argument acts as eval"),
    (r'setInterval\s*\(\s*["\']', Severity.HIGH, "code_injection", "setInterval with string argument acts as eval"),
    (r'\.innerHTML\s*=', Severity.MEDIUM, "xss", "innerHTML assignment can introduce XSS"),
    (r'document\.write\s*\(', Severity.HIGH, "xss", "document.write can inject arbitrary HTML"),
    (r'\.insertAdjacentHTML\s*\(', Severity.MEDIUM, "xss", "insertAdjacentHTML can introduce XSS"),

    # Network / exfiltration
    (r'\bfetch\s*\(', Severity.INFO, "network", "fetch() makes network requests"),
    (r'XMLHttpRequest', Severity.INFO, "network", "XMLHttpRequest makes network requests"),
    (r'\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE)', Severity.INFO, "network", "XHR open with HTTP method"),
    (r'WebSocket\s*\(', Severity.MEDIUM, "network", "WebSocket connection"),
    (r'navigator\.sendBeacon', Severity.HIGH, "data_exfiltration", "sendBeacon can transmit data silently"),
    (r'new\s+Image\s*\(\s*\).*\.src\s*=', Severity.HIGH, "data_exfiltration", "Image pixel tracking/exfiltration"),

    # Script injection
    (r'document\.createElement\s*\(\s*["\']script', Severity.HIGH, "script_injection", "Dynamic script element creation"),
    (r'\.appendChild\s*\(.*script', Severity.HIGH, "script_injection", "Script element appended to DOM"),
    (r'\.src\s*=.*https?://', Severity.MEDIUM, "script_injection", "External resource loading via .src"),

    # Obfuscation
    (r'atob\s*\(', Severity.MEDIUM, "obfuscation", "Base64 decode (atob) may hide payloads"),
    (r'String\.fromCharCode', Severity.MEDIUM, "obfuscation", "Character code construction may hide strings"),
    (r'\\x[0-9a-fA-F]{2}', Severity.LOW, "obfuscation", "Hex-encoded characters"),
    (r'\\u[0-9a-fA-F]{4}', Severity.LOW, "obfuscation", "Unicode-escaped characters"),
    (r'unescape\s*\(', Severity.MEDIUM, "obfuscation", "unescape() may decode hidden content"),

    # Data access
    (r'localStorage', Severity.LOW, "data_access", "localStorage access"),
    (r'sessionStorage', Severity.LOW, "data_access", "sessionStorage access"),
    (r'document\.cookie', Severity.MEDIUM, "data_access", "Cookie access"),
    (r'navigator\.userAgent', Severity.LOW, "telemetry", "User agent reading"),
    (r'navigator\.language', Severity.LOW, "telemetry", "Language detection"),

    # Telemetry
    (r'google[\-_]?analytics|gtag|ga\s*\(', Severity.HIGH, "telemetry", "Google Analytics tracking"),
    (r'sentry', Severity.LOW, "telemetry", "Sentry error tracking"),
    (r'analytics', Severity.LOW, "telemetry", "Possible analytics/telemetry"),
    (r'mixpanel|amplitude|segment', Severity.MEDIUM, "telemetry", "Third-party analytics SDK"),

    # JSONP
    (r'jsonp|callback=', Severity.MEDIUM, "network", "JSONP pattern detected"),
]

# Compiled patterns for performance
_COMPILED = [(re.compile(pat, re.IGNORECASE), sev, cat, desc) for pat, sev, cat, desc in JS_PATTERNS]


def scan_js_file(filepath: Path) -> list[Finding]:
    """Scan a single JS/TS file for suspicious patterns."""
    findings = []
    try:
        source = filepath.read_text(errors="replace")
    except OSError as e:
        log.warning("Cannot read %s: %s", filepath, e)
        return findings

    if len(source) > settings.max_file_size_kb * 1024:
        # For large JS files (bundles), still scan but note it
        findings.append(Finding(
            severity=Severity.INFO, category="size",
            file=str(filepath),
            description=f"Large file ({len(source) // 1024}KB), may be bundled/minified",
        ))

    lines = source.splitlines()
    for regex, sev, cat, desc in _COMPILED:
        for i, line in enumerate(lines, 1):
            if regex.search(line):
                findings.append(Finding(
                    severity=sev, category=cat, file=str(filepath),
                    line=i, code=line.strip()[:120], description=desc,
                ))
                break  # One finding per pattern per file

    return findings


def scan_js_repo(repo_path: Path) -> list[Finding]:
    """Scan all JS/TS files in a repository."""
    findings = []
    extensions = {".js", ".ts", ".jsx", ".tsx", ".mjs"}
    for jsfile in repo_path.rglob("*"):
        if jsfile.suffix not in extensions:
            continue
        rel = str(jsfile.relative_to(repo_path))
        if any(skip in rel for skip in ["node_modules", ".venv", "__pycache__", "test/"]):
            continue
        findings.extend(scan_js_file(jsfile))
    return findings
