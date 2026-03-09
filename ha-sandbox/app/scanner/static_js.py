"""Phase 2: JavaScript/TypeScript static analysis via AST (esprima) + regex fallback."""

import logging
import re
from pathlib import Path

import esprima

from app.config import settings
from app.models import Finding, Severity

log = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────
# AST-based analysis (primary path — eliminates false positives from
# comments, strings, and variable names that regex cannot distinguish)
# ──────────────────────────────────────────────────────────────────────

# Dangerous global function calls
_DANGEROUS_CALLS: dict[str, tuple[Severity, str, str]] = {
    "eval": (Severity.CRITICAL, "code_injection",
             "eval() executes arbitrary code — replace with JSON.parse() or remove; if needed, verify input is sanitized"),
    "Function": (Severity.CRITICAL, "code_injection",
                 "Function() constructor creates executable code — replace with direct function definition"),
    "unescape": (Severity.MEDIUM, "obfuscation",
                 "unescape() decodes hidden content — replace with decodeURIComponent(); check what is being decoded"),
}

# Dangerous method calls (object.method)
_DANGEROUS_METHODS: dict[tuple[str, str], tuple[Severity, str, str]] = {
    ("document", "write"): (Severity.HIGH, "xss",
                            "document.write() injects raw HTML — replace with textContent or DOM API; verify no user input flows here"),
    ("document", "writeln"): (Severity.HIGH, "xss",
                              "document.writeln() injects raw HTML — replace with textContent or DOM API"),
    ("document", "createElement"): (Severity.MEDIUM, "script_injection", "Dynamic element creation"),
    ("navigator", "sendBeacon"): (Severity.HIGH, "data_exfiltration",
                                  "sendBeacon() silently sends data to external server — verify destination URL and payload contents"),
    ("String", "fromCharCode"): (Severity.MEDIUM, "obfuscation",
                                 "String.fromCharCode() builds strings from char codes — check if used to hide URLs or malicious code"),
}

# Dangerous property member access (object.property)
_DANGEROUS_MEMBERS: dict[tuple[str, str], tuple[Severity, str, str]] = {
    ("document", "cookie"): (Severity.MEDIUM, "data_access",
                             "Reads document.cookie — check if cookies are sent externally or stored; HA cards should not need cookie access"),
    ("navigator", "userAgent"): (Severity.LOW, "telemetry",
                                 "Reads browser user-agent — often used for fingerprinting; verify it's for compatibility, not tracking"),
    ("navigator", "language"): (Severity.LOW, "telemetry",
                                "Reads browser language — verify it's for localization, not user profiling"),
}

# Dangerous property assignments (x.property = ...)
_DANGEROUS_ASSIGNMENTS: dict[str, tuple[Severity, str, str]] = {
    "innerHTML": (Severity.MEDIUM, "xss",
                  "innerHTML assignment — if value contains user/entity data, use textContent or sanitize with DOMPurify"),
    "outerHTML": (Severity.MEDIUM, "xss",
                  "outerHTML assignment — if value contains user/entity data, use DOM API or sanitize"),
}

# Dangerous constructor calls (new X(...))
_DANGEROUS_CONSTRUCTORS: dict[str, tuple[Severity, str, str]] = {
    "WebSocket": (Severity.MEDIUM, "network",
                  "WebSocket connection — verify destination is the HA instance, not an external server"),
    "Image": (Severity.MEDIUM, "data_exfiltration",
              "new Image() can silently load external URLs (tracking pixel) — check if .src is set to external domain"),
}

# Network/fetch calls (INFO level — not inherently dangerous)
_NETWORK_CALLS: set[str] = {"fetch", "XMLHttpRequest"}

# setTimeout/setInterval with string argument (acts as eval)
_TIMER_FUNCTIONS: set[str] = {"setTimeout", "setInterval"}

# Telemetry identifiers
_TELEMETRY_IDS: dict[str, tuple[Severity, str]] = {
    "gtag": (Severity.HIGH, "Google Analytics (gtag) — tracks user behavior; HA components should not include analytics"),
    "ga": (Severity.HIGH, "Google Analytics (ga) — tracks user behavior; HA components should not include analytics"),
    "mixpanel": (Severity.MEDIUM, "Mixpanel analytics — sends user interaction data to third party; should be removed"),
    "amplitude": (Severity.MEDIUM, "Amplitude analytics — sends user interaction data to third party; should be removed"),
    "segment": (Severity.MEDIUM, "Segment analytics — aggregates user data to third party; should be removed"),
}

# Storage APIs
_STORAGE_IDS: set[str] = {"localStorage", "sessionStorage"}


def _get_source_line(source: str, node: dict) -> tuple[int, str]:
    """Extract line number and code snippet from an AST node."""
    loc = node.get("loc")
    if loc and loc.get("start"):
        line_num = loc["start"].get("line", 0)
        lines = source.splitlines()
        if 0 < line_num <= len(lines):
            return line_num, lines[line_num - 1].strip()[:120]
    return 0, ""


def _resolve_callee_name(node: dict) -> str | None:
    """Resolve a simple identifier name from a callee node."""
    if node.get("type") == "Identifier":
        return node.get("name")
    return None


def _resolve_member(node: dict) -> tuple[str, str] | None:
    """Resolve object.property from a MemberExpression."""
    if node.get("type") != "MemberExpression":
        return None
    obj = node.get("object", {})
    prop = node.get("property", {})
    obj_name = obj.get("name") if obj.get("type") == "Identifier" else None
    prop_name = prop.get("name") if prop.get("type") == "Identifier" else None
    if obj_name and prop_name:
        return (obj_name, prop_name)
    return None


def _walk_ast(node: dict | list):
    """Recursively yield all AST nodes."""
    if isinstance(node, list):
        for item in node:
            yield from _walk_ast(item)
    elif isinstance(node, dict):
        yield node
        for value in node.values():
            if isinstance(value, (dict, list)):
                yield from _walk_ast(value)


def _has_string_arg(node: dict) -> bool:
    """Check if a CallExpression's first argument is a string literal."""
    args = node.get("arguments", [])
    if args and isinstance(args, list) and len(args) > 0:
        first_arg = args[0]
        return first_arg.get("type") == "Literal" and isinstance(first_arg.get("value"), str)
    return False


def _check_createElement_dangerous(node: dict) -> str | None:
    """Check if createElement is called with 'script' or 'iframe' argument."""
    args = node.get("arguments", [])
    if args and isinstance(args, list) and len(args) > 0:
        first_arg = args[0]
        if first_arg.get("type") == "Literal":
            val = first_arg.get("value")
            if val in ("script", "iframe"):
                return val
    return None


def _scan_js_ast(source: str, filepath: str) -> list[Finding]:
    """Scan JavaScript source via AST analysis."""
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()  # (category, line) dedup

    def add(sev: Severity, cat: str, desc: str, node: dict):
        line, code = _get_source_line(source, node)
        key = (cat, line)
        if key not in seen:
            seen.add(key)
            findings.append(Finding(
                severity=sev, category=cat, file=filepath,
                line=line, code=code, description=desc,
            ))

    try:
        tree = esprima.parseModule(source, loc=True, tolerant=True)
    except esprima.Error:
        try:
            tree = esprima.parseScript(source, loc=True, tolerant=True)
        except esprima.Error:
            return []  # Cannot parse — caller will use regex fallback

    ast_dict = tree.toDict()

    for node in _walk_ast(ast_dict):
        ntype = node.get("type")

        # --- CallExpression: eval(), fetch(), setTimeout("string"), etc. ---
        if ntype == "CallExpression":
            callee = node.get("callee", {})
            name = _resolve_callee_name(callee)

            # Direct calls: eval(), Function(), unescape()
            if name in _DANGEROUS_CALLS:
                sev, cat, desc = _DANGEROUS_CALLS[name]
                add(sev, cat, desc, node)

            # Network calls: fetch(), XMLHttpRequest()
            elif name in _NETWORK_CALLS:
                add(Severity.INFO, "network", f"{name}() makes network requests", node)

            # Timer with string arg (acts as eval)
            elif name in _TIMER_FUNCTIONS and _has_string_arg(node):
                add(Severity.HIGH, "code_injection",
                    f"{name} with string argument acts as eval", node)

            # Telemetry calls: gtag(), ga(), etc.
            elif name in _TELEMETRY_IDS:
                sev, desc = _TELEMETRY_IDS[name]
                add(sev, "telemetry", desc, node)

            # Method calls: document.write(), navigator.sendBeacon(), etc.
            member = _resolve_member(callee)
            if member:
                if member in _DANGEROUS_METHODS:
                    sev, cat, desc = _DANGEROUS_METHODS[member]
                    # Special case: document.createElement('script'/'iframe')
                    if member == ("document", "createElement"):
                        tag = _check_createElement_dangerous(node)
                        if tag == "script":
                            add(Severity.HIGH, "script_injection",
                                "Dynamic script element creation", node)
                        elif tag == "iframe":
                            add(Severity.HIGH, "script_injection",
                                "Dynamic iframe creation — may load external content", node)
                    else:
                        add(sev, cat, desc, node)

                # insertAdjacentHTML
                if member[1] == "insertAdjacentHTML":
                    add(Severity.MEDIUM, "xss",
                        "insertAdjacentHTML — sanitize input or use insertAdjacentText for plain text", node)

        # --- NewExpression: new WebSocket(), new Image() ---
        elif ntype == "NewExpression":
            callee = node.get("callee", {})
            name = _resolve_callee_name(callee)
            if name in _DANGEROUS_CONSTRUCTORS:
                sev, cat, desc = _DANGEROUS_CONSTRUCTORS[name]
                add(sev, cat, desc, node)

        # --- MemberExpression: document.cookie, localStorage, etc. ---
        elif ntype == "MemberExpression":
            member = _resolve_member(node)
            if member and member in _DANGEROUS_MEMBERS:
                sev, cat, desc = _DANGEROUS_MEMBERS[member]
                add(sev, cat, desc, node)

            # Storage APIs
            obj = node.get("object", {})
            obj_name = obj.get("name") if obj.get("type") == "Identifier" else None
            if obj_name in _STORAGE_IDS:
                add(Severity.LOW, "data_access",
                    f"{obj_name} — check what data is stored; HA cards should not persist sensitive tokens or credentials",
                    node)

        # --- AssignmentExpression: x.innerHTML = ... ---
        elif ntype == "AssignmentExpression":
            left = node.get("left", {})
            if left.get("type") == "MemberExpression":
                prop = left.get("property", {})
                prop_name = prop.get("name") if prop.get("type") == "Identifier" else None
                if prop_name in _DANGEROUS_ASSIGNMENTS:
                    sev, cat, desc = _DANGEROUS_ASSIGNMENTS[prop_name]
                    add(sev, cat, desc, node)

                # .src = "https://..." assignment
                if prop_name == "src":
                    right = node.get("right", {})
                    if right.get("type") == "Literal":
                        val = str(right.get("value", ""))
                        if val.startswith(("http://", "https://")):
                            add(Severity.MEDIUM, "script_injection",
                                "External resource loading via .src", node)

        # --- Identifier references: atob, sentry, analytics ---
        elif ntype == "Identifier":
            name = node.get("name")
            if name == "atob":
                add(Severity.MEDIUM, "obfuscation",
                    "Base64 decode (atob) may hide payloads", node)
            elif name == "sentry":
                add(Severity.LOW, "telemetry", "Sentry error tracking", node)

    return findings


# ──────────────────────────────────────────────────────────────────────
# Regex fallback (for files that fail AST parsing — ES2020+ syntax)
# ──────────────────────────────────────────────────────────────────────

JS_PATTERNS: list[tuple[str, Severity, str, str]] = [
    (r'\beval\s*\(', Severity.CRITICAL, "code_injection",
     "eval() executes arbitrary code — replace with JSON.parse() or remove"),
    # Function() constructor handled separately (case-sensitive) below
    (r'setTimeout\s*\(\s*["\']', Severity.HIGH, "code_injection",
     "setTimeout with string argument acts as eval — pass a function reference instead"),
    (r'setInterval\s*\(\s*["\']', Severity.HIGH, "code_injection",
     "setInterval with string argument acts as eval — pass a function reference instead"),
    (r'\.innerHTML\s*=', Severity.MEDIUM, "xss",
     "innerHTML assignment — use textContent for plain text or sanitize with DOMPurify"),
    (r'document\.write\s*\(', Severity.HIGH, "xss",
     "document.write() injects raw HTML — replace with DOM API (createElement/textContent)"),
    (r'\.insertAdjacentHTML\s*\(', Severity.MEDIUM, "xss",
     "insertAdjacentHTML — sanitize input or use insertAdjacentText for plain text"),
    (r'\bfetch\s*\(', Severity.INFO, "network",
     "fetch() makes network requests — verify URL points to HA instance, not external server"),
    (r'XMLHttpRequest', Severity.INFO, "network",
     "XMLHttpRequest — verify URL points to HA instance, not external server"),
    (r'WebSocket\s*\(', Severity.MEDIUM, "network",
     "WebSocket connection — verify destination is HA instance, not external server"),
    (r'navigator\.sendBeacon', Severity.HIGH, "data_exfiltration",
     "sendBeacon() silently sends data — verify destination URL and what data is transmitted"),
    (r'document\.createElement\s*\(\s*["\']script', Severity.HIGH, "script_injection",
     "Dynamic <script> creation — verify src attribute is not loading external/untrusted code"),
    (r'document\.createElement\s*\(\s*["\']iframe', Severity.HIGH, "script_injection",
     "Dynamic <iframe> creation — verify src is not loading external content into HA dashboard"),
    (r'atob\s*\(', Severity.MEDIUM, "obfuscation",
     "Base64 decode (atob) — check what is being decoded; may hide URLs or malicious payloads"),
    (r'String\.fromCharCode', Severity.MEDIUM, "obfuscation",
     "String.fromCharCode() — check if used to construct hidden URLs or bypass content filters"),
    (r'unescape\s*\(', Severity.MEDIUM, "obfuscation",
     "unescape() decodes encoded content — replace with decodeURIComponent(); check decoded value"),
    (r'localStorage', Severity.LOW, "data_access",
     "localStorage — check what data is stored; HA cards should not persist sensitive tokens"),
    (r'sessionStorage', Severity.LOW, "data_access",
     "sessionStorage — check what data is stored; avoid persisting auth tokens or entity states"),
    (r'document\.cookie', Severity.MEDIUM, "data_access",
     "Cookie access — HA cards should not read/write cookies; check if cookies are sent externally"),
    (r'google[\-_]?analytics|gtag|ga\s*\(', Severity.HIGH, "telemetry",
     "Google Analytics — tracks user behavior on your HA dashboard; should be removed from HA components"),
    (r'sentry', Severity.LOW, "telemetry",
     "Sentry error tracking — sends error reports to external service; verify no sensitive HA data is included"),
    (r'mixpanel|amplitude|segment', Severity.MEDIUM, "telemetry",
     "Third-party analytics SDK — sends user interaction data externally; should be removed from HA components"),
    (r'paypal\.com|paypal\.me|paypalobjects\.com', Severity.MEDIUM, "payment",
     "PayPal integration — unusual in HA components; may indicate hidden paywall or donation prompt"),
    (r'stripe\.com|stripe\.js', Severity.MEDIUM, "payment",
     "Stripe integration — unusual in HA components; may indicate hidden paywall or payment system"),
    (r'workers\.dev', Severity.MEDIUM, "network",
     "Cloudflare Workers proxy — data may be relayed through third-party; verify what is proxied and why"),
]

_COMPILED = [(re.compile(pat, re.IGNORECASE), sev, cat, desc)
             for pat, sev, cat, desc in JS_PATTERNS]

# Case-sensitive patterns (Function vs function distinction matters)
_COMPILED_CASE_SENSITIVE = [
    (re.compile(r'(?:^|[^a-z])Function\s*\('), Severity.CRITICAL, "code_injection",
     "Function() constructor creates executable code"),
]


def _scan_js_regex(source: str, filepath: str) -> list[Finding]:
    """Regex-based scan — fallback when AST parsing fails."""
    findings = []
    lines = source.splitlines()
    for regex, sev, cat, desc in _COMPILED + _COMPILED_CASE_SENSITIVE:
        for i, line in enumerate(lines, 1):
            if regex.search(line):
                findings.append(Finding(
                    severity=sev, category=cat, file=filepath,
                    line=i, code=line.strip()[:120], description=desc,
                ))
                break  # One finding per pattern per file
    return findings


# ──────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────

_OBFUSCATION_PATTERNS: list[tuple[str, str]] = [
    (r'_0x[0-9a-f]{4,}\s*[\(\[=]', "Hex-prefixed variable names (_0x pattern)"),
    (r'function\s+_0x[0-9a-f]{4,}', "Obfuscated function definitions (_0x pattern)"),
    (r"\['push'\]\s*\(\s*\w+\s*\[\s*'shift'\s*\]", "String array rotation (anti-analysis)"),
    (r'parseInt\s*\([^)]+\)\s*/\s*\d+\s*\*\s*\(\s*-?\s*parseInt', "Control flow flattening (parseInt shuffle)"),
]

_COMPILED_OBFUSCATION = [(re.compile(p), d) for p, d in _OBFUSCATION_PATTERNS]


def _detect_obfuscation(source: str, filepath: str) -> list[Finding]:
    """Detect deliberate code obfuscation — a major red flag in open-source HA components.

    Minification (short var names, no whitespace) is normal for production JS bundles.
    Obfuscation (hex-encoded names, string rotation, control flow flattening) is not —
    it actively hides what the code does, which is incompatible with open-source trust.
    """
    findings: list[Finding] = []
    # Count _0x references as a heuristic — minified code doesn't use this pattern
    hex_vars = len(re.findall(r'_0x[0-9a-f]{4,}', source))
    if hex_vars < 5:
        return findings

    # This is obfuscated code — report the main finding
    matched_techniques = []
    for regex, desc in _COMPILED_OBFUSCATION:
        if regex.search(source):
            matched_techniques.append(desc)

    techniques = "; ".join(matched_techniques) if matched_techniques else "Hex-encoded variable names"
    findings.append(Finding(
        severity=Severity.HIGH,
        category="obfuscation",
        file=filepath,
        line=1,
        code=source[:120].strip(),
        description=(
            f"Deliberately obfuscated code ({hex_vars} hex-encoded references). "
            f"Techniques: {techniques}. "
            "Obfuscation in open-source HA components hides intent and prevents security review — "
            "this code cannot be trusted without deobfuscation."
        ),
    ))

    # Check for external URLs hidden in the obfuscated code
    urls = re.findall(r'https?://[^\s\'"\\]{10,}', source)
    external_urls = [u for u in urls if not any(safe in u for safe in
                     ["github.com", "githubusercontent.com", "home-assistant.io",
                      "hacs.xyz", "jsdelivr.net", "unpkg.com"])]
    if external_urls:
        unique_domains = set()
        for u in external_urls[:20]:
            try:
                domain = u.split("//")[1].split("/")[0]
                unique_domains.add(domain)
            except IndexError:
                pass
        if unique_domains:
            findings.append(Finding(
                severity=Severity.HIGH,
                category="data_exfiltration",
                file=filepath,
                line=1,
                description=(
                    f"External URLs found in obfuscated code: {', '.join(sorted(unique_domains)[:10])}. "
                    "Hidden network calls in obfuscated code may exfiltrate data."
                ),
            ))

    # Detect hidden license/activation/paywall system
    license_refs = len(re.findall(r'\blicen[sc]e\b', source, re.IGNORECASE))
    activation_refs = len(re.findall(r'\bactivat(?:ion|e|ed)\b', source, re.IGNORECASE))
    premium_refs = len(re.findall(r'\b(?:premium|freemium|subscription|trial)\b', source, re.IGNORECASE))
    paywall_score = license_refs + activation_refs * 3 + premium_refs * 2
    if paywall_score >= 20:
        findings.append(Finding(
            severity=Severity.HIGH,
            category="hidden_paywall",
            file=filepath,
            line=1,
            description=(
                f"Hidden license/activation system in obfuscated code "
                f"({license_refs} license, {activation_refs} activation, {premium_refs} premium refs). "
                "Users cannot review licensing terms or verify what data is sent for validation."
            ),
        ))

    # Detect payment integration hidden in obfuscated code
    paypal_refs = len(re.findall(r'paypal', source, re.IGNORECASE))
    stripe_refs = len(re.findall(r'stripe', source, re.IGNORECASE))
    if paypal_refs >= 5 or stripe_refs >= 5:
        provider = "PayPal" if paypal_refs > stripe_refs else "Stripe"
        count = max(paypal_refs, stripe_refs)
        findings.append(Finding(
            severity=Severity.HIGH,
            category="hidden_payment",
            file=filepath,
            line=1,
            description=(
                f"{provider} payment integration hidden in obfuscated code ({count} references). "
                "Payment processing code should be transparent and auditable."
            ),
        ))

    # Detect iframe injection in obfuscated code
    iframe_refs = len(re.findall(r'\biframe\b', source, re.IGNORECASE))
    if iframe_refs >= 3:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category="iframe_injection",
            file=filepath,
            line=1,
            description=(
                f"Iframe references in obfuscated code ({iframe_refs} occurrences). "
                "Hidden iframes may load external content or phishing pages."
            ),
        ))

    return findings


def scan_js_file(filepath: Path) -> list[Finding]:
    """Scan a single JS/TS file — AST primary, regex fallback."""
    findings: list[Finding] = []
    try:
        source = filepath.read_text(errors="replace")
    except OSError as e:
        log.warning("Cannot read %s: %s", filepath, e)
        return findings

    if len(source) > settings.max_file_size_kb * 1024:
        findings.append(Finding(
            severity=Severity.INFO, category="size",
            file=str(filepath),
            description=f"Large file ({len(source) // 1024}KB), may be bundled/minified",
        ))

    # Check for deliberate obfuscation before detailed analysis
    obf_findings = _detect_obfuscation(source, str(filepath))
    if obf_findings:
        findings.extend(obf_findings)

    # Try AST first
    ast_findings = _scan_js_ast(source, str(filepath))
    if ast_findings is not None and len(ast_findings) > 0:
        return findings + ast_findings

    # AST returned empty — could be clean file or parse failure. Try parsing
    # to distinguish: if parse succeeds with no findings, file is clean.
    try:
        esprima.parseModule(source, tolerant=True)
        # Parsed OK, just no findings — file is clean
        return findings
    except esprima.Error:
        pass

    try:
        esprima.parseScript(source, tolerant=True)
        return findings
    except esprima.Error:
        pass

    # Parse failed — use regex fallback with a note
    findings.append(Finding(
        severity=Severity.INFO, category="parse_info",
        file=str(filepath),
        description="AST parse failed (ES2020+ syntax?), using regex fallback",
    ))
    findings.extend(_scan_js_regex(source, str(filepath)))
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


# Third-party/vendor files that are not part of the component's own code
_VENDOR_PATTERNS = {"docsify", "prism", "marked", "highlight", "mermaid"}


def scan_js_repo(repo_path: Path) -> list[Finding]:
    """Scan all JS/TS files in a repository."""
    findings = []
    parse_fail_count = 0
    extensions = {".js", ".ts", ".jsx", ".tsx", ".mjs"}
    for jsfile in repo_path.rglob("*"):
        if jsfile.suffix not in extensions:
            continue
        rel = str(jsfile.relative_to(repo_path))
        if any(skip in rel.split("/") for skip in
               ["node_modules", ".venv", "__pycache__", "tests", "docs"]):
            continue
        # Skip well-known third-party vendor files (e.g. docsify.min.js)
        stem = jsfile.stem.lower().replace(".min", "")
        if any(v in stem for v in _VENDOR_PATTERNS):
            continue
        file_findings = scan_js_file(jsfile)
        # Count parse_info separately — aggregate at end
        file_parse_info = [f for f in file_findings if f.category == "parse_info"]
        file_other = [f for f in file_findings if f.category != "parse_info"]
        findings.extend(file_other)
        parse_fail_count += len(file_parse_info)

    # Aggregate parse_info into a single finding (reduces 400+ to 1)
    if parse_fail_count > 0:
        findings.append(Finding(
            severity=Severity.INFO,
            category="parse_info",
            file=str(repo_path),
            description=f"{parse_fail_count} file(s) used regex fallback (ES2020+ syntax)",
        ))

    return _cap_findings_per_file(findings)
