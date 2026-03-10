# HA Security Sandbox

[![Version](https://img.shields.io/badge/version-0.13.0-blue.svg)](ha-sandbox/config.yaml)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-265%20passed-brightgreen.svg)](#testing)
[![HA Add-on](https://img.shields.io/badge/Home%20Assistant-Add--on-41BDF5.svg)](https://www.home-assistant.io/addons/)

Security scanner for **Home Assistant custom components**. Analyzes HACS integrations and Lovelace cards for potential vulnerabilities using multi-layer static analysis and AI-powered code review.

## What's New (v0.9–0.13)

- **v0.13** — AI review rewrite: qwen2.5-coder model, single-step prompt, 95% confidence, PDF export, zero duplicate findings
- **v0.12** — Actionable findings: every description says what to do, not just what was found
- **v0.11** — Full dependency scanning: npm, pip, pyproject.toml + 55 known malicious packages + OSV.dev batch CVE
- **v0.10** — Structural YAML parser: automation flow injection, `choose/sequence` nesting, `!include` path traversal
- **v0.9** — 90% noise reduction after testing on 50 HACS repos (804→13 findings on large repos)

See [CHANGELOG](ha-sandbox/CHANGELOG.md) for full history.

## Why?

HACS components run with full access to your Home Assistant instance — they can read your tokens, control your devices, and access your network. Most users install them without any security review. This add-on changes that by automatically scanning component source code for dangerous patterns before they can cause harm.

## Features

### Static Analysis (5 scanners)

| Scanner | What it detects |
|---------|----------------|
| **Python AST** | `eval()`, `exec()`, `subprocess`, `pickle`, `ctypes`, dynamic imports |
| **Python Taint Flow** | User input (`config_entry.data`, `request.json`) flowing into dangerous sinks |
| **JavaScript AST** | `innerHTML`, `eval()`, `document.cookie`, data exfiltration, obfuscated code |
| **YAML/Jinja2** | `shell_command`, hardcoded secrets, unsafe HTTP, Jinja2 injection, `service_template`, nested `choose/sequence` flow injection, `rest_command` HTTP, `!include` path traversal, secrets in comments |
| **HA API Patterns** | Dynamic service injection, event bus abuse, auth access, unvalidated schemas |
| **Dependencies** | Known CVEs (OSV.dev), malicious/typosquatting packages (PyPI + npm) |

### AI Review

LLM-powered security audit with structured scoring rubric (0-10 scale), per-finding confidence levels, and few-shot examples. The AI only reports issues the static analyzer missed — no duplicate noise. Supports:

- **Ollama** (local) — privacy-first, no data leaves your network (default: `qwen2.5-coder:14b`)
- **OpenRouter / OpenAI** (public) — for users without local GPU

### PDF Export

Download scan reports as PDF with severity-colored findings, score summary, and AI analysis.

### Dependency Scanning

Full dependency analysis across all package ecosystems:

- **npm** — parses `package.json` (dependencies + devDependencies)
- **pip** — auto-discovers all `requirements*.txt` files in repo
- **pyproject.toml** — extracts `[project.dependencies]`
- **OSV.dev batch API** — bulk CVE lookup (100 packages per request)
- **Malicious package detection** — 30+ PyPI + 25+ npm known typosquatting/supply-chain packages (CRITICAL severity)

### Actionable Findings

Every finding follows the pattern: **What was detected → Why it's risky → What to do**.

Instead of generic "investigate this code", you get specific remediation:
- `eval()` → "replace with `JSON.parse()` or remove; if needed, verify input is sanitized"
- `innerHTML` → "use `textContent` for plain text or sanitize with DOMPurify"
- `hass.services.call()` → "check that domain and service arguments are constants, not from user input"

### Finding Deduplication

Merges overlapping findings from different scanners (e.g., static + AI + taint) using category aliases and severity ranking — no duplicate noise.

### Batch Scanning

Scan all installed HACS components at once with progress tracking and SQLite-backed queue.

### Reporting

- **Web dashboard** with Nord theme, severity sorting, and AI summary
- **MQTT auto-discovery** — 4 HA sensors (status, last scan, score, total scans)
- **Export** — JSON, CSV, and standalone HTML (print/PDF ready)

## Installation

### As Home Assistant Add-on (recommended)

1. Add this repository to your HA Add-on Store:
   ```
   https://github.com/jrx-code/ha-security-sandbox
   ```
2. Install "HA Security Sandbox" from the store
3. Configure your AI provider in the add-on settings
4. Start the add-on — it appears in the HA sidebar as **Security Sandbox**

### Standalone (Docker)

```bash
cp .env.example .env
# Edit .env with your MQTT and Ollama settings
docker compose up -d
```

Open `http://localhost:8099` in your browser.

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `ai_provider` | `ollama` | AI backend: `ollama` or `public` |
| `ollama_url` | `http://homeassistant:11434` | Ollama API endpoint |
| `ollama_model` | `qwen2.5-coder:14b` | Model for code review |
| `public_provider` | `openrouter` | Public API: `openrouter` or `openai` |
| `public_api_key` | — | API key for public provider |
| `mqtt_enabled` | `true` | Publish results to MQTT |
| `mqtt_tls` | `true` | Use TLS for MQTT connection |
| `log_level` | `info` | Logging verbosity |

## Architecture

```
ha-sandbox/
├── app/
│   ├── ai/              # AI review (Ollama + public API)
│   │   └── ollama.py    # Structured prompting, JSON parsing, confidence scores
│   ├── scanner/          # Static analysis engines
│   │   ├── static_python.py  # Python AST + taint tracking
│   │   ├── static_js.py      # JavaScript AST (esprima) + regex fallback
│   │   ├── static_yaml.py    # YAML/Jinja2 structural parser + automation flow analysis
│   │   ├── static_ha.py      # HA API pattern validator
│   │   ├── cve_lookup.py     # OSV.dev CVE + malicious package detection (npm, pip, pyproject)
│   │   ├── pipeline.py       # Orchestrator + deduplication
│   │   ├── fetch.py          # Git clone + manifest parsing
│   │   └── hacs_list.py      # HACS WebSocket component listing
│   ├── report/           # Output generation
│   │   ├── generator.py  # JSON, CSV, HTML export
│   │   └── mqtt.py       # HA MQTT auto-discovery
│   ├── storage.py        # SQLite persistence + batch queue
│   ├── main.py           # FastAPI REST API
│   ├── models.py         # Pydantic models
│   └── web/templates/    # Dashboard UI
├── config.yaml           # HA Add-on manifest
├── Dockerfile            # Multi-arch build (amd64, aarch64)
└── run.sh                # Entrypoint (Supervisor + standalone)
```

### Scan Pipeline

```
Clone repo → Parse manifest
    → Phase 1a: CVE lookup (manifest deps)
    → Phase 1b: Static analysis (5 scanners)
    → Phase 1c: Repo-wide dependency scan (npm, pip, pyproject.toml)
    → Phase 2: AI review
    → Deduplicate findings → Filter whitelist → Generate report → MQTT publish
```

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan` | Scan a single repository URL |
| `POST` | `/api/scan/batch` | Scan multiple repositories |
| `POST` | `/api/scan/installed` | Scan all installed HACS components |
| `GET` | `/api/scan/{id}` | Get scan job status |
| `GET` | `/api/scan/batch/{id}` | Get batch status |
| `GET` | `/api/reports` | List all scan reports |
| `GET` | `/api/report/{id}` | Get report details |
| `GET` | `/api/report/{id}/csv` | Export report as CSV |
| `GET` | `/api/report/{id}/html` | Export report as HTML |
| `GET` | `/api/hacs/installed` | List installed HACS components |
| `POST` | `/api/whitelist` | Add finding to whitelist (false positive) |
| `DELETE` | `/api/whitelist/{hash}` | Remove whitelist entry |
| `GET` | `/api/whitelist` | List all whitelisted patterns |
| `GET` | `/api/reputation/{domain}` | Get component reputation (trend, history) |
| `GET` | `/api/reputation` | Get all component reputations |

## Code Learning

The scanner learns from accumulated scan data to provide better results over time:

| Module | What it does |
|--------|-------------|
| **L.1 Pattern Fingerprinting** | Extracts structural fingerprints (imports, HA APIs, network domains, file types) and tracks changes across versions |
| **L.2 Baseline / Norm Database** | Computes statistical profile from 10+ scans; flags components that deviate >2σ from the norm |
| **L.3 Whitelist / False Positives** | "Ignoruj" button in UI marks findings as false positives; whitelisted patterns are filtered on re-scan |
| **L.4 Reputation Score** | Tracks safety score trends across versions with ↑/↓/→ indicators; builds component reputation |
| **L.5 Cross-Component Intelligence** *(planned)* | Compare components against known-good patterns; detect supply chain risks |

## Testing

```bash
pip install -r ha-sandbox/requirements.txt
cd ha-sandbox && python -m pytest tests/ -q
```

**265 tests** across 14 suites covering all pipeline phases:

| Suite | Tests | Coverage |
|-------|-------|----------|
| Phase 1 — Fetch & Parse | 15 | Clone, manifest detection, component types |
| Phase 2 — Static (Python) | 23 | AST patterns, taint flow, dangerous calls |
| Phase 2 — Static (JS) | 18 | AST + regex, XSS, eval, exfiltration, obfuscation, noise reduction |
| Phase 2 — YAML | 10 | Shell commands, secrets, Jinja2 injection |
| Phase 2 — YAML Enhanced | 22 | Structural parsing, automation flow injection, !include, choose/sequence |
| Phase 2 — HA Patterns | 11 | Dynamic services, event bus, auth, schemas |
| Phase 2 — Batch | 13 | Queue, progress, SQLite persistence |
| Phase 2 — Dedup | 10 | Category aliases, severity merge, taint merge |
| Phase 4 — AI Review | 10 | Prompting, JSON parsing, error handling |
| Phase 5 — Reports | 12 | JSON, CSV, HTML export, MQTT discovery |
| Phase 6 — API | 8 | REST endpoints, error responses |
| Phase 7 — Pipeline | 5 | End-to-end integration |
| Code Learning | 25 | Fingerprinting, baseline, whitelist, reputation |
| CVE Lookup | 9 | OSV.dev queries, version matching |
| Dependency Scanner | 21 | npm, pip, pyproject.toml, malicious packages, batch CVE |
| Storage | 8 | SQLite CRUD, migrations |

## Security Scoring

| Score | Label | Meaning |
|-------|-------|---------|
| 9-10 | **SAFE** | No security issues found |
| 7-8 | **SAFE** | Minor concerns, no exploitable vulnerabilities |
| 5-6 | **CAUTION** | Moderate risks requiring review |
| 3-4 | **CAUTION** | Significant risks present |
| 0-2 | **DANGER** | Critical — actively dangerous patterns |

## Future Plans

| Priority | Feature | Description |
|----------|---------|-------------|
| **High** | L.5 Cross-Component Intelligence | Compare components against known-good fingerprints; detect supply chain anomalies and typosquatting |
| **High** | Scheduled re-scans | Periodically re-scan installed components to detect upstream changes |
| **Medium** | HACS webhook integration | Auto-scan components on HACS install/update events |
| **Medium** | Grafana dashboard | Visualize scan trends, reputation history, and baseline deviations |
| **Low** | Multi-user whitelist | Per-user whitelist with shared/global rules |
| **Low** | SBOM export | Software Bill of Materials in CycloneDX/SPDX format |

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License — see [LICENSE](LICENSE) for details.
