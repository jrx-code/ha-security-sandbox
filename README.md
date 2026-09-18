# HA Security Sandbox

[![Version](https://img.shields.io/badge/version-0.21.1-blue.svg)](ha-sandbox/config.yaml)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-265%20passed-brightgreen.svg)](#testing)
[![HA Add-on](https://img.shields.io/badge/Home%20Assistant-Add--on-41BDF5.svg)](https://www.home-assistant.io/addons/)

Security scanner for **Home Assistant custom components**. Analyzes HACS integrations and Lovelace cards for potential vulnerabilities using multi-layer static analysis and AI-powered code review.

## What's New (v0.14–0.21)

- **v0.21.1** — Notification alerts on critical/high findings (HA + MQTT + optional mobile push)
- **v0.20** — English GUI, settings preserved on upgrade, OpenRouter 401 fix
- **v0.19** — CVE watch: periodic vulnerability monitoring for installed deps
- **v0.18** — SARIF export for CI/CD integration (GitHub Code Scanning, GitLab SAST)
- **v0.17** — Cross-component intelligence: detect shared suspicious patterns across components
- **v0.16** — Fingerprint diff/delta API: track changes between scan versions
- **v0.15** — Scheduled periodic scans of installed HACS components
- **v0.14** — Hot reload, configurable AI timeout, repo cache cleanup, rate limiting

See [CHANGELOG](ha-sandbox/CHANGELOG.md) for latest release notes.

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

### Scheduled Scans & CVE Watch

- **Scheduled scans** — periodically re-scan all installed HACS components (configurable interval)
- **CVE watch** — lightweight periodic check for new vulnerabilities in installed deps without full scan
- **MQTT alerts** on new CVE findings

### Batch Scanning

Scan all installed HACS components at once with progress tracking and SQLite-backed queue.

### SARIF Export

Export scan results in [SARIF](https://sarifweb.azurewebsites.net/) format for CI/CD integration — compatible with GitHub Code Scanning, GitLab SAST, and other tools.


### Notification Alerts

When a scan finds issues at or above a configurable severity threshold (default: **critical**):

- **HA persistent notifications** via REST
- **MQTT alerts** on `{node_id}/alert` with optional discovery sensors
- **Optional mobile push** through any HA notify service (`alert_notify_service`)
- **Rate limiting** (`alert_cooldown_seconds`, default 1 hour) to avoid alert fatigue
- Toggle with `alerts_enabled` / addon option / `GET|POST /api/alerts`

### Reporting

- **Web dashboard** with Nord theme, severity sorting, and AI summary
- **MQTT auto-discovery** — sensors (status, last scan, score, total scans, last alert) + alert binary_sensor
- **Export** — JSON, CSV, HTML, PDF, and SARIF

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
# Edit .env with your settings
docker compose up -d
```

Open http://localhost:8099

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `ai_provider` | `ollama` | `ollama` or `public` |
| `ollama_url` | `http://homeassistant:11434` | Ollama API URL |
| `ollama_model` | `qwen2.5-coder:14b` | Local model |
| `public_provider` | `openrouter` | `openrouter` or `openai` |
| `public_api_key` | — | API key for public provider |
| `ha_url` / `ha_token` | — | HA REST for installed components + alerts |
| `mqtt_*` | — | MQTT auto-discovery / alert publish |
| `alerts_enabled` | `true` | Send alerts on findings at/above threshold |
| `alert_severity_threshold` | `critical` | `critical` / `high` / `medium` |
| `alert_cooldown_seconds` | `3600` | Per-component alert rate limit |
| `alert_notify_service` | _(empty)_ | Optional HA notify service for mobile push |

## Usage

1. Open **Security Sandbox** from the HA sidebar
2. Scan a GitHub URL, pick an installed HACS component, or batch-scan all
3. Review findings by severity; export PDF/SARIF as needed
4. On critical findings, check HA notifications / MQTT `…/alert` (if enabled)

## MQTT Sensors

| Sensor | Topic | Description |
|--------|-------|-------------|
| Status | `{node_id}/status` | Current scanner state |
| Last Scan | `{node_id}/last_scan` | Component name of last scan |
| Last Score | `{node_id}/last_score` | AI safety score |
| Total Scans | `{node_id}/scans_total` | Lifetime scan count |
| Last Alert | `{node_id}/last_alert` | Last alert title/component |
| Alert Active | `{node_id}/alert_active` | Binary sensor (problem) |
| Alert payload | `{node_id}/alert` | JSON alert event |

## Testing

```bash
pip install -r requirements-dev.txt
pytest tests/ -q
```

Offline alert tests (no HA/MQTT):

```bash
pytest tests/test_alerts.py -q
```

## Architecture

```
ha-sandbox/
  app/
    alerts.py          # Notification alerts (#3)
    alerts_api.py      # GET/POST /api/alerts
    scanner/           # Static + pipeline
    ai/                # Ollama / public LLM
    report/            # MQTT, PDF, SARIF
    web/               # FastAPI + dashboard
  config.yaml          # Add-on metadata
  run.sh               # Add-on entrypoint
```

## Future Plans

| Priority | Feature | Description |
|----------|---------|-------------|
| **High** | HACS webhook / auto-scan | Auto-scan components on HACS install/update events |
| **Medium** | HA Dashboard Lovelace card | Custom card showing security summary for installed components |
| **Medium** | Comparative reports | Track score changes between versions, detect regressions |
| **Low** | Multi-instance support | Scan components on remote HA instances |
| **Low** | Community safety database | Crowd-sourced component safety ratings |
| **Low** | HACS Store integration | Security badges in HACS store UI |

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License — see [LICENSE](LICENSE) for details.
