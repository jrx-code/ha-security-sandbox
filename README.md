# HA Security Sandbox

[![Version](https://img.shields.io/badge/version-0.7.0-blue.svg)](ha-sandbox/config.yaml)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-178%20passed-brightgreen.svg)](#testing)
[![HA Add-on](https://img.shields.io/badge/Home%20Assistant-Add--on-41BDF5.svg)](https://www.home-assistant.io/addons/)

Security scanner for **Home Assistant custom components**. Analyzes HACS integrations and Lovelace cards for potential vulnerabilities using multi-layer static analysis and AI-powered code review.

## Why?

HACS components run with full access to your Home Assistant instance — they can read your tokens, control your devices, and access your network. Most users install them without any security review. This add-on changes that by automatically scanning component source code for dangerous patterns before they can cause harm.

## Features

### Static Analysis (5 scanners)

| Scanner | What it detects |
|---------|----------------|
| **Python AST** | `eval()`, `exec()`, `subprocess`, `pickle`, `ctypes`, dynamic imports |
| **Python Taint Flow** | User input (`config_entry.data`, `request.json`) flowing into dangerous sinks |
| **JavaScript AST** | `innerHTML`, `eval()`, `document.cookie`, data exfiltration, obfuscated code |
| **YAML/Jinja2** | `shell_command`, hardcoded secrets, unsafe HTTP, Jinja2 injection |
| **HA API Patterns** | Dynamic service injection, event bus abuse, auth access, unvalidated schemas |

### AI Review

LLM-powered security audit with structured scoring rubric (0-10 scale), per-finding confidence levels, and few-shot examples. Supports:

- **Ollama** (local) — privacy-first, no data leaves your network
- **OpenRouter / OpenAI** (public) — for users without local GPU

### Dependency Scanning

Checks `requirements.txt` against the [OSV.dev](https://osv.dev/) vulnerability database for known CVEs.

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
| `ollama_model` | `gemma3:12b` | Model for code review |
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
│   │   ├── static_yaml.py    # YAML/Jinja2 patterns
│   │   ├── static_ha.py      # HA API pattern validator
│   │   ├── cve_lookup.py     # OSV.dev dependency scanning
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
Clone repo → Parse manifest → CVE lookup → Static analysis (5 scanners)
    → AI review → Deduplicate findings → Generate report → MQTT publish
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

## Testing

```bash
pip install -r ha-sandbox/requirements.txt
cd ha-sandbox && python -m pytest tests/ -q
```

**178 tests** across 10 suites covering all pipeline phases:

| Suite | Tests | Coverage |
|-------|-------|----------|
| Phase 1 — Fetch & Parse | 15 | Clone, manifest detection, component types |
| Phase 2 — Static (Python) | 23 | AST patterns, taint flow, dangerous calls |
| Phase 2 — Static (JS) | 13 | AST + regex, XSS, eval, exfiltration |
| Phase 2 — YAML | 10 | Shell commands, secrets, Jinja2 injection |
| Phase 2 — HA Patterns | 11 | Dynamic services, event bus, auth, schemas |
| Phase 2 — Batch | 13 | Queue, progress, SQLite persistence |
| Phase 2 — Dedup | 10 | Category aliases, severity merge, taint merge |
| Phase 4 — AI Review | 10 | Prompting, JSON parsing, error handling |
| Phase 5 — Reports | 12 | JSON, CSV, HTML export, MQTT discovery |
| Phase 6 — API | 8 | REST endpoints, error responses |
| Phase 7 — Pipeline | 5 | End-to-end integration |
| CVE Lookup | 8 | OSV.dev queries, version matching |
| Storage | 8 | SQLite CRUD, migrations |

## Security Scoring

| Score | Label | Meaning |
|-------|-------|---------|
| 9-10 | **SAFE** | No security issues found |
| 7-8 | **SAFE** | Minor concerns, no exploitable vulnerabilities |
| 5-6 | **CAUTION** | Moderate risks requiring review |
| 3-4 | **CAUTION** | Significant risks present |
| 0-2 | **DANGER** | Critical — actively dangerous patterns |

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License — see [LICENSE](LICENSE) for details.
