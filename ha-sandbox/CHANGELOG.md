# Changelog

## [0.10.0] - 2026-03-09

### Added (YAML Scanner Enhancement — 2/5 → 4/5)
- **Structural YAML parsing** via `yaml.safe_load()` — analyzes parsed tree, not just regex
- **Automation flow injection detection** — `service_template`, dynamic `service` with templates, template values in `data` flowing to `shell_command`
- **Nested action scanning** — follows `choose/sequence/then/else/default` structures
- **rest_command HTTP detection** — flags `rest_command` and `rest` using HTTP (not HTTPS)
- **!include path validation** — detects template paths, absolute paths, parent traversal (`..`)
- **Secrets in comments** — finds password/token/api_key values accidentally left in YAML comments
- **Per-file finding cap** — max 3 per category per file (consistent with Python/JS/HA scanners)
- **Standalone automation list support** — scans list-at-root automation files
- 22 new tests (244 total)

## [0.9.0] - 2026-03-09

### Improved (batch scan on 50 HACS repos)
- **Noise reduction**: findings cut by 90%+ on large repos (e.g. 804→13 for waste_collection_schedule)
- `re.compile()` no longer flagged as code injection (only bare `compile()`)
- `compile()` severity reduced from HIGH to MEDIUM (legitimate use common)
- Per-file finding cap: max 3 findings per category per file
- Network import aggregation: max 5 kept + summary for repos with many modules
- `parse_info` aggregated: 1 per repo instead of 1 per file (412→1 for large cards)
- Removed noisy `appendChild` detection (LOW value, extreme volume)
- Vendor/third-party JS files skipped (docsify, prism, marked, etc.)
- `docs/` directory excluded from JS scanning
- 8 new tests for noise reduction (222 total)

## [0.8.0] - 2026-03-09

### Added
- **Code Learning** — 4-module learning pipeline:
  - L.1 Pattern Fingerprinting — extract structural fingerprints (imports, HA APIs, network domains, file types)
  - L.2 Baseline / Norm Database — statistical profiling from scan history, deviation detection (z-score > 2σ)
  - L.3 Whitelist / False Positives — "Ignoruj" button in UI, pattern-based whitelist with category+file matching
  - L.4 Reputation Score — track safety score trends across versions with ↑/↓/→ trend indicators
- Reputation display in report modal (scan count, average score, trend)
- CSV/HTML export buttons in report modal
- REST API endpoints: `/api/whitelist` (CRUD), `/api/reputation` (per-domain + all)
- 25 new tests covering all learning modules (208 total)

### Changed
- Scan pipeline now filters whitelisted findings before report generation
- Fingerprint and reputation data recorded automatically after each scan

## [0.7.0] - 2026-03-09

### Added
- JavaScript AST parser using esprima with regex fallback for ES2020+
- Python taint tracking — data flow analysis from user input to dangerous sinks
- HA API pattern validator — detects risky hass.services, event bus, auth access
- Batch scanning with SQLite-backed queue and progress tracking
- Report export: CSV and standalone HTML (print/PDF ready)
- Finding deduplication with category aliases and severity merge
- Structured AI prompting with scoring rubric, few-shot examples, confidence scores

## [0.6.0] - 2026-03-09

### Added
- YAML/Jinja2 scanner (shell_command, hardcoded secrets, unsafe HTTP, injection)
- CVE database lookup via OSV.dev for dependency scanning
- SQLite job persistence (survives restarts)
- MQTT scans_total counter (persisted across restarts)

### Fixed
- MQTT TLS connection with proper certificate verification

## [0.5.1] - 2026-03-07

### Fixed
- Active scans no longer stay visible after completion
- Failed scans show red badge instead of spinner

### Added
- Version tag visible in UI header (both pages)
- Findings sorted by severity in report details (critical → info)

## [0.5.0] - 2026-03-07

### Changed
- Converted to HA Add-on format (config.yaml, run.sh, build.yaml)
- Dockerfile uses HA base images (Alpine + Python 3.13)
- Version sourced from config.yaml (single source of truth)
- Added HA Ingress support (X-Ingress-Path, SSO)
- MQTT auto-detects Supervisor MQTT service
- HA token auto-injected via Supervisor API
- Data stored in /share/ha-sandbox/

## [0.4.0] - 2026-03-06

### Added
- Settings page with dual AI provider support (Ollama/Public API)
- Clear Results button on dashboard
- Centralized version constant
- Test suite (87 tests) covering all phases

### Fixed
- 3 production bugs found via test suite

## [0.3.0] - 2026-03-06

### Changed
- UI theme switched from dark blue to Nord color palette

## [0.2.0] - 2026-03-06

### Added
- MQTT auto-discovery for Home Assistant
- Static analysis for JavaScript/TypeScript
- AI review via Ollama with code context
- Report generation with JSON persistence
- Installed HACS component listing via WebSocket

## [0.1.0] - 2026-03-06

### Added
- Initial release
- Repository cloning and manifest parsing
- Static Python analysis (AST-based)
- FastAPI web dashboard
- Background scan pipeline
