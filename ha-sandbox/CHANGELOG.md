# Changelog

## [0.12.2] - 2026-03-10

### Fixed
- **Ingress double-slash** — `GET //` from Supervisor proxy now redirects to `/` (was returning 404)
- **Startup race condition** — retry loop waits for Supervisor API before reading config (fixes "Unable to access the API, forbidden" on fresh install)
- **MQTT graceful fallback** — no more error when MQTT service not configured in Supervisor

## [0.12.1] - 2026-03-10

### Fixed
- **AppArmor install error** — removed custom `apparmor.txt` profile that caused `Can't load profile` / `exit status 1` on HAOS (AppArmor 3.1.2); Supervisor now uses default Docker AppArmor profile
- Reproduced and verified on fresh HAOS 14.2 KVM VM

## [0.12.0] - 2026-03-09

### Improved (Actionable Finding Descriptions)
- **JS scanner** — all descriptions rewritten: eval→JSON.parse, innerHTML→textContent/DOMPurify, fetch→verify URL, localStorage→check stored data
- **Python scanner** — subprocess, pickle, exec, os.system, requests descriptions now include specific remediation
- **HA scanner** — services.call, bus.fire, auth access, dynamic entity descriptions include attack scenarios
- **Pattern**: "What was detected → Why it's risky → What to do" across all scanners
- No new tests needed (descriptions only, 265 tests still passing)

## [0.11.0] - 2026-03-09

### Added (Dependency Scanner Enhancement — 3/5 → 5/5)
- **npm/package.json scanning** — parse dependencies + devDependencies, query OSV.dev with ecosystem=npm
- **requirements.txt auto-discovery** — find and scan all `requirements*.txt` files in repo
- **pyproject.toml parsing** — extract `[project.dependencies]` for CVE checking
- **Known malicious package detection** — 30+ PyPI + 25+ npm typosquatting/supply chain packages (CRITICAL severity)
- **OSV.dev batch query** — `/v1/querybatch` for efficient bulk CVE lookup (100 per batch)
- **Repo-wide dependency scan** — `check_cve_repo()` discovers all dep files automatically
- **Pipeline integration** — Phase 1c scans repo deps in addition to manifest requirements
- 21 new tests (265 total)

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
