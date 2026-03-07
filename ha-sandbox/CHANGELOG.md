# Changelog

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
