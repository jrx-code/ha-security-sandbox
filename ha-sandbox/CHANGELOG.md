# Changelog

## [0.20.3] - 2026-03-10

### Fixed
- **Settings preserved on upgrade** — env vars from addon config now only seed settings.json on first start; web UI settings survive restarts and upgrades
- **OpenRouter 401 Forbidden** — addon config API key (set in HA UI) synced to settings.json on first start
- **Changelog** — now shows only latest version (was showing full history)
