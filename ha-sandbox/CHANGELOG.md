# Changelog

## [0.21.0] - 2026-09-18

### Added
- **HACS auto-scan on install/update** — long-lived WebSocket watcher subscribes to `hacs/repository` events (with snapshot-diff fallback every 120s), queues a scan, and publishes MQTT critical alerts when severity is critical or AI score is in DANGER range
- Settings toggle `hacs_autoscan_enabled` (default on) + `/api/hacs-autoscan` GET/POST + add-on config option

### Fixed
- **Installed HACS list** — `fetch_installed_hacs` now includes `full_name` (alias of `repository`) so scheduled/CVE/batch scans resolve clone URLs correctly

## [0.20.3] - 2026-03-10

### Fixed
- **Settings preserved on upgrade** — env vars from addon config now only seed settings.json on first start; web UI settings survive restarts and upgrades
- **OpenRouter 401 Forbidden** — addon config API key (set in HA UI) synced to settings.json on first start
- **Changelog** — now shows only latest version (was showing full history)
