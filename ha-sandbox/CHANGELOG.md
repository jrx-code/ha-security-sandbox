# Changelog

## [0.22.0] - 2026-09-30

### Added
- **HACS auto-scan on install/update** (opt-in, `hacs_autoscan_enabled`, default off)
  - Subscribes to HACS's `hacs_dispatch_repository` signal via `hacs/subscribe`; HACS
    does not use the HA event bus for this
  - Snapshot diff of installed repositories (every 2 min, and 5 s after an install signal)
    decides what changed and to which version
  - Scans run through the shared queue (concurrency limit, job records); alerts come from
    the notification alerts added in 0.21.1
  - `GET/POST /api/hacs-autoscan`, add-on option + `SANDBOX_HACS_AUTOSCAN_ENABLED` seed
- `fetch_installed_hacs` also returns `full_name`

## [0.21.1] - 2026-09-18

### Added
- **Notification alerts on critical/high findings** — after a successful scan, optionally notify via:
  - HA persistent notifications (`persistent_notification.create`)
  - MQTT `{node_id}/alert` (+ `last_alert` sensor / `alert_active` binary_sensor)
  - Optional mobile push via `alert_notify_service` (e.g. `notify.mobile_app_xxx`)
- Settings: `alerts_enabled` (default true), `alert_severity_threshold` (critical|high|medium), `alert_cooldown_seconds` (default 3600), `alert_notify_service`
- API: `GET/POST /api/alerts` for status and config
- In-memory rate limiting per component+threshold bucket
- Addon option `alerts_enabled` + `SANDBOX_ALERTS_ENABLED` env seed on first start
- Offline unit tests in `tests/test_alerts.py`

### Fixed (before release)
- HA notifications use the supervisor token in the add-on (settings.json has none there)
- `alert_active` is momentary: not retained, cleared by `off_delay` after the cooldown
