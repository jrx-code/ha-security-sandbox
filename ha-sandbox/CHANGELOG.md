# Changelog

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

### Notes
- Version **0.21.1** (not 0.21.0) to avoid colliding with open PR #9 (`feat/hacs-autoscan-on-install`). Rebase/version bump may be needed after #9 merges.
- Independently mergeable from `main` (does not stack on #9).
- **Do not merge without user OK.** Refs #3.
