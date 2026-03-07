# HA Security Sandbox

Security scanner for Home Assistant custom components. Analyzes HACS integrations and Lovelace cards for potential security issues using static analysis and AI review.

## Features

- **Static Analysis** — AST-based Python scanning for dangerous calls (eval, exec, subprocess, pickle, ctypes) and regex-based JavaScript/TypeScript scanning (XSS, exfiltration, obfuscation)
- **AI Review** — LLM-powered code review via local Ollama or public APIs (OpenRouter, OpenAI)
- **HACS Integration** — Automatically lists installed HACS components for one-click scanning
- **MQTT Reporting** — Publishes scan results to Home Assistant via MQTT auto-discovery
- **Security Scoring** — 0-10 safety score with SAFE/CAUTION/DANGER classification

## Configuration

### AI Provider

Choose between local Ollama instance or a public API:

- **Ollama** (default) — Set the URL to your Ollama server (e.g., `http://192.168.1.100:11434`)
- **Public API** — Supports OpenRouter and OpenAI. Requires an API key.

### MQTT

MQTT is auto-configured when the Supervisor MQTT service is available. The add-on publishes:
- `ha_sandbox/status` — current status (idle/scanning)
- `ha_sandbox/last_scan` — name of last scanned component
- `ha_sandbox/last_score` — safety score of last scan
- `ha_sandbox/scans_total` — total number of scans

### Data Storage

Scan reports and cloned repositories are stored in `/share/ha-sandbox/`. This persists across add-on restarts.

## Usage

1. Open the add-on from the HA sidebar (Security Sandbox)
2. Enter a GitHub repository URL or select from installed HACS components
3. Click "Scan" — the analysis runs in the background
4. View results in the "Results" tab with detailed findings and AI summary
