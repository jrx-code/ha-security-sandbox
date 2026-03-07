#!/usr/bin/with-contenv bashio

bashio::log.info "Starting HA Security Sandbox"

# Read add-on configuration
export SANDBOX_OLLAMA_URL="$(bashio::config 'ollama_url')"
export SANDBOX_OLLAMA_MODEL="$(bashio::config 'ollama_model')"

# AI provider settings
AI_PROVIDER="$(bashio::config 'ai_provider')"
if [ "$AI_PROVIDER" = "public" ]; then
    export SANDBOX_PUBLIC_PROVIDER="$(bashio::config 'public_provider')"
    export SANDBOX_PUBLIC_API_KEY="$(bashio::config 'public_api_key')"
    export SANDBOX_PUBLIC_MODEL="$(bashio::config 'public_model')"
    export SANDBOX_PUBLIC_URL="$(bashio::config 'public_url')"
fi
export SANDBOX_AI_PROVIDER="$AI_PROVIDER"

# MQTT — use HA Supervisor MQTT service if available, else from config
if bashio::services.available "mqtt"; then
    export SANDBOX_MQTT_HOST="$(bashio::services mqtt 'host')"
    export SANDBOX_MQTT_PORT="$(bashio::services mqtt 'port')"
    export SANDBOX_MQTT_USER="$(bashio::services mqtt 'username')"
    export SANDBOX_MQTT_PASS="$(bashio::services mqtt 'password')"
    export SANDBOX_MQTT_USE_TLS="false"
    bashio::log.info "Using Supervisor MQTT service at ${SANDBOX_MQTT_HOST}:${SANDBOX_MQTT_PORT}"
else
    bashio::log.info "No Supervisor MQTT service, using config"
fi
export SANDBOX_MQTT_ENABLED="$(bashio::config 'mqtt_enabled')"
export SANDBOX_MQTT_TLS="$(bashio::config 'mqtt_tls')"

# Home Assistant API — use Supervisor token (auto-injected)
export SANDBOX_HA_URL="http://supervisor/core"
export SANDBOX_HA_TOKEN="${SUPERVISOR_TOKEN}"

# Log level
LOG_LEVEL="$(bashio::config 'log_level')"
bashio::log.info "Log level: ${LOG_LEVEL}"

# Data directory on shared storage
export SANDBOX_REPOS_DIR="/share/ha-sandbox/repos"
export SANDBOX_REPORTS_DIR="/share/ha-sandbox/reports"
mkdir -p "${SANDBOX_REPOS_DIR}" "${SANDBOX_REPORTS_DIR}"

bashio::log.info "Starting web server on port 8099"
exec uvicorn app.main:app --host 0.0.0.0 --port 8099 --log-level "${LOG_LEVEL}"
