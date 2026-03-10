#!/usr/bin/with-contenv bashio

# Detect if running inside HA Supervisor or standalone Docker
if bashio::supervisor.ping 2>/dev/null; then
    STANDALONE=false
    bashio::log.info "Running as HA Add-on (Supervisor detected)"
    # Wait for Supervisor API to be fully ready (avoids "forbidden" on fresh install)
    for i in 1 2 3; do
        if bashio::config 'log_level' &>/dev/null; then break; fi
        bashio::log.info "Waiting for Supervisor API... ($i/3)"
        sleep 2
    done
else
    STANDALONE=true
    bashio::log.info "Running standalone (no Supervisor)"
fi

# --- Configuration ---

if [ "$STANDALONE" = "false" ]; then
    # HA Add-on mode: read from Supervisor config
    export SANDBOX_OLLAMA_URL="$(bashio::config 'ollama_url')"
    export SANDBOX_OLLAMA_MODEL="$(bashio::config 'ollama_model')"
    AI_PROVIDER="$(bashio::config 'ai_provider')"
    if [ "$AI_PROVIDER" = "public" ]; then
        export SANDBOX_PUBLIC_PROVIDER="$(bashio::config 'public_provider')"
        export SANDBOX_PUBLIC_API_KEY="$(bashio::config 'public_api_key')"
        export SANDBOX_PUBLIC_MODEL="$(bashio::config 'public_model')"
        export SANDBOX_PUBLIC_URL="$(bashio::config 'public_url')"
    fi
    export SANDBOX_AI_PROVIDER="$AI_PROVIDER"

    # MQTT — use HA Supervisor MQTT service if available
    if bashio::services.available "mqtt" 2>/dev/null; then
        export SANDBOX_MQTT_HOST="$(bashio::services mqtt 'host' 2>/dev/null || echo '')"
        export SANDBOX_MQTT_PORT="$(bashio::services mqtt 'port' 2>/dev/null || echo '1883')"
        export SANDBOX_MQTT_USER="$(bashio::services mqtt 'username' 2>/dev/null || echo '')"
        export SANDBOX_MQTT_PASS="$(bashio::services mqtt 'password' 2>/dev/null || echo '')"
        export SANDBOX_MQTT_USE_TLS="false"
        if [ -n "${SANDBOX_MQTT_HOST}" ]; then
            bashio::log.info "Using Supervisor MQTT service at ${SANDBOX_MQTT_HOST}:${SANDBOX_MQTT_PORT}"
        else
            bashio::log.warning "MQTT service available but could not read config"
        fi
    else
        bashio::log.info "No MQTT service found in Supervisor"
    fi
    export SANDBOX_MQTT_ENABLED="$(bashio::config 'mqtt_enabled')"
    export SANDBOX_MQTT_TLS="$(bashio::config 'mqtt_tls')"

    # HA API via Supervisor
    export SANDBOX_HA_URL="http://supervisor/core"
    export SANDBOX_HA_TOKEN="${SUPERVISOR_TOKEN:-}"
    if [ -z "${SANDBOX_HA_TOKEN}" ]; then
        bashio::log.warning "SUPERVISOR_TOKEN not set — HA API access disabled"
    fi

    LOG_LEVEL="$(bashio::config 'log_level')"
else
    # Standalone mode: use environment variables (already set via docker run -e)
    LOG_LEVEL="${SANDBOX_LOG_LEVEL:-info}"
    bashio::log.info "Using environment variables for configuration"
fi

# Data directory
REPOS_DIR="${SANDBOX_REPOS_DIR:-/data/repos}"
REPORTS_DIR="${SANDBOX_REPORTS_DIR:-/data/reports}"
export SANDBOX_REPOS_DIR="$REPOS_DIR"
export SANDBOX_REPORTS_DIR="$REPORTS_DIR"
mkdir -p "${REPOS_DIR}" "${REPORTS_DIR}"

bashio::log.info "Starting web server on port 8099 (log_level=${LOG_LEVEL})"
exec uvicorn app.main:app --host 0.0.0.0 --port 8099 --log-level "${LOG_LEVEL}"
