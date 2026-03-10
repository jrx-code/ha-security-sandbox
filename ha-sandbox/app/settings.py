"""Persistent settings stored in /data/settings.json."""

import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

SETTINGS_FILE = Path("/data/settings.json")

DEFAULTS = {
    "ai_provider": "ollama",  # "ollama" or "public"
    "ollama_url": "http://homeassistant:11434",
    "ollama_model": "qwen2.5-coder:14b",
    "public_provider": "openrouter",  # "openrouter" or "openai"
    "public_api_key": "",
    "public_model": "google/gemma-3-27b-it",
    "public_url": "https://openrouter.ai/api/v1",
    "ha_url": "http://homeassistant:8123",
    "ha_token": "",
    "mqtt_enabled": True,
    "mqtt_host": "localhost",
    "mqtt_port": 8883,
    "mqtt_user": "",
    "mqtt_pass": "",
    "mqtt_tls": True,
    "mqtt_tls_verify": True,
    "max_code_context": 15000,
    "ai_timeout": 300,
    "max_file_size_kb": 500,
    "log_level": "info",
    "schedule_enabled": False,
    "schedule_interval_hours": 24,
}

# Public API provider presets
PROVIDER_PRESETS = {
    "openrouter": {
        "url": "https://openrouter.ai/api/v1",
        "models": [
            "google/gemma-3-27b-it",
            "google/gemma-3-12b-it",
            "qwen/qwen-2.5-coder-32b-instruct",
            "meta-llama/llama-4-scout",
            "deepseek/deepseek-chat-v3-0324",
            "anthropic/claude-sonnet-4",
        ],
    },
    "openai": {
        "url": "https://api.openai.com/v1",
        "models": [
            "gpt-4o-mini",
            "gpt-4o",
            "gpt-4.1-mini",
        ],
    },
}


def _load_raw() -> dict:
    if SETTINGS_FILE.exists():
        try:
            return json.loads(SETTINGS_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def load() -> dict:
    raw = _load_raw()
    merged = {**DEFAULTS, **raw}
    return merged


def save(data: dict) -> None:
    current = load()
    current.update(data)
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(current, indent=2))
    log.info("Settings saved to %s", SETTINGS_FILE)
    _apply_to_runtime(current)


def get(key: str, default: Any = None) -> Any:
    return load().get(key, default)


def _apply_to_runtime(data: dict) -> None:
    """Push settings into the runtime config singleton."""
    from app.config import settings as cfg
    import os

    if data.get("ai_provider") == "ollama":
        cfg.ollama_url = data.get("ollama_url", cfg.ollama_url)
        cfg.ollama_model = data.get("ollama_model", cfg.ollama_model)
    cfg.ha_url = data.get("ha_url", cfg.ha_url)
    if data.get("ha_token"):
        cfg.ha_token = data["ha_token"]
    cfg.mqtt_host = data.get("mqtt_host", cfg.mqtt_host)
    cfg.mqtt_port = int(data.get("mqtt_port", cfg.mqtt_port))
    cfg.mqtt_user = data.get("mqtt_user", cfg.mqtt_user)
    if data.get("mqtt_pass"):
        cfg.mqtt_pass = data["mqtt_pass"]
    cfg.mqtt_use_tls = data.get("mqtt_tls", cfg.mqtt_use_tls)
    cfg.mqtt_tls_verify = data.get("mqtt_tls_verify", cfg.mqtt_tls_verify)
    cfg.max_file_size_kb = int(data.get("max_file_size_kb", cfg.max_file_size_kb))
    cfg.scan_timeout_seconds = int(data.get("ai_timeout", cfg.scan_timeout_seconds))


def init_from_env() -> None:
    """On startup, merge env vars into saved settings (env takes precedence for secrets)."""
    import os
    data = load()
    env_token = os.environ.get("HA_TOKEN", "")
    if env_token and not data.get("ha_token"):
        data["ha_token"] = env_token
    env_mqtt_pass = os.environ.get("MQTT_PASS", "")
    if env_mqtt_pass and not data.get("mqtt_pass"):
        data["mqtt_pass"] = env_mqtt_pass
    save(data)
