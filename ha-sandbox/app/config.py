import os

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # MQTT
    mqtt_host: str = "localhost"
    mqtt_port: int = 8883
    mqtt_user: str = ""
    mqtt_pass: str = ""
    mqtt_use_tls: bool = True
    mqtt_tls_verify: bool = True
    mqtt_enabled: bool = True
    mqtt_node_id: str = "ha_sandbox"

    # AI provider
    ai_provider: str = "ollama"  # "ollama" or "public"

    # Ollama
    ollama_url: str = "http://ollama:11434"
    ollama_model: str = "gemma3:12b"

    # Public API
    public_provider: str = "openrouter"
    public_api_key: str = ""
    public_model: str = "google/gemma-3-27b-it"
    public_url: str = "https://openrouter.ai/api/v1"

    # Home Assistant (for installed HACS list)
    ha_url: str = "http://supervisor/core"
    ha_token: str = ""

    # Paths
    repos_dir: str = "/data/repos"
    reports_dir: str = "/data/reports"

    # Scan settings
    max_file_size_kb: int = 500
    scan_timeout_seconds: int = 300

    model_config = {"env_prefix": "SANDBOX_", "env_file": ".env"}


_settings = Settings()

# Fallback: read HA supervisor token and legacy env vars
if not _settings.ha_token:
    _settings.ha_token = os.environ.get("SUPERVISOR_TOKEN", os.environ.get("HA_TOKEN", ""))
if _settings.ha_url == "http://supervisor/core":
    _settings.ha_url = os.environ.get("HA_URL", _settings.ha_url)

settings = _settings
