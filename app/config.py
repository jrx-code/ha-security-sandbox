import os

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # MQTT
    mqtt_host: str = "mqtt.iwanus.eu"
    mqtt_port: int = 8883
    mqtt_user: str = "_mqtt_client"
    mqtt_pass: str = "Service001"
    mqtt_use_tls: bool = True
    mqtt_node_id: str = "ha_sandbox"

    # Ollama
    ollama_url: str = "http://ai.iwanus.eu:11434"
    ollama_model: str = "gemma3:12b"

    # Home Assistant (for installed HACS list)
    ha_url: str = "https://ha.iwanus.eu:8123"
    ha_token: str = ""

    # Paths
    repos_dir: str = "/data/repos"
    reports_dir: str = "/data/reports"

    # Scan settings
    max_file_size_kb: int = 500
    scan_timeout_seconds: int = 300

    model_config = {"env_prefix": "SANDBOX_", "env_file": ".env"}


# Fallback: read HA_TOKEN and HA_URL directly from env if SANDBOX_ prefixed are empty
_settings = Settings()
if not _settings.ha_token:
    _settings.ha_token = os.environ.get("HA_TOKEN", "")
if _settings.ha_url == "https://ha.iwanus.eu:8123":
    _settings.ha_url = os.environ.get("HA_URL", _settings.ha_url)

settings = _settings
