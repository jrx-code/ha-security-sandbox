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
    ollama_model: str = "qwen2.5-coder:32b"

    # Home Assistant (for installed HACS list)
    ha_url: str = "http://192.168.19.120:8123"
    ha_token: str = ""

    # HACS default repo list
    hacs_repo_url: str = "https://github.com/hacs/default/raw/master"

    # Paths
    repos_dir: str = "/data/repos"
    reports_dir: str = "/data/reports"

    # Scan settings
    max_file_size_kb: int = 500
    scan_timeout_seconds: int = 300

    model_config = {"env_prefix": "SANDBOX_", "env_file": ".env"}


settings = Settings()
