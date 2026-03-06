"""MQTT auto-discovery and status reporting for Home Assistant."""

import json
import logging
import ssl

import paho.mqtt.client as mqtt

from app.config import settings
from app.models import ScanJob

log = logging.getLogger(__name__)

_client: mqtt.Client | None = None


def _get_client() -> mqtt.Client:
    global _client
    if _client is not None and _client.is_connected():
        return _client

    _client = mqtt.Client(
        client_id="ha-sandbox",
        protocol=mqtt.MQTTv5,
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
    )
    _client.username_pw_set(settings.mqtt_user, settings.mqtt_pass)
    if settings.mqtt_use_tls:
        _client.tls_set(cert_reqs=ssl.CERT_NONE)
        _client.tls_insecure_set(True)
    _client.connect(settings.mqtt_host, settings.mqtt_port)
    _client.loop_start()
    return _client


def publish_discovery():
    """Publish MQTT auto-discovery config for HA sensor."""
    client = _get_client()
    node = settings.mqtt_node_id
    base = f"homeassistant/sensor/{node}"

    device = {
        "identifiers": [node],
        "name": "HA Sandbox Analyzer",
        "model": "Sandbox v0.4.0",
        "manufacturer": "JI Engineering",
    }

    sensors = [
        ("status", "Status", None, "mdi:shield-search"),
        ("last_scan", "Last Scan", None, "mdi:clock-check"),
        ("last_score", "Last Score", None, "mdi:counter"),
        ("scans_total", "Total Scans", None, "mdi:numeric"),
    ]

    for obj_id, name, dev_class, icon in sensors:
        config = {
            "name": name,
            "unique_id": f"{node}_{obj_id}",
            "state_topic": f"{node}/{obj_id}",
            "device": device,
            "icon": icon,
        }
        if dev_class:
            config["device_class"] = dev_class
        topic = f"{base}/{obj_id}/config"
        client.publish(topic, json.dumps(config), retain=True)

    log.info("MQTT discovery published for %d sensors", len(sensors))


def publish_scan_result(job: ScanJob):
    """Publish scan result to MQTT."""
    client = _get_client()
    node = settings.mqtt_node_id

    client.publish(f"{node}/status", job.status.value, retain=True)
    client.publish(f"{node}/last_scan", job.name, retain=True)
    score = str(job.ai_score) if job.ai_score is not None else "N/A"
    client.publish(f"{node}/last_score", score, retain=True)


def publish_status(status: str):
    """Publish simple status update."""
    try:
        client = _get_client()
        client.publish(f"{settings.mqtt_node_id}/status", status, retain=True)
    except Exception as e:
        log.warning("MQTT publish failed: %s", e)


def disconnect():
    global _client
    if _client:
        _client.loop_stop()
        _client.disconnect()
        _client = None


def test_mqtt_connection(host: str, port: int, user: str, password: str, use_tls: bool) -> dict:
    """Test MQTT connection."""
    import time
    try:
        test_client = mqtt.Client(
            client_id="ha-sandbox-test",
            protocol=mqtt.MQTTv5,
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        )
        test_client.username_pw_set(user, password)
        if use_tls:
            test_client.tls_set(cert_reqs=ssl.CERT_NONE)
            test_client.tls_insecure_set(True)
        test_client.connect(host, port, keepalive=5)
        test_client.loop_start()
        time.sleep(2)
        connected = test_client.is_connected()
        test_client.loop_stop()
        test_client.disconnect()
        return {"ok": connected, "error": "" if connected else "Connection failed"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
