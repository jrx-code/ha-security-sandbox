"""Phase 2.3 tests: HA API pattern validator."""

from pathlib import Path

import pytest

from app.models import Severity
from app.scanner.static_ha import scan_ha_patterns, scan_ha_repo


class TestHAAPIValidator:
    def test_services_call_detected(self, tmp_path):
        """hass.services.call() should be flagged."""
        f = tmp_path / "init.py"
        f.write_text(
            'async def async_setup(hass, config):\n'
            '    await hass.services.async_call("light", "turn_on", {"entity_id": "light.test"})\n'
        )
        findings = scan_ha_patterns(f)
        assert any(f.category == "ha_api_risk" for f in findings)

    def test_services_call_dynamic_domain(self, tmp_path):
        """Dynamic domain in hass.services.call() should be HIGH."""
        f = tmp_path / "init.py"
        f.write_text(
            'async def async_setup(hass, config):\n'
            '    domain = config.get("domain")\n'
            '    await hass.services.async_call(domain, "turn_on")\n'
        )
        findings = scan_ha_patterns(f)
        assert any(f.category == "ha_dynamic_service" and f.severity == Severity.HIGH
                   for f in findings)

    def test_services_call_literal_domain_ok(self, tmp_path):
        """Literal domain in hass.services.call() should NOT be ha_dynamic_service."""
        f = tmp_path / "init.py"
        f.write_text(
            'async def async_setup(hass, config):\n'
            '    await hass.services.async_call("light", "turn_on")\n'
        )
        findings = scan_ha_patterns(f)
        assert not any(f.category == "ha_dynamic_service" for f in findings)

    def test_bus_fire_detected(self, tmp_path):
        """hass.bus.fire() should flag event injection."""
        f = tmp_path / "init.py"
        f.write_text(
            'def setup(hass, config):\n'
            '    hass.bus.fire("custom_event", {"data": "value"})\n'
        )
        findings = scan_ha_patterns(f)
        assert any(f.category == "ha_event_injection" for f in findings)

    def test_hass_auth_access(self, tmp_path):
        """Direct hass.auth access should be HIGH."""
        f = tmp_path / "init.py"
        f.write_text(
            'async def async_setup(hass, config):\n'
            '    users = await hass.auth.async_get_users()\n'
        )
        findings = scan_ha_patterns(f)
        assert any(f.category == "ha_auth_access" and f.severity == Severity.HIGH
                   for f in findings)

    def test_states_set_dynamic_entity(self, tmp_path):
        """Dynamic entity_id in hass.states.set() should be flagged."""
        f = tmp_path / "init.py"
        f.write_text(
            'def update(hass, entity_id, state):\n'
            '    hass.states.set(entity_id, state)\n'
        )
        findings = scan_ha_patterns(f)
        assert any(f.category == "ha_dynamic_entity" for f in findings)

    def test_states_set_literal_ok(self, tmp_path):
        """Literal entity_id in hass.states.set() should NOT flag dynamic."""
        f = tmp_path / "init.py"
        f.write_text(
            'def update(hass):\n'
            '    hass.states.set("sensor.my_sensor", "online")\n'
        )
        findings = scan_ha_patterns(f)
        assert not any(f.category == "ha_dynamic_entity" for f in findings)

    def test_schema_without_vol(self, tmp_path):
        """PLATFORM_SCHEMA without vol.Schema should be flagged."""
        f = tmp_path / "init.py"
        f.write_text(
            'PLATFORM_SCHEMA = {}\n'
        )
        findings = scan_ha_patterns(f)
        assert any(f.category == "ha_no_validation" for f in findings)

    def test_schema_with_vol_ok(self, tmp_path):
        """PLATFORM_SCHEMA with vol.Schema should NOT flag."""
        f = tmp_path / "init.py"
        f.write_text(
            'import voluptuous as vol\n'
            'PLATFORM_SCHEMA = vol.Schema({})\n'
        )
        findings = scan_ha_patterns(f)
        assert not any(f.category == "ha_no_validation" for f in findings)

    def test_safe_integration_no_findings(self, tmp_path):
        """A clean HA integration should have no HA-specific findings."""
        f = tmp_path / "init.py"
        f.write_text(
            'import logging\n'
            '_LOGGER = logging.getLogger(__name__)\n'
            'async def async_setup(hass, config):\n'
            '    _LOGGER.info("Setup")\n'
            '    return True\n'
        )
        findings = scan_ha_patterns(f)
        assert len(findings) == 0

    def test_repo_scan(self, tmp_path):
        """scan_ha_repo should scan .py files and skip tests/venv."""
        repo = tmp_path / "repo"
        cc = repo / "custom_components" / "test"
        cc.mkdir(parents=True)
        (cc / "__init__.py").write_text(
            'def setup(hass):\n'
            '    hass.bus.fire("evt", {})\n'
        )
        tests = repo / "tests"
        tests.mkdir()
        (tests / "test_init.py").write_text(
            'def test():\n'
            '    hass.bus.fire("evt", {})\n'
        )
        findings = scan_ha_repo(repo)
        assert any(f.category == "ha_event_injection" for f in findings)
        assert not any("tests" in f.file for f in findings)
