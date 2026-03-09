"""Tests for enhanced YAML scanner (v0.10.0): structural parsing, automation flow, includes."""

from pathlib import Path

import pytest

from app.models import Severity
from app.scanner.static_yaml import scan_yaml_file, scan_yaml_repo


class TestStructuralYAML:
    """Test structural YAML parsing (Y.1)."""

    def test_parsed_rest_command_http(self, tmp_path):
        """rest_command with HTTP URL detected via structural parsing."""
        f = tmp_path / "config.yaml"
        f.write_text(
            "rest_command:\n"
            "  notify_server:\n"
            "    url: http://external.example.com/api/notify\n"
            "    method: POST\n"
        )
        findings = scan_yaml_file(f)
        assert any(
            f.category == "insecure_transport" and "rest_command" in f.description
            for f in findings
        )

    def test_rest_command_https_not_flagged(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            "rest_command:\n"
            "  notify_server:\n"
            "    url: https://secure.example.com/api\n"
        )
        findings = scan_yaml_file(f)
        assert not any(
            "rest_command" in f.description and f.category == "insecure_transport"
            for f in findings
        )

    def test_rest_command_local_http_not_flagged(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            "rest_command:\n"
            "  local_api:\n"
            "    url: http://192.168.1.100/api\n"
        )
        findings = scan_yaml_file(f)
        assert not any(
            "rest_command" in f.description and f.category == "insecure_transport"
            for f in findings
        )

    def test_rest_sensor_http(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            "rest:\n"
            "  - resource: http://insecure.example.com/data\n"
            "    sensor:\n"
            "      - name: Test\n"
        )
        findings = scan_yaml_file(f)
        assert any(
            f.category == "insecure_transport" and "REST resource" in f.description
            for f in findings
        )


class TestAutomationFlowInjection:
    """Test automation flow injection detection (Y.2, Y.5)."""

    def test_service_template_detected(self, tmp_path):
        f = tmp_path / "automations.yaml"
        f.write_text(
            "automation:\n"
            "  - alias: Dynamic service\n"
            "    trigger:\n"
            "      - platform: state\n"
            "        entity_id: input_boolean.test\n"
            "    action:\n"
            "      - service_template: \"{{ states('input_select.service') }}\"\n"
        )
        findings = scan_yaml_file(f)
        assert any(f.category == "automation_injection" for f in findings)

    def test_dynamic_service_in_action(self, tmp_path):
        f = tmp_path / "automations.yaml"
        f.write_text(
            "automation:\n"
            "  - alias: Dynamic\n"
            "    trigger:\n"
            "      - platform: time\n"
            "        at: '12:00'\n"
            "    action:\n"
            "      - service: \"{{ trigger.event.data.service }}\"\n"
        )
        findings = scan_yaml_file(f)
        assert any(f.category == "automation_injection" for f in findings)

    def test_static_service_not_flagged(self, tmp_path):
        f = tmp_path / "automations.yaml"
        f.write_text(
            "automation:\n"
            "  - alias: Safe\n"
            "    trigger:\n"
            "      - platform: state\n"
            "        entity_id: binary_sensor.motion\n"
            "    action:\n"
            "      - service: light.turn_on\n"
            "        entity_id: light.living_room\n"
        )
        findings = scan_yaml_file(f)
        assert not any(f.category == "automation_injection" for f in findings)

    def test_template_in_shell_command_data(self, tmp_path):
        """Template value flowing to shell_command via service data."""
        f = tmp_path / "automations.yaml"
        f.write_text(
            "automation:\n"
            "  - alias: Shell inject\n"
            "    trigger:\n"
            "      - platform: state\n"
            "        entity_id: sensor.test\n"
            "    action:\n"
            "      - service: shell_command.run\n"
            "        data:\n"
            "          command: \"{{ states('sensor.user_input') }}\"\n"
        )
        findings = scan_yaml_file(f)
        assert any(f.category == "template_injection" for f in findings)

    def test_standalone_automation_list(self, tmp_path):
        """Standalone automation file (list at root) should be scanned."""
        f = tmp_path / "automations.yaml"
        f.write_text(
            "- alias: Dynamic standalone\n"
            "  trigger:\n"
            "    - platform: state\n"
            "      entity_id: input_boolean.x\n"
            "  action:\n"
            "    - service_template: \"{{ states('input_select.svc') }}\"\n"
        )
        findings = scan_yaml_file(f)
        assert any(f.category == "automation_injection" for f in findings)

    def test_nested_action_sequence(self, tmp_path):
        """Nested action sequences (choose/then/else) should be scanned."""
        f = tmp_path / "automations.yaml"
        f.write_text(
            "automation:\n"
            "  - alias: Nested\n"
            "    trigger:\n"
            "      - platform: state\n"
            "        entity_id: input_boolean.x\n"
            "    action:\n"
            "      - choose:\n"
            "          - conditions: []\n"
            "            sequence:\n"
            "              - service_template: \"{{ states('input_select.svc') }}\"\n"
        )
        # choose actions are nested under sequence — scanner should follow
        # Note: yaml.safe_load will parse this, but the choose structure
        # has conditions+sequence, which is handled by nested scanning
        findings = scan_yaml_file(f)
        # The choose action itself won't match directly because choose
        # uses conditions+sequence structure, but sequence key IS scanned
        assert any(f.category == "automation_injection" for f in findings)


class TestIncludePatterns:
    """Test !include pattern detection (Y.3)."""

    def test_include_with_template_path(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            'sensor: !include "{{ config_dir }}/sensors/{{ type }}.yaml"\n'
        )
        findings = scan_yaml_file(f)
        assert any(f.category == "unsafe_include" for f in findings)

    def test_include_with_parent_path(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            "sensor: !include ../../secrets/config.yaml\n"
        )
        findings = scan_yaml_file(f)
        assert any(f.category == "unsafe_include" for f in findings)

    def test_include_with_absolute_path(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            "sensor: !include /etc/ha/sensors.yaml\n"
        )
        findings = scan_yaml_file(f)
        assert any(f.category == "unsafe_include" for f in findings)

    def test_normal_include_not_flagged(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            "sensor: !include sensors.yaml\n"
            "automation: !include automations.yaml\n"
        )
        findings = scan_yaml_file(f)
        assert not any(f.category == "unsafe_include" for f in findings)


class TestSecretComments:
    """Test secrets-in-comments detection (Y.4)."""

    def test_secret_in_comment(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            "mqtt:\n"
            "  broker: 192.168.1.1\n"
            "  password: !secret mqtt_password\n"
            "  # old password: SuperSecret123Password\n"
        )
        findings = scan_yaml_file(f)
        assert any(
            f.category == "hardcoded_secret" and "comment" in f.description
            for f in findings
        )

    def test_normal_comment_not_flagged(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            "# This is a normal configuration comment\n"
            "sensor:\n"
            "  - platform: mqtt\n"
        )
        findings = scan_yaml_file(f)
        assert not any(
            "comment" in f.description
            for f in findings
        )


class TestYAMLPerFileCap:
    """Test per-file finding cap for YAML scanner."""

    def test_cap_per_file(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        # File with many shell commands
        (repo / "config.yaml").write_text(
            "\n".join(f"shell_command:\n  cmd{i}: echo {i}" for i in range(10))
        )
        findings = scan_yaml_repo(repo)
        cmd_findings = [f for f in findings if f.category == "command_execution"]
        assert len(cmd_findings) <= 3


class TestExistingYAMLScanner:
    """Existing tests ported to ensure backward compatibility."""

    def test_shell_command_detected(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            "shell_command:\n"
            "  restart_service: systemctl restart nginx\n"
        )
        findings = scan_yaml_file(f)
        assert any(f.category == "command_execution" for f in findings)

    def test_hardcoded_password_detected(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            "mqtt:\n"
            "  broker: 192.168.1.1\n"
            '  password: "SuperSecretPassword123"\n'
        )
        findings = scan_yaml_file(f)
        assert any(f.category == "hardcoded_secret" for f in findings)

    def test_secret_reference_not_flagged(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            "mqtt:\n"
            "  broker: 192.168.1.1\n"
            "  password: !secret mqtt_password\n"
        )
        findings = scan_yaml_file(f)
        assert not any(f.category == "hardcoded_secret" for f in findings)

    def test_jinja2_eval_detected(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            "template:\n"
            '  value: "{{ eval(user_input) }}"\n'
        )
        findings = scan_yaml_file(f)
        assert any(f.category == "code_injection" and f.severity == Severity.CRITICAL for f in findings)

    def test_safe_yaml(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            "sensor:\n"
            "  - platform: mqtt\n"
            "    name: Temperature\n"
            "    state_topic: home/temp\n"
        )
        findings = scan_yaml_file(f)
        high_or_above = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(high_or_above) == 0
