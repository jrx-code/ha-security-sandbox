"""Offline unit tests for notification alerts (#3)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.alerts import (
    call_notify_service,
    component_key,
    create_persistent_notification,
    filter_alertable_findings,
    format_alert_message,
    is_rate_limited,
    mark_alerted,
    maybe_alert,
    notification_id_for,
    reset_rate_limits,
    severity_meets_threshold,
)
from app.models import Finding, ManifestInfo, ScanJob, ScanStatus, Severity


def _finding(
    sev: Severity,
    category: str = "code_injection",
    file: str = "a.py",
    line: int = 1,
) -> Finding:
    return Finding(
        severity=sev,
        category=category,
        file=file,
        line=line,
        code="x",
        description=f"{category} issue",
    )


def _job(
    *findings: Finding,
    domain: str = "evil",
    name: str = "Evil",
    status: ScanStatus = ScanStatus.DONE,
) -> ScanJob:
    return ScanJob(
        id="job1",
        repo_url="https://github.com/example/evil.git",
        name=name,
        status=status,
        manifest=ManifestInfo(domain=domain, name=name),
        findings=list(findings),
        ai_score=2.0,
    )


@pytest.fixture(autouse=True)
def _clear_cooldowns():
    reset_rate_limits()
    yield
    reset_rate_limits()


class TestSeverityThreshold:
    def test_critical_only(self):
        findings = [
            _finding(Severity.CRITICAL),
            _finding(Severity.HIGH),
            _finding(Severity.MEDIUM),
            _finding(Severity.LOW),
            _finding(Severity.INFO),
        ]
        got = filter_alertable_findings(findings, "critical")
        assert [f.severity for f in got] == [Severity.CRITICAL]

    def test_high_includes_critical(self):
        findings = [
            _finding(Severity.CRITICAL),
            _finding(Severity.HIGH),
            _finding(Severity.MEDIUM),
        ]
        got = filter_alertable_findings(findings, "high")
        assert [f.severity for f in got] == [Severity.CRITICAL, Severity.HIGH]

    def test_medium(self):
        findings = [
            _finding(Severity.HIGH),
            _finding(Severity.MEDIUM),
            _finding(Severity.LOW),
        ]
        got = filter_alertable_findings(findings, "medium")
        assert [f.severity for f in got] == [Severity.HIGH, Severity.MEDIUM]

    def test_meets_threshold_helper(self):
        assert severity_meets_threshold(Severity.CRITICAL, "critical")
        assert severity_meets_threshold(Severity.CRITICAL, "high")
        assert not severity_meets_threshold(Severity.HIGH, "critical")
        assert severity_meets_threshold(Severity.HIGH, "high")
        assert severity_meets_threshold("medium", "medium")
        assert not severity_meets_threshold(Severity.INFO, "medium")


class TestRateLimit:
    def test_cooldown_skips_duplicate(self):
        assert not is_rate_limited("evil", "critical", 3600)
        mark_alerted("evil", "critical", 3600)
        assert is_rate_limited("evil", "critical", 3600)

    def test_different_component(self):
        mark_alerted("evil", "critical", 3600)
        assert not is_rate_limited("other", "critical", 3600)

    def test_different_threshold_bucket(self):
        mark_alerted("evil", "critical", 3600)
        assert not is_rate_limited("evil", "high", 3600)

    def test_zero_cooldown(self):
        mark_alerted("evil", "critical", 0)
        assert not is_rate_limited("evil", "critical", 0)

    @pytest.mark.asyncio
    async def test_maybe_alert_rate_limits_second_call(self):
        job = _job(_finding(Severity.CRITICAL))
        cfg = {
            "alerts_enabled": True,
            "alert_severity_threshold": "critical",
            "alert_cooldown_seconds": 3600,
            "alert_notify_service": "",
            "ha_url": "http://ha:8123",
            "ha_token": "token",
            "mqtt_enabled": False,
        }
        with patch("app.alerts.app_settings.load", return_value=cfg), patch(
            "app.alerts.create_persistent_notification",
            new_callable=AsyncMock,
            return_value=True,
        ) as mock_pn:
            first = await maybe_alert(job)
            second = await maybe_alert(job)
        assert first is not None and "skipped" not in first
        assert second == {"skipped": "rate_limited", "component": "evil"}
        assert mock_pn.await_count == 1


class TestDisabled:
    @pytest.mark.asyncio
    async def test_disabled_noop(self):
        job = _job(_finding(Severity.CRITICAL))
        cfg = {
            "alerts_enabled": False,
            "alert_severity_threshold": "critical",
            "alert_cooldown_seconds": 3600,
            "alert_notify_service": "",
            "ha_url": "http://ha:8123",
            "ha_token": "token",
            "mqtt_enabled": True,
        }
        with patch("app.alerts.app_settings.load", return_value=cfg), patch(
            "app.alerts.create_persistent_notification",
            new_callable=AsyncMock,
        ) as mock_pn, patch("app.report.mqtt.publish_finding_alert") as mock_mqtt:
            result = await maybe_alert(job)
        assert result == {"skipped": "disabled"}
        mock_pn.assert_not_awaited()
        mock_mqtt.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_findings(self):
        job = _job(_finding(Severity.LOW))
        cfg = {
            "alerts_enabled": True,
            "alert_severity_threshold": "critical",
            "alert_cooldown_seconds": 3600,
            "alert_notify_service": "",
            "ha_url": "http://ha:8123",
            "ha_token": "token",
            "mqtt_enabled": False,
        }
        with patch("app.alerts.app_settings.load", return_value=cfg):
            result = await maybe_alert(job)
        assert result == {"skipped": "no_findings"}


class TestMessageFormatting:
    def test_title_and_body(self):
        job = _job(
            _finding(Severity.CRITICAL, category="eval", file="evil.py", line=10),
            _finding(Severity.HIGH, category="shell", file="cmd.py", line=2),
            domain="evil_comp",
        )
        findings = filter_alertable_findings(job.findings, "high")
        title, message = format_alert_message(job, findings)
        assert "evil_comp" in title
        assert "critical" in title
        assert "evil.py:10" in message
        assert "eval" in message
        assert job.repo_url in message

    def test_truncates(self):
        findings = [_finding(Severity.CRITICAL, file=f"f{i}.py", line=i) for i in range(8)]
        job = _job(*findings)
        _title, message = format_alert_message(job, findings, max_items=3)
        assert "...and 5 more" in message

    def test_notification_id(self):
        assert notification_id_for("my_domain") == "ha_sandbox_my_domain"
        assert notification_id_for("weird name!") == "ha_sandbox_weird_name_"

    def test_component_key_prefers_domain(self):
        job = _job(domain="dom", name="Name")
        assert component_key(job) == "dom"


class TestHttpxCalls:
    @pytest.mark.asyncio
    async def test_persistent_notification(self):
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        ok = await create_persistent_notification(
            "http://ha:8123",
            "tok",
            "ha_sandbox_evil",
            "Title",
            "Message",
            client=mock_client,
        )
        assert ok is True
        mock_client.post.assert_awaited_once()
        args, kwargs = mock_client.post.await_args
        assert args[0] == "http://ha:8123/api/services/persistent_notification/create"
        assert kwargs["headers"]["Authorization"] == "Bearer tok"
        assert kwargs["json"]["notification_id"] == "ha_sandbox_evil"

    @pytest.mark.asyncio
    async def test_notify_service(self):
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        ok = await call_notify_service(
            "http://ha:8123",
            "tok",
            "notify.mobile_app_phone",
            "Title",
            "Message",
            client=mock_client,
        )
        assert ok is True
        args, kwargs = mock_client.post.await_args
        assert args[0] == "http://ha:8123/api/services/notify/mobile_app_phone"

    @pytest.mark.asyncio
    async def test_notify_invalid(self):
        mock_client = MagicMock()
        mock_client.post = AsyncMock()
        ok = await call_notify_service(
            "http://ha:8123", "tok", "not-a-service", "T", "M", client=mock_client,
        )
        assert ok is False
        mock_client.post.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_maybe_alert_calls_notify(self):
        job = _job(_finding(Severity.CRITICAL))
        cfg = {
            "alerts_enabled": True,
            "alert_severity_threshold": "critical",
            "alert_cooldown_seconds": 3600,
            "alert_notify_service": "notify.mobile_app_x",
            "ha_url": "http://ha:8123",
            "ha_token": "token",
            "mqtt_enabled": False,
        }
        with patch("app.alerts.app_settings.load", return_value=cfg), patch(
            "app.alerts.create_persistent_notification",
            new_callable=AsyncMock,
            return_value=True,
        ) as mock_pn, patch(
            "app.alerts.call_notify_service",
            new_callable=AsyncMock,
            return_value=True,
        ) as mock_ns:
            result = await maybe_alert(job)
        assert result["persistent_notification"] is True
        assert result["notify_service"] is True
        mock_pn.assert_awaited_once()
        mock_ns.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_ha_failure_nonfatal(self):
        job = _job(_finding(Severity.CRITICAL))
        cfg = {
            "alerts_enabled": True,
            "alert_severity_threshold": "critical",
            "alert_cooldown_seconds": 3600,
            "alert_notify_service": "",
            "ha_url": "http://ha:8123",
            "ha_token": "token",
            "mqtt_enabled": False,
        }
        with patch("app.alerts.app_settings.load", return_value=cfg), patch(
            "app.alerts.create_persistent_notification",
            new_callable=AsyncMock,
            side_effect=RuntimeError("boom"),
        ):
            result = await maybe_alert(job)
        assert result is not None
        assert result.get("persistent_notification") is False
        assert result.get("count") == 1
