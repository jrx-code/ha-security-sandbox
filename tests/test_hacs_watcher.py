"""Unit tests for HACS auto-scan watcher (offline, mocked)."""

import time
from unittest.mock import AsyncMock, patch

import pytest

from app.hacs_watcher import (
    cooldown_key,
    in_cooldown,
    mark_scanned,
    parse_hacs_event,
    snapshot_diff,
    snapshot_from_installed,
    start,
    stop,
    status,
)


class TestParseHacsEvent:
    def test_hacs_repository_install(self):
        event = {
            "event_type": "hacs/repository",
            "data": {
                "action": "download",
                "repository": "custom-components/awesome",
                "installed_version": "1.0.0",
            },
        }
        parsed = parse_hacs_event(event)
        assert parsed is not None
        assert parsed["full_name"] == "custom-components/awesome"
        assert parsed["version"] == "1.0.0"
        assert parsed["action"] == "download"

    def test_hacs_repository_underscore_event(self):
        event = {
            "event_type": "hacs_repository",
            "data": {
                "action": "update",
                "repository": {
                    "full_name": "owner/card",
                    "installed_version": "2.1.0",
                },
            },
        }
        parsed = parse_hacs_event(event)
        assert parsed is not None
        assert parsed["full_name"] == "owner/card"
        assert parsed["version"] == "2.1.0"
        assert parsed["action"] == "update"

    def test_ignores_non_scan_action(self):
        event = {
            "event_type": "hacs/repository",
            "data": {"action": "remove", "repository": "owner/gone"},
        }
        assert parse_hacs_event(event) is None

    def test_thin_payload_with_repo_on_known_event(self):
        event = {
            "event_type": "hacs/repository",
            "data": {"full_name": "owner/thin"},
        }
        parsed = parse_hacs_event(event)
        assert parsed is not None
        assert parsed["full_name"] == "owner/thin"
        assert parsed["action"] == "update"

    def test_missing_repo_returns_none(self):
        assert parse_hacs_event({"event_type": "hacs/repository", "data": {}}) is None


class TestSnapshotDiff:
    def test_new_install(self):
        old = {"a/b": "1.0.0"}
        new = {"a/b": "1.0.0", "c/d": "0.1.0"}
        changes = snapshot_diff(old, new)
        assert changes == [{"full_name": "c/d", "version": "0.1.0", "action": "install"}]

    def test_version_bump(self):
        old = {"a/b": "1.0.0"}
        new = {"a/b": "1.1.0"}
        changes = snapshot_diff(old, new)
        assert changes == [{"full_name": "a/b", "version": "1.1.0", "action": "update"}]

    def test_no_change(self):
        snap = {"a/b": "1.0.0"}
        assert snapshot_diff(snap, snap) == []

    def test_snapshot_from_installed_uses_full_name(self):
        installed = [
            {"full_name": "x/y", "repository": "x/y", "installed_version": "3.0"},
            {"repository": "only/repo", "installed_version": "1"},
        ]
        snap = snapshot_from_installed(installed)
        assert snap == {"x/y": "3.0", "only/repo": "1"}


class TestCooldown:
    def test_cooldown_skips_duplicate(self):
        store: dict[str, float] = {}
        now = 1000.0
        mark_scanned("o/r", "1.0", store, now=now)
        assert in_cooldown("o/r", "1.0", store, now=now + 60, cooldown=600)
        assert not in_cooldown("o/r", "1.0", store, now=now + 601, cooldown=600)

    def test_different_version_not_in_cooldown(self):
        store: dict[str, float] = {}
        mark_scanned("o/r", "1.0", store, now=100.0)
        assert not in_cooldown("o/r", "2.0", store, now=110.0, cooldown=600)

    def test_cooldown_key(self):
        assert cooldown_key("a/b", "1") == "a/b@1"
        assert cooldown_key("a/b", "") == "a/b@unknown"


class TestWatcherLifecycle:
    @pytest.mark.asyncio
    async def test_disabled_watcher_does_nothing(self):
        stop()
        cb = AsyncMock()
        # Ensure loop is not running with our callback while disabled
        assert status()["enabled"] is False
        assert status()["running"] is False

        # start then immediately stop - callback must not be invoked by idle token path
        with patch("app.config.settings.ha_token", ""):
            start(scan_callback=cb)
            assert status()["enabled"] is True
            await asyncio_sleep_brief()
            stop()
        cb.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_start_stop_status(self):
        stop()
        with patch("app.config.settings.ha_token", ""):
            start()
            st = status()
            assert st["enabled"] is True
            assert st["running"] is True
            stop()
            st = status()
            assert st["enabled"] is False


async def asyncio_sleep_brief():
    import asyncio
    await asyncio.sleep(0.05)
