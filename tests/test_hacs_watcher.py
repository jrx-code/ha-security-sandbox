"""Unit tests for HACS auto-scan watcher (offline, mocked)."""

import time
from unittest.mock import AsyncMock, patch

import pytest

from app.hacs_watcher import (
    cooldown_key,
    in_cooldown,
    mark_scanned,
    parse_hacs_signal,
    snapshot_diff,
    snapshot_from_installed,
    start,
    stop,
    status,
)


class TestParseHacsSignal:
    """Payloads as HACS sends them on hacs_dispatch_repository
    (hacs/integration, repositories/base.py and base.py)."""

    def test_install(self):
        data = {"id": 1337, "action": "install", "repository": "owner/repo", "repository_id": 1}
        assert parse_hacs_signal(data) == "owner/repo"

    def test_uninstall_is_ignored(self):
        data = {"id": 1337, "action": "uninstall", "repository": "owner/repo", "repository_id": 1}
        assert parse_hacs_signal(data) is None

    def test_registration_is_ignored(self):
        data = {"action": "registration", "repository": "owner/repo", "repository_id": 1}
        assert parse_hacs_signal(data) is None

    def test_empty_refresh_payload_is_ignored(self):
        assert parse_hacs_signal({}) is None
        assert parse_hacs_signal(None) is None

    def test_install_without_repository(self):
        assert parse_hacs_signal({"action": "install"}) is None


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


class TestSubscription:
    @pytest.mark.asyncio
    async def test_subscribes_to_the_hacs_dispatcher_signal(self):
        """The watcher must use hacs/subscribe, not subscribe_events: HACS never
        puts these on the HA event bus."""
        import json

        import app.hacs_watcher as hw

        sent: list[dict] = []

        class _WS:
            def __init__(self):
                self._in = [
                    json.dumps({"type": "auth_required"}),
                    json.dumps({"type": "auth_ok"}),
                ]

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def send(self, raw):
                msg = json.loads(raw)
                sent.append(msg)
                if msg.get("type") == "hacs/subscribe":
                    self._in.append(json.dumps(
                        {"id": msg["id"], "type": "result", "success": True, "result": None}
                    ))

            async def recv(self):
                if self._in:
                    return self._in.pop(0)
                hw._enabled = False  # end the session loop
                raise TimeoutError

        hw._enabled = True
        with patch("websockets.connect", return_value=_WS()), patch(
            "app.scanner.hacs_list.fetch_installed_hacs", AsyncMock(return_value=[])
        ):
            await hw._watch_session("http://supervisor/core", "t")
        hw._enabled = False

        subs = [m for m in sent if m.get("type") == "hacs/subscribe"]
        assert subs == [{"id": subs[0]["id"], "type": "hacs/subscribe",
                         "signal": "hacs_dispatch_repository"}]
        assert not [m for m in sent if m.get("type") == "subscribe_events"]


class TestDefaultScanUsesTheSharedRunner:
    @pytest.mark.asyncio
    async def test_goes_through_run_scan_background(self):
        import app.hacs_watcher as hw

        with patch("app.main._run_scan_background", AsyncMock()) as runner:
            await hw._default_scan("https://github.com/o/r", "o/r", "1.0")
        runner.assert_awaited_once_with("https://github.com/o/r", "o/r", batch_id="hacs_autoscan")


class TestAutoscanDefault:
    def test_off_by_default(self):
        from app.settings import DEFAULTS

        assert DEFAULTS["hacs_autoscan_enabled"] is False
