"""Tests for SQLite job persistence."""

from unittest.mock import patch

import pytest

from app import storage


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path):
    """Use isolated DB for each test."""
    db_path = tmp_path / "test.db"
    with patch.object(storage, "DB_PATH", db_path):
        storage._conn = None  # reset connection
        storage.init()
        yield
        storage.close()


class TestStorage:
    def test_create_and_get_active(self):
        storage.create_job("job1", "test-scan", "https://github.com/test/repo")
        active = storage.get_active_jobs()
        assert "job1" in active
        assert active["job1"]["status"] == "running"
        assert active["job1"]["name"] == "test-scan"

    def test_complete_job(self):
        storage.create_job("job2", "scan2", "https://github.com/test/repo2")
        storage.complete_job("job2")
        active = storage.get_active_jobs()
        assert "job2" not in active

    def test_fail_job(self):
        storage.create_job("job3", "scan3", "https://github.com/test/repo3")
        storage.fail_job("job3", "something broke")
        active = storage.get_active_jobs()
        assert "job3" not in active  # failed jobs not in active

    def test_scans_total(self):
        assert storage.get_scans_total() == 0
        storage.create_job("a", "s1", "url1")
        storage.complete_job("a")
        assert storage.get_scans_total() == 1
        storage.create_job("b", "s2", "url2")
        storage.complete_job("b")
        assert storage.get_scans_total() == 2

    def test_init_marks_stale_running_as_failed(self, tmp_path):
        storage.create_job("stale", "stale-scan", "url")
        # Re-init simulates restart
        storage.init()
        active = storage.get_active_jobs()
        assert "stale" not in active

    def test_cleanup_old(self):
        storage.create_job("old", "old-scan", "url")
        storage.complete_job("old")
        # With days=0, everything completed should be cleaned
        deleted = storage.cleanup_old(days=0)
        assert deleted >= 1

    def test_multiple_active_jobs(self):
        storage.create_job("j1", "scan-a", "url-a")
        storage.create_job("j2", "scan-b", "url-b")
        active = storage.get_active_jobs()
        assert len(active) == 2

    def test_replace_existing_job(self):
        storage.create_job("same", "first", "url1")
        storage.create_job("same", "second", "url2")
        active = storage.get_active_jobs()
        assert active["same"]["name"] == "second"
