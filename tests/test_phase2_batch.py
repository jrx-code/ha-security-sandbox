"""Phase 2.4 tests: Batch scanning + queue."""

import pytest
from unittest.mock import patch, AsyncMock

from app import storage


class TestBatchStorage:
    def test_create_batch(self):
        storage.create_batch("batch001", 3)
        batch = storage.get_batch("batch001")
        assert batch is not None
        assert batch["total"] == 3
        assert batch["completed"] == 0
        assert batch["failed"] == 0
        assert batch["status"] == "running"

    def test_batch_job_done_success(self):
        storage.create_batch("batch002", 2)
        storage.batch_job_done("batch002", success=True)
        batch = storage.get_batch("batch002")
        assert batch["completed"] == 1
        assert batch["status"] == "running"

    def test_batch_job_done_failure(self):
        storage.create_batch("batch003", 2)
        storage.batch_job_done("batch003", success=False)
        batch = storage.get_batch("batch003")
        assert batch["failed"] == 1
        assert batch["status"] == "running"

    def test_batch_auto_complete(self):
        storage.create_batch("batch004", 2)
        storage.batch_job_done("batch004", success=True)
        storage.batch_job_done("batch004", success=True)
        batch = storage.get_batch("batch004")
        assert batch["status"] == "done"
        assert batch["completed_at"] is not None

    def test_batch_complete_mixed(self):
        storage.create_batch("batch005", 3)
        storage.batch_job_done("batch005", success=True)
        storage.batch_job_done("batch005", success=False)
        storage.batch_job_done("batch005", success=True)
        batch = storage.get_batch("batch005")
        assert batch["status"] == "done"
        assert batch["completed"] == 2
        assert batch["failed"] == 1

    def test_get_active_batches(self):
        storage.create_batch("batch006", 5)
        active = storage.get_active_batches()
        assert any(b["id"] == "batch006" for b in active)

    def test_get_batch_not_found(self):
        assert storage.get_batch("nonexistent") is None

    def test_create_job_with_batch_id(self):
        storage.create_job("job001", "test", "https://example.com", batch_id="batch007")
        # Verify job was created (no exception)
        jobs = storage.get_active_jobs()
        assert "job001" in jobs


class TestBatchAPI:
    @pytest.fixture
    def client(self):
        from starlette.testclient import TestClient
        from app.main import app
        return TestClient(app, raise_server_exceptions=False)

    @patch("app.main.run_scan", new_callable=AsyncMock)
    def test_batch_scan_endpoint(self, mock_scan, client):
        mock_scan.return_value = None
        resp = client.post("/api/scan/batch", json={
            "repos": [
                {"url": "https://github.com/user/repo1.git", "name": "Repo1"},
                {"url": "https://github.com/user/repo2.git", "name": "Repo2"},
            ]
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "batch_id" in data
        assert data["total"] == 2

    def test_batch_scan_empty(self, client):
        resp = client.post("/api/scan/batch", json={"repos": []})
        assert resp.status_code == 400

    @patch("app.main.run_scan", new_callable=AsyncMock)
    def test_batch_status_endpoint(self, mock_scan, client):
        storage.create_batch("test_batch", 3)
        resp = client.get("/api/scan/batch/test_batch")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert data["status"] == "running"

    def test_batch_status_not_found(self, client):
        resp = client.get("/api/scan/batch/nonexistent")
        assert resp.status_code == 404

    @patch("app.main.run_scan", new_callable=AsyncMock)
    def test_batch_url_normalization(self, mock_scan, client):
        """Short repo names should be expanded to full GitHub URLs."""
        mock_scan.return_value = None
        resp = client.post("/api/scan/batch", json={
            "repos": [{"url": "user/repo1", "name": "Test"}]
        })
        assert resp.status_code == 200
