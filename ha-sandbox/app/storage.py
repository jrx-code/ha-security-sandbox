"""Job persistence using SQLite."""

import logging
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DB_PATH = Path("/data/sandbox.db")

_conn: sqlite3.Connection | None = None


def _get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is not None:
        return _conn
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    _conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    _conn.row_factory = sqlite3.Row
    _conn.execute("PRAGMA journal_mode=WAL")
    _conn.execute("""
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL DEFAULT '',
            repo_url TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'running',
            created_at TEXT NOT NULL,
            completed_at TEXT,
            error TEXT
        )
    """)
    _conn.commit()
    return _conn


def init():
    """Initialize DB and clean up stale running jobs from previous runs."""
    conn = _get_conn()
    # Ensure batch_id column exists (added in 2.4)
    try:
        conn.execute("SELECT batch_id FROM jobs LIMIT 0")
    except sqlite3.OperationalError:
        conn.execute("ALTER TABLE jobs ADD COLUMN batch_id TEXT DEFAULT ''")
        conn.commit()
    # Ensure batches table exists
    conn.execute("""
        CREATE TABLE IF NOT EXISTS batches (
            id TEXT PRIMARY KEY,
            total INTEGER NOT NULL DEFAULT 0,
            completed INTEGER NOT NULL DEFAULT 0,
            failed INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'running',
            created_at TEXT NOT NULL,
            completed_at TEXT
        )
    """)
    conn.commit()
    # Mark leftover 'running' jobs as failed (crashed)
    conn.execute(
        "UPDATE jobs SET status='failed', error='interrupted by restart' WHERE status='running'"
    )
    conn.execute(
        "UPDATE batches SET status='failed' WHERE status='running'"
    )
    conn.commit()


def create_job(job_id: str, name: str, repo_url: str, batch_id: str = "") -> None:
    conn = _get_conn()
    conn.execute(
        "INSERT OR REPLACE INTO jobs (id, name, repo_url, status, created_at, batch_id) VALUES (?, ?, ?, 'running', ?, ?)",
        (job_id, name, repo_url, datetime.now().isoformat(), batch_id),
    )
    conn.commit()


def update_job(job_id: str, status: str, error: str = "") -> None:
    conn = _get_conn()
    completed = datetime.now().isoformat() if status in ("done", "failed") else None
    conn.execute(
        "UPDATE jobs SET status=?, error=?, completed_at=? WHERE id=?",
        (status, error, completed, job_id),
    )
    conn.commit()


def complete_job(job_id: str) -> None:
    update_job(job_id, "done")


def fail_job(job_id: str, error: str) -> None:
    update_job(job_id, "failed", error)


def get_active_jobs() -> dict[str, dict[str, Any]]:
    """Get currently running jobs as dict compatible with old _active_jobs format."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT id, name, repo_url, status, error FROM jobs WHERE status='running'"
    ).fetchall()
    result = {}
    for row in rows:
        result[row["id"]] = {
            "status": row["status"],
            "name": row["name"],
            "url": row["repo_url"],
        }
        if row["error"]:
            result[row["id"]]["error"] = row["error"]
    return result


def get_scans_total() -> int:
    """Count total completed scans."""
    conn = _get_conn()
    row = conn.execute("SELECT COUNT(*) as cnt FROM jobs WHERE status='done'").fetchone()
    return row["cnt"] if row else 0


def cleanup_old(days: int = 30) -> int:
    """Remove job records older than N days. Returns count deleted."""
    conn = _get_conn()
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    cursor = conn.execute(
        "DELETE FROM jobs WHERE created_at < ? AND status != 'running'", (cutoff,)
    )
    conn.commit()
    deleted = cursor.rowcount
    if deleted:
        log.info("Cleaned up %d old job records", deleted)
    return deleted


def create_batch(batch_id: str, total: int) -> None:
    conn = _get_conn()
    conn.execute(
        "INSERT OR REPLACE INTO batches (id, total, completed, failed, status, created_at) "
        "VALUES (?, ?, 0, 0, 'running', ?)",
        (batch_id, total, datetime.now().isoformat()),
    )
    conn.commit()


def batch_job_done(batch_id: str, success: bool) -> None:
    """Increment completed/failed counter for a batch. Mark done when all jobs finish."""
    conn = _get_conn()
    col = "completed" if success else "failed"
    conn.execute(f"UPDATE batches SET {col} = {col} + 1 WHERE id = ?", (batch_id,))
    row = conn.execute(
        "SELECT total, completed, failed FROM batches WHERE id = ?", (batch_id,)
    ).fetchone()
    if row and (row["completed"] + row["failed"]) >= row["total"]:
        conn.execute(
            "UPDATE batches SET status='done', completed_at=? WHERE id=?",
            (datetime.now().isoformat(), batch_id),
        )
    conn.commit()


def get_batch(batch_id: str) -> dict[str, Any] | None:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM batches WHERE id = ?", (batch_id,)).fetchone()
    if not row:
        return None
    return dict(row)


def get_active_batches() -> list[dict[str, Any]]:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM batches WHERE status='running' ORDER BY created_at DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def close():
    global _conn
    if _conn:
        _conn.close()
        _conn = None
