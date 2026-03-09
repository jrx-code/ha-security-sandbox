"""L.4 — Reputation Score.

Tracks a component's safety score across versions/scans and provides
trend indicators (improving, stable, declining). Components that consistently
score well build reputation; sudden drops are flagged.
"""

import logging
import sqlite3
from typing import Any

log = logging.getLogger(__name__)


def record_scan(conn: sqlite3.Connection, domain: str, repo_url: str,
                version: str, score: float | None, findings_count: int,
                fingerprint_hash: str = "", total_lines: int = 0,
                py_files: int = 0, js_files: int = 0,
                network_domain_count: int = 0) -> None:
    """Record a completed scan in history for reputation tracking."""
    conn.execute(
        "INSERT INTO scan_history "
        "(domain, repo_url, version, score, findings_count, fingerprint_hash, "
        " total_lines, py_files, js_files, network_domain_count, scanned_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
        (domain, repo_url, version, score, findings_count, fingerprint_hash,
         total_lines, py_files, js_files, network_domain_count),
    )
    conn.commit()


def get_reputation(conn: sqlite3.Connection, domain: str = "",
                   repo_url: str = "") -> dict[str, Any] | None:
    """Get reputation data for a component.

    Returns dict with: scans_count, avg_score, trend, last_score, score_history
    Or None if no scan history exists.
    """
    if domain:
        rows = conn.execute(
            "SELECT score, findings_count, version, scanned_at FROM scan_history "
            "WHERE domain = ? ORDER BY scanned_at ASC", (domain,)
        ).fetchall()
    elif repo_url:
        rows = conn.execute(
            "SELECT score, findings_count, version, scanned_at FROM scan_history "
            "WHERE repo_url = ? ORDER BY scanned_at ASC", (repo_url,)
        ).fetchall()
    else:
        return None

    if not rows:
        return None

    scores = [r["score"] for r in rows if r["score"] is not None]
    if not scores:
        return {"scans_count": len(rows), "avg_score": None, "trend": "unknown",
                "last_score": None, "score_history": []}

    avg_score = round(sum(scores) / len(scores), 1)
    last_score = scores[-1]
    trend = _compute_trend(scores)

    return {
        "scans_count": len(rows),
        "avg_score": avg_score,
        "last_score": last_score,
        "trend": trend,
        "trend_symbol": {"improving": "\u2191", "stable": "\u2192", "declining": "\u2193"}.get(trend, "?"),
        "score_history": [
            {"score": r["score"], "findings": r["findings_count"],
             "version": r["version"], "date": r["scanned_at"]}
            for r in rows
        ],
    }


def _compute_trend(scores: list[float]) -> str:
    """Determine trend from score history.

    Uses the last 3 scores (or fewer if not enough data).
    """
    if len(scores) < 2:
        return "stable"

    recent = scores[-3:] if len(scores) >= 3 else scores
    first, last = recent[0], recent[-1]
    diff = last - first

    if diff > 0.5:
        return "improving"
    if diff < -0.5:
        return "declining"
    return "stable"


def get_all_reputations(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Get reputation summary for all known components."""
    domains = conn.execute(
        "SELECT DISTINCT domain, repo_url FROM scan_history WHERE domain != '' "
        "ORDER BY domain"
    ).fetchall()

    results = []
    for row in domains:
        rep = get_reputation(conn, domain=row["domain"])
        if rep:
            rep["domain"] = row["domain"]
            rep["repo_url"] = row["repo_url"]
            results.append(rep)
    return results
