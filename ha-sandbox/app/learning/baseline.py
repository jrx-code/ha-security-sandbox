"""L.2 — Baseline / Norm Database.

Computes statistical profiles from accumulated scan data. After enough scans
(configurable threshold, default 20), we know what a "normal" component looks
like — how many findings, what imports are common, typical code size, etc.

Components that deviate significantly from the norm get flagged so the user
knows something unusual is going on (not necessarily bad, but worth attention).
"""

import json
import logging
import math
import sqlite3
from typing import Any

log = logging.getLogger(__name__)

MIN_SAMPLES = 10  # Minimum scans before baseline is meaningful


def compute_baseline(conn: sqlite3.Connection) -> dict[str, Any] | None:
    """Recompute baseline statistics from scan_history + component_fingerprints.

    Returns None if not enough data yet (< MIN_SAMPLES scans).
    """
    rows = conn.execute(
        "SELECT findings_count, score, total_lines, py_files, js_files, network_domain_count "
        "FROM scan_history WHERE score IS NOT NULL"
    ).fetchall()
    if len(rows) < MIN_SAMPLES:
        return None

    metrics = {}
    for col in ("findings_count", "score", "total_lines", "py_files", "js_files", "network_domain_count"):
        values = [r[col] for r in rows if r[col] is not None]
        if not values:
            continue
        n = len(values)
        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / n if n > 1 else 0
        stddev = math.sqrt(variance)
        sorted_vals = sorted(values)
        p95_idx = min(int(n * 0.95), n - 1)
        metrics[col] = {
            "mean": round(mean, 2),
            "stddev": round(stddev, 2),
            "percentile_95": sorted_vals[p95_idx],
            "sample_count": n,
        }

    # Persist to baseline_stats table
    for metric_name, stats in metrics.items():
        conn.execute(
            "INSERT OR REPLACE INTO baseline_stats (metric, mean, stddev, percentile_95, sample_count, updated_at) "
            "VALUES (?, ?, ?, ?, ?, datetime('now'))",
            (metric_name, stats["mean"], stats["stddev"], stats["percentile_95"], stats["sample_count"]),
        )
    conn.commit()
    return metrics


def check_deviations(conn: sqlite3.Connection, fingerprint: dict, score: float | None,
                     findings_count: int) -> list[dict]:
    """Check if a component deviates from the established baseline.

    Returns a list of deviation alerts (may be empty).
    """
    rows = conn.execute("SELECT metric, mean, stddev, percentile_95 FROM baseline_stats").fetchall()
    if not rows:
        return []

    baseline = {r["metric"]: dict(r) for r in rows}
    alerts = []

    def _check(metric: str, value: float, label: str) -> None:
        if metric not in baseline:
            return
        b = baseline[metric]
        if b["stddev"] == 0:
            return
        z = abs(value - b["mean"]) / b["stddev"]
        if z > 2.0:  # More than 2 standard deviations
            direction = "above" if value > b["mean"] else "below"
            alerts.append({
                "metric": metric,
                "label": label,
                "value": value,
                "mean": b["mean"],
                "stddev": b["stddev"],
                "z_score": round(z, 1),
                "direction": direction,
            })

    _check("findings_count", findings_count, "Total findings")
    if score is not None:
        _check("score", score, "AI safety score")
    _check("total_lines", fingerprint.get("total_lines", 0), "Code size (lines)")
    _check("network_domain_count", len(fingerprint.get("network_domains", [])), "External domains")

    return alerts
