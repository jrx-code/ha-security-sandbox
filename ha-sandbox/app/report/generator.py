"""Generate JSON, CSV, and HTML reports from scan jobs."""

import csv
import io
import json
import logging
from datetime import datetime
from pathlib import Path

from app.config import settings
from app.models import ScanJob

log = logging.getLogger(__name__)


def generate_report(job: ScanJob, learning_data: dict | None = None) -> Path:
    """Generate and save JSON report for a scan job.

    learning_data (optional): dict with keys fingerprint_changes, deviations, fingerprint
    """
    report_dir = Path(settings.reports_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    report = {
        "id": job.id,
        "name": job.name,
        "repo_url": job.repo_url,
        "status": job.status.value,
        "created_at": job.created_at.isoformat(),
        "completed_at": datetime.now().isoformat(),
        "component_type": job.manifest.component_type.value if job.manifest else "unknown",
        "ai_score": job.ai_score,
        "ai_summary": job.ai_summary,
        "score_label": job.score_label(),
        "stats": {
            "critical": job.critical_count,
            "high": job.high_count,
            "total_findings": len(job.findings),
        },
        "findings": [
            {
                "severity": f.severity.value,
                "category": f.category,
                "file": f.file,
                "line": f.line,
                "code": f.code,
                "description": f.description,
            }
            for f in job.findings
        ],
    }

    if learning_data:
        report["learning"] = learning_data

    filepath = report_dir / f"{job.id}.json"
    filepath.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    log.info("Report saved: %s", filepath)
    return filepath


def load_all_reports() -> list[dict]:
    """Load all existing reports for the dashboard."""
    report_dir = Path(settings.reports_dir)
    if not report_dir.exists():
        return []
    reports = []
    for f in sorted(report_dir.glob("*.json"), reverse=True):
        try:
            reports.append(json.loads(f.read_text()))
        except (json.JSONDecodeError, OSError):
            continue
    return reports


def load_report(report_id: str) -> dict | None:
    """Load a single report by ID."""
    report_dir = Path(settings.reports_dir)
    filepath = report_dir / f"{report_id}.json"
    if filepath.exists():
        try:
            return json.loads(filepath.read_text())
        except (json.JSONDecodeError, OSError):
            return None
    return None


def export_csv(report: dict) -> str:
    """Export findings as CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["severity", "category", "file", "line", "description", "code"])
    for f in report.get("findings", []):
        writer.writerow([
            f.get("severity", ""),
            f.get("category", ""),
            f.get("file", ""),
            f.get("line", ""),
            f.get("description", ""),
            f.get("code", ""),
        ])
    return output.getvalue()


def export_html(report: dict) -> str:
    """Export report as standalone printable HTML (can be saved as PDF)."""
    name = report.get("name", "Unknown")
    repo = report.get("repo_url", "")
    score = report.get("ai_score")
    label = report.get("score_label", "N/A")
    summary = report.get("ai_summary", "")
    stats = report.get("stats", {})
    findings = report.get("findings", [])
    completed = report.get("completed_at", "")

    severity_colors = {
        "critical": "#dc2626", "high": "#ea580c",
        "medium": "#ca8a04", "low": "#2563eb", "info": "#6b7280",
    }

    rows = []
    for f in findings:
        sev = f.get("severity", "info")
        color = severity_colors.get(sev, "#6b7280")
        rows.append(
            f'<tr>'
            f'<td style="color:{color};font-weight:bold">{sev.upper()}</td>'
            f'<td>{f.get("category", "")}</td>'
            f'<td>{f.get("file", "")}</td>'
            f'<td>{f.get("line", "")}</td>'
            f'<td>{f.get("description", "")}</td>'
            f'<td><code>{f.get("code", "")}</code></td>'
            f'</tr>'
        )

    score_color = "#16a34a" if score and score >= 8 else "#ea580c" if score and score >= 5 else "#dc2626"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Report — {name}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 1100px; margin: 0 auto; padding: 20px; color: #1f2937; }}
  h1 {{ border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; }}
  .meta {{ background: #f9fafb; padding: 12px 16px; border-radius: 8px; margin: 16px 0; }}
  .meta span {{ margin-right: 24px; }}
  .score {{ font-size: 1.5em; font-weight: bold; color: {score_color}; }}
  .summary {{ background: #fffbeb; padding: 12px 16px; border-left: 4px solid #f59e0b; margin: 16px 0; white-space: pre-wrap; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9em; }}
  th {{ background: #f3f4f6; text-align: left; padding: 8px; border-bottom: 2px solid #d1d5db; }}
  td {{ padding: 6px 8px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
  code {{ background: #f3f4f6; padding: 2px 4px; border-radius: 3px; font-size: 0.85em; }}
  @media print {{ body {{ max-width: none; }} .no-print {{ display: none; }} }}
</style>
</head>
<body>
<h1>Security Report: {name}</h1>
<div class="meta">
  <span><strong>Repository:</strong> {repo}</span>
  <span><strong>Scanned:</strong> {completed[:19] if completed else 'N/A'}</span><br>
  <span><strong>Score:</strong> <span class="score">{score if score is not None else 'N/A'}/10 ({label})</span></span>
  <span><strong>Findings:</strong> {stats.get('total_findings', 0)} total, {stats.get('critical', 0)} critical, {stats.get('high', 0)} high</span>
</div>
{"<div class='summary'><strong>AI Summary:</strong> " + summary + "</div>" if summary else ""}
<h2>Findings ({len(findings)})</h2>
<table>
<thead><tr><th>Severity</th><th>Category</th><th>File</th><th>Line</th><th>Description</th><th>Code</th></tr></thead>
<tbody>
{''.join(rows) if rows else '<tr><td colspan="6" style="text-align:center;color:#6b7280">No findings</td></tr>'}
</tbody>
</table>
<p style="color:#9ca3af;font-size:0.8em;margin-top:24px">Generated by HA Sandbox Analyzer</p>
</body>
</html>"""
