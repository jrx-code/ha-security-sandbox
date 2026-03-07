"""Generate JSON report from scan job."""

import json
import logging
from datetime import datetime
from pathlib import Path

from app.config import settings
from app.models import ScanJob

log = logging.getLogger(__name__)


def generate_report(job: ScanJob) -> Path:
    """Generate and save JSON report for a scan job."""
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
