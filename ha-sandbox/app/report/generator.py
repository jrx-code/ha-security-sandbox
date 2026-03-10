"""Generate JSON, CSV, HTML, and PDF reports from scan jobs."""

import csv
import html as html_mod
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

    e = html_mod.escape
    rows = []
    for f in findings:
        sev = f.get("severity", "info")
        color = severity_colors.get(sev, "#6b7280")
        rows.append(
            f'<tr>'
            f'<td style="color:{color};font-weight:bold">{e(sev.upper())}</td>'
            f'<td>{e(f.get("category", ""))}</td>'
            f'<td>{e(f.get("file", ""))}</td>'
            f'<td>{e(str(f.get("line", "")))}</td>'
            f'<td>{e(f.get("description", ""))}</td>'
            f'<td><code>{e(f.get("code", ""))}</code></td>'
            f'</tr>'
        )

    name = e(name)
    repo = e(repo)
    summary = e(summary)
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


def export_pdf(report: dict) -> bytes:
    """Export report as PDF bytes using fpdf2."""
    from fpdf import FPDF

    name = report.get("name", "Unknown")
    repo = report.get("repo_url", "")
    score = report.get("ai_score")
    label = report.get("score_label", "N/A")
    summary = report.get("ai_summary", "")
    stats = report.get("stats", {})
    findings = report.get("findings", [])
    completed = report.get("completed_at", "")

    severity_colors = {
        "critical": (220, 38, 38), "high": (234, 88, 12),
        "medium": (202, 138, 4), "low": (37, 99, 235), "info": (107, 114, 128),
    }

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Use DejaVu for full Unicode support
    font_dirs = [
        Path("/usr/share/fonts/truetype/dejavu"),   # Debian/Ubuntu
        Path("/usr/share/fonts/dejavu"),             # Alpine (font-dejavu)
        Path("/usr/share/fonts/TTF"),                # Arch
    ]
    font_dir = next((d for d in font_dirs if d.exists()), None)
    if font_dir:
        pdf.add_font("dejavu", style="", fname=str(font_dir / "DejaVuSans.ttf"))
        pdf.add_font("dejavu", style="B", fname=str(font_dir / "DejaVuSans-Bold.ttf"))
        pdf.add_font("dejavu", style="I", fname=str(font_dir / "DejaVuSans-Oblique.ttf"))
        FONT = "dejavu"
    else:
        FONT = "Helvetica"

    def _s(text: str) -> str:
        """Sanitize text for current font (replace Unicode if no Unicode font)."""
        if FONT != "Helvetica":
            return text
        text = text.replace("\u2014", " - ").replace("\u2013", "-")
        text = text.replace("\u2192", "->").replace("\u2190", "<-")
        text = text.replace("\u2022", "*").replace("\u2026", "...")
        text = text.replace("\u2018", "'").replace("\u2019", "'")
        text = text.replace("\u201c", '"').replace("\u201d", '"')
        return text.encode("latin-1", errors="replace").decode("latin-1")

    pdf.add_page()

    # Title
    pdf.set_font(FONT, "B", 18)
    pdf.cell(0, 12, _s(f"Security Report: {name}"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(229, 231, 235)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)

    # Meta
    pdf.set_font(FONT, "", 10)
    pdf.cell(0, 6, _s(f"Repository: {repo}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, _s(f"Scanned: {completed[:19] if completed else 'N/A'}"), new_x="LMARGIN", new_y="NEXT")

    score_r, score_g, score_b = (22, 163, 74) if score and score >= 8 else (234, 88, 12) if score and score >= 5 else (220, 38, 38)
    pdf.set_font(FONT, "B", 14)
    pdf.set_text_color(score_r, score_g, score_b)
    pdf.cell(0, 10, _s(f"Score: {score if score is not None else 'N/A'}/10 ({label})"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)

    pdf.set_font(FONT, "", 10)
    pdf.cell(0, 6, _s(
        f"Findings: {stats.get('total_findings', 0)} total, "
        f"{stats.get('critical', 0)} critical, {stats.get('high', 0)} high"),
        new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # AI Summary
    if summary:
        pdf.set_font(FONT, "B", 11)
        pdf.cell(0, 7, "AI Summary", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font(FONT, "", 9)
        pdf.multi_cell(0, 5, _s(summary))
        pdf.ln(4)

    # Findings
    pdf.set_font(FONT, "B", 12)
    pdf.cell(0, 8, f"Findings ({len(findings)})", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    if not findings:
        pdf.set_font(FONT, "I", 10)
        pdf.cell(0, 8, "No findings", new_x="LMARGIN", new_y="NEXT")
    else:
        for i, f in enumerate(findings):
            sev = f.get("severity", "info")
            r, g, b = severity_colors.get(sev, (107, 114, 128))
            cat = f.get("category", "")
            file = f.get("file", "")
            line = f.get("line", "")
            desc = f.get("description", "")
            code = f.get("code", "")

            # Page break check
            if pdf.get_y() > 260:
                pdf.add_page()

            # Severity + category header line
            pdf.set_font(FONT, "B", 9)
            pdf.set_text_color(r, g, b)
            pdf.cell(20, 5, _s(sev.upper()))
            pdf.set_text_color(80, 80, 80)
            pdf.set_font(FONT, "", 9)
            pdf.cell(0, 5, _s(f"[{cat}]  {file}{(':' + str(line)) if line else ''}"), new_x="LMARGIN", new_y="NEXT")

            # Description
            pdf.set_text_color(0, 0, 0)
            pdf.set_font(FONT, "", 8)
            pdf.multi_cell(0, 4, _s(desc))

            # Code snippet (wrapped to fit page)
            if code:
                pdf.set_font(FONT, "", 7)
                pdf.set_text_color(100, 100, 100)
                pdf.set_x(10)
                pdf.multi_cell(0, 4, _s(code[:120]))

            pdf.set_text_color(0, 0, 0)
            # Separator line
            pdf.set_draw_color(229, 231, 235)
            pdf.line(10, pdf.get_y() + 1, 200, pdf.get_y() + 1)
            pdf.ln(4)

    # Footer
    pdf.ln(4)
    pdf.set_font(FONT, "I", 8)
    pdf.set_text_color(156, 163, 175)
    pdf.cell(0, 5, "Generated by HA Sandbox Analyzer", align="C")

    return pdf.output()
