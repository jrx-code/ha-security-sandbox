"""Phase 4: Ollama AI-powered code review."""

import json
import logging
from pathlib import Path

import httpx

from app.config import settings
from app.models import Finding, ScanJob, Severity

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a security auditor specializing in Home Assistant custom components.
Analyze the provided code for security issues, data exfiltration, obfuscated code,
unnecessary network calls, and code quality problems.

Respond ONLY with valid JSON in this exact format:
{
  "score": <float 0-10, where 10 is perfectly safe>,
  "summary": "<2-3 sentence summary>",
  "findings": [
    {
      "severity": "<critical|high|medium|low>",
      "category": "<category>",
      "description": "<what and why it's a problem>",
      "file": "<filename if applicable>"
    }
  ]
}"""


def _build_code_context(repo_path: Path, max_chars: int = 30000) -> str:
    """Build a code context string from repo files, staying within token limits."""
    parts = []
    total = 0
    extensions = {".py", ".js", ".ts", ".yaml", ".yml", ".json"}

    # Prioritize manifest and main files
    priority_files = []
    other_files = []
    for f in repo_path.rglob("*"):
        if not f.is_file() or f.suffix not in extensions:
            continue
        rel = str(f.relative_to(repo_path))
        if any(skip in rel for skip in ["node_modules", ".venv", "__pycache__", "test", ".git"]):
            continue
        if any(p in rel for p in ["manifest.json", "hacs.json", "__init__.py", "const.py"]):
            priority_files.append(f)
        else:
            other_files.append(f)

    for f in priority_files + other_files:
        if total >= max_chars:
            break
        try:
            content = f.read_text(errors="replace")
        except OSError:
            continue
        rel = str(f.relative_to(repo_path))
        chunk = f"--- {rel} ---\n{content[:8000]}\n"
        parts.append(chunk)
        total += len(chunk)

    return "\n".join(parts)


def _format_static_findings(findings: list[Finding]) -> str:
    """Format static analysis findings for AI context."""
    if not findings:
        return "No static analysis findings."
    lines = ["Static analysis findings:"]
    for f in findings[:20]:  # Limit to avoid token overflow
        lines.append(f"- [{f.severity.value}] {f.category}: {f.description} ({f.file}:{f.line})")
    return "\n".join(lines)


async def ai_review(job: ScanJob, repo_path: Path) -> None:
    """Run Ollama AI review on the repository."""
    code_context = _build_code_context(repo_path)
    static_context = _format_static_findings(job.findings)

    user_prompt = f"""Review this Home Assistant component: {job.name}
Type: {job.manifest.component_type.value if job.manifest else 'unknown'}

{static_context}

Code:
{code_context}"""

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                f"{settings.ollama_url}/api/generate",
                json={
                    "model": settings.ollama_model,
                    "system": SYSTEM_PROMPT,
                    "prompt": user_prompt,
                    "stream": False,
                    "options": {"temperature": 0.1, "num_predict": 2000},
                },
            )
            resp.raise_for_status()
            result = resp.json()
            response_text = result.get("response", "")

        # Parse JSON from response
        # Handle potential markdown wrapping
        text = response_text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            text = text.rsplit("```", 1)[0]

        data = json.loads(text)
        job.ai_score = float(data.get("score", 5.0))
        job.ai_summary = data.get("summary", "")

        for f in data.get("findings", []):
            sev = f.get("severity", "medium")
            try:
                severity = Severity(sev)
            except ValueError:
                severity = Severity.MEDIUM
            job.findings.append(Finding(
                severity=severity,
                category=f.get("category", "ai_review"),
                file=f.get("file", ""),
                description=f.get("description", ""),
                code="[AI finding]",
            ))

    except httpx.HTTPError as e:
        log.error("Ollama request failed: %s", e)
        job.ai_summary = f"AI review failed: {e}"
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        log.error("Failed to parse Ollama response: %s", e)
        job.ai_summary = f"AI review parse error: {e}"
