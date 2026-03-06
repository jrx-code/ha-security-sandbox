"""Phase 4: Ollama AI-powered code review."""

import json
import logging
from pathlib import Path

import httpx

from app.config import settings
from app.models import Finding, ScanJob, Severity

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a security auditor for Home Assistant custom components.
Analyze the provided code and respond with a JSON security report.
Output ONLY valid JSON with this schema:
{"score": number 0-10, "summary": "string", "findings": [{"severity": "critical|high|medium|low", "category": "string", "description": "string", "file": "string"}]}
Score 10 = perfectly safe. Score 0 = critically dangerous.
Be specific about actual issues found in the code provided. Do not invent findings."""


def _build_code_context(repo_path: Path, max_chars: int = 15000) -> str:
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
        async with httpx.AsyncClient(timeout=300.0) as client:
            # Step 1: Get analysis in natural language
            resp1 = await client.post(
                f"{settings.ollama_url}/api/chat",
                json={
                    "model": settings.ollama_model,
                    "messages": [
                        {"role": "user", "content": user_prompt + "\n\nList security issues found."},
                    ],
                    "stream": False,
                    "options": {"temperature": 0.1, "num_predict": 1500},
                },
            )
            resp1.raise_for_status()
            analysis = resp1.json().get("message", {}).get("content", "")
            log.info("Step 1 analysis: %d chars", len(analysis))

            # Step 2: Convert to structured JSON using format:json
            json_schema_prompt = f"""Convert this security analysis into a JSON object with exactly these fields:
- score: a number from 0 to 10 (10=safe, 0=dangerous)
- summary: a 1-2 sentence summary
- findings: array of objects with severity (critical/high/medium/low), category, description, file

Analysis to convert:
{analysis[:3000]}

Return ONLY the JSON object."""

            resp2 = await client.post(
                f"{settings.ollama_url}/api/generate",
                json={
                    "model": settings.ollama_model,
                    "prompt": json_schema_prompt,
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0.0, "num_predict": 1500},
                },
            )
            resp2.raise_for_status()
            response_text = resp2.json().get("response", "")

        # Parse JSON from response
        text = response_text.strip()
        # Clean trailing markdown
        if "```" in text:
            text = text[:text.index("```")]
        # Find matching closing brace
        depth = 0
        end = len(text)
        for i, ch in enumerate(text):
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        text = text[:end]

        log.debug("AI JSON (%d chars): %s", len(text), text[:500])
        data = json.loads(text)
        job.ai_score = min(10.0, max(0.0, float(data.get("score", 5.0))))
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
