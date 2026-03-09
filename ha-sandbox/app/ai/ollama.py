"""AI-powered code review via Ollama or public API."""

import json
import logging
from pathlib import Path

import httpx

from app.models import Finding, ScanJob, Severity

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a security auditor specializing in Home Assistant custom components (integrations and Lovelace cards installed via HACS).

## Scoring rubric

Rate the component 0–10 using this rubric:
- 9-10: No security issues. Standard HA patterns, no dangerous APIs.
- 7-8: Minor concerns (e.g., localStorage usage, telemetry, broad entity access) but no exploitable vulnerabilities.
- 5-6: Moderate risks (e.g., innerHTML assignment, dynamic service calls, network requests to external servers without user visibility).
- 3-4: Significant risks (e.g., eval/exec usage, shell commands with user input, unrestricted file access, data exfiltration patterns).
- 0-2: Critical — actively dangerous (e.g., arbitrary code execution, credential theft, backdoor functionality).

## Output format

Respond with ONLY valid JSON matching this schema:
{
  "score": <number 0-10>,
  "confidence": <number 0-100, your confidence in the score>,
  "summary": "<2-3 sentence summary of security posture>",
  "findings": [
    {
      "severity": "critical|high|medium|low",
      "category": "<e.g. code_injection, xss, data_exfiltration, command_execution>",
      "description": "<specific description of what the code does and why it's risky>",
      "file": "<relative file path>",
      "confidence": <number 0-100, confidence this is a real issue>
    }
  ]
}

## Rules

- Only report issues actually present in the provided code. Do NOT invent findings.
- If static analysis already flagged an issue, confirm or dismiss it — don't just repeat it.
- For each finding, explain the specific code pattern you found and why it matters.
- Set confidence lower when you're uncertain (e.g., the code pattern might be safe in context).
- HA integrations legitimately use hass.services.call, hass.states.set, network requests — these are normal. Only flag when the usage pattern is unsafe.

## Example

For a component that uses eval() with user config data:
{
  "score": 2,
  "confidence": 95,
  "summary": "Critical: Component passes user configuration directly to eval(), enabling arbitrary code execution on the HA host.",
  "findings": [
    {
      "severity": "critical",
      "category": "code_injection",
      "description": "config_entry.data['expression'] is passed directly to eval() in sensor.py:45, allowing arbitrary Python execution",
      "file": "custom_components/evil/sensor.py",
      "confidence": 98
    }
  ]
}"""


def _get_ai_config() -> dict:
    """Get current AI configuration from settings."""
    from app import settings as s
    cfg = s.load()
    return cfg


def _build_code_context(repo_path: Path, max_chars: int | None = None) -> str:
    """Build a code context string from repo files, staying within token limits."""
    if max_chars is None:
        from app import settings as s
        max_chars = s.get("max_code_context", 15000)

    parts = []
    total = 0
    extensions = {".py", ".js", ".ts", ".yaml", ".yml", ".json"}

    priority_files = []
    other_files = []
    for f in repo_path.rglob("*"):
        if not f.is_file() or f.suffix not in extensions:
            continue
        rel = str(f.relative_to(repo_path))
        if any(skip in rel.split("/") for skip in ["node_modules", ".venv", "__pycache__", "tests", ".git"]):
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
    if not findings:
        return "No static analysis findings."
    lines = ["Static analysis findings:"]
    for f in findings[:20]:
        lines.append(f"- [{f.severity.value}] {f.category}: {f.description} ({f.file}:{f.line})")
    return "\n".join(lines)


async def _review_ollama(cfg: dict, user_prompt: str) -> dict:
    """2-step Ollama review: analysis -> JSON conversion."""
    url = cfg.get("ollama_url", "http://ollama:11434")
    model = cfg.get("ollama_model", "gemma3:12b")
    timeout = float(cfg.get("ai_timeout", 300))

    async with httpx.AsyncClient(timeout=timeout) as client:
        # Step 1: analysis
        resp1 = await client.post(f"{url}/api/chat", json={
            "model": model,
            "messages": [{"role": "user", "content": user_prompt + "\n\nList security issues found."}],
            "stream": False,
            "options": {"temperature": 0.1, "num_predict": 1500},
        })
        resp1.raise_for_status()
        analysis = resp1.json().get("message", {}).get("content", "")
        log.info("Ollama step 1: %d chars", len(analysis))

        # Step 2: JSON conversion
        json_prompt = f"""Convert this security analysis into a JSON object with exactly these fields:
- score: a number from 0 to 10 (10=safe, 0=dangerous)
- summary: a 1-2 sentence summary
- findings: array of objects with severity (critical/high/medium/low), category, description, file

Analysis to convert:
{analysis[:3000]}

Return ONLY the JSON object."""

        resp2 = await client.post(f"{url}/api/generate", json={
            "model": model,
            "prompt": json_prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.0, "num_predict": 1500},
        })
        resp2.raise_for_status()
        return {"text": resp2.json().get("response", ""), "analysis": analysis}


async def _review_public_api(cfg: dict, user_prompt: str) -> dict:
    """Single-call review via OpenRouter/OpenAI-compatible API."""
    api_url = cfg.get("public_url", "https://openrouter.ai/api/v1")
    api_key = cfg.get("public_api_key", "")
    model = cfg.get("public_model", "google/gemma-3-27b-it")
    timeout = float(cfg.get("ai_timeout", 300))

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    if "openrouter" in api_url:
        headers["HTTP-Referer"] = "https://github.com/jrx-code/ha-security-sandbox"
        headers["X-Title"] = "HA Sandbox Analyzer"

    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.1,
        "max_tokens": 2000,
        "response_format": {"type": "json_object"},
    }

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(f"{api_url}/chat/completions", json=body, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        content = data["choices"][0]["message"]["content"]
        log.info("Public API response: %d chars, model=%s", len(content), model)
        return {"text": content, "analysis": ""}


def _parse_json_response(text: str) -> dict:
    """Extract and parse JSON from AI response."""
    text = text.strip()
    # Extract content from markdown code blocks
    if "```" in text:
        import re
        m = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
        if m:
            text = m.group(1).strip()
    # Find first { and matching }
    start = text.find("{")
    if start == -1:
        return json.loads(text)  # will raise JSONDecodeError
    depth = 0
    for i in range(start, len(text)):
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])
    return json.loads(text[start:])


async def ai_review(job: ScanJob, repo_path: Path) -> None:
    """Run AI review on the repository using configured provider."""
    cfg = _get_ai_config()
    code_context = _build_code_context(repo_path, cfg.get("max_code_context"))
    static_context = _format_static_findings(job.findings)

    comp_type = job.manifest.component_type.value if job.manifest else "unknown"
    user_prompt = f"""Review this Home Assistant custom component for security issues.

Component: {job.name}
Type: {comp_type}
Repository: {job.repo_url}

{static_context}

The static analyzer flagged the issues above. Review the actual code below and:
1. Confirm or dismiss each static finding based on context
2. Identify any additional security issues the static analyzer missed
3. Score the component using the rubric (0-10)
4. Set confidence levels for each finding and the overall score

Code:
{code_context}"""

    try:
        provider = cfg.get("ai_provider", "ollama")
        if provider == "public" and cfg.get("public_api_key"):
            result = await _review_public_api(cfg, user_prompt)
        else:
            result = await _review_ollama(cfg, user_prompt)

        data = _parse_json_response(result["text"])
        job.ai_score = min(10.0, max(0.0, float(data.get("score", 5.0))))
        confidence = data.get("confidence", 50)
        summary = data.get("summary", "")
        if confidence < 100:
            summary += f" (AI confidence: {confidence}%)"
        job.ai_summary = summary

        for f in data.get("findings", []):
            sev = f.get("severity", "medium")
            try:
                severity = Severity(sev)
            except ValueError:
                severity = Severity.MEDIUM
            finding_confidence = f.get("confidence", 50)
            desc = f.get("description", "")
            if finding_confidence < 80:
                desc += f" [confidence: {finding_confidence}%]"
            job.findings.append(Finding(
                severity=severity,
                category=f.get("category", "ai_review"),
                file=f.get("file", ""),
                description=desc,
                code="[AI finding]",
            ))

    except httpx.HTTPError as e:
        log.error("AI request failed: %s", e)
        job.ai_summary = f"AI review failed: {e}"
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        log.error("Failed to parse AI response: %s", e)
        job.ai_summary = f"AI review parse error: {e}"


async def test_ollama(url: str, model: str) -> dict:
    """Test Ollama connection and model availability."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{url}/api/tags")
            resp.raise_for_status()
            models = [m["name"] for m in resp.json().get("models", [])]
            available = model in models
            return {"ok": True, "models": models, "model_available": available}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def test_public_api(url: str, api_key: str, model: str) -> dict:
    """Test public API connection."""
    try:
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        body = {
            "model": model,
            "messages": [{"role": "user", "content": "Say OK"}],
            "max_tokens": 5,
        }
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(f"{url}/chat/completions", json=body, headers=headers)
            resp.raise_for_status()
            return {"ok": True, "response": resp.json()["choices"][0]["message"]["content"]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def list_ollama_models(url: str) -> list[str]:
    """Fetch available models from Ollama."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{url}/api/tags")
            resp.raise_for_status()
            return [m["name"] for m in resp.json().get("models", [])]
    except Exception:
        return []
