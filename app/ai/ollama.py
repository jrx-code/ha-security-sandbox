"""AI-powered code review via Ollama or public API."""

import json
import logging
from pathlib import Path

import httpx

from app.models import Finding, ScanJob, Severity

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a security auditor for Home Assistant custom components.
Analyze the provided code and respond with a JSON security report.
Output ONLY valid JSON with this schema:
{"score": number 0-10, "summary": "string", "findings": [{"severity": "critical|high|medium|low", "category": "string", "description": "string", "file": "string"}]}
Score 10 = perfectly safe. Score 0 = critically dangerous.
Be specific about actual issues found in the code provided. Do not invent findings."""


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
        headers["HTTP-Referer"] = "https://ha-sandbox.iwanus.eu"
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
    if "```" in text:
        text = text[:text.index("```")]
    # Find matching braces
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
    return json.loads(text)


async def ai_review(job: ScanJob, repo_path: Path) -> None:
    """Run AI review on the repository using configured provider."""
    cfg = _get_ai_config()
    code_context = _build_code_context(repo_path, cfg.get("max_code_context"))
    static_context = _format_static_findings(job.findings)

    user_prompt = f"""Review this Home Assistant component: {job.name}
Type: {job.manifest.component_type.value if job.manifest else 'unknown'}

{static_context}

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
