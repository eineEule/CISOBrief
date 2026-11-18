"""
One place for every AI call, so any OpenAI-compatible provider works:

  AI off (default)   AI_BASE_URL=  AI_API_KEY=            briefs still build, minus the written sections
  Local, free        AI_BASE_URL=http://ollama:11434/v1   AI_MODEL=qwen2.5:7b   (docker compose --profile local-ai)
  Google Gemini      AI_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai/  AI_API_KEY=...  (free tier)
  OpenAI             AI_BASE_URL=  AI_API_KEY=sk-...       AI_MODEL=gpt-4.1-mini
"""
import json
import logging
import re
from typing import Dict, Tuple
from urllib.parse import urlparse

from django.conf import settings

logger = logging.getLogger(__name__)


def enabled() -> bool:
    return bool(settings.AI_API_KEY or settings.AI_BASE_URL)


def provider_label() -> str:
    url = (settings.AI_BASE_URL or "").lower()
    if not url:
        return "OpenAI" if settings.AI_API_KEY else "off"
    host = urlparse(url).hostname or url
    if "googleapis.com" in host:
        return "Google Gemini"
    if "openai.com" in host:
        return "OpenAI"
    if "ollama" in host or ":11434" in url:
        return "Ollama (local)"
    if host in ("localhost", "127.0.0.1", "host.docker.internal"):
        return f"local server ({host})"
    return host


def _client():
    from openai import OpenAI

    return OpenAI(
        api_key=settings.AI_API_KEY or "not-needed",  # local servers ignore the key, the SDK still wants one
        base_url=settings.AI_BASE_URL or None,
        timeout=settings.AI_TIMEOUT,
        max_retries=3,  # the SDK backs off between tries; covers brief provider hiccups (5xx/429)
    )


def _repair(text: str) -> str:
    """Fix the slips small models make: smart quotes, trailing commas, stray control characters."""
    text = text.replace("\u201c", '"').replace("\u201d", '"').replace("\u2018", "'").replace("\u2019", "'")
    text = re.sub(r",\s*([}\]])", r"\1", text)                 # trailing commas
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", text)    # control chars JSON forbids
    return text


def _parse_json(text: str) -> Dict:
    """Accept clean JSON, ```json fenced JSON, or JSON with chatter around it (common with small models)."""
    text = (text or "").strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.S)
    if fenced:
        text = fenced.group(1)
    start, end = text.find("{"), text.rfind("}")
    candidates = [text] + ([text[start:end + 1]] if start != -1 and end > start else [])
    for c in candidates:
        for attempt in (c, _repair(c)):
            try:
                data = json.loads(attempt)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict):
                return data
    raise ValueError("model reply had no valid JSON object")


def friendly_error(e) -> str:
    name = type(e).__name__
    where = provider_label()
    hints = {
        "AuthenticationError": f"{where} rejected the API key",
        "PermissionDeniedError": f"this key can't use model '{settings.AI_MODEL}'",
        "NotFoundError": f"model '{settings.AI_MODEL}' not found on {where}"
                         + (" — pull it first: docker compose exec ollama ollama pull " + settings.AI_MODEL if "Ollama" in where else ""),
        "RateLimitError": f"{where} rate limit or quota reached",
        "InternalServerError": f"{where} had a temporary server error (retried 3 times) — the next run usually works",
        "APITimeoutError": f"{where} took longer than {settings.AI_TIMEOUT}s (raise AI_TIMEOUT for slow local models)",
        "APIConnectionError": f"couldn't reach {where} at {settings.AI_BASE_URL or 'api.openai.com'}"
                              + (" — is the Ollama container running? docker compose --profile local-ai up -d" if "Ollama" in where else ""),
    }
    if isinstance(e, (ValueError, json.JSONDecodeError)):
        return f"{where} didn't return valid JSON (try a larger model)"
    return hints.get(name, f"{where}: {name}")


def chat_json(system: str, user: str, temperature: float = 0.2) -> Tuple[Dict, str]:
    """Returns (data, error). data is {} when anything fails; error is a short human-readable reason."""
    if not enabled():
        return {}, "no AI provider configured"
    try:
        import openai

        client = _client()
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        kwargs = {"model": settings.AI_MODEL, "temperature": temperature, "max_tokens": settings.AI_MAX_TOKENS}
        try:
            resp = client.chat.completions.create(messages=messages, response_format={"type": "json_object"}, **kwargs)
            json_mode = True
        except openai.BadRequestError as e:
            # Some OpenAI-compatible servers reject response_format; the prompt already demands JSON.
            if "response_format" not in str(e) and "json" not in str(e).lower():
                raise
            resp = client.chat.completions.create(messages=messages, **kwargs)
            json_mode = False
        reply = resp.choices[0].message.content or ""
        try:
            return _parse_json(reply), ""
        except ValueError:
            finish = getattr(resp.choices[0], "finish_reason", "")
            logger.warning("AI reply was not valid JSON (finish_reason=%s, %d chars). Start: %r",
                           finish, len(reply), reply[:300])
        # One more try: hand the reply back and ask for clean JSON only.
        retry = messages + [{"role": "assistant", "content": reply[:6000]},
                            {"role": "user", "content": "That was not valid JSON (it may have been cut off). "
                                                        "Reply again with ONLY the complete JSON object, shorter if needed."}]
        extra = {"response_format": {"type": "json_object"}} if json_mode else {}
        resp = client.chat.completions.create(messages=retry, **kwargs, **extra)
        return _parse_json(resp.choices[0].message.content), ""
    except Exception as e:  # noqa: BLE001 - every failure becomes a visible, non-fatal status
        logger.error("AI call failed (%s, %s): %s", provider_label(), settings.AI_MODEL, e)
        return {}, friendly_error(e)
