"""
Ollama client — calls /api/chat with retry and model fallback.

Retry policy:
    - On JSON parse failure: retry once with the same model, appending
      the previous bad output to the prompt ("your previous response was
      not valid JSON, try again")
    - On timeout: switch to fallback model (no retry on fallback)

The client is stateless — instantiate once and reuse across requests.
"""
from __future__ import annotations

import json
import time
from typing import Any

import httpx
import structlog

from shared.config import get_settings

log = structlog.get_logger()

_JSON_RETRY_PROMPT = (
    "\n\nYour previous response was not valid JSON. "
    "Return ONLY a valid JSON object starting with '{'. No prose, no markdown."
)


class OllamaClient:
    """Async Ollama client with retry and model fallback."""

    def __init__(self) -> None:
        settings = get_settings()
        self._base_url = settings.ollama_base_url
        self._primary_model = settings.llm_model
        self._fallback_model = settings.llm_fallback_model
        self._timeout = settings.llm_timeout_seconds
        self._num_ctx = settings.llm_num_ctx
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "OllamaClient":
        settings = get_settings()
        headers = {}
        if settings.ollama_bearer_token:
            headers["Authorization"] = f"Bearer {settings.ollama_bearer_token}"
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers=headers,
            timeout=httpx.Timeout(self._timeout, connect=10.0),
        )
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def extract_stix(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> tuple[list[dict[str, Any]], str, int]:
        """
        Call Ollama and parse STIX objects from the response.

        Returns:
            (stix_objects, model_used, duration_ms)

        On total failure, returns ([], model_used, duration_ms).
        """
        assert self._client is not None, "Client not initialised — use async with"

        # Try primary model
        result, model, duration_ms = await self._call_with_retry(
            model=self._primary_model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )

        if result is not None:
            return result, model, duration_ms

        # Fallback to smaller model on timeout or persistent parse failure
        log.warning(
            "llm_falling_back",
            primary=self._primary_model,
            fallback=self._fallback_model,
        )
        result, model, duration_ms = await self._call_with_retry(
            model=self._fallback_model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_retries=1,  # Only one attempt on fallback
        )

        return result or [], model, duration_ms

    async def _call_with_retry(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        max_retries: int = 2,
    ) -> tuple[list[dict[str, Any]] | None, str, int]:
        """
        Call Ollama with JSON retry logic.

        Returns (objects, model, duration_ms) or (None, model, duration_ms) on failure.
        """
        current_user_prompt = user_prompt
        last_raw: str = ""

        for attempt in range(max_retries):
            start = time.monotonic()
            raw = await self._call_ollama(model, system_prompt, current_user_prompt)
            duration_ms = int((time.monotonic() - start) * 1000)

            if raw is None:
                # Network/timeout error — do not retry
                return None, model, duration_ms

            last_raw = raw
            parsed = _parse_json_response(raw)

            if parsed is not None:
                objects = parsed.get("objects", [])
                if isinstance(objects, list):
                    log.info(
                        "llm_inference_success",
                        model=model,
                        attempt=attempt + 1,
                        objects=len(objects),
                        duration_ms=duration_ms,
                    )
                    return objects, model, duration_ms

            # JSON parse failed — add correction hint and retry
            log.warning(
                "llm_json_parse_failed",
                model=model,
                attempt=attempt + 1,
                raw_prefix=raw[:200],
            )
            current_user_prompt = user_prompt + _JSON_RETRY_PROMPT

        log.error("llm_json_retry_exhausted", model=model, raw_prefix=last_raw[:200])
        return None, model, 0

    async def _call_ollama(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
    ) -> str | None:
        """
        Make a single /api/chat request.
        Returns the assistant message content, or None on error.
        """
        assert self._client is not None

        payload = {
            "model": model,
            "stream": False,
            "options": {
                "num_ctx": self._num_ctx,
                "temperature": 0.1,   # Low temperature for deterministic extraction
                "top_p": 0.9,
            },
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }

        try:
            resp = await self._client.post("/api/chat", json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["message"]["content"]
        except httpx.TimeoutException as exc:
            log.warning("llm_timeout", model=model, error=str(exc))
            return None
        except httpx.HTTPStatusError as exc:
            log.error("llm_http_error", model=model, status=exc.response.status_code)
            return None
        except Exception as exc:
            log.error("llm_unexpected_error", model=model, error=str(exc))
            return None


def _parse_json_response(raw: str) -> dict[str, Any] | None:
    """
    Parse JSON from LLM output, handling common formatting issues.
    Returns the parsed dict, or None if parsing fails.
    """
    text = raw.strip()

    # Strip markdown code fences if present (```json ... ``` or ``` ... ```)
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first line (```json or ```) and last line (```)
        inner = "\n".join(lines[1:])
        if inner.rstrip().endswith("```"):
            inner = inner.rstrip()[:-3].rstrip()
        text = inner.strip()

    # Find the first '{' and last '}' — truncate any surrounding prose
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None

    json_str = text[start : end + 1]

    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        return None
