"""Abstract base class for LLM providers."""
from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod

MAX_JSON_RETRIES = 3
JSON_RETRY_NOTE = (
    "Your previous response was not valid JSON. Return only raw JSON, "
    "no explanation, no markdown."
)

_FENCE_OPEN_RE = re.compile(r"^```[a-zA-Z0-9]*\n?")
_FENCE_CLOSE_RE = re.compile(r"\n?```$")


class BaseLLM(ABC):
    """Common interface implemented by every LLM provider (Ollama, Groq, ...)."""

    @abstractmethod
    def complete(self, prompt: str, system: str) -> str:
        """Return a raw text completion for the given prompt.

        Args:
            prompt: The user-role message to send.
            system: The system-role instruction to send.

        Returns:
            The raw text of the model's response.
        """

    def complete_json(self, prompt: str, system: str) -> dict:
        """Return a parsed JSON dict, retrying up to MAX_JSON_RETRIES times on invalid JSON.

        Each retry re-sends the *original* prompt (not the previous attempt's
        malformed output) with JSON_RETRY_NOTE appended, so retries don't compound.

        Args:
            prompt: The user-role message to send.
            system: The system-role instruction to send.

        Returns:
            The parsed JSON value (typically a dict, but any valid JSON value
            the model returns will be passed through as-is).

        Raises:
            json.JSONDecodeError: If the model still returns invalid JSON after
                MAX_JSON_RETRIES attempts.
        """
        current_prompt = prompt
        last_error: json.JSONDecodeError | None = None

        for _ in range(MAX_JSON_RETRIES):
            raw = self.complete(current_prompt, system)
            cleaned = self._strip_code_fences(raw)
            try:
                return json.loads(cleaned)
            except json.JSONDecodeError as exc:
                last_error = exc
                current_prompt = f"{prompt}\n\n{JSON_RETRY_NOTE}"

        raise last_error

    @staticmethod
    def _strip_code_fences(text: str) -> str:
        """Strip a leading/trailing ``` or ```lang markdown code fence, if present."""
        stripped = text.strip()
        if not stripped.startswith("```"):
            return stripped
        stripped = _FENCE_OPEN_RE.sub("", stripped, count=1)
        stripped = _FENCE_CLOSE_RE.sub("", stripped, count=1)
        return stripped.strip()
