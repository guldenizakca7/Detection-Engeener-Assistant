"""Mistral AI LLM provider — cloud inference via the Mistral API.

NOTE: verified against the installed mistralai>=1.0.0 SDK (2.7.2 at the time
of writing). `from mistralai import Mistral` does NOT work with this SDK --
the top-level `mistralai` package has an empty namespace. The real client
lives at `mistralai.client.Mistral`. Similarly there is no
`MistralAPIStatusException`; HTTP-level failures raise
`mistralai.client.errors.SDKError`, which carries a `.status_code` int
attribute (429 for rate limiting, 401 for auth) instead of being split into
separate exception classes per status code.
"""
from __future__ import annotations

import os
import time

import httpx
from mistralai.client import Mistral
from mistralai.client.errors import SDKError

from .base import BaseLLM

STAGE_TEMPERATURES = {"stage1": 0.1, "stage2": 0.05}
STAGE_ENV_VARS = {"stage1": "STAGE1_MODEL_MISTRAL", "stage2": "STAGE2_MODEL_MISTRAL"}
STAGE_DEFAULT_MODELS = {"stage1": "mistral-small-latest", "stage2": "mistral-large-latest"}
RATE_LIMIT_BACKOFF_SECONDS = (2, 4, 8)
MAX_TOKENS = 2000
HTTP_TOO_MANY_REQUESTS = 429
HTTP_UNAUTHORIZED = 401


class MistralLLM(BaseLLM):
    """Cloud inference via the Mistral AI API (chat completions)."""

    def __init__(self, model_type: str):
        """Configure this provider for one pipeline stage.

        Args:
            model_type: Either "stage1" or "stage2" -- selects which model
                (STAGE1_MODEL_MISTRAL / STAGE2_MODEL_MISTRAL) and temperature to use.

        Raises:
            ValueError: If model_type is unknown, or MISTRAL_API_KEY isn't set.
        """
        if model_type not in STAGE_TEMPERATURES:
            raise ValueError(f"Unknown model_type '{model_type}', expected 'stage1' or 'stage2'")

        api_key = os.getenv("MISTRAL_API_KEY")
        if not api_key:
            raise ValueError("MISTRAL_API_KEY is not set in .env")

        env_var = STAGE_ENV_VARS[model_type]
        self.model = os.getenv(env_var) or STAGE_DEFAULT_MODELS[model_type]
        self.temperature = STAGE_TEMPERATURES[model_type]
        self.client = Mistral(api_key=api_key)

    def complete(self, prompt: str, system: str) -> str:
        """Send a chat completion request to the Mistral API.

        On a 429 SDKError (rate limit), retries with exponential backoff
        (2s, 4s, 8s) before letting a final attempt's SDKError propagate.

        Args:
            prompt: The user-role message to send.
            system: The system-role instruction to send.

        Returns:
            The raw text of the model's response.

        Raises:
            RuntimeError: If the API key is invalid or Mistral is unreachable.
            mistralai.client.errors.SDKError: If still rate-limited after all
                backoff retries.
        """
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ]

        for delay in RATE_LIMIT_BACKOFF_SECONDS:
            try:
                return self._call(messages)
            except SDKError as exc:
                if exc.status_code == HTTP_TOO_MANY_REQUESTS:
                    time.sleep(delay)
                    continue
                raise

        # Final attempt: let a rate-limit SDKError propagate if still failing.
        return self._call(messages)

    def _call(self, messages: list[dict]) -> str:
        """Issue a single chat completion request (no rate-limit retry logic)."""
        try:
            response = self.client.chat.complete(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=MAX_TOKENS,
            )
        except SDKError as exc:
            if exc.status_code == HTTP_UNAUTHORIZED:
                raise RuntimeError(
                    "Mistral API key geçersiz. .env dosyasındaki MISTRAL_API_KEY değerini kontrol edin."
                ) from exc
            raise
        except httpx.ConnectError as exc:
            raise RuntimeError(
                "Mistral API'ye bağlanılamadı. İnternet bağlantınızı kontrol edin."
            ) from exc

        return response.choices[0].message.content
