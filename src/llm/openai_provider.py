"""OpenAI LLM provider — cloud inference via the OpenAI API."""
from __future__ import annotations

import os
import time

import openai
from openai import OpenAI

from .base import BaseLLM

STAGE_TEMPERATURES = {"stage1": 0.1, "stage2": 0.05}
STAGE_ENV_VARS = {"stage1": "STAGE1_MODEL_OPENAI", "stage2": "STAGE2_MODEL_OPENAI"}
STAGE_DEFAULT_MODELS = {"stage1": "gpt-4o-mini", "stage2": "gpt-4o"}
RATE_LIMIT_BACKOFF_SECONDS = (2, 4, 8)
MAX_TOKENS = 2000


class OpenAILLM(BaseLLM):
    """Cloud inference via the OpenAI API (chat completions)."""

    def __init__(self, model_type: str):
        """Configure this provider for one pipeline stage.

        Args:
            model_type: Either "stage1" or "stage2" -- selects which model
                (STAGE1_MODEL_OPENAI / STAGE2_MODEL_OPENAI) and temperature to use.

        Raises:
            ValueError: If model_type is unknown, or OPENAI_API_KEY isn't set.
        """
        if model_type not in STAGE_TEMPERATURES:
            raise ValueError(f"Unknown model_type '{model_type}', expected 'stage1' or 'stage2'")

        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY is not set in .env")

        env_var = STAGE_ENV_VARS[model_type]
        self.model = os.getenv(env_var) or STAGE_DEFAULT_MODELS[model_type]
        self.temperature = STAGE_TEMPERATURES[model_type]
        self.client = OpenAI(api_key=api_key)

    def complete(self, prompt: str, system: str) -> str:
        """Send a chat completion request to the OpenAI API.

        On openai.RateLimitError, retries with exponential backoff (2s, 4s, 8s)
        before letting a final attempt's RateLimitError propagate.

        Args:
            prompt: The user-role message to send.
            system: The system-role instruction to send.

        Returns:
            The raw text of the model's response.

        Raises:
            RuntimeError: If the API key is invalid or OpenAI is unreachable.
            openai.RateLimitError: If still rate-limited after all backoff retries.
        """
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ]

        for delay in RATE_LIMIT_BACKOFF_SECONDS:
            try:
                return self._call(messages)
            except openai.RateLimitError:
                time.sleep(delay)

        # Final attempt: let a RateLimitError propagate if still failing.
        return self._call(messages)

    def _call(self, messages: list[dict]) -> str:
        """Issue a single chat completion request (no rate-limit retry logic)."""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=MAX_TOKENS,
            )
        except openai.AuthenticationError as exc:
            raise RuntimeError(
                "OpenAI API key geçersiz. .env dosyasındaki OPENAI_API_KEY değerini kontrol edin."
            ) from exc
        except openai.APIConnectionError as exc:
            raise RuntimeError(
                "OpenAI API'ye bağlanılamadı. İnternet bağlantınızı kontrol edin."
            ) from exc

        return response.choices[0].message.content
