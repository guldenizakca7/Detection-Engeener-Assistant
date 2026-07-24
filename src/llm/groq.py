"""Groq LLM provider — cloud inference via the Groq API."""
from __future__ import annotations

import os
import time

import groq

from .base import BaseLLM

STAGE_TEMPERATURES = {"stage1": 0.1, "stage2": 0.2}
STAGE_ENV_VARS = {"stage1": "STAGE1_MODEL_GROQ", "stage2": "STAGE2_MODEL_GROQ"}
RATE_LIMIT_BACKOFF_SECONDS = (2, 4, 8)


class GroqLLM(BaseLLM):
    """Cloud inference via the Groq API (OpenAI-compatible chat completions)."""

    def __init__(self, model_type: str):
        """Configure this provider for one pipeline stage.

        Args:
            model_type: Either "stage1" or "stage2" -- selects which model
                (STAGE1_MODEL_GROQ / STAGE2_MODEL_GROQ) and temperature to use.

        Raises:
            ValueError: If model_type is unknown, or GROQ_API_KEY / the model
                env var isn't set.
        """
        if model_type not in STAGE_TEMPERATURES:
            raise ValueError(f"Unknown model_type '{model_type}', expected 'stage1' or 'stage2'")

        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise ValueError("GROQ_API_KEY is not set in .env")

        env_var = STAGE_ENV_VARS[model_type]
        self.model = os.getenv(env_var)
        if not self.model:
            raise ValueError(f"{env_var} is not set in .env")

        self.temperature = STAGE_TEMPERATURES[model_type]
        self.client = groq.Groq(api_key=api_key)

    def complete(self, prompt: str, system: str) -> str:
        """Send a chat completion request to the Groq API.

        On groq.RateLimitError, retries with exponential backoff (2s, 4s, 8s)
        before letting a final attempt's RateLimitError propagate.

        Args:
            prompt: The user-role message to send.
            system: The system-role instruction to send.

        Returns:
            The raw text of the model's response.

        Raises:
            groq.RateLimitError: If still rate-limited after all backoff retries.
        """
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ]

        for delay in RATE_LIMIT_BACKOFF_SECONDS:
            try:
                return self._call(messages)
            except groq.RateLimitError:
                time.sleep(delay)

        # Final attempt: let a RateLimitError propagate if still failing.
        return self._call(messages)

    def _call(self, messages: list[dict]) -> str:
        """Issue a single chat completion request (no retry logic)."""
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=self.temperature,
        )
        return response.choices[0].message.content
