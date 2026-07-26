"""Anthropic (Claude) LLM provider — cloud inference via the Anthropic API."""
from __future__ import annotations

import os
import time

import anthropic
from anthropic import Anthropic

from .base import BaseLLM

STAGE_TEMPERATURES = {"stage1": 0.1, "stage2": 0.05}
STAGE_ENV_VARS = {"stage1": "STAGE1_MODEL_ANTHROPIC", "stage2": "STAGE2_MODEL_ANTHROPIC"}
# NOTE: claude-haiku-4-5-20251001 is a verified real, current model ID.
# claude-sonnet-4-6 does not match any Anthropic model naming pattern we could
# confirm and could not be verified live (no real API calls made per task
# instructions) -- if Stage 2 fails with a model-not-found error, check
# https://docs.claude.com/en/docs/about-claude/models for the current Sonnet
# model ID and update STAGE2_MODEL_ANTHROPIC in .env.
STAGE_DEFAULT_MODELS = {"stage1": "claude-haiku-4-5-20251001", "stage2": "claude-sonnet-4-6"}
RATE_LIMIT_BACKOFF_SECONDS = (2, 4, 8)
MAX_TOKENS = 2000


class AnthropicLLM(BaseLLM):
    """Cloud inference via the Anthropic API (Claude messages)."""

    def __init__(self, model_type: str):
        """Configure this provider for one pipeline stage.

        Args:
            model_type: Either "stage1" or "stage2" -- selects which model
                (STAGE1_MODEL_ANTHROPIC / STAGE2_MODEL_ANTHROPIC) and temperature to use.

        Raises:
            ValueError: If model_type is unknown, or ANTHROPIC_API_KEY isn't set.
        """
        if model_type not in STAGE_TEMPERATURES:
            raise ValueError(f"Unknown model_type '{model_type}', expected 'stage1' or 'stage2'")

        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY is not set in .env")

        env_var = STAGE_ENV_VARS[model_type]
        self.model = os.getenv(env_var) or STAGE_DEFAULT_MODELS[model_type]
        self.temperature = STAGE_TEMPERATURES[model_type]
        self.client = Anthropic(api_key=api_key)

    def complete(self, prompt: str, system: str) -> str:
        """Send a message request to the Anthropic API.

        On anthropic.RateLimitError, retries with exponential backoff (2s, 4s, 8s)
        before letting a final attempt's RateLimitError propagate.

        Args:
            prompt: The user-role message to send.
            system: The system-role instruction to send.

        Returns:
            The raw text of the model's response.

        Raises:
            RuntimeError: If the API key is invalid or Anthropic is unreachable.
            anthropic.RateLimitError: If still rate-limited after all backoff retries.
        """
        for delay in RATE_LIMIT_BACKOFF_SECONDS:
            try:
                return self._call(prompt, system)
            except anthropic.RateLimitError:
                time.sleep(delay)

        # Final attempt: let a RateLimitError propagate if still failing.
        return self._call(prompt, system)

    def _call(self, prompt: str, system: str) -> str:
        """Issue a single message request (no rate-limit retry logic)."""
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=MAX_TOKENS,
                system=system,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.temperature,
            )
        except anthropic.AuthenticationError as exc:
            raise RuntimeError(
                "Anthropic API key geçersiz. .env dosyasındaki ANTHROPIC_API_KEY değerini kontrol edin."
            ) from exc
        except anthropic.APIConnectionError as exc:
            raise RuntimeError(
                "Anthropic API'ye bağlanılamadı. İnternet bağlantınızı kontrol edin."
            ) from exc

        return response.content[0].text
