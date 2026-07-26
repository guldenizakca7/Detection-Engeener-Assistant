"""Google Gemini LLM provider — cloud inference via the Gemini API.

NOTE: the `google-generativeai` package is deprecated upstream (Google says
it "will no longer be receiving updates or bug fixes" and recommends
migrating to the `google.genai` package). It is still functional today and
is what this project's dependency (google-generativeai>=0.7.0) installs, but
expect a FutureWarning at runtime and plan to migrate eventually --
see https://github.com/google-gemini/deprecated-generative-ai-python
"""
from __future__ import annotations

import os
import time

import google.generativeai as genai
from google.api_core.exceptions import ResourceExhausted, Unauthenticated

from .base import BaseLLM

STAGE_TEMPERATURES = {"stage1": 0.1, "stage2": 0.05}
STAGE_ENV_VARS = {"stage1": "STAGE1_MODEL_GEMINI", "stage2": "STAGE2_MODEL_GEMINI"}
STAGE_DEFAULT_MODELS = {"stage1": "gemini-2.0-flash", "stage2": "gemini-1.5-pro"}
RATE_LIMIT_BACKOFF_SECONDS = (2, 4, 8)
MAX_OUTPUT_TOKENS = 2000


class GeminiLLM(BaseLLM):
    """Cloud inference via the Google Gemini API."""

    def __init__(self, model_type: str):
        """Configure this provider for one pipeline stage.

        Args:
            model_type: Either "stage1" or "stage2" -- selects which model
                (STAGE1_MODEL_GEMINI / STAGE2_MODEL_GEMINI) and temperature to use.

        Raises:
            ValueError: If model_type is unknown, or GEMINI_API_KEY isn't set.
        """
        if model_type not in STAGE_TEMPERATURES:
            raise ValueError(f"Unknown model_type '{model_type}', expected 'stage1' or 'stage2'")

        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY is not set in .env")

        env_var = STAGE_ENV_VARS[model_type]
        self.model = os.getenv(env_var) or STAGE_DEFAULT_MODELS[model_type]
        self.temperature = STAGE_TEMPERATURES[model_type]
        genai.configure(api_key=api_key)

    def complete(self, prompt: str, system: str) -> str:
        """Send a generate_content request to the Gemini API.

        On google.api_core.exceptions.ResourceExhausted (rate limit), retries
        with exponential backoff (2s, 4s, 8s) before letting a final attempt's
        ResourceExhausted propagate.

        Args:
            prompt: The user-role message to send.
            system: The system-role instruction to send.

        Returns:
            The raw text of the model's response.

        Raises:
            RuntimeError: If the API key is invalid or Gemini is unreachable.
            google.api_core.exceptions.ResourceExhausted: If still rate-limited
                after all backoff retries.
        """
        for delay in RATE_LIMIT_BACKOFF_SECONDS:
            try:
                return self._call(prompt, system)
            except ResourceExhausted:
                time.sleep(delay)

        # Final attempt: let a ResourceExhausted propagate if still failing.
        return self._call(prompt, system)

    def _call(self, prompt: str, system: str) -> str:
        """Issue a single generate_content request (no rate-limit retry logic)."""
        model = genai.GenerativeModel(model_name=self.model, system_instruction=system)
        try:
            response = model.generate_content(
                prompt,
                generation_config=genai.GenerationConfig(
                    temperature=self.temperature,
                    max_output_tokens=MAX_OUTPUT_TOKENS,
                ),
            )
        except ResourceExhausted:
            # Not handled here -- let complete()'s backoff loop catch this.
            raise
        except Unauthenticated as exc:
            raise RuntimeError(
                "Gemini API key geçersiz. .env dosyasındaki GEMINI_API_KEY değerini kontrol edin."
            ) from exc
        except Exception as exc:  # noqa: BLE001 -- Gemini has no single dedicated connection-error class
            if "API_KEY" in str(exc):
                raise RuntimeError(
                    "Gemini API key geçersiz. .env dosyasındaki GEMINI_API_KEY değerini kontrol edin."
                ) from exc
            raise RuntimeError(f"Gemini API'ye bağlanılamadı: {exc}") from exc

        return response.text
