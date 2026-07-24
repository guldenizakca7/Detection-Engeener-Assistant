"""Ollama LLM provider — local inference via the Ollama REST API."""
from __future__ import annotations

import os

import requests

from .base import BaseLLM

DEFAULT_TIMEOUT = 120
STAGE_TEMPERATURES = {"stage1": 0.1, "stage2": 0.2}
STAGE_ENV_VARS = {"stage1": "STAGE1_MODEL_OLLAMA", "stage2": "STAGE2_MODEL_OLLAMA"}


class OllamaLLM(BaseLLM):
    """Local inference via the Ollama REST API (POST /api/chat)."""

    def __init__(self, model_type: str):
        """Configure this provider for one pipeline stage.

        Args:
            model_type: Either "stage1" or "stage2" -- selects which model
                (STAGE1_MODEL_OLLAMA / STAGE2_MODEL_OLLAMA) and temperature to use.

        Raises:
            ValueError: If model_type is unknown, or its model env var isn't set.
        """
        if model_type not in STAGE_TEMPERATURES:
            raise ValueError(f"Unknown model_type '{model_type}', expected 'stage1' or 'stage2'")

        self.base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")

        env_var = STAGE_ENV_VARS[model_type]
        self.model = os.getenv(env_var)
        if not self.model:
            raise ValueError(f"{env_var} is not set in .env")

        self.temperature = STAGE_TEMPERATURES[model_type]

    def complete(self, prompt: str, system: str) -> str:
        """Send a chat completion request to the local Ollama server.

        Args:
            prompt: The user-role message to send.
            system: The system-role instruction to send.

        Returns:
            The raw text of the model's response.

        Raises:
            RuntimeError: If Ollama isn't reachable, or the request otherwise fails.
        """
        url = f"{self.base_url}/api/chat"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "options": {"temperature": self.temperature},
        }

        try:
            response = requests.post(url, json=payload, timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
        except requests.exceptions.ConnectionError as exc:
            raise RuntimeError(
                f"Could not connect to Ollama at {self.base_url}. Is Ollama running? "
                "Start it with 'ollama serve', or install it from https://ollama.com/download."
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Ollama request failed: {exc}") from exc

        return response.json()["message"]["content"]
