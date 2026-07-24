"""Factory for LLM providers, selected via the LLM_PROVIDER env variable."""
from __future__ import annotations

import os

from .base import BaseLLM
from .groq import GroqLLM
from .ollama import OllamaLLM

_PROVIDERS = {
    "ollama": OllamaLLM,
    "groq": GroqLLM,
}


def get_llm(model_type: str) -> BaseLLM:
    """Return an LLM provider instance for the given stage.

    The provider is selected via the LLM_PROVIDER env variable ('ollama' or 'groq').

    Args:
        model_type: Either "stage1" or "stage2".

    Returns:
        An OllamaLLM or GroqLLM instance configured for that stage.

    Raises:
        ValueError: If LLM_PROVIDER is unset or not one of the known providers.
    """
    provider = os.getenv("LLM_PROVIDER")
    if not provider:
        raise ValueError(
            "LLM_PROVIDER is not set. Add LLM_PROVIDER=ollama or LLM_PROVIDER=groq to your .env file."
        )

    provider = provider.strip().lower()
    if provider not in _PROVIDERS:
        raise ValueError(
            f"Unknown LLM_PROVIDER '{provider}'. Expected one of: {', '.join(_PROVIDERS)}."
        )

    return _PROVIDERS[provider](model_type)


if __name__ == "__main__":
    # Run with: python -m src.llm
    from dotenv import load_dotenv

    load_dotenv()

    llm = get_llm("stage1")

    print("=== complete() ===")
    print(llm.complete("Say hello", "You are a helpful assistant"))

    print("\n=== complete_json() ===")
    print(
        llm.complete_json(
            'Return this exact JSON: {"test": true}',
            "You are a helpful assistant. Return only raw JSON.",
        )
    )
