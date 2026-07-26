"""Factory for LLM providers, selected via the LLM_PROVIDER env variable."""
from __future__ import annotations

import importlib
import os

from .base import BaseLLM

# (module path, class name). Providers are imported lazily inside get_llm()
# so that a missing optional SDK (e.g. `openai` not installed) only breaks
# that one provider, not every provider or the whole package import.
PROVIDER_MAP = {
    "ollama": ("src.llm.ollama", "OllamaLLM"),
    "groq": ("src.llm.groq", "GroqLLM"),
    "openai": ("src.llm.openai_provider", "OpenAILLM"),
    "anthropic": ("src.llm.anthropic_provider", "AnthropicLLM"),
    "gemini": ("src.llm.gemini_provider", "GeminiLLM"),
    "mistral": ("src.llm.mistral_provider", "MistralLLM"),
    "together": ("src.llm.together_provider", "TogetherLLM"),
}


def get_llm(model_type: str) -> BaseLLM:
    """Return an LLM provider instance for the given stage.

    The provider is selected via the LLM_PROVIDER env variable (one of
    PROVIDER_MAP's keys: ollama, groq, openai, anthropic, gemini, mistral,
    together). The provider's module is imported lazily, so only the SDK for
    the selected provider needs to be installed.

    Args:
        model_type: Either "stage1" or "stage2".

    Returns:
        A BaseLLM instance configured for that stage.

    Raises:
        ValueError: If LLM_PROVIDER is unset or not one of PROVIDER_MAP's keys.
        RuntimeError: If the selected provider's SDK package isn't installed.
    """
    provider = os.getenv("LLM_PROVIDER", "").strip().lower()
    if not provider:
        raise ValueError(
            "LLM_PROVIDER is not set. Add LLM_PROVIDER=<provider> to your .env file. "
            f"Supported: {', '.join(PROVIDER_MAP)}."
        )

    if provider not in PROVIDER_MAP:
        raise ValueError(f"Unknown LLM_PROVIDER: {provider}. Supported: {list(PROVIDER_MAP.keys())}")

    module_path, class_name = PROVIDER_MAP[provider]
    try:
        module = importlib.import_module(module_path)
        cls = getattr(module, class_name)
    except ImportError as exc:
        raise RuntimeError(
            f"Provider '{provider}' requires additional packages. "
            f"Run: pip install -r requirements.txt\nDetails: {exc}"
        ) from exc

    return cls(model_type)


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
