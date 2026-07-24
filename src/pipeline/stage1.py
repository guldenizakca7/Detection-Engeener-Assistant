"""Stage 1 — MITRE ATT&CK technique detection from natural language input."""
from __future__ import annotations

import json
import re

from src.llm import get_llm

_DIRECT_TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

SYSTEM_PROMPT = (
    "You are a Detection Engineering expert specialized in MITRE ATT&CK. "
    "Analyze the input and return ONLY a raw JSON object, no markdown, no explanation. "
    "The JSON object must have exactly these keys: mitre_tactic (string), "
    "mitre_technique_id (string, format T1XXX or T1XXX.XXX), "
    "mitre_technique_name (string), "
    "log_sources (array of: windows, linux, macos, cloud, network), "
    "confidence (one of: high, medium, low), "
    "reasoning (one sentence explaining why). "
    "You must return exactly one JSON object. Never return an array. "
    "Never return multiple JSON objects. Never add any text, explanation, "
    "or markdown outside the JSON object."
)

REQUIRED_KEYS = {
    "mitre_tactic",
    "mitre_technique_id",
    "mitre_technique_name",
    "log_sources",
    "confidence",
    "reasoning",
}

FEW_SHOT_EXAMPLES = [
    (
        "Detect PowerShell credential dumping",
        {
            "mitre_tactic": "Credential Access",
            "mitre_technique_id": "T1003.001",
            "mitre_technique_name": "LSASS Memory",
            "log_sources": ["windows"],
            "confidence": "high",
            "reasoning": "PowerShell combined with credential dumping indicates LSASS memory access for credential theft.",
        },
    ),
    (
        "Detect persistence via scheduled tasks",
        {
            "mitre_tactic": "Persistence",
            "mitre_technique_id": "T1053.005",
            "mitre_technique_name": "Scheduled Task",
            "log_sources": ["windows"],
            "confidence": "high",
            "reasoning": "Scheduled task creation is the primary mechanism for this Windows persistence technique.",
        },
    ),
    (
        "Detect phishing emails with malicious attachments",
        {
            "mitre_tactic": "Initial Access",
            "mitre_technique_id": "T1566.001",
            "mitre_technique_name": "Spearphishing Attachment",
            "log_sources": ["network", "windows"],
            "confidence": "high",
            "reasoning": "Malicious email attachments are the defining indicator of spearphishing attachment delivery.",
        },
    ),
    (
        "Detect lateral movement via RDP",
        {
            "mitre_tactic": "Lateral Movement",
            "mitre_technique_id": "T1021.001",
            "mitre_technique_name": "Remote Desktop Protocol",
            "log_sources": ["windows", "network"],
            "confidence": "high",
            "reasoning": "Movement between hosts using RDP sessions is the Remote Desktop Protocol technique.",
        },
    ),
    (
        "Detect persistence via registry run keys",
        {
            "mitre_tactic": "Persistence",
            "mitre_technique_id": "T1547.001",
            "mitre_technique_name": "Registry Run Keys / Startup Folder",
            "log_sources": ["windows"],
            "confidence": "high",
            "reasoning": "Registry run key modification is the canonical boot/logon autostart persistence mechanism.",
        },
    ),
]


def _build_prompt(user_input: str) -> str:
    """Build the full Stage 1 prompt: the 5 few-shot examples followed by the real input."""
    examples_block = "\n\n".join(
        f"Input: {example_input}\nOutput: {json.dumps(example_output)}"
        for example_input, example_output in FEW_SHOT_EXAMPLES
    )
    return (
        f"{examples_block}\n\n"
        "Return exactly one JSON object and nothing else.\n"
        f"Input: {user_input}\nOutput:"
    )


def _clean_technique_id(value: str) -> str:
    """Normalize a Stage 1 technique_id value that may contain multiple
    comma/space-joined IDs (e.g. "T1003.001,T1021.001") or stray
    quote/bracket characters (e.g. "[T1003.001]"), keeping only the first ID.
    """
    cleaned = value.strip()
    if "," in cleaned:
        cleaned = cleaned.split(",", 1)[0].strip()
    if " " in cleaned:
        cleaned = cleaned.split(" ", 1)[0].strip()
    cleaned = cleaned.strip("[]\"'")
    return cleaned


def extract_direct_technique_id(user_input: str) -> str | None:
    """Return a MITRE technique ID found directly in user_input, or None.

    Args:
        user_input: The raw user input, e.g. "T1003 tespit et" or "detect T1003".

    Returns:
        The matched technique ID (e.g. "T1003" or "T1003.001"), or None if
        no technique ID pattern is present.
    """
    match = _DIRECT_TECHNIQUE_ID_RE.search(user_input)
    return match.group(0) if match else None


def detect_mitre_technique(user_input: str) -> dict:
    """Detect the MITRE ATT&CK tactic/technique for a natural language description.

    Calls the Stage 1 LLM (temperature 0.1, set in OllamaLLM/GroqLLM) with a
    5-example few-shot prompt and parses/retries via complete_json().

    Args:
        user_input: A short natural-language attack description, e.g.
            "Detect PowerShell credential dumping".

    Returns:
        A dict with keys: mitre_tactic, mitre_technique_id, mitre_technique_name,
        log_sources, confidence, reasoning. Note mitre_technique_id is the LLM's
        own guess and is not yet validated against the real MITRE catalog --
        pass this to src.mitre.handle_validation() for that.

    Raises:
        ValueError: If the parsed JSON is missing any required key.
        json.JSONDecodeError: If the LLM never returns valid JSON (via complete_json).
    """
    direct_id = extract_direct_technique_id(user_input)
    if direct_id is not None:
        return {
            "mitre_tactic": "",
            "mitre_technique_id": direct_id,
            "mitre_technique_name": "",
            "log_sources": [],
            "confidence": "high",
            "reasoning": "Direct technique ID provided by user",
        }

    llm = get_llm("stage1")
    prompt = _build_prompt(user_input)
    result = llm.complete_json(prompt, SYSTEM_PROMPT)

    missing = REQUIRED_KEYS - result.keys()
    if missing:
        raise ValueError(f"Stage 1 output missing required keys: {sorted(missing)}")

    if isinstance(result.get("mitre_technique_id"), str):
        result["mitre_technique_id"] = _clean_technique_id(result["mitre_technique_id"])

    return result


if __name__ == "__main__":
    # Run with: python -m src.pipeline.stage1
    from src.llm.base import BaseLLM

    class _FakeLLM(BaseLLM):
        def complete(self, prompt: str, system: str) -> str:
            return json.dumps(
                {
                    "mitre_tactic": "Credential Access",
                    "mitre_technique_id": "T1003.001",
                    "mitre_technique_name": "LSASS Memory",
                    "log_sources": ["windows"],
                    "confidence": "high",
                    "reasoning": "PowerShell + credential dumping indicates LSASS memory access.",
                }
            )

    get_llm = lambda model_type: _FakeLLM()  # noqa: E731 -- mock for standalone test

    output = detect_mitre_technique("detect PowerShell credential dumping")
    for key in REQUIRED_KEYS:
        assert key in output, f"missing key: {key}"

    print("Stage 1 test passed")
