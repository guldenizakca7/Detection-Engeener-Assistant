"""Stage 2 — IR generation from a validated MITRE technique + user input or CTI context."""
from __future__ import annotations

from src.llm import get_llm

try:
    from src.ir.validator import validate_ir, IRValidationError
    _IR_VALIDATION_AVAILABLE = True
except ImportError:
    _IR_VALIDATION_AVAILABLE = False


SYSTEM_PROMPT = (
    "You are a Detection Engineering expert. Generate a detection IR JSON "
    "for the given MITRE technique. Return ONLY raw JSON."
)

IR_SCHEMA_DESCRIPTION = """Return a JSON object with exactly this structure:
{
  "meta": {"title": str, "description": str, "severity": "low|medium|high|critical", "confidence": "low|medium|high"},
  "mitre": {"tactic": str, "technique_id": str, "technique_name": str},
  "log_source": {"platform": "windows|linux|macos|cloud|network", "category": str, "product": str (optional)},
  "detection": {
    "logic": "AND|OR (only needed when 2+ of process/network/file/registry are present, default AND)",
    "process": {"name": [str], "command_contains": [str], "parent_name": [str]},
    "network": {"destination_ip": [str], "destination_port": [str], "protocol": str},
    "file": {"path_contains": [str], "name": [str], "extension": [str]},
    "registry": {"key_contains": [str], "value_contains": [str]}
  },
  "false_positives": [str, ...] (at least one),
  "references": [str, ...] (optional)
}
Only include the detection.* sub-objects that are actually relevant; omit the rest."""

MAX_VALIDATION_RETRIES = 3


def _build_prompt(user_input: str, mitre_technique: dict, context_snippet: str | None) -> str:
    """Build the Stage 2 prompt from the validated technique plus input or CTI context."""
    technique_block = (
        "MITRE Technique:\n"
        f"  ID: {mitre_technique.get('id')}\n"
        f"  Name: {mitre_technique.get('name')}\n"
        f"  Tactic: {mitre_technique.get('tactic')}\n"
    )

    if context_snippet is not None:
        input_block = f"CTI context snippet:\n{context_snippet}"
    else:
        input_block = f"User input:\n{user_input}"

    return f"{technique_block}\n{input_block}\n\n{IR_SCHEMA_DESCRIPTION}"


def generate_ir(
    user_input: str,
    mitre_technique: dict,
    context_snippet: str | None = None,
) -> dict:
    """Generate an IR JSON for a validated MITRE technique.

    In CTI mode (context_snippet given), only the extracted context snippet is
    sent to the LLM — never the full report. In short-sentence mode
    (context_snippet is None), the original user_input is sent instead.

    Calls the Stage 2 LLM (temperature 0.2, set in OllamaLLM/GroqLLM). If
    src.ir.validator is importable, retries up to MAX_VALIDATION_RETRIES times,
    re-prompting with the validation errors on failure; otherwise returns the
    LLM's JSON output unvalidated (with a printed warning).

    Args:
        user_input: The original natural-language input or full CTI report.
            Ignored when context_snippet is provided.
        mitre_technique: The validated technique dict (id, name, tactic, ...),
            as returned by src.mitre.handle_validation().
        context_snippet: Extracted CTI context for this technique (from
            src.pipeline.extract_context_for_technique), or None for
            short-sentence mode.

    Returns:
        A dict matching the IR schema (see src.ir.schema.IR_SCHEMA).

    Raises:
        IRValidationError: If src.ir.validator is available but the LLM still
            produces an invalid IR after MAX_VALIDATION_RETRIES attempts.
        json.JSONDecodeError: If the LLM never returns valid JSON (via complete_json).
    """
    llm = get_llm("stage2")
    prompt = _build_prompt(user_input, mitre_technique, context_snippet)

    if not _IR_VALIDATION_AVAILABLE:
        print("[stage2] Warning: src.ir.validator not available, skipping IR validation.")
        return llm.complete_json(prompt, SYSTEM_PROMPT)

    current_prompt = prompt
    errors = None
    for _ in range(MAX_VALIDATION_RETRIES):
        ir = llm.complete_json(current_prompt, SYSTEM_PROMPT)
        errors = validate_ir(ir)
        if not errors:
            return ir
        current_prompt = (
            f"{prompt}\n\nYour previous response had validation errors: {errors}. "
            "Fix them and return the corrected raw JSON only."
        )

    raise IRValidationError(f"IR failed validation after {MAX_VALIDATION_RETRIES} attempts: {errors}")
