"""IR (Intermediate Representation) validation and auto-fix."""
from __future__ import annotations

import copy

import jsonschema

from .schema import IR_SCHEMA


class IRValidationError(Exception):
    """Raised when an IR still fails validation after auto-fixing."""


def validate_ir(ir_dict: dict) -> list[str]:
    """Validate ir_dict against IR_SCHEMA.

    Args:
        ir_dict: The candidate IR dict to validate.

    Returns:
        A list of human-readable "path: message" error strings; an empty list
        means the IR is valid. Note jsonschema.validate() stops at the first
        error, so this list will contain at most one entry per call.
    """
    try:
        jsonschema.validate(instance=ir_dict, schema=IR_SCHEMA)
    except jsonschema.ValidationError as exc:
        path = ".".join(str(p) for p in exc.path) or "<root>"
        return [f"{path}: {exc.message}"]
    return []


def auto_fix_ir(ir_dict: dict) -> dict:
    """Return a fixed copy of ir_dict with common LLM formatting issues corrected.

    Fixes: lowercases/strips meta.severity and meta.confidence, strips
    meta.title and meta.description, uppercases detection.logic, and strips/
    drops empty entries from false_positives (falling back to ["Unknown"] if
    that leaves the list empty). Never mutates the input.

    Args:
        ir_dict: The IR dict to fix.

    Returns:
        A new, fixed dict. Does not itself guarantee schema validity -- pair
        with validate_ir() or use validate_and_fix().
    """
    fixed = copy.deepcopy(ir_dict)

    meta = fixed.get("meta")
    if isinstance(meta, dict):
        if isinstance(meta.get("severity"), str):
            meta["severity"] = meta["severity"].strip().lower()
        if isinstance(meta.get("confidence"), str):
            meta["confidence"] = meta["confidence"].strip().lower()
        if isinstance(meta.get("title"), str):
            meta["title"] = meta["title"].strip()
        if isinstance(meta.get("description"), str):
            meta["description"] = meta["description"].strip()

    detection = fixed.get("detection")
    if isinstance(detection, dict) and isinstance(detection.get("logic"), str):
        detection["logic"] = detection["logic"].strip().upper()

    false_positives = fixed.get("false_positives")
    if isinstance(false_positives, list):
        cleaned = [fp.strip() for fp in false_positives if isinstance(fp, str) and fp.strip()]
        fixed["false_positives"] = cleaned or ["Unknown"]

    return fixed


def validate_and_fix(ir_dict: dict) -> dict:
    """Auto-fix ir_dict, then validate it.

    Args:
        ir_dict: The IR dict to fix and validate.

    Returns:
        The fixed, schema-valid dict.

    Raises:
        IRValidationError: If validation errors remain after auto-fixing.
    """
    fixed = auto_fix_ir(ir_dict)
    errors = validate_ir(fixed)
    if errors:
        raise IRValidationError("; ".join(errors))
    return fixed


if __name__ == "__main__":
    # Run with: python -m src.ir.validator

    # Test 1 — valid IR
    valid_ir = {
        "meta": {
            "title": "PowerShell Credential Dumping",
            "description": "Detects LSASS memory access via PowerShell",
            "severity": "high",
            "confidence": "high",
        },
        "mitre": {
            "tactic": "Credential Access",
            "technique_id": "T1003.001",
            "technique_name": "LSASS Memory",
        },
        "log_source": {"platform": "windows", "category": "process_creation"},
        "detection": {
            "process": {
                "name": ["powershell.exe", "pwsh.exe"],
                "command_contains": ["sekurlsa", "lsass", "mimikatz"],
            }
        },
        "false_positives": ["Legitimate system administration tools"],
    }
    errors1 = validate_ir(valid_ir)
    print("Test 1 — valid IR errors:", errors1)
    assert errors1 == [], f"expected no errors, got {errors1}"

    # Test 2 — missing required fields
    errors2 = validate_ir({})
    print("Test 2 — empty dict errors:", errors2)
    assert errors2, "expected validation errors for an empty dict"

    # Test 3 — auto_fix in action
    messy_ir = {
        "meta": {
            "title": "  Test Rule  ",
            "description": "  desc  ",
            "severity": "HIGH",
            "confidence": "Medium",
        },
        "mitre": {"tactic": "x", "technique_id": "T1003.001", "technique_name": "x"},
        "log_source": {"platform": "windows", "category": "process_creation"},
        "detection": {"logic": "and", "process": {"name": ["x.exe"]}},
        "false_positives": ["  ", "Legitimate tool  "],
    }
    fixed = auto_fix_ir(messy_ir)
    print(
        "Test 3 — auto_fix result:",
        "severity=" + fixed["meta"]["severity"],
        "confidence=" + fixed["meta"]["confidence"],
        "logic=" + fixed["detection"]["logic"],
        "false_positives=" + repr(fixed["false_positives"]),
    )
    assert fixed["meta"]["severity"] == "high"
    assert fixed["meta"]["confidence"] == "medium"
    assert fixed["detection"]["logic"] == "AND"
    assert fixed["false_positives"] == ["Legitimate tool"]

    print("All IR validator tests passed")
