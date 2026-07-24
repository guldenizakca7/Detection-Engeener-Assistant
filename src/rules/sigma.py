"""Deterministic IR → Sigma YAML conversion (no LLM involved)."""
from __future__ import annotations

import re

import yaml

DETECTION_TYPES = ("process", "network", "file", "registry")


def build_condition(detection: dict) -> str:
    """Return the Sigma condition string for a given IR detection block.

    Args:
        detection: The IR "detection" sub-dict (process/network/file/registry/logic).

    Returns:
        "selection" for 0-1 active detection types; "all of selection_*" /
        "1 of selection_*" for 2+ active types, per detection["logic"]
        (default "AND"). See ir_to_sigma() for why the selection key itself is
        named differently in each case.
    """
    active = [t for t in DETECTION_TYPES if detection.get(t)]
    if len(active) <= 1:
        return "selection"

    logic = detection.get("logic", "AND")
    if logic == "OR":
        return "1 of selection_*"
    return "all of selection_*"


def _build_process_selection(process: dict) -> dict:
    """Map IR detection.process fields to Sigma field|modifier keys."""
    selection = {}
    if process.get("name"):
        selection["Image|endswith"] = [f"\\{name}" for name in process["name"]]
    if process.get("command_contains"):
        selection["CommandLine|contains"] = list(process["command_contains"])
    if process.get("parent_name"):
        selection["ParentImage|endswith"] = [f"\\{name}" for name in process["parent_name"]]
    return selection


def _build_network_selection(network: dict) -> dict:
    """Map IR detection.network fields to Sigma field keys."""
    selection = {}
    if network.get("destination_ip"):
        selection["DestinationIp"] = list(network["destination_ip"])
    if network.get("destination_port"):
        selection["DestinationPort"] = list(network["destination_port"])
    if network.get("protocol"):
        selection["Protocol"] = network["protocol"]
    return selection


def _build_file_selection(file_: dict) -> dict:
    """Map IR detection.file fields to Sigma field|modifier keys.

    name and extension both target Sigma's TargetFilename|endswith, so their
    values are merged into a single list under one key rather than producing
    two conflicting dict entries for the same field|modifier.
    """
    selection = {}
    if file_.get("path_contains"):
        selection["TargetFilename|contains"] = list(file_["path_contains"])
    name_and_extension = list(file_.get("name") or []) + list(file_.get("extension") or [])
    if name_and_extension:
        selection["TargetFilename|endswith"] = name_and_extension
    return selection


def _build_registry_selection(registry: dict) -> dict:
    """Map IR detection.registry fields to Sigma field|modifier keys."""
    selection = {}
    if registry.get("key_contains"):
        selection["TargetObject|contains"] = list(registry["key_contains"])
    if registry.get("value_contains"):
        selection["Details|contains"] = list(registry["value_contains"])
    return selection


_SELECTION_BUILDERS = {
    "process": _build_process_selection,
    "network": _build_network_selection,
    "file": _build_file_selection,
    "registry": _build_registry_selection,
}


def _build_selections(detection: dict) -> dict:
    """Build {detection_type: selection_dict} for every non-empty detection type."""
    built = {}
    for det_type, builder in _SELECTION_BUILDERS.items():
        data = detection.get(det_type)
        if data:
            selection = builder(data)
            if selection:
                built[det_type] = selection
    return built


def _tag_for_tactic(tactic: str) -> str:
    """Build the Sigma attack.<tactic_slug> tag, e.g. "Credential Access" -> "attack.credential_access"."""
    slug = re.sub(r"[\s-]+", "_", tactic.strip().lower())
    return f"attack.{slug}"


def _tag_for_technique_id(technique_id: str) -> str:
    """Build the Sigma attack.<technique_slug> tag, e.g. "T1003.001" -> "attack.t1003001"."""
    slug = technique_id.lower().replace(".", "")
    return f"attack.{slug}"


def ir_to_sigma(ir_dict: dict) -> str:
    """Build a Sigma rule from a validated IR dict and return it as a YAML string.

    Field mapping (see ARCHITECTURE.md "sigma.py — IR to Sigma" for the full
    table): meta.title/description -> title/description; meta.severity ->
    level; status is always "experimental"; mitre.tactic/technique_id -> tags;
    log_source.* -> logsource.*; detection.* -> one selection_<type> block per
    active detection type; false_positives -> falsepositives.

    Args:
        ir_dict: A validated IR dict (typically the output of
            src.ir.validator.validate_and_fix, or already-valid output from
            src.pipeline.stage2.generate_ir).

    Returns:
        The Sigma rule serialized as a YAML string.
    """
    meta = ir_dict["meta"]
    mitre = ir_dict["mitre"]
    log_source = ir_dict["log_source"]
    detection = ir_dict["detection"]

    logsource = {
        "product": log_source["platform"],
        "category": log_source["category"],
    }
    if log_source.get("product"):
        logsource["service"] = log_source["product"]

    # Selection key naming must stay in sync with build_condition()'s output:
    # build_condition() returns the literal string "selection" when there's
    # only one active detection type, and "all/1 of selection_*" (a wildcard
    # over "selection_process", "selection_network", etc.) when there are
    # several. So a single active type is stored under the plain key
    # "selection" -- not "selection_process" -- specifically so the condition
    # string actually resolves to a real key; multiple active types each get
    # their own "selection_<type>" key for the wildcard condition to match.
    selections = _build_selections(detection)
    detection_block = {}
    if len(selections) == 1:
        (only_selection,) = selections.values()
        detection_block["selection"] = only_selection
    else:
        for det_type, selection in selections.items():
            detection_block[f"selection_{det_type}"] = selection
    detection_block["condition"] = build_condition(detection)

    sigma_rule = {
        "title": meta["title"],
        "description": meta["description"],
        "status": "experimental",
    }
    if ir_dict.get("references"):
        sigma_rule["references"] = ir_dict["references"]
    sigma_rule["tags"] = [_tag_for_tactic(mitre["tactic"]), _tag_for_technique_id(mitre["technique_id"])]
    sigma_rule["logsource"] = logsource
    sigma_rule["detection"] = detection_block
    sigma_rule["falsepositives"] = ir_dict["false_positives"]
    sigma_rule["level"] = meta["severity"]

    return yaml.dump(sigma_rule, default_flow_style=False, allow_unicode=True, sort_keys=False)


if __name__ == "__main__":
    # Run with: python -m src.rules.sigma
    test_ir = {
        "meta": {
            "title": "PowerShell Credential Dumping",
            "description": "Detects LSASS memory access via PowerShell",
            "severity": "high",
            "confidence": "high",
        },
        "mitre": {
            "tactic": "credential-access",
            "technique_id": "T1003.001",
            "technique_name": "LSASS Memory",
        },
        "log_source": {
            "platform": "windows",
            "category": "process_creation",
            "product": "sysmon",
        },
        "detection": {
            "process": {
                "name": ["powershell.exe", "pwsh.exe"],
                "command_contains": ["sekurlsa", "lsass", "mimikatz"],
            }
        },
        "false_positives": ["Legitimate system administration tools"],
        "references": ["https://attack.mitre.org/techniques/T1003/001"],
    }

    sigma_yaml = ir_to_sigma(test_ir)
    print(sigma_yaml)

    assert "title: PowerShell Credential Dumping" in sigma_yaml
    assert "attack.credential_access" in sigma_yaml
    assert "attack.t1003001" in sigma_yaml
    assert "condition: selection" in sigma_yaml
    assert "level: high" in sigma_yaml

    print("Sigma generation test passed")
