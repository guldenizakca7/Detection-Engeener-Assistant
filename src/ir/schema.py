"""JSON Schema (Draft 7) for the Intermediate Representation (IR).

The IR is the central data structure of the pipeline: Stage 2 (src.pipeline.stage2)
produces it, src.ir.validator validates/auto-fixes it, and src.rules.sigma converts
it deterministically into a Sigma rule -- see ARCHITECTURE.md for the full field
reference and the worked example.
"""

_STRING_ARRAY = {"type": "array", "items": {"type": "string"}}

IR_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["meta", "mitre", "log_source", "detection", "false_positives"],
    "properties": {
        "meta": {
            "type": "object",
            "required": ["title", "description", "severity", "confidence"],
            "properties": {
                "title": {"type": "string"},
                "description": {"type": "string"},
                "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
            },
        },
        "mitre": {
            "type": "object",
            "required": ["tactic", "technique_id", "technique_name"],
            "properties": {
                "tactic": {"type": "string"},
                "technique_id": {"type": "string", "pattern": r"^T\d{4}(\.\d{3})?$"},
                "technique_name": {"type": "string"},
            },
        },
        "log_source": {
            "type": "object",
            "required": ["platform", "category"],
            "properties": {
                "platform": {
                    "type": "string",
                    "enum": ["windows", "linux", "macos", "cloud", "network"],
                },
                "category": {"type": "string"},
                "product": {"type": "string"},
            },
        },
        "detection": {
            "type": "object",
            "properties": {
                "logic": {"type": "string", "enum": ["AND", "OR"]},
                "process": {
                    "type": "object",
                    "properties": {
                        "name": _STRING_ARRAY,
                        "command_contains": _STRING_ARRAY,
                        "parent_name": _STRING_ARRAY,
                    },
                },
                "network": {
                    "type": "object",
                    "properties": {
                        "destination_ip": _STRING_ARRAY,
                        "destination_port": _STRING_ARRAY,
                        "protocol": {"type": "string"},
                    },
                },
                "file": {
                    "type": "object",
                    "properties": {
                        "path_contains": _STRING_ARRAY,
                        "name": _STRING_ARRAY,
                        "extension": _STRING_ARRAY,
                    },
                },
                "registry": {
                    "type": "object",
                    "properties": {
                        "key_contains": _STRING_ARRAY,
                        "value_contains": _STRING_ARRAY,
                    },
                },
            },
            # At least one detection type must be present: an IR with an empty
            # `detection` block would produce a Sigma rule with no selections at
            # all, which src.rules.sigma.build_condition() can't turn into a
            # meaningful condition string. "anyOf required" (rather than
            # minProperties) is used because `detection.logic` is itself an
            # optional sibling property that shouldn't count toward this check.
            "anyOf": [
                {"required": ["process"]},
                {"required": ["network"]},
                {"required": ["file"]},
                {"required": ["registry"]},
            ],
        },
        "false_positives": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
        },
        "references": _STRING_ARRAY,
    },
}
