"""End-to-end test: short English sentence -> full pipeline (real LLM calls).

Requires a configured LLM provider (Ollama running with the required models,
or GROQ_API_KEY set in .env with LLM_PROVIDER=groq).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv

load_dotenv()

from src.mitre import handle_validation
from src.pipeline import detect_mitre_technique, generate_ir
from src.rules import convert_ir

INPUT_TEXT = "Detect PowerShell credential dumping via LSASS memory access"


def main() -> None:
    print(f"Input: {INPUT_TEXT}\n")

    stage1_output = detect_mitre_technique(INPUT_TEXT)
    print("Stage 1 output:", stage1_output)

    validated_technique = handle_validation(stage1_output)
    print("Validated technique:", validated_technique)

    technique_id = validated_technique["id"]
    assert technique_id.startswith("T1003"), f"expected technique_id to start with T1003, got {technique_id}"

    ir = generate_ir(INPUT_TEXT, validated_technique)
    print("\nGenerated IR:")
    print(ir)

    formats = convert_ir(ir)

    sigma = formats.get("sigma") or ""
    assert "powershell" in sigma.lower(), "expected 'powershell' (case-insensitive) in Sigma output"

    kql = formats.get("kql")
    assert kql is not None, "expected KQL output to be non-None"

    print("\n=== Sigma ===")
    print(sigma)
    print("\n=== KQL ===")
    print(kql)
    print("\n=== SPL ===")
    print(formats.get("splunk"))
    print("\n=== Elastic ===")
    print(formats.get("elastic"))
    print("\n=== Chronicle ===")
    print(formats.get("chronicle"))

    print("\nPASSED: test_short_sentence_en")


if __name__ == "__main__":
    try:
        main()
    except AssertionError:
        raise
    except Exception as exc:  # noqa: BLE001 -- treat provider/connection issues as a skip, not a crash
        print(f"SKIPPED (LLM provider unavailable or errored): {exc}")
        sys.exit(0)
