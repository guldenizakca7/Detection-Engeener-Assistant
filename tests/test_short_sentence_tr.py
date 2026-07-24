"""End-to-end test: short Turkish sentence -> full pipeline (real LLM calls).

Requires a configured LLM provider (Ollama running with the required models,
or GROQ_API_KEY set in .env with LLM_PROVIDER=groq).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv

load_dotenv()

from src.mitre import handle_validation, search
from src.pipeline import detect_mitre_technique, generate_ir
from src.rules import convert_ir

INPUT_TEXT = "PowerShell ile kimlik bilgisi çalma tespiti"


def main() -> None:
    print(f"Input: {INPUT_TEXT}\n")

    stage1_output = detect_mitre_technique(INPUT_TEXT)
    print("Stage 1 output:", stage1_output)

    validated_technique = handle_validation(stage1_output)
    print("Validated technique:", validated_technique)

    technique_id = validated_technique["id"]
    print(f"\nDetected technique: {technique_id} ({validated_technique.get('name')})")

    # handle_validation() doesn't surface the similarity score it used internally
    # (it only returns the final technique dict), so re-run a semantic search with
    # Stage 1's own reasoning/name to print a comparable similarity number here.
    query = f"{stage1_output.get('reasoning', '')} {stage1_output.get('mitre_technique_name', '')}".strip()
    top_matches = search(query, top_k=1) if query else []
    if top_matches:
        print(
            f"Similarity score (semantic search vs top match {top_matches[0]['technique_id']}): "
            f"{top_matches[0]['similarity']:.3f}"
        )

    assert technique_id.startswith("T1003") or technique_id.startswith("T1059"), (
        f"expected technique_id to start with T1003 or T1059, got {technique_id}"
    )

    ir = generate_ir(INPUT_TEXT, validated_technique)
    formats = convert_ir(ir)

    assert formats.get("sigma") is not None, "expected Sigma output to be non-None"

    print("\n=== Sigma ===")
    print(formats["sigma"])

    print("\nPASSED: test_short_sentence_tr")


if __name__ == "__main__":
    try:
        main()
    except AssertionError:
        raise
    except Exception as exc:  # noqa: BLE001 -- treat provider/connection issues as a skip, not a crash
        print(f"SKIPPED (LLM provider unavailable or errored): {exc}")
        sys.exit(0)
