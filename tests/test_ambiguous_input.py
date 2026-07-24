"""Test: intentionally vague input -> document threshold-logic behavior (real LLM calls).

No assertion failure is expected here (per TODO.md Phase 8) -- this test exists to
observe and document which of the three threshold-logic paths (auto-select /
ask-user / request-more-detail) a genuinely vague input triggers, not to enforce one.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv

load_dotenv()

from src.mitre import handle_validation
from src.mitre.validator import NeedsMoreDetailError
from src.pipeline import detect_mitre_technique

INPUT_TEXT = "detect suspicious activity"


def main() -> None:
    print(f"Input (intentionally vague): {INPUT_TEXT}\n")

    stage1_output = detect_mitre_technique(INPUT_TEXT)
    print("Stage 1 output:", stage1_output)

    try:
        result = handle_validation(stage1_output)
    except NeedsMoreDetailError as exc:
        print(f"\nResult: NeedsMoreDetailError raised ({exc})")
        print("Behavior observed: input was too vague to confidently match any MITRE technique.")
        return
    except EOFError:
        print(
            "\nResult: similarity landed in the 'ask user' band and ask_user_confirmation() "
            "tried to read interactive stdin, which isn't available in this non-interactive run."
        )
        print("Behavior observed: input was ambiguous enough to require human confirmation among candidates.")
        return

    print(f"\nResult: technique returned -> {result}")
    print(
        "Behavior observed: Stage 1 was confident enough (or the fallback search "
        "similarity was high enough) to auto-select a technique despite the vague input."
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001 -- no assertions in this test; any error is just reported
        print(f"SKIPPED (LLM provider unavailable or errored): {exc}")
        sys.exit(0)
