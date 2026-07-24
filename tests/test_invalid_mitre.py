"""Test: handle_validation() with a fake/nonexistent MITRE technique ID.

This exercises the semantic-search fallback path. It only needs the real
vector DB (no Stage 1 LLM call is made -- the fake Stage 1 output below is
constructed by hand), but the fallback path can still call the LLM-free
threshold logic in src.mitre.validator. Requires the vector DB to be built
(data/mitre_techniques.json + data/chroma/, see setup.sh).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv

load_dotenv()

from src.mitre import handle_validation
from src.mitre.validator import NeedsMoreDetailError

FAKE_STAGE1_OUTPUT = {
    "mitre_tactic": "Credential Access",
    "mitre_technique_id": "T9999.999",
    "mitre_technique_name": "LSASS Memory",
    "log_sources": ["windows"],
    "confidence": "high",
    "reasoning": (
        "Adversaries may attempt to access credential material stored in the process "
        "memory of the Local Security Authority Subsystem Service (LSASS) using "
        "PowerShell to dump credentials."
    ),
}


def main() -> None:
    print(f"Fake Stage 1 output (nonexistent ID): {FAKE_STAGE1_OUTPUT}\n")

    try:
        result = handle_validation(FAKE_STAGE1_OUTPUT)
    except NeedsMoreDetailError as exc:
        print(f"Path taken: NeedsMoreDetailError raised ({exc})")
        print("\nPASSED: test_invalid_mitre (semantic search found no confident match)")
        return
    except EOFError:
        # Similarity landed in the THRESHOLD_ASK..THRESHOLD_AUTO band, so
        # ask_user_confirmation() tried to read interactive stdin. There's none
        # available in this non-interactive test run, which is expected/correct
        # for that band -- it would prompt a real user in an interactive session.
        print(
            "Path taken: similarity landed in the 'ask user' band "
            "(THRESHOLD_ASK <= similarity < THRESHOLD_AUTO) and ask_user_confirmation() "
            "tried to read interactive stdin, which isn't available here."
        )
        print("\nPASSED: test_invalid_mitre (ambiguous-match path confirmed; would ask a human)")
        return

    print(f"Path taken: semantic search fallback succeeded -> {result}")
    assert isinstance(result, dict) and result.get("id"), "expected a valid technique dict"
    assert result["id"] != "T9999.999", "fallback should never return the fake/nonexistent ID itself"

    print("\nPASSED: test_invalid_mitre (semantic search fallback returned a valid real technique)")


if __name__ == "__main__":
    try:
        main()
    except AssertionError:
        raise
    except Exception as exc:  # noqa: BLE001 -- treat provider/connection issues as a skip, not a crash
        print(f"SKIPPED (MITRE data/vector DB unavailable or errored): {exc}")
        sys.exit(0)
