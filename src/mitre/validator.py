"""Validate MITRE technique IDs, falling back to semantic search when needed."""
from __future__ import annotations

import json
import os
from pathlib import Path

from rich.console import Console
from rich.table import Table

from . import vector_db

console = Console()

_techniques: dict | None = None


class NeedsMoreDetailError(Exception):
    """Raised when the input is too vague to confidently match a MITRE technique."""


def _data_dir() -> Path:
    """Return the configured data directory (DATA_DIR, default ./data)."""
    return Path(os.getenv("DATA_DIR", "./data"))


def _load_techniques() -> dict:
    """Return the technique catalog, loading it from disk once and caching it."""
    global _techniques
    if _techniques is None:
        path = _data_dir() / "mitre_techniques.json"
        if not path.exists():
            raise RuntimeError(f"{path} not found. Run download_mitre_data() first.")
        with open(path, "r", encoding="utf-8") as f:
            _techniques = json.load(f)
    return _techniques


def validate_technique_id(technique_id: str) -> dict | None:
    """Return the technique dict if technique_id exists in the local catalog, else None.

    Args:
        technique_id: A MITRE technique ID, e.g. "T1003.001".

    Returns:
        The technique dict (id, name, description, tactic, is_subtechnique), or
        None if technique_id isn't a real, current technique.
    """
    techniques = _load_techniques()
    return techniques.get(technique_id)


def handle_validation(llm_stage1_output: dict) -> dict:
    """Validate a Stage 1 LLM output, falling back to semantic search if the ID is invalid.

    Args:
        llm_stage1_output: Stage 1's parsed JSON output. Must contain
            "mitre_technique_id"; "mitre_technique_name" and "reasoning" are
            used to build the fallback search query if the ID is invalid.

    Returns:
        The resolved technique dict (id, name, description, tactic, is_subtechnique).

    Raises:
        NeedsMoreDetailError: If no technique could be confidently resolved
            (see request_more_detail).
    """
    threshold_auto = float(os.getenv("THRESHOLD_AUTO", "0.85"))
    threshold_ask = float(os.getenv("THRESHOLD_ASK", "0.65"))

    technique_id = llm_stage1_output.get("mitre_technique_id")
    technique = validate_technique_id(technique_id) if technique_id else None

    if technique is not None:
        # Fast path: Stage 1 already gave us a real technique ID, no search needed.
        console.print(f"[green]MITRE technique {technique_id} validated.[/green]")
        return technique

    console.print(
        f"[yellow]'{technique_id}' is not a recognized MITRE technique ID. "
        "Searching for the closest match...[/yellow]"
    )

    technique_name = llm_stage1_output.get("mitre_technique_name", "")
    reasoning = llm_stage1_output.get("reasoning", "")
    query = f"{reasoning} {technique_name}".strip()

    results = vector_db.search(query, top_k=3)
    if not results:
        return request_more_detail()

    # Three-band threshold logic (see ARCHITECTURE.md "Similarity Threshold Logic"):
    #   similarity >= THRESHOLD_AUTO (0.85) -> confident enough to auto-select,
    #     no human involved.
    #   THRESHOLD_ASK (0.65) <= similarity < THRESHOLD_AUTO -> plausible but not
    #     certain; show the top 3 candidates and let a human pick.
    #   similarity < THRESHOLD_ASK -> too far off to guess; ask for more detail
    #     instead of risking a wrong technique.
    # This human-in-the-loop middle band is a deliberate design choice: wrong
    # detections are worse than asking, since these rules get deployed.
    top = results[0]
    if top["similarity"] >= threshold_auto:
        console.print(
            f"[green]Auto-selected {top['technique_id']} ({top['name']}) "
            f"— similarity {top['similarity']:.2f}[/green]"
        )
        return validate_technique_id(top["technique_id"])
    elif top["similarity"] >= threshold_ask:
        return ask_user_confirmation(results)
    else:
        return request_more_detail()


def ask_user_confirmation(candidates: list[dict]) -> dict:
    """Show the top 3 candidate techniques and let the user pick one via CLI prompt.

    Args:
        candidates: Semantic search results, sorted by similarity descending
            (only the first 3 are shown/selectable).

    Returns:
        The chosen technique dict, or the result of request_more_detail() if
        the user enters 0 or an invalid choice.
    """
    top3 = candidates[:3]

    table = Table(title="Closest MITRE Technique Matches")
    table.add_column("#", justify="right")
    table.add_column("Technique ID")
    table.add_column("Name")
    table.add_column("Tactic")
    table.add_column("Similarity", justify="right")

    for i, candidate in enumerate(top3, start=1):
        table.add_row(
            str(i),
            candidate["technique_id"],
            candidate["name"] or "",
            candidate["tactic"] or "",
            f"{candidate['similarity']:.2f}",
        )

    console.print(table)

    choice = console.input("Select a technique [1-3], or 0 to cancel: ").strip()
    if choice not in ("1", "2", "3"):
        return request_more_detail()

    selected = top3[int(choice) - 1]
    return validate_technique_id(selected["technique_id"])


def request_more_detail() -> None:
    """Print a helpful message asking the user to rephrase with more detail, then raise.

    Raises:
        NeedsMoreDetailError: Always -- this function never returns normally.
    """
    console.print(
        "[red]Couldn't confidently match a MITRE technique.[/red] "
        "Please rephrase your input with more detail (e.g. the tool, "
        "log source, or specific behavior involved)."
    )
    raise NeedsMoreDetailError("Input was too vague to match a MITRE technique.")


if __name__ == "__main__":
    # Run with: python -m src.mitre.validator
    from dotenv import load_dotenv

    load_dotenv()

    print("validate_technique_id('T1003.001') ->", validate_technique_id("T1003.001"))
    print("validate_technique_id('T9999.999') ->", validate_technique_id("T9999.999"))

    result = handle_validation(
        {
            "mitre_technique_id": "T1003.001",
            "mitre_technique_name": "LSASS Memory",
            "reasoning": "credential dumping via LSASS",
        }
    )
    print("handle_validation(...) ->", result)
