#!/usr/bin/env python3
"""Detection Engineering Assistant — CLI entry point."""
import argparse
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.syntax import Syntax

from src.ir import IRValidationError
from src.mitre import get_subtechniques, handle_validation
from src.mitre.validator import NeedsMoreDetailError
from src.pipeline import (
    detect_mitre_technique,
    extract_context_for_technique,
    extract_techniques_from_report,
    generate_ir,
    is_cti_report,
)
from src.pipeline.cti_processor import chunk_report
from src.rules import convert_ir

console = Console()

PROJECT_NAME = "Detection Engineering Assistant"

# (result dict key, display label, pygments lexer, file extension)
# Note: "qradar" and "insightidr" are intentionally not listed here -- see the
# comment in src.rules.converter.sigma_to_all() for why those two backends
# aren't added (pysigma version incompatibility, not a naming issue).
FORMATS = [
    ("sigma", "Sigma YAML", "yaml", "sigma"),
    ("kql", "KQL (Microsoft Sentinel)", "text", "kql"),
    ("splunk", "SPL (Splunk)", "text", "splunk"),
    ("elastic", "Elastic DSL", "text", "elastic"),
    ("chronicle", "Chronicle YARA-L", "text", "chronicle"),
    ("crowdstrike", "CrowdStrike LogScale", "text", "crowdstrike"),
    ("loki", "Grafana Loki", "text", "loki"),
    ("sentinelone", "SentinelOne", "text", "sentinelone"),
    ("carbonblack", "Carbon Black", "text", "carbonblack"),
]


def print_banner() -> None:
    provider = os.getenv("LLM_PROVIDER", "not set")
    console.print(
        Panel.fit(
            f"[bold]{PROJECT_NAME}[/bold]\nActive LLM provider: [cyan]{provider}[/cyan]",
            border_style="blue",
        )
    )


# --- Pipeline orchestration -------------------------------------------------


def run_short_sentence(user_input: str) -> list[tuple[dict, dict, dict]]:
    console.print("[dim]Detecting MITRE technique...[/dim]")
    stage1_output = detect_mitre_technique(user_input)

    console.print("[dim]Validating technique...[/dim]")
    validated_technique = handle_validation(stage1_output)

    console.print("[dim]Generating detection IR...[/dim]")
    ir = generate_ir(user_input, validated_technique)

    console.print("[dim]Converting to SIEM formats...[/dim]")
    formats = convert_ir(ir)

    results = [({"technique_id": validated_technique["id"]}, ir, formats)]

    if not validated_technique.get("is_subtechnique", False):
        subtechniques = get_subtechniques(validated_technique["id"])
        if subtechniques:
            console.print(
                f"[cyan]Found {len(subtechniques)} sub-techniques for "
                f"{validated_technique['id']}. Generating rules for all.[/cyan]"
            )
            for subtechnique in subtechniques:
                sub_ir = generate_ir(user_input, subtechnique)
                sub_formats = convert_ir(sub_ir)
                results.append(({"technique_id": subtechnique["id"]}, sub_ir, sub_formats))

    return results


def run_cti_report(report: str) -> list[tuple[dict, dict, dict]]:
    console.print("[dim]Extracting candidate techniques from report...[/dim]")
    technique_list = extract_techniques_from_report(report)
    report_chunks = chunk_report(report)

    results = []
    for tech in technique_list:
        console.print(f"[dim]Processing {tech['technique_id']}...[/dim]")

        validated_technique = handle_validation(
            {
                "mitre_technique_id": tech["technique_id"],
                "mitre_technique_name": "",
                "reasoning": "",
            }
        )
        context = extract_context_for_technique(report_chunks, validated_technique)
        ir = generate_ir(report, validated_technique, context_snippet=context)
        formats = convert_ir(ir)

        results.append((tech, ir, formats))

        if not validated_technique.get("is_subtechnique", False):
            subtechniques = get_subtechniques(validated_technique["id"])
            if subtechniques:
                console.print(
                    f"[cyan]Found {len(subtechniques)} sub-techniques for "
                    f"{validated_technique['id']}. Generating rules for all.[/cyan]"
                )
                for subtechnique in subtechniques:
                    sub_context = extract_context_for_technique(report_chunks, subtechnique)
                    sub_ir = generate_ir(report, subtechnique, context_snippet=sub_context)
                    sub_formats = convert_ir(sub_ir)
                    results.append(({"technique_id": subtechnique["id"]}, sub_ir, sub_formats))

    return results


def run_pipeline_for_text(text: str) -> list[tuple[dict, dict, dict]]:
    if is_cti_report(text):
        console.print("[dim]Detected CTI report — running multi-technique extraction.[/dim]")
        return run_cti_report(text)

    console.print("[dim]Detected short-sentence input — running single-technique pipeline.[/dim]")
    return run_short_sentence(text)


# --- Display / save ----------------------------------------------------------


def _technique_folder_name(technique_id: str) -> str:
    return technique_id.replace(".", "_")


def display_results(results: list[tuple[dict, dict, dict]]) -> None:
    for tech_info, ir, formats in results:
        mitre = ir["mitre"]
        header = f"[bold]{mitre['technique_id']}[/bold] — {mitre['technique_name']} ({mitre['tactic']})"
        if "similarity" in tech_info:
            header += f"\nSimilarity: {tech_info['similarity']:.2f}"
        if "confidence" in tech_info:
            header += f"  Confidence: {tech_info['confidence']}"

        console.print(Panel(header, title=ir["meta"]["title"], border_style="cyan"))

        for key, label, lexer, _ext in FORMATS:
            content = formats.get(key)
            console.print(f"[bold]{label}[/bold]")
            if content is None:
                console.print("[dim][not available][/dim]")
            else:
                console.print(Syntax(content, lexer, theme="ansi_dark", word_wrap=True))
            console.print()

    print_summary(results)


def save_results(output_dir: Path, results: list[tuple[dict, dict, dict]]) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    saved_folders = []

    for _tech_info, ir, formats in results:
        technique_id = ir["mitre"]["technique_id"]
        folder = output_dir / _technique_folder_name(technique_id)
        folder.mkdir(parents=True, exist_ok=True)

        for key, _label, _lexer, ext in FORMATS:
            content = formats.get(key)
            if content is None:
                continue
            (folder / f"rule.{ext}").write_text(content, encoding="utf-8")

        (folder / "ir.json").write_text(json.dumps(ir, indent=2), encoding="utf-8")
        saved_folders.append(folder)

    return saved_folders


def print_summary(results: list[tuple[dict, dict, dict]]) -> None:
    total_rules = sum(1 for _, _, formats in results for value in formats.values() if value is not None)
    console.print(f"[bold]Generated {total_rules} rules from {len(results)} technique(s)[/bold]")


# --- Modes --------------------------------------------------------------------


def run_interactive() -> None:
    console.print("[dim]Describe an attack scenario or paste a CTI report. Press Ctrl+C to exit.[/dim]\n")

    while True:
        try:
            user_input = Prompt.ask("[bold green]Describe the detection you need[/bold green]")
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Goodbye.[/dim]")
            return

        if not user_input.strip():
            continue

        try:
            results = run_pipeline_for_text(user_input)
        except NeedsMoreDetailError:
            continue  # helpful message already printed by request_more_detail()
        except IRValidationError as exc:
            console.print(f"[red]IR generation failed after retries:[/red] {exc}")
            continue
        except RuntimeError as exc:
            console.print(f"[red]LLM error:[/red] {exc}")
            continue
        except KeyboardInterrupt:
            console.print("\n[dim]Goodbye.[/dim]")
            return
        except Exception as exc:  # noqa: BLE001 -- keep the REPL alive on unexpected errors
            console.print(f"[red]Unexpected error:[/red] {exc}")
            continue

        display_results(results)

        try:
            again = Confirm.ask("Generate another?", default=True)
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Goodbye.[/dim]")
            return

        if not again:
            console.print("[dim]Goodbye.[/dim]")
            return


def run_file_mode(input_path: str, output_dir: str) -> int:
    path = Path(input_path)
    if not path.exists():
        console.print(f"[red]Input file not found:[/red] {input_path}")
        return 1

    text = path.read_text(encoding="utf-8")

    try:
        results = run_pipeline_for_text(text)
    except NeedsMoreDetailError:
        return 1
    except IRValidationError as exc:
        console.print(f"[red]IR generation failed after retries:[/red] {exc}")
        return 1
    except RuntimeError as exc:
        console.print(f"[red]LLM error:[/red] {exc}")
        return 1

    saved_folders = save_results(Path(output_dir), results)

    console.print(f"\n[green]Saved {len(saved_folders)} technique(s) to {output_dir}:[/green]")
    for folder in saved_folders:
        console.print(f"  - {folder}")

    print_summary(results)
    return 0


def main() -> int:
    load_dotenv()

    parser = argparse.ArgumentParser(description=PROJECT_NAME)
    parser.add_argument("--input", help="Path to a CTI report or input file (enables file mode)")
    parser.add_argument("--output", default=os.getenv("OUTPUT_DIR", "./output"), help="Output directory for generated rules")
    args = parser.parse_args()

    print_banner()

    if args.input:
        return run_file_mode(args.input, args.output)

    run_interactive()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        console.print("\n[dim]Goodbye.[/dim]")
        sys.exit(130)
