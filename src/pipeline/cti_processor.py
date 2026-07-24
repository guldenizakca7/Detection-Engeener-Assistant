"""CTI report preprocessing: chunking, technique extraction, and context extraction."""
from __future__ import annotations

import os
import re

from src.llm import get_llm
from src.mitre import vector_db

CTI_REPORT_MIN_CHARS = 500
DEFAULT_MAX_CHUNK_CHARS = 4000
CONSOLIDATION_CANDIDATE_LIMIT = 10
CONSOLIDATION_EXCERPT_MAX_CHARS = 6000
CONTEXT_MAX_CHARS = 2000

CONSOLIDATION_SYSTEM_PROMPT = (
    "You are a Detection Engineering expert specialized in MITRE ATT&CK. "
    "Return ONLY a raw JSON array, no markdown, no explanation."
)

# Keyword-triggered queries: a second search pass for short reports where the
# whole thing fits in one chunk, so the chunk-level query alone is too generic
# and can miss techniques whose signal is a specific term rather than the
# chunk's overall gist. Each tuple is (keywords to look for, query to search).
KEYWORD_QUERY_RULES = [
    (("mimikatz", "lsass", "credential dump"), "credential dumping LSASS memory mimikatz"),
    (("rdp", "remote desktop"), "remote desktop protocol lateral movement RDP"),
    (("scheduled task", "schtasks"), "scheduled task persistence execution"),
    (("registry", "run key"), "registry run key persistence"),
    (("phishing", "spearphishing"), "spearphishing email initial access"),
    (("powershell",), "PowerShell execution command"),
]

# Priority order for sorting confirmed techniques; tactics not listed sort last.
# This mirrors the kill-chain ordering CONTEXT.md/ARCHITECTURE.md specify for CTI
# processing (credential access before execution before persistence before
# lateral movement, ...): a report usually describes multiple techniques out of
# chronological/narrative order, so results are re-ordered by attacker-impact
# priority rather than by where they happened to appear in the text or by raw
# similarity score, since credential theft is generally the higher-priority
# finding for an analyst to see first regardless of paragraph order.
TACTIC_PRIORITY = [
    "credential-access",
    "execution",
    "persistence",
    "lateral-movement",
    "defense-evasion",
    "discovery",
    "collection",
    "exfiltration",
    "impact",
]

_PARAGRAPH_SPLIT_RE = re.compile(r"\n\s*\n")
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")


def is_cti_report(text: str) -> bool:
    """Heuristic: treat any input longer than 500 characters as a CTI report."""
    return len(text) > CTI_REPORT_MIN_CHARS


def chunk_report(text: str, max_chars: int = DEFAULT_MAX_CHUNK_CHARS) -> list[str]:
    """Split a report into chunks: first on paragraph boundaries, then on sentence
    boundaries for any paragraph that still exceeds max_chars.

    Args:
        text: The full report text.
        max_chars: Maximum characters per chunk (soft limit for oversized
            paragraphs; a single sentence longer than this is kept whole).

    Returns:
        The list of chunk strings, in original order.
    """
    paragraphs = [p.strip() for p in _PARAGRAPH_SPLIT_RE.split(text) if p.strip()]

    chunks = []
    for paragraph in paragraphs:
        if len(paragraph) <= max_chars:
            chunks.append(paragraph)
            continue

        sentences = _SENTENCE_SPLIT_RE.split(paragraph)
        current = ""
        for sentence in sentences:
            candidate = f"{current} {sentence}".strip() if current else sentence
            if len(candidate) > max_chars and current:
                chunks.append(current)
                current = sentence
            else:
                current = candidate
        if current:
            chunks.append(current)

    return chunks


def _tactic_priority(tactic: str | None) -> int:
    """Return tactic's sort rank in TACTIC_PRIORITY (unlisted/unknown tactics sort last)."""
    try:
        return TACTIC_PRIORITY.index(tactic)
    except ValueError:
        return len(TACTIC_PRIORITY)


def _confidence_from_similarity(similarity: float, threshold_auto: float) -> str:
    """Map a search similarity score to a coarse "high"/"medium" confidence label."""
    return "high" if similarity >= threshold_auto else "medium"


def _consolidate_with_llm(report: str, candidates: list[dict]) -> set[str]:
    """Ask the Stage 1 LLM which of the semantic-search candidates are actually
    described in the report, filtering out adjacent/false-positive matches."""
    excerpt = report[:CONSOLIDATION_EXCERPT_MAX_CHARS]
    candidates_block = "\n".join(
        f"- {c['technique_id']}: {c['name']} ({c['tactic']}), similarity {c['similarity']:.2f}"
        for c in candidates
    )

    prompt = (
        "Given this CTI report excerpt and these candidate MITRE techniques, "
        "confirm which ones are actually present. Return JSON array of "
        "confirmed technique IDs only.\n\n"
        f"CTI report excerpt:\n{excerpt}\n\n"
        f"Candidate techniques:\n{candidates_block}"
    )

    llm = get_llm("stage1")
    confirmed = llm.complete_json(prompt, CONSOLIDATION_SYSTEM_PROMPT)
    return set(confirmed)


def extract_techniques_from_report(report: str) -> list[dict]:
    """Full CTI processing pipeline: chunk, semantic search, LLM consolidation,
    and priority-sort by tactic.

    Args:
        report: The full CTI report text.

    Returns:
        A list of {technique_id, confidence, similarity} dicts, one per
        confirmed technique, sorted by TACTIC_PRIORITY. Empty if no candidate
        cleared THRESHOLD_ASK.
    """
    threshold_ask = float(os.getenv("THRESHOLD_ASK", "0.65"))
    threshold_auto = float(os.getenv("THRESHOLD_AUTO", "0.85"))

    chunks = chunk_report(report)

    best_by_id: dict[str, dict] = {}
    for chunk in chunks:
        for match in vector_db.search(chunk, top_k=3):
            technique_id = match["technique_id"]
            if technique_id not in best_by_id or match["similarity"] > best_by_id[technique_id]["similarity"]:
                best_by_id[technique_id] = match

    # Second pass: keyword-triggered queries. Short reports fit in a single
    # chunk, so the chunk-level search above produces one generic query for
    # the whole report and can miss techniques that only show up as a
    # specific term. Scanning for known keywords and running targeted queries
    # catches those without changing the chunk-level search or dedup logic.
    report_lower = report.lower()
    for keywords, query in KEYWORD_QUERY_RULES:
        if any(keyword in report_lower for keyword in keywords):
            for match in vector_db.search(query, top_k=3):
                technique_id = match["technique_id"]
                if technique_id not in best_by_id or match["similarity"] > best_by_id[technique_id]["similarity"]:
                    best_by_id[technique_id] = match

    candidates = [m for m in best_by_id.values() if m["similarity"] >= threshold_ask]
    candidates.sort(key=lambda m: m["similarity"], reverse=True)
    top_candidates = candidates[:CONSOLIDATION_CANDIDATE_LIMIT]

    if not top_candidates:
        return []

    confirmed_ids = _consolidate_with_llm(report, top_candidates)
    confirmed = [c for c in top_candidates if c["technique_id"] in confirmed_ids]
    confirmed.sort(key=lambda c: _tactic_priority(c["tactic"]))

    return [
        {
            "technique_id": c["technique_id"],
            "confidence": _confidence_from_similarity(c["similarity"], threshold_auto),
            "similarity": c["similarity"],
        }
        for c in confirmed
    ]


def extract_context_for_technique(report_chunks: list[str], technique: dict) -> str:
    """Extract the report sentences/paragraphs most relevant to a confirmed technique.

    Args:
        report_chunks: The report split into chunks (from chunk_report()).
        technique: A full MITRE technique dict (id, name, tactic, ...) as
            returned by src.mitre.validate_technique_id.

    Returns:
        The most relevant chunks joined with "\\n---\\n", truncated to
        CONTEXT_MAX_CHARS. This is what gets passed to generate_ir() as
        context_snippet -- never the full report.
    """
    query = f"{technique.get('id')} {technique.get('name')} {technique.get('tactic')}"
    relevant = vector_db.search_in_chunks(query, corpus=report_chunks, top_k=5)
    context = "\n---\n".join(relevant)
    return context[:CONTEXT_MAX_CHARS]
