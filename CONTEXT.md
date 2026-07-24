# Project Context

## What This Project Is

Detection Engineering Assistant is an AI-powered system that automatically generates security detection rules from natural language input or CTI (Cyber Threat Intelligence) reports. The user describes an attack scenario, and the system produces ready-to-use detection rules in multiple SIEM formats.

## Core Problem Being Solved

Writing detection rules manually is:
- Time-consuming (hours per rule)
- Requires deep expertise in both MITRE ATT&CK and SIEM query languages
- Error-prone and inconsistent
- Hard to scale across all MITRE ATT&CK coverage

## Two Input Modes

1. **Short sentence**: `"Detect PowerShell credential dumping"`
2. **CTI report**: Long threat intelligence report pasted by the user

Both inputs go through the same pipeline. CTI reports go through a summarization step first.

## Two-Stage LLM Architecture

The system uses two different LLMs for two different tasks:

### Stage 1 — MITRE Detection (Qwen2.5 Coder 14B)
- Input: User's natural language
- Output: MITRE tactic, technique ID, log sources
- Why Qwen: Specialized for structured JSON output, very reliable format adherence

### Stage 2 — IR Generation (Llama 3.3 70B)
- Input: Validated MITRE technique + original user input
- Output: Intermediate Representation (IR) JSON
- Why Llama 3.3: Strong reasoning for complex CTI analysis, available free on Groq

## Intermediate Representation (IR)

IR is the central data structure of the system. It is a structured JSON that sits between LLM output and rule generation. All rule formats (Sigma, KQL, SPL, etc.) are generated FROM the IR deterministically — no LLM involved in rule generation.

```json
{
  "meta": {
    "title": "PowerShell Credential Dumping Detection",
    "description": "Detects LSASS memory access via PowerShell",
    "severity": "high",
    "confidence": "high"
  },
  "mitre": {
    "tactic": "Credential Access",
    "technique_id": "T1003.001",
    "technique_name": "LSASS Memory"
  },
  "log_source": {
    "platform": "windows",
    "category": "process_creation",
    "product": "sysmon"
  },
  "detection": {
    "process": {
      "name": ["powershell.exe", "pwsh.exe"],
      "command_contains": ["sekurlsa", "lsass", "mimikatz"]
    },
    "network": null,
    "file": null,
    "registry": null
  },
  "false_positives": [
    "Legitimate system administration tools"
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1003/001"
  ]
}
```

## MITRE Validation + Semantic Search

After Stage 1, the system validates the MITRE technique ID:

1. **Check MITRE JSON**: Is T1003.001 a real technique?
2. **If valid** → proceed to Stage 2
3. **If invalid** → run ChromaDB semantic search to find closest real technique
4. **Similarity thresholds**:
   - `> 0.85` → auto-select, proceed
   - `0.65 - 0.85` → ask user to confirm from top 3 candidates
   - `< 0.65` → ask user for more detail

The "ask user" step is intentional (Human-in-the-loop). Security rules must be accurate — user confirmation prevents wrong detections.

## Rule Generation Flow

```
IR (JSON)
  → ir_to_sigma() → Sigma YAML (deterministic Python, no LLM)
  → pySigma backend → KQL
  → pySigma backend → SPL
  → pySigma backend → Elastic DSL
  → pySigma backend → Chronicle YARA-L
```

## CTI Report Processing

When a CTI report is provided:
1. Extract keywords (LSASS, scheduled task, etc.)
2. Semantic search for candidate techniques
3. LLM validation: "Are these techniques correct? Anything missing?"
4. Priority sorting (Credential Access > Execution > Persistence > Lateral Movement)
5. Generate one IR per technique → one rule per technique

## LLM Provider Strategy

The system supports two providers, configurable via `.env`:

```
LLM_PROVIDER=ollama  → runs models locally via Ollama
LLM_PROVIDER=groq    → uses Groq API (free tier, Llama 3.3 70B available)
```

Model mapping:
- Stage 1: `qwen2.5-coder:14b` (Ollama) or `qwen-2.5-coder-14b` (Groq if available)
- Stage 2: `llama3.3:70b` (Ollama) or `llama-3.3-70b-versatile` (Groq)

For users without a powerful GPU, Groq fallback ensures the project still works.

## Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| Stage 1 LLM | Qwen2.5 Coder 14B | MITRE technique detection |
| Stage 2 LLM | Llama 3.3 70B | IR generation, CTI analysis |
| Vector DB | ChromaDB | MITRE semantic search |
| Embeddings | all-MiniLM-L6-v2 | Text → vector (offline capable) |
| Rule conversion | pySigma | Sigma → KQL/SPL/Elastic/Chronicle |
| Local inference | Ollama | Run models locally |
| Cloud inference | Groq API | Free cloud fallback |

## Key Design Decisions

1. **IR as central format**: Decouples LLM from rule generation. LLM only produces IR; rules are generated deterministically.
2. **Two-stage LLM**: Stage 1 is fast/cheap (small model, JSON output). Stage 2 is powerful (large model, complex reasoning).
3. **Human-in-the-loop**: When similarity is ambiguous (0.65-0.85), ask the user. Security accuracy > automation convenience.
4. **pySigma for conversions**: Do not reinvent rule conversion. pySigma handles 10+ SIEM backends reliably.
5. **Offline-first**: ChromaDB + local embeddings + Ollama = fully offline capable. Groq is optional fallback.

## Project Structure

```
detection-engineering-assistant/
├── main.py                    # Entry point, CLI interface
├── setup.sh                   # One-command setup script
├── .env.example               # Environment variable template
├── requirements.txt           # Python dependencies
├── README.md                  # User-facing documentation (Turkish)
├── CONTEXT.md                 # This file — for AI assistants
├── ARCHITECTURE.md            # System architecture details
├── TODO.md                    # Implementation checklist
└── src/
    ├── llm/
    │   ├── __init__.py
    │   ├── base.py            # Abstract LLM interface
    │   ├── ollama.py          # Ollama provider
    │   └── groq.py            # Groq provider
    ├── mitre/
    │   ├── __init__.py
    │   ├── downloader.py      # Download MITRE ATT&CK JSON
    │   ├── validator.py       # Validate technique IDs
    │   └── vector_db.py       # ChromaDB setup and search
    ├── pipeline/
    │   ├── __init__.py
    │   ├── stage1.py          # MITRE detection prompt + call
    │   ├── stage2.py          # IR generation prompt + call
    │   └── cti_processor.py   # CTI report preprocessing
    ├── ir/
    │   ├── __init__.py
    │   ├── schema.py          # IR JSON schema definition
    │   └── validator.py       # IR validation + auto-fix
    └── rules/
        ├── __init__.py
        ├── sigma.py           # IR → Sigma YAML
        └── converter.py       # Sigma → KQL/SPL/Elastic/Chronicle via pySigma
```
