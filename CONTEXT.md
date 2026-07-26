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

The model names above are the Ollama defaults and the original design
rationale. Since then, 5 more providers were added (OpenAI, Anthropic,
Gemini, Mistral, Together AI) — see [LLM Provider Strategy](#llm-provider-strategy)
below for the full list. Whichever provider is active, Stage 1 always runs
at temperature 0.1 and Stage 2 at 0.05 (lowered from 0.2 for more
consistent IR output).

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
  → pySigma backend → KQL, SPL, Elastic DSL, Chronicle YARA-L,
                       CrowdStrike LogScale, Grafana Loki, SentinelOne, Carbon Black
```

## CTI Report Processing

When a CTI report is provided:
1. Extract keywords (LSASS, scheduled task, etc.)
2. Semantic search for candidate techniques
3. LLM validation: "Are these techniques correct? Anything missing?"
4. Priority sorting (Credential Access > Execution > Persistence > Lateral Movement)
5. Generate one IR per technique → one rule per technique

## LLM Provider Strategy

The system supports seven providers, configurable via `.env`:

```
LLM_PROVIDER=ollama     → runs models locally via Ollama
LLM_PROVIDER=groq       → Groq API (free tier, Llama 3.3 70B available)
LLM_PROVIDER=openai     → OpenAI API
LLM_PROVIDER=anthropic  → Anthropic (Claude) API
LLM_PROVIDER=gemini     → Google Gemini API
LLM_PROVIDER=mistral    → Mistral AI API
LLM_PROVIDER=together   → Together AI API
```

Model mapping (env var → default model):
- Stage 1: `qwen2.5-coder:14b` (Ollama) / `llama-3.1-8b-instant` (Groq) /
  `gpt-4o-mini` (OpenAI) / `claude-haiku-4-5-20251001` (Anthropic) /
  `gemini-2.0-flash` (Gemini) / `mistral-small-latest` (Mistral) /
  `Qwen/Qwen2.5-Coder-32B-Instruct` (Together)
- Stage 2: `llama3.3:70b` (Ollama) / `llama-3.3-70b-versatile` (Groq) /
  `gpt-4o` (OpenAI) / `claude-sonnet-4-6` (Anthropic) / `gemini-1.5-pro`
  (Gemini) / `mistral-large-latest` (Mistral) /
  `meta-llama/Llama-3.3-70B-Instruct-Turbo` (Together)

Provider is selected via the `LLM_PROVIDER` env variable. All providers
implement `BaseLLM` — pipeline code never changes. The 5 cloud providers
beyond Ollama/Groq are optional dependencies, imported lazily by
`src/llm/__init__.py`'s `get_llm()` factory so an uninstalled SDK only
affects that one provider. For users without a powerful GPU, any of the
cloud providers ensures the project still works; Groq remains the
free-tier default recommendation.

## Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| LLM providers | Ollama, Groq, OpenAI, Anthropic, Google Gemini, Mistral AI, Together AI (7 total) | Stage 1 (MITRE technique detection) + Stage 2 (IR generation) |
| Vector DB | ChromaDB | MITRE semantic search |
| Embeddings | all-MiniLM-L6-v2 | Text → vector (offline capable) |
| Rule conversion | pySigma | Sigma → 8 SIEM formats (KQL, SPL, Elastic, Chronicle, CrowdStrike, Loki, SentinelOne, Carbon Black) |
| Local inference | Ollama | Run models locally |
| Cloud inference | Groq / OpenAI / Anthropic / Gemini / Mistral / Together | Optional cloud fallbacks (Groq is the free-tier default) |
| Web dashboard | FastAPI (`dashboard/app.py`) | Browser UI + REST API, alternative to the CLI |
| PDF extraction | pdfplumber | CTI report PDF upload (dashboard only) |
| Input caching | SHA-256 + JSON files (`src/pipeline/cache.py`) | Skip repeated LLM calls, <10ms cache hits |

## Key Design Decisions

1. **IR as central format**: Decouples LLM from rule generation. LLM only produces IR; rules are generated deterministically.
2. **Two-stage LLM**: Stage 1 is fast/cheap (small model, JSON output). Stage 2 is powerful (large model, complex reasoning).
3. **Human-in-the-loop**: When similarity is ambiguous (0.65-0.85), ask the user. Security accuracy > automation convenience.
4. **pySigma for conversions**: Do not reinvent rule conversion. pySigma handles 10+ SIEM backends reliably.
5. **Offline-first**: ChromaDB + local embeddings + Ollama = fully offline capable. Groq (and the other 4 cloud providers) are optional fallbacks.
6. **Sub-technique expansion**: when a parent technique is provided, `get_subtechniques()` automatically expands to all child techniques, generating one rule set per technique.
7. **SHA-256 caching**: repeated identical inputs return cached results in <10ms without LLM calls.

## Project Structure

```
detection-engineering-assistant/
├── main.py                    # Entry point, CLI interface
├── setup.sh                   # One-command setup script
├── .env.example                # Environment variable template
├── requirements.txt            # Python dependencies (+ optional cloud LLM SDKs)
├── README.md                  # User-facing documentation (Turkish)
├── CONTEXT.md                 # This file — for AI assistants
├── ARCHITECTURE.md            # System architecture details
├── TODO.md                    # Implementation checklist
├── src/
│   ├── llm/
│   │   ├── __init__.py         # get_llm() factory, lazy importlib-based
│   │   ├── base.py            # Abstract LLM interface
│   │   ├── ollama.py          # Ollama provider
│   │   ├── groq.py            # Groq provider
│   │   ├── openai_provider.py     # OpenAI provider
│   │   ├── anthropic_provider.py  # Anthropic (Claude) provider
│   │   ├── gemini_provider.py     # Google Gemini provider
│   │   ├── mistral_provider.py    # Mistral AI provider
│   │   └── together_provider.py   # Together AI provider
│   ├── mitre/
│   │   ├── __init__.py
│   │   ├── downloader.py      # Download MITRE ATT&CK JSON, get_subtechniques()
│   │   ├── validator.py       # Validate technique IDs
│   │   └── vector_db.py       # ChromaDB setup and search
│   ├── pipeline/
│   │   ├── __init__.py
│   │   ├── stage1.py          # MITRE detection prompt + call
│   │   ├── stage2.py          # IR generation prompt + call (+ few-shot examples)
│   │   ├── cti_processor.py   # CTI report preprocessing
│   │   └── cache.py           # SHA-256 input caching
│   ├── ir/
│   │   ├── __init__.py
│   │   ├── schema.py          # IR JSON schema definition
│   │   └── validator.py       # IR validation + auto-fix
│   └── rules/
│       ├── __init__.py
│       ├── sigma.py           # IR → Sigma YAML
│       └── converter.py       # Sigma → 8 SIEM formats via pySigma
└── dashboard/                 # FastAPI web UI (alternative to the CLI)
    ├── app.py                  # REST API: /api/generate, /api/upload-pdf, /api/history, /health
    ├── static/index.html       # Self-contained HTML/CSS/JS frontend
    ├── requirements.txt        # fastapi, uvicorn, pdfplumber, python-multipart
    └── README.md
```
