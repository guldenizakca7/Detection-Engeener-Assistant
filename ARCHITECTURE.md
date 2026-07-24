# Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────┐
│                     INPUT LAYER                          │
│                                                          │
│   [Short Sentence]          [CTI Report]                 │
│   "Detect PS credential     Long threat intel report     │
│    dumping"                 pasted by user               │
└──────────────┬──────────────────────┬───────────────────┘
               │                      │
               │              ┌───────▼────────────┐
               │              │ CTI Processor      │
               │              │ - Chunk report     │
               │              │ - Find techniques  │
               │              │ - Extract context  │
               │              └───────┬────────────┘
               │                      │
               └──────────┬───────────┘
                          │
┌─────────────────────────▼───────────────────────────────┐
│                     STAGE 1                              │
│             LLM: Qwen2.5 Coder 14B                       │
│                                                          │
│   Input:  Natural language description                   │
│   Output: { tactic, technique_id, log_sources,           │
│             confidence, reasoning }                      │
└─────────────────────────┬───────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────┐
│                   VALIDATION LAYER                       │
│                                                          │
│   1. MITRE JSON check: Does T1003.001 exist?             │
│                                                          │
│   2a. similarity > 0.85  → auto-proceed                  │
│   2b. similarity 0.65-0.85 → ask user (top 3 options)   │
│   2c. similarity < 0.65  → request more detail           │
│                                                          │
│   [ChromaDB]  ←→  [all-MiniLM-L6-v2 embeddings]         │
│   600+ MITRE techniques as vectors                       │
└─────────────────────────┬───────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────┐
│                     STAGE 2                              │
│              LLM: Llama 3.3 70B                          │
│                                                          │
│   Input:  Validated MITRE technique + user input         │
│   Output: Intermediate Representation (IR) JSON          │
└─────────────────────────┬───────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────┐
│                  IR VALIDATION                           │
│                                                          │
│   - JSON schema check                                    │
│   - Required fields present                              │
│   - Auto-fix minor issues                                │
│   - Reject and re-prompt if invalid                      │
└─────────────────────────┬───────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────┐
│                  RULE GENERATION                         │
│              (Deterministic — no LLM)                    │
│                                                          │
│   IR → ir_to_sigma() → Sigma YAML                        │
└─────────────────────────┬───────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────┐
│                  pySigma CONVERSION                      │
│                                                          │
│   Sigma → KQL        (Microsoft Sentinel)                │
│   Sigma → SPL        (Splunk)                            │
│   Sigma → Elastic DSL                                    │
│   Sigma → Chronicle YARA-L                               │
└─────────────────────────────────────────────────────────┘
```

## Component Details

### LLM Provider Layer (`src/llm/`)

Abstract interface supporting multiple backends:

```python
class BaseLLM:
    def complete(self, prompt: str, system: str) -> str: ...
    def complete_json(self, prompt: str, system: str) -> dict: ...

class OllamaLLM(BaseLLM): ...   # local inference
class GroqLLM(BaseLLM): ...     # cloud fallback
```

Provider is selected via `LLM_PROVIDER` env variable. Both providers use the same interface so the pipeline code never changes.

### MITRE Layer (`src/mitre/`)

**downloader.py**
- Downloads MITRE ATT&CK Enterprise JSON from GitHub on first run
- Saves locally to `data/mitre_techniques.json`
- Extracts: technique ID, name, description, tactic, sub-techniques

**validator.py**
- Checks if a technique ID exists in local JSON
- Returns technique metadata if valid
- Triggers semantic search if invalid

**vector_db.py**
- ChromaDB collection: `mitre_techniques`
- Embedding model: `all-MiniLM-L6-v2` (384 dimensions, offline)
- Each technique stored as: `"{id} {name} {tactic} {description}"`
- Search returns top-k results with cosine similarity scores
- Built once on setup, updated weekly via scheduler

### Pipeline Layer (`src/pipeline/`)

**stage1.py** — MITRE Detection
```
System prompt: "You are a detection engineering expert..."
Few-shot examples: 5 examples from SigmaHQ rules
Output format: strict JSON schema
Temperature: 0.1 (low creativity, high consistency)
```

**stage2.py** — IR Generation
```
System prompt: "You are a detection rule author..."
Input (short sentence): validated MITRE technique + original user input
Input (CTI report):     validated MITRE technique + extracted context snippets only
                        (NOT the full report — see cti_processor.py)
Output format: IR JSON schema
Temperature: 0.2
Max retries: 3 (re-prompt if JSON invalid)
```

**cti_processor.py** — CTI Report Handling
```
1. Chunk long reports (max 4096 tokens per chunk)
2. Extract keywords per chunk
3. Semantic search for candidate techniques per chunk
4. LLM consolidation: deduplicate and rank techniques
5. Priority sort: Credential Access > Execution > Persistence > Lateral Movement
6. [NEW] Context extraction per technique:
     → For each confirmed technique, re-query ChromaDB against report chunks
     → Return only the relevant sentences/IOCs for that technique
     → This extracted context (not full report) is passed to Stage 2
7. Return ordered list of { technique_id, confidence, context_snippet } dicts
```

**Why context extraction matters:**
Passing a 10-page CTI report to Stage 2 causes two problems:
- Token cost explodes (report × number of techniques)
- Stage 2 model gets lost searching for relevant IOCs inside unrelated content

Solution: ChromaDB is already available. Re-use it to extract only the paragraphs
relevant to each technique before calling Stage 2. No extra LLM call needed.

```python
def extract_context_for_technique(report_chunks: list, technique: dict) -> str:
    """
    Uses ChromaDB semantic search against report chunks to extract
    only the sentences/IOCs relevant to the given technique.
    Returns a short context string (max ~500 tokens) for Stage 2 input.
    """
    query = f"{technique['id']} {technique['name']} {technique['tactic']}"
    relevant = vector_db.search_in_chunks(query, corpus=report_chunks, top_k=5)
    return "\n".join(relevant)
```

### IR Layer (`src/ir/`)

**schema.py** — IR JSON Schema

```json
{
  "meta": {
    "title": "string (required)",
    "description": "string (required)",
    "severity": "low|medium|high|critical (required)",
    "confidence": "low|medium|high (required)"
  },
  "mitre": {
    "tactic": "string (required)",
    "technique_id": "string (required, format: T\d{4}(\.\d{3})?)",
    "technique_name": "string (required)"
  },
  "log_source": {
    "platform": "windows|linux|macos|cloud|network (required)",
    "category": "string (required)",
    "product": "string (optional)"
  },
  "detection": {
    "logic": "AND|OR (required when multiple detection types are present, default: AND)",
    "process": {
      "name": ["array of strings"],
      "command_contains": ["array of strings"],
      "parent_name": ["array of strings"]
    },
    "network": {
      "destination_ip": ["array"],
      "destination_port": ["array"],
      "protocol": "string"
    },
    "file": {
      "path_contains": ["array"],
      "name": ["array"],
      "extension": ["array"]
    },
    "registry": {
      "key_contains": ["array"],
      "value_contains": ["array"]
    }
  },
  "false_positives": ["array of strings (required, min 1)"],
  "references": ["array of URLs (optional)"]
}
```

**validator.py** — IR Validation
- Validates against schema using `jsonschema`
- Auto-fixes: lowercase severity/confidence, strip whitespace
- Re-prompts LLM up to 3 times on validation failure
- Raises `IRValidationError` after max retries

### Rules Layer (`src/rules/`)

**sigma.py** — IR to Sigma

Deterministic mapping (no LLM):

```
IR field                    → Sigma field
─────────────────────────────────────────
meta.title                  → title
meta.description            → description
meta.severity               → level
mitre.technique_id          → tags (attack.tXXXXXXX)
mitre.tactic                → tags (attack.tactic_name)
log_source.platform         → logsource.product
log_source.category         → logsource.category
detection.process.name      → detection.selection_process.Image|endswith
detection.process.command   → detection.selection_process.CommandLine|contains
detection.network.*         → detection.selection_network.DestinationIp / Port
detection.file.*            → detection.selection_file.TargetFilename|contains
detection.registry.*        → detection.selection_registry.TargetObject|contains
false_positives             → falsepositives
detection.logic = "AND"     → condition: all of selection_*
detection.logic = "OR"      → condition: 1 of selection_*
(single detection type)     → condition: selection  (default, no logic field needed)
```

**Why logic is AND/OR only (not raw Sigma syntax):**
LLM is asked only for a simple AND/OR decision. The actual Sigma condition string
is built deterministically by sigma.py — no risk of LLM producing invalid syntax.

```python
def build_condition(ir_detection: dict) -> str:
    active_types = [k for k in ["process", "network", "file", "registry"]
                    if ir_detection.get(k)]
    if len(active_types) == 1:
        return "selection"
    logic = ir_detection.get("logic", "AND")
    if logic == "AND":
        return "all of selection_*"
    return "1 of selection_*"
```

**converter.py** — Sigma to SIEM formats via pySigma

```python
from sigma.backends.microsoft365defender import KustoBackend
from sigma.backends.splunk import SplunkBackend
from sigma.backends.elasticsearch import LuceneBackend
from sigma.backends.secops import SecOpsBackend

BACKENDS = {
    "kql":       KustoBackend,
    "splunk":    SplunkBackend,
    "elastic":   LuceneBackend,
    "chronicle": SecOpsBackend,
}
```

**pySigma version pinning note:**
Backend package names are verified against PyPI at time of writing. Names may change
across pySigma ecosystem updates. Versions are pinned in requirements.txt and verified
via `pip freeze` after setup.sh runs successfully. If a backend import fails, check
the pySigma backend registry at https://github.com/SigmaHQ/pySigma

Verified package names (confirmed by actually installing them in Phase 5, 2026-07-23
— do not rename without testing):
- `pysigma-backend-microsoft365defender` — package name is correct, but the class it
  exports is `KustoBackend`, not `Microsoft365DefenderBackend`
- `pysigma-backend-splunk` — exports `SplunkBackend`
- `pysigma-backend-elasticsearch` — exports `LuceneBackend`
- `pysigma-backend-secops` — **not** `pysigma-backend-chronicle` (that package does not
  exist on PyPI). Chronicle was rebranded to Google SecOps; the community backend is
  `pysigma-backend-secops`, module `sigma.backends.secops`, class `SecOpsBackend`.

## Data Flow: Short Sentence Example

```
Input: "Detect PowerShell credential dumping"

Stage 1 output:
{
  "mitre_tactic": "Credential Access",
  "mitre_technique_id": "T1003.001",
  "mitre_technique_name": "LSASS Memory",
  "log_sources": ["windows"],
  "confidence": "high",
  "reasoning": "PowerShell + credential dumping = LSASS access"
}

Validation: T1003.001 exists in MITRE JSON ✓

Stage 2 output (IR):
{
  "meta": { "title": "PowerShell Credential Dumping", "severity": "high", ... },
  "mitre": { "technique_id": "T1003.001", ... },
  "log_source": { "platform": "windows", "category": "process_creation" },
  "detection": {
    "process": {
      "name": ["powershell.exe", "pwsh.exe"],
      "command_contains": ["sekurlsa", "lsass", "mimikatz"]
    }
  },
  "false_positives": ["Legitimate admin tools"]
}

Sigma output:
title: PowerShell Credential Dumping
tags: [attack.credential_access, attack.t1003.001]
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: ['\powershell.exe', '\pwsh.exe']
    CommandLine|contains: ['sekurlsa', 'lsass', 'mimikatz']
  condition: selection
level: high

KQL output:
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("sekurlsa", "lsass", "mimikatz")
```

## Data Flow: CTI Report Example

```
Input: Long report (10 pages) describing multiple attack techniques

CTI Processor:
  → Chunk report into segments (max 4096 tokens each)
  → Keyword extraction: "LSASS", "scheduled task", "PowerShell"
  → Semantic search: T1003.001 (0.97), T1053.005 (0.89), T1059.001 (0.85)
  → LLM validation: all 3 confirmed
  → Priority sort: T1003.001 > T1059.001 > T1053.005
  → [NEW] Context extraction per technique (via ChromaDB on report chunks):
      T1003.001 context: "attacker dumped LSASS memory using sekurlsa::logonpasswords..."
      T1059.001 context: "PowerShell was invoked with -EncodedCommand flag..."
      T1053.005 context: "persistence achieved via schtasks /create /tn backdoor..."

Pipeline runs 3 times (once per technique):
  Stage 2 input = MITRE technique + context snippet (NOT full report)
  → 3 IRs generated
  → 3 Sigma rules generated
  → 3 × 4 = 12 SIEM queries generated

Token cost comparison:
  Without context extraction: 10 pages × 3 techniques = 30 pages sent to LLM
  With context extraction:    ~500 tokens × 3 techniques = ~1500 tokens sent to LLM
```

## LLM Provider Configuration

```
.env:
  LLM_PROVIDER=ollama OR groq
  GROQ_API_KEY=gsk_...  (only for groq)

Model assignment:
  Stage 1 model:
    ollama → qwen2.5-coder:14b
    groq   → llama-3.1-8b-instant

  Stage 2 model:
    ollama → llama3.3:70b
    groq   → llama-3.3-70b-versatile
```

**Groq model availability note (verified 2026-07-24, Phase 8 testing):**
`qwen-2.5-coder-32b-instruct` does not exist on Groq's current model catalog and returns a
404 `model_not_found` error. The Qwen model actually available on Groq (`qwen/qwen3.6-27b`)
is a "thinking" model that always prepends a `<think>...</think>` reasoning block to its
output, which breaks `complete_json()`'s markdown-fence stripping and fails JSON parsing.
`llama-3.1-8b-instant` was verified to return clean, schema-correct JSON for the Stage 1
prompt and matches the "fast/cheap, high format-adherence" design intent for Stage 1 — it
is now the Groq fallback for Stage 1. Groq's model catalog changes over time; re-verify
with `client.models.list()` if this stops working.

## Similarity Threshold Logic

```python
THRESHOLD_AUTO   = 0.85   # proceed automatically
THRESHOLD_ASK    = 0.65   # ask user to confirm
# below 0.65             # request more detail

def handle_similarity(results):
    top = results[0]
    if top.similarity >= THRESHOLD_AUTO:
        return top.technique_id
    elif top.similarity >= THRESHOLD_ASK:
        return ask_user(results[:3])   # show top 3
    else:
        return request_more_detail()
```