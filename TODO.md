# TODO — Implementation Checklist

## Phase 0: Project Setup
- [x] Create project directory structure (`src/` subfolders)
- [x] Create `requirements.txt` with all dependencies
- [x] Create `.env.example` with all required variables
- [x] Create `setup.sh` one-command installation script
- [x] Create `main.py` entry point (CLI interface)

## Phase 1: LLM Provider Layer (`src/llm/`)
- [x] Create `base.py` — abstract `BaseLLM` class with `complete()` and `complete_json()` methods
- [x] Create `ollama.py` — Ollama provider implementation
  - [x] `complete()` method calling Ollama REST API
  - [x] `complete_json()` with JSON parsing and retry logic
  - [x] Model name configuration (stage1 vs stage2 model)
- [x] Create `groq.py` — Groq provider implementation
  - [x] `complete()` method using groq Python SDK
  - [x] `complete_json()` with JSON parsing and retry logic
  - [x] Model name mapping for Groq available models
- [x] Create `__init__.py` — factory function `get_llm_provider()` reading from `.env`
- [x] Test: fence-stripping, retry logic, factory error paths, Ollama connection-refused case

## Phase 2: MITRE Layer (`src/mitre/`)
- [x] Create `downloader.py`
  - [x] `download_mitre_data()` — fetch from MITRE GitHub, save to `data/mitre_techniques.json`
  - [x] Parse only `attack-pattern` objects (skip revoked + deprecated)
  - [x] Extract: id, name, description, tactic, is_subtechnique
  - [x] Handle network errors gracefully (use cached file if download fails)
- [x] Create `vector_db.py`
  - [x] `build_vector_db()` — embed all techniques and store in ChromaDB
  - [x] Use `all-MiniLM-L6-v2` from sentence-transformers
  - [x] Text format per technique: `"{id} {name} {tactic} {description[:500]}"`
  - [x] `search(query, top_k=3)` — return list of `{technique_id, name, similarity}`
  - [x] Persist ChromaDB to `data/chroma/` directory
  - [x] Skip rebuild if collection count matches techniques file
  - [x] `search_in_chunks(query, corpus, top_k=5)` — temporary in-memory collection for CTI context extraction
- [x] Create `validator.py`
  - [x] `validate_technique_id(technique_id)` — check against local JSON
  - [x] `handle_validation(llm_stage1_output)` — full validation flow with threshold logic
  - [x] `ask_user_confirmation(candidates)` — rich CLI prompt showing top 3 options
  - [x] `request_more_detail()` — raises NeedsMoreDetailError
- [x] Create `__init__.py` — export all public functions
- [x] Add `data/mitre_techniques.json` and `data/chroma/` to `.gitignore`
- [x] Syntax-check all Phase 2 files
- [x] Unit-test `downloader.py` parsing logic with fake STIX bundle
- [x] Smoke-test `vector_db.py` + `validator.py` end-to-end (real chromadb + sentence-transformers, fake technique set)
  - [x] Rebuild-skip on matching count verified
  - [x] Semantic search returns correct top match ("dumping credentials from lsass memory" → T1003.001)
  - [x] Bug fixed: ChromaDB rejects collection names starting with `_` → renamed `_temp_...` to `temp-...`
  - [x] All three threshold branches tested (auto-select, ask-user, request-more-detail)
  - [x] `python -m src.mitre.validator` output matches spec

## Phase 3: Pipeline Layer (`src/pipeline/`)
- [ ] Create `stage1.py`
  - [ ] Write system prompt for MITRE detection
  - [ ] Write 5 few-shot examples (input → JSON output pairs)
  - [ ] `detect_mitre_technique(user_input)` — call Stage 1 LLM, return parsed JSON
  - [ ] Set temperature to 0.1
  - [ ] Retry up to 3 times on JSON parse failure
- [ ] Create `stage2.py`
  - [ ] Write system prompt for IR generation
  - [ ] `generate_ir(user_input, mitre_technique, context_snippet=None)` — call Stage 2 LLM
    - [ ] If `context_snippet` is provided (CTI mode): use snippet as input, not full report
    - [ ] If `context_snippet` is None (short sentence mode): use original user input
  - [ ] Set temperature to 0.2
  - [ ] Retry up to 3 times on validation failure
- [ ] Create `cti_processor.py`
  - [ ] `is_cti_report(text)` — heuristic to detect if input is a long CTI report
  - [ ] `chunk_report(text, max_tokens=4096)` — split long reports
  - [ ] `extract_techniques_from_report(report)` — full CTI processing pipeline
    - [ ] Keyword extraction per chunk
    - [ ] Semantic search per chunk
    - [ ] LLM consolidation and deduplication
    - [ ] Priority sorting by tactic
  - [ ] `extract_context_for_technique(report_chunks, technique)` — [NEW]
    - [ ] Re-query ChromaDB using technique ID + name + tactic against report chunks
    - [ ] Return top 5 most relevant sentences/paragraphs (max ~500 tokens)
    - [ ] This context snippet (not full report) is what gets passed to Stage 2
  - [ ] Return ordered list of `{technique_id, confidence, context_snippet}` dicts
- [ ] Test: run Stage 1 with 5 different inputs, verify MITRE output is correct

## Phase 4: IR Layer (`src/ir/`)
- [ ] Create `schema.py`
  - [ ] Define IR JSON schema using `jsonschema` format
  - [ ] Include all fields: meta, mitre, log_source, detection (process/network/file/registry), false_positives, references
  - [ ] Add `detection.logic` field: enum `["AND", "OR"]`, required only when 2+ detection types are present
  - [ ] Default value for `detection.logic` is `"AND"` when field is absent
- [ ] Create `validator.py`
  - [ ] `validate_ir(ir_dict)` — validate against schema, return errors list
  - [ ] `auto_fix_ir(ir_dict)` — fix common issues (lowercase severity, strip whitespace, etc.)
  - [ ] `IRValidationError` exception class
- [ ] Test: validate a correct IR, an IR missing required fields, an IR with wrong severity value

## Phase 5: Rules Layer (`src/rules/`)
- [ ] Create `sigma.py`
  - [ ] `ir_to_sigma(ir_dict)` — deterministic IR → Sigma YAML conversion
  - [ ] Map all detection fields (process, network, file, registry)
  - [ ] Each active detection type → separate named selection (selection_process, selection_network, etc.)
  - [ ] `build_condition(ir_detection)` — deterministic condition string:
    - [ ] Single detection type → `condition: selection`
    - [ ] Multiple + logic AND → `condition: all of selection_*`
    - [ ] Multiple + logic OR  → `condition: 1 of selection_*`
  - [ ] Map MITRE technique to `tags` field correctly
  - [ ] Return valid Sigma YAML string
- [ ] Create `converter.py`
  - [ ] Install and configure pySigma backends: microsoft365defender, splunk, elasticsearch, chronicle
  - [ ] `sigma_to_kql(sigma_yaml)` → KQL string
  - [ ] `sigma_to_spl(sigma_yaml)` → SPL string
  - [ ] `sigma_to_elastic(sigma_yaml)` → Elastic DSL string
  - [ ] `sigma_to_chronicle(sigma_yaml)` → Chronicle YARA-L string
  - [ ] `convert_all(sigma_yaml)` → dict with all formats
- [ ] Test: convert a PowerShell detection IR to all 4 formats, verify output syntax

## Phase 6: Main Entry Point (`main.py`)
- [ ] CLI interface with two modes:
  - [ ] Interactive mode: prompt user for input, show results
  - [ ] File mode: `python main.py --input report.txt --output rules/`
- [ ] Display results clearly:
  - [ ] Show detected MITRE technique
  - [ ] Show similarity score and confirmation if needed
  - [ ] Show generated Sigma rule
  - [ ] Show all SIEM format outputs
  - [ ] Option to save to files
- [ ] Error handling: graceful messages for network errors, model errors, etc.

## Phase 7: Setup & Packaging
- [ ] Write `setup.sh`:
  - [ ] Check Python version (3.10+)
  - [ ] Create virtual environment
  - [ ] Install requirements
  - [ ] Check Ollama installation (prompt to install if missing)
  - [ ] Pull required Ollama models (qwen2.5-coder:14b, llama3.3:70b)
  - [ ] Download MITRE ATT&CK JSON
  - [ ] Build ChromaDB vector database
  - [ ] Copy `.env.example` to `.env` if not exists
- [ ] Write `requirements.txt` with pinned versions:
  - [ ] `ollama`
  - [ ] `groq`
  - [ ] `chromadb`
  - [ ] `sentence-transformers`
  - [ ] `pySigma>=0.11.0`
  - [ ] `pysigma-backend-microsoft365defender` (verified name — NOT pysigma-backend-kusto)
  - [ ] `pysigma-backend-splunk`
  - [ ] `pysigma-backend-elasticsearch`
  - [ ] `pysigma-backend-chronicle`
  - [ ] `jsonschema`
  - [ ] `pyyaml`
  - [ ] `python-dotenv`
  - [ ] `requests`
  - [ ] `rich`
  - [ ] After first successful setup: run `pip freeze > requirements.lock` to pin exact versions

## Phase 8: Testing
- [ ] Test short sentence input (English)
- [ ] Test short sentence input (Turkish)
- [ ] Test CTI report with multiple techniques
- [ ] Test with invalid MITRE ID (verify semantic search fallback)
- [ ] Test with ambiguous input (verify user confirmation prompt)
- [ ] Test with Ollama provider
- [ ] Test with Groq provider
- [ ] Verify all 4 output formats are syntactically valid

## Phase 9: Documentation
- [ ] Add docstrings to all functions
- [ ] Add inline comments for non-obvious logic
- [ ] Update README with any changes from implementation
- [ ] Add example outputs to README
- [ ] Create `examples/` folder with sample inputs and outputs

## Known Risks & Mitigations

| Risk | Mitigation |
|---|---|
| LLM produces invalid JSON | Retry up to 3 times with stricter prompt |
| LLM hallucinates MITRE ID | MITRE JSON validation + semantic search fallback |
| Sigma rule fails pySigma parsing | Validate Sigma schema before passing to pySigma |
| Ollama model not installed | setup.sh checks and pulls models automatically |
| MITRE JSON download fails | Use cached file if available |
| Groq rate limit hit | Exponential backoff retry |
| CTI report too long | Chunk processing (4096 tokens per chunk) |
| Stage 2 gets lost in full CTI report | Context extraction per technique via ChromaDB (only ~500 tokens passed) |
| Multiple detection types produce wrong condition | IR logic field (AND/OR) → deterministic condition via build_condition() |
| pySigma backend package renamed | Versions pinned in requirements.txt, verified names documented in ARCHITECTURE.md |