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
- [x] Create `stage1.py`
  - [x] Write system prompt for MITRE detection
  - [x] Write 5 few-shot examples (input → JSON output pairs)
  - [x] `detect_mitre_technique(user_input)` — call Stage 1 LLM, return parsed JSON
  - [x] Set temperature to 0.1
  - [x] Retry up to 3 times on JSON parse failure
- [x] Create `stage2.py`
  - [x] Write system prompt for IR generation
  - [x] `generate_ir(user_input, mitre_technique, context_snippet=None)` — call Stage 2 LLM
    - [x] If `context_snippet` is provided (CTI mode): use snippet as input, not full report
    - [x] If `context_snippet` is None (short sentence mode): use original user input
  - [x] Set temperature (0.2 originally, lowered to 0.05 post-Phase-9 — see below)
  - [x] Retry up to 3 times on validation failure
- [x] Create `cti_processor.py`
  - [x] `is_cti_report(text)` — heuristic to detect if input is a long CTI report
  - [x] `chunk_report(text, max_tokens=4096)` — split long reports
  - [x] `extract_techniques_from_report(report)` — full CTI processing pipeline
    - [x] Keyword extraction per chunk
    - [x] Semantic search per chunk
    - [x] LLM consolidation and deduplication
    - [x] Priority sorting by tactic
  - [x] `extract_context_for_technique(report_chunks, technique)` — [NEW]
    - [x] Re-query ChromaDB using technique ID + name + tactic against report chunks
    - [x] Return top 5 most relevant sentences/paragraphs (max ~500 tokens)
    - [x] This context snippet (not full report) is what gets passed to Stage 2
  - [x] Return ordered list of `{technique_id, confidence, context_snippet}` dicts
- [x] Test: mocked-LLM unit tests for stage1/stage2/cti_processor (see chat history); real Stage 1 testing with 5 inputs happened in Phase 8

## Phase 4: IR Layer (`src/ir/`)
- [x] Create `schema.py`
  - [x] Define IR JSON schema using `jsonschema` format
  - [x] Include all fields: meta, mitre, log_source, detection (process/network/file/registry), false_positives, references
  - [x] Add `detection.logic` field: enum `["AND", "OR"]`, required only when 2+ detection types are present
  - [x] Default value for `detection.logic` is `"AND"` when field is absent
- [x] Create `validator.py`
  - [x] `validate_ir(ir_dict)` — validate against schema, return errors list
  - [x] `auto_fix_ir(ir_dict)` — fix common issues (lowercase severity, strip whitespace, etc.)
  - [x] `IRValidationError` exception class
- [x] Test: validate a correct IR, an IR missing required fields, an IR with wrong severity value

## Phase 5: Rules Layer (`src/rules/`)
- [x] Create `sigma.py`
  - [x] `ir_to_sigma(ir_dict)` — deterministic IR → Sigma YAML conversion
  - [x] Map all detection fields (process, network, file, registry)
  - [x] Each active detection type → separate named selection (selection_process, selection_network, etc.)
  - [x] `build_condition(ir_detection)` — deterministic condition string:
    - [x] Single detection type → `condition: selection`
    - [x] Multiple + logic AND → `condition: all of selection_*`
    - [x] Multiple + logic OR  → `condition: 1 of selection_*`
  - [x] Map MITRE technique to `tags` field correctly
  - [x] Return valid Sigma YAML string
- [x] Create `converter.py`
  - [x] Install and configure pySigma backends: microsoft365defender, splunk, elasticsearch, chronicle/secops
  - [x] `sigma_to_all(sigma_yaml)` → dict with all formats (superseded the originally-planned separate `sigma_to_kql`/`sigma_to_spl`/etc. functions)
  - [x] Post-Phase-9: 4 more backends added (crowdstrike, loki, sentinelone, carbonblack) — see below
- [x] Test: convert a PowerShell detection IR to all formats, verify output syntax (all 4 originally, all 9 after the post-Phase-9 backend additions)

## Phase 6: Main Entry Point (`main.py`)
- [x] CLI interface with two modes:
  - [x] Interactive mode: prompt user for input, show results
  - [x] File mode: `python main.py --input report.txt --output rules/`
- [x] Display results clearly:
  - [x] Show detected MITRE technique
  - [x] Show similarity score and confirmation if needed
  - [x] Show generated Sigma rule
  - [x] Show all SIEM format outputs
  - [x] Option to save to files
- [x] Error handling: graceful messages for network errors, model errors, etc.

## Phase 7: Setup & Packaging
- [x] Write `setup.sh`:
  - [x] Check Python version (3.10+)
  - [x] Create virtual environment
  - [x] Install requirements
  - [x] Check Ollama installation (prompt to install if missing)
  - [x] Pull required Ollama models (qwen2.5-coder:14b, llama3.3:70b)
  - [x] Download MITRE ATT&CK JSON
  - [x] Build ChromaDB vector database
  - [x] Copy `.env.example` to `.env` if not exists
- [x] Write `requirements.txt` with pinned versions:
  - [x] `ollama` — evaluated and deliberately NOT included: `src/llm/ollama.py` talks to the Ollama REST API directly via `requests`, never imports the `ollama` PyPI package
  - [x] `groq`
  - [x] `chromadb`
  - [x] `sentence-transformers`
  - [x] `pySigma>=1.0.0` (raised from the originally-planned `>=0.11.0` — `pysigma-backend-secops` itself requires `>=1.0.0`)
  - [x] `pysigma-backend-microsoft365defender` (verified name — NOT pysigma-backend-kusto; exports `KustoBackend`, not `Microsoft365DefenderBackend`)
  - [x] `pysigma-backend-splunk`
  - [x] `pysigma-backend-elasticsearch`
  - [x] `pysigma-backend-secops` (verified name — NOT `pysigma-backend-chronicle`, which does not exist on PyPI; Chronicle was rebranded to Google SecOps)
  - [x] `jsonschema`
  - [x] `pyyaml`
  - [x] `python-dotenv`
  - [x] `requests`
  - [x] `rich`
  - [x] After first successful setup: ran `pip freeze > requirements.lock` to pin exact versions (128 packages; gitignored, not committed — see requirements.txt note)

## Phase 8: Testing
- [x] Test short sentence input (English) — real Groq calls, `tests/test_short_sentence_en.py`
- [x] Test short sentence input (Turkish) — real Groq calls, `tests/test_short_sentence_tr.py`
- [x] Test CTI report with multiple techniques — `tests/test_cti_report.py`
- [x] Test with invalid MITRE ID (verify semantic search fallback) — `tests/test_invalid_mitre.py`
- [x] Test with ambiguous input (verify user confirmation prompt) — `tests/test_ambiguous_input.py`
- [x] Test with Groq provider (real calls; Ollama was not available in the dev environment used, so Ollama-specific live testing was not performed — Ollama's REST-API code path is exercised by `src/llm/ollama.py`'s own logic but not with a live server)
- [x] Verify all output formats are syntactically valid (4 originally, all 9 after post-Phase-9 backend additions)

## Phase 9: Documentation
- [x] Add docstrings to all functions
- [x] Add inline comments for non-obvious logic
- [x] Update README with any changes from implementation
- [x] Add example outputs to README
- [x] Create `examples/` folder with sample inputs and outputs

## Post-Phase 9 Improvements

- [x] Sub-technique auto-expansion (`get_subtechniques()` in `downloader.py`,
      integrated in `main.py` and `dashboard/app.py`)
- [x] Stage 2 temperature lowered from 0.2 to 0.05 for more consistent IR output
- [x] Few-shot examples (2 worked examples) added to Stage 2 prompt
- [x] SHA-256 input caching (`src/pipeline/cache.py`); CLI and dashboard use
      disjoint cache-mode keys (`"sentence"/"cti"` vs
      `"dashboard-sentence"/"dashboard-cti"`) since they cache differently-shaped
      result tuples — see ARCHITECTURE.md "Input Caching"
- [x] FastAPI web dashboard (`dashboard/app.py` + `dashboard/static/index.html`)
- [x] PDF upload support in dashboard (`pdfplumber`, `/api/upload-pdf`)
- [x] 4 additional pySigma backends: CrowdStrike, Loki, SentinelOne, Carbon
      Black (Chronicle/SecOps was already present since Phase 5, not new).
      2 more backends (QRadar-AQL, InsightIDR) were evaluated and deliberately
      NOT added — both are hard-pinned to `pysigma<0.12.0`, incompatible with
      the `pysigma>=1.0.0` the other 8 backends need
- [x] OpenSearch backend added, then removed at the project owner's request
- [x] 5 new LLM providers: OpenAI, Anthropic, Gemini, Mistral, Together AI —
      `src/llm/__init__.py` rewritten to lazily import providers via
      `importlib` so an uninstalled optional SDK only breaks that one
      provider. Found and fixed 2 real spec-vs-SDK mismatches while wiring
      these up: `mistralai`'s client is `mistralai.client.Mistral`, not
      `mistralai.Mistral` as commonly assumed, and there's no
      `MistralAPIStatusException` (real class: `mistralai.client.errors.SDKError`
      with a `.status_code` attribute); `together`'s exceptions live on the
      top-level `together` package, not a `together.error` submodule.
- [x] `is_cti_report()` threshold lowered from 1500 to 500 chars
- [x] CTI keyword-triggered second search pass added to `cti_processor.py`
      (`KEYWORD_QUERY_RULES`) for short reports that fit in a single chunk
- [x] Stage 1 direct MITRE ID bypass (`extract_direct_technique_id()`) — skips
      the LLM entirely when the input already contains a technique ID
- [x] Stage 1 multi-ID cleanup (`_clean_technique_id()`) — takes the first ID
      when the LLM returns several joined together
- [x] Stage 1 prompt hardened to require exactly one JSON object (system
      prompt + user prompt both state this explicitly) after a real
      multi-JSON-object parse failure was reported
- [ ] ~~Splunk syntax post-processing "fix" in converter.py~~ — **investigated,
      not implemented.** A regex-based `fix_splunk_syntax()` was proposed to
      insert `AND` between adjacent Splunk field expressions. Testing against
      the real `pysigma-backend-splunk` output showed the premise was wrong:
      Splunk's space-separated terms are valid implicit-AND syntax already.
      Worse, the proposed regex corrupted real OR-logic queries (turned
      `... OR ...` into `... AND OR ...`). Declined; no change was made to
      `converter.py`.
- [x] Bug fixes found via direct verification (installing packages / running
      real calls, not just reading docs): ChromaDB collection naming
      (`_temp_...` names rejected — renamed to `temp-...`), 3 separate pySigma
      backend package/class name corrections (Phase 5 + post-Phase-9), Groq's
      Stage 1 model no longer existing in its catalog (`STAGE1_MODEL_GROQ`
      fixed to `llama-3.1-8b-instant`), and the 2 Mistral/Together SDK import
      corrections noted above

## ✅ PROJECT COMPLETE — All phases done + post-phase improvements

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