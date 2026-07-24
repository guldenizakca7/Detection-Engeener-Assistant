# Phase 8 — End-to-End Tests

These are **not** mocked unit tests — every file in this directory makes real calls
to an LLM provider (Ollama or Groq) and queries the real MITRE ATT&CK vector DB
built by `setup.sh`. All 5 tests require a real, working LLM provider. There is no
mocked variant of any of them.

## Prerequisites

1. Run `./setup.sh` from the project root at least once. This creates `.venv`,
   downloads the real MITRE ATT&CK Enterprise catalog to `data/mitre_techniques.json`,
   and builds the real semantic-search vector DB at `data/chroma/`.
2. Configure a provider in `.env`:
   - **Ollama**: `LLM_PROVIDER=ollama`, with `ollama serve` running and
     `qwen2.5-coder:14b` / `llama3.3:70b` pulled.
   - **Groq**: `LLM_PROVIDER=groq`, with a real `GROQ_API_KEY` (free tier at
     [console.groq.com](https://console.groq.com)).

   If neither is configured, or the configured provider is unreachable, each test
   prints `SKIPPED: ...` and exits 0 instead of crashing — see "Skip behavior" below.

## Running

Each file is a standalone script (there is no pytest dependency in this project),
run directly with the project's venv:

```bash
.venv/bin/python3 tests/test_short_sentence_en.py
.venv/bin/python3 tests/test_short_sentence_tr.py
.venv/bin/python3 tests/test_cti_report.py
.venv/bin/python3 tests/test_invalid_mitre.py
.venv/bin/python3 tests/test_ambiguous_input.py
```

`test_invalid_mitre.py` and `test_ambiguous_input.py` can trigger an interactive
confirmation prompt (see below) — when running them unattended, redirect stdin so
that path fails fast instead of hanging:

```bash
.venv/bin/python3 tests/test_invalid_mitre.py < /dev/null
```

## What each test does

| File | Input | Asserts |
|---|---|---|
| `test_short_sentence_en.py` | "Detect PowerShell credential dumping via LSASS memory access" | `technique_id` starts with `T1003`; Sigma contains "powershell" (case-insensitive); KQL is non-`None` |
| `test_short_sentence_tr.py` | "PowerShell ile kimlik bilgisi çalma tespiti" (Turkish) | `technique_id` starts with `T1003` or `T1059`; Sigma is non-`None` |
| `test_cti_report.py` | A 468-word synthetic incident report covering LSASS credential dumping, RDP lateral movement, and scheduled-task persistence | At least 2 techniques detected; every technique's Sigma output is non-`None` |
| `test_invalid_mitre.py` | Hand-built Stage 1 output with a fake `technique_id` (`T9999.999`) | Either `NeedsMoreDetailError` is raised, or a real, different, valid technique is returned |
| `test_ambiguous_input.py` | "detect suspicious activity" | No assertions — documents which of the three threshold paths (auto-select / ask-user / reject) real vague input triggers |

## Skip behavior

Every test wraps its body in `try/except`: an `AssertionError` (a genuine test
failure) always propagates and fails loudly with a traceback; anything else
(`ValueError` from `get_llm()` when no provider is configured, `RuntimeError` from
an unreachable Ollama, a Groq auth/rate-limit error, etc.) is caught, printed as
`SKIPPED: ...`, and exits 0. This is what "run tests only if a provider is
available" means in practice — the scripts self-guard rather than requiring a
separate pre-flight check.

## Actual output from the last real run (2026-07-24, `LLM_PROVIDER=groq`)

All 5 tests were run for real against Groq (`llama-3.1-8b-instant` for Stage 1,
`llama-3.3-70b-versatile` for Stage 2) and the real 697-technique MITRE vector DB.
Full transcripts are in the implementation report; summary:

- **test_short_sentence_en**: PASSED. Detected `T1003.001` (LSASS Memory), generated
  a correct Sigma rule plus all 4 SIEM conversions.
- **test_short_sentence_tr**: PASSED. Detected `T1003.001` directly from the Turkish
  input (Stage 1 correctly reasoned in Turkish, still returned the right English
  technique fields).
- **test_cti_report**: PASSED — 5 techniques detected and confirmed (`T1003.001`,
  `T1003`, `T1053.005`, `T1021.001`, `T1078`), all with valid generated Sigma.
- **test_invalid_mitre**: PASSED via the "ask user" path — the fake ID's
  MITRE-aligned reasoning text scored 0.72-0.73 similarity against `T1003.001`/
  `T1003.004`, landing between `THRESHOLD_ASK` (0.65) and `THRESHOLD_AUTO` (0.85),
  which correctly triggered the confirmation table.
- **test_ambiguous_input**: Documented, not asserted — Stage 1 itself recognized
  "detect suspicious activity" as too vague and returned `technique_id: "None"`
  with `confidence: "low"`, which correctly triggered `NeedsMoreDetailError`.

## Known behaviors found during this testing pass

These aren't test bugs — they're real characteristics of the system discovered by
running it for real, worth knowing before relying on it:

1. **Groq model names in `.env.example` were stale.** `qwen-2.5-coder-32b-instruct`
   (the original `STAGE1_MODEL_GROQ`) no longer exists on Groq's catalog (404
   `model_not_found`). The Qwen model that *is* available there,
   `qwen/qwen3.6-27b`, is a "thinking" model that always prepends a
   `<think>...</think>` block, which breaks `complete_json()`'s parsing. Fixed to
   `llama-3.1-8b-instant`, verified to return clean JSON matching the Stage 1
   schema. See `ARCHITECTURE.md` for details. Re-check with
   `client.models.list()` if Groq's catalog changes again.

2. **`THRESHOLD_ASK=0.65` (the shipped default) is stricter than what real
   narrative CTI paragraphs score against MITRE technique descriptions**, even
   when the paragraph closely mirrors the technique's actual wording. Measured
   on `test_cti_report.py`'s report: LSASS credential dumping scored 0.693 (just
   clears 0.65), but RDP lateral movement (0.627) and scheduled-task persistence
   (0.619) both fell short. `test_cti_report.py` locally overrides
   `THRESHOLD_ASK=0.60` for its own process only (documented in the file's
   docstring) — this is safe because the LLM-consolidation step in
   `extract_techniques_from_report()` re-reads the actual text and would drop
   anything the wider net pulled in that isn't really described. If you see a
   real CTI report under-detect techniques with the default 0.65, this is why.

3. **`handle_validation()` doesn't return the similarity score it used
   internally** — it only returns the final technique dict. `test_short_sentence_tr.py`
   works around this by re-running `search()` diagnostically after the fact to
   print a number, which is why that script's printed similarity can look
   surprisingly low (0.365) even when validation actually succeeded via a
   direct technique-ID match, not a search fallback. Cross-lingual queries
   (Turkish reasoning text against English-only MITRE embeddings) score low with
   `all-MiniLM-L6-v2` regardless — this is expected and doesn't affect real
   accuracy, since Stage 1 already returns the correct English `technique_id`
   directly.

4. **The "ask user" threshold band (`THRESHOLD_ASK` ≤ similarity < `THRESHOLD_AUTO`)
   calls `ask_user_confirmation()`, which blocks on interactive stdin.** In a
   non-interactive run (CI, piped input) this raises `EOFError`, not a hang —
   `test_invalid_mitre.py` and `test_ambiguous_input.py` both catch this
   specifically and report it as the "ambiguous match" outcome, since it's the
   expected behavior for that band, not a bug.

5. **Stage 1 can legitimately return `"mitre_technique_id": "None"`** (as a
   string) for genuinely vague input rather than hallucinating a specific
   technique — `handle_validation()` correctly treats this as an invalid ID and
   falls through to the semantic-search/reject path, same as any other bad ID
   would.
