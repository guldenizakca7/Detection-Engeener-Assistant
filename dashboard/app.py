"""Detection Engineering Assistant — web dashboard (FastAPI + static HTML/CSS/JS).

Run with: uvicorn dashboard.app:app --reload --port 8000
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Literal

# Ensure the project root (parent of this dashboard/ folder) is importable as
# `src`, regardless of the working directory uvicorn was launched from.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv

load_dotenv()

import pdfplumber
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from src.mitre import get_subtechniques, handle_validation
from src.mitre.validator import NeedsMoreDetailError
from src.pipeline import (
    detect_mitre_technique,
    extract_context_for_technique,
    extract_techniques_from_report,
    generate_ir,
)
from src.pipeline.cti_processor import chunk_report
from src.rules import convert_ir

STATIC_DIR = Path(__file__).resolve().parent / "static"
HISTORY_PATH = Path(__file__).resolve().parent / "history.json"
HISTORY_LIMIT = 20

app = FastAPI(title="Detection Engineering Assistant Dashboard")


class GenerateRequest(BaseModel):
    input: str
    mode: Literal["sentence", "cti"]


# --- Pipeline orchestration ---------------------------------------------------
# Thin glue over the existing src/ functions, mirroring main.py's
# run_short_sentence()/run_cti_report() but without their Rich-console/CLI
# dependencies (not appropriate for a web request). No pipeline logic is
# reimplemented here -- every actual step (detection, validation, IR
# generation, rule conversion) is delegated to the existing src/ functions.
#
# Both functions also mirror main.py's parent-technique sub-technique
# expansion: if the validated technique is a parent (not itself a
# sub-technique), every one of its sub-techniques (src.mitre.get_subtechniques)
# is processed too and appended to the results list, so a query like "T1059"
# returns rules for the parent plus all of its sub-techniques, not just one.


def _run_short_sentence(user_input: str) -> list[dict]:
    stage1_output = detect_mitre_technique(user_input)
    validated_technique = handle_validation(stage1_output)

    ir = generate_ir(user_input, validated_technique)
    formats = convert_ir(ir)
    results = [(ir, formats)]

    if not validated_technique.get("is_subtechnique", False):
        for sub in get_subtechniques(validated_technique["id"]):
            sub_ir = generate_ir(user_input, sub)
            sub_formats = convert_ir(sub_ir)
            results.append((sub_ir, sub_formats))

    return results


def _run_cti_report(report: str) -> list[dict]:
    technique_list = extract_techniques_from_report(report)
    report_chunks = chunk_report(report)

    results = []
    for tech in technique_list:
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
        results.append((ir, formats))

        if not validated_technique.get("is_subtechnique", False):
            for sub in get_subtechniques(validated_technique["id"]):
                sub_context = extract_context_for_technique(report_chunks, sub)
                sub_ir = generate_ir(report, sub, context_snippet=sub_context)
                sub_formats = convert_ir(sub_ir)
                results.append((sub_ir, sub_formats))

    return results


# --- History -------------------------------------------------------------------


def _load_history() -> list[dict]:
    """Return the saved generation history, creating an empty history.json if missing."""
    if not HISTORY_PATH.exists():
        HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        HISTORY_PATH.write_text("[]", encoding="utf-8")
        return []
    with open(HISTORY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_history_entry(user_input: str, technique_count: int, rule_count: int) -> None:
    """Append a generation summary to history.json, keeping only the last HISTORY_LIMIT entries."""
    history = _load_history()
    history.append(
        {
            "id": len(history) + 1,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "input": user_input,
            "technique_count": technique_count,
            "rule_count": rule_count,
        }
    )
    history = history[-HISTORY_LIMIT:]
    with open(HISTORY_PATH, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2, ensure_ascii=False)


# --- API routes ------------------------------------------------------------------


@app.post("/api/generate")
def api_generate(payload: GenerateRequest) -> dict:
    try:
        if payload.mode == "cti":
            results = _run_cti_report(payload.input)
        else:
            results = _run_short_sentence(payload.input)
    except NeedsMoreDetailError:
        raise HTTPException(status_code=422, detail="Girdi çok belirsiz, lütfen daha fazla detay ekleyin")
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 -- surface any pipeline error as a 500
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    techniques = []
    total_rules = 0
    for ir, formats in results:
        techniques.append(
            {
                "technique_id": ir["mitre"]["technique_id"],
                "technique_name": ir["mitre"]["technique_name"],
                "tactic": ir["mitre"]["tactic"],
                "rules": formats,
            }
        )
        total_rules += sum(1 for value in formats.values() if value is not None)

    _save_history_entry(payload.input, len(techniques), total_rules)

    return {"techniques": techniques, "total_rules": total_rules}


@app.post("/api/upload-pdf")
async def api_upload_pdf(file: UploadFile = File(...)) -> dict:
    filename = file.filename or ""
    content_type = (file.content_type or "").lower()

    if not (filename.lower().endswith(".pdf") and "pdf" in content_type):
        raise HTTPException(status_code=422, detail="Sadece PDF dosyaları kabul edilir.")

    try:
        with pdfplumber.open(file.file) as pdf:
            text = "\n".join(page.extract_text() or "" for page in pdf.pages)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 -- surface any extraction error as a 500
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    if not text.strip():
        raise HTTPException(
            status_code=422,
            detail="PDF'den metin çıkarılamadı. Taramalı (scanned) PDF olabilir.",
        )

    return {"text": text}


@app.get("/api/history")
def api_history() -> list[dict]:
    return _load_history()[-HISTORY_LIMIT:]


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "llm_provider": os.getenv("LLM_PROVIDER", "not set")}


# Mounted last so it never shadows the API routes above; html=True serves
# static/index.html for GET /.
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
