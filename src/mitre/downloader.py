"""Download and cache the MITRE ATT&CK Enterprise technique catalog."""
from __future__ import annotations

import json
import os
from pathlib import Path

import requests

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
DESCRIPTION_MAX_CHARS = 500
DOWNLOAD_TIMEOUT = 60


def _data_dir() -> Path:
    """Return the configured data directory (DATA_DIR, default ./data)."""
    return Path(os.getenv("DATA_DIR", "./data"))


def _output_path() -> Path:
    """Return the path to the cached technique catalog JSON file."""
    return _data_dir() / "mitre_techniques.json"


def _extract_technique(obj: dict) -> dict | None:
    """Extract a flat technique dict from one STIX object, or None if it should be skipped.

    Skips anything that isn't an active (non-revoked, non-deprecated)
    attack-pattern object, since those are the only STIX objects that
    represent real, current MITRE techniques.
    """
    if obj.get("type") != "attack-pattern":
        return None
    if obj.get("revoked") is True or obj.get("x_mitre_deprecated") is True:
        return None

    external_references = obj.get("external_references") or []
    if not external_references:
        return None
    technique_id = external_references[0].get("external_id")
    if not technique_id:
        return None

    kill_chain_phases = obj.get("kill_chain_phases") or []
    tactic = kill_chain_phases[0].get("phase_name") if kill_chain_phases else None

    return {
        "id": technique_id,
        "name": obj.get("name"),
        "description": (obj.get("description") or "")[:DESCRIPTION_MAX_CHARS],
        "tactic": tactic,
        "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
    }


def _parse_bundle(bundle: dict) -> dict:
    """Parse a raw MITRE ATT&CK STIX bundle into {technique_id: technique_dict}."""
    techniques = {}
    for obj in bundle.get("objects", []):
        technique = _extract_technique(obj)
        if technique:
            techniques[technique["id"]] = technique
    return techniques


def download_mitre_data() -> dict:
    """Download the MITRE ATT&CK Enterprise technique catalog.

    Saves the result to data/mitre_techniques.json. Falls back to that
    cached file if the download fails, and raises RuntimeError if neither
    the download nor the cache is available.

    Returns:
        A {technique_id: technique_dict} mapping, e.g.
        {"T1003.001": {"id": ..., "name": ..., "description": ..., "tactic": ...,
        "is_subtechnique": ...}, ...}.

    Raises:
        RuntimeError: If the download fails and no cached file exists.
    """
    output_path = _output_path()

    try:
        response = requests.get(MITRE_URL, timeout=DOWNLOAD_TIMEOUT)
        response.raise_for_status()
        bundle = response.json()
        techniques = _parse_bundle(bundle)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(techniques, f, indent=2)

        print(f"[mitre] Downloaded and parsed {len(techniques)} techniques from MITRE ATT&CK.")
        return techniques

    except requests.exceptions.RequestException as exc:
        print(f"[mitre] Download failed ({exc}). Checking for cached data at {output_path}...")

        if output_path.exists():
            with open(output_path, "r", encoding="utf-8") as f:
                techniques = json.load(f)
            print(f"[mitre] Loaded {len(techniques)} techniques from cache.")
            return techniques

        raise RuntimeError(
            f"Could not download MITRE ATT&CK data and no cached file found at {output_path}. "
            "Check your internet connection and try again."
        ) from exc


def get_subtechniques(parent_id: str) -> list[dict]:
    """Return all sub-techniques of a parent MITRE technique from the cached catalog.

    Args:
        parent_id: A parent technique ID, e.g. "T1003".

    Returns:
        Technique dicts (id, name, description, tactic, is_subtechnique) whose
        id starts with "{parent_id}." and whose is_subtechnique is True,
        sorted by id. Empty list if none found.

    Raises:
        RuntimeError: If data/mitre_techniques.json doesn't exist yet.
    """
    output_path = _output_path()
    if not output_path.exists():
        raise RuntimeError(f"{output_path} not found. Run download_mitre_data() first.")

    with open(output_path, "r", encoding="utf-8") as f:
        techniques = json.load(f)

    prefix = f"{parent_id}."
    subtechniques = [
        technique
        for technique in techniques.values()
        if technique.get("is_subtechnique") and technique["id"].startswith(prefix)
    ]
    subtechniques.sort(key=lambda technique: technique["id"])
    return subtechniques
