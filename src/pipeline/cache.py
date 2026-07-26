"""SHA-256-keyed JSON cache for pipeline results, to skip redundant LLM calls
for repeated inputs."""
import hashlib
import json
import os
from pathlib import Path
from datetime import datetime

CACHE_DIR = Path(os.getenv("DATA_DIR", "./data")) / "cache"


def _get_cache_key(user_input: str, mode: str) -> str:
    """Generate SHA-256 hash key from input + mode."""
    content = f"{mode}:{user_input.strip().lower()}"
    return hashlib.sha256(content.encode()).hexdigest()


def get_cached_result(user_input: str, mode: str) -> dict | None:
    """
    Check if a cached result exists for this input.
    Returns the cached result dict or None if not found.
    Cache hit returns in <10ms.
    """
    key = _get_cache_key(user_input, mode)
    cache_file = CACHE_DIR / f"{key}.json"

    if cache_file.exists():
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("result")
        except Exception:
            return None
    return None


def save_to_cache(user_input: str, mode: str, result: list) -> None:
    """
    Save pipeline result to cache using SHA-256 keyed file.
    result is the list of technique dicts returned by the pipeline.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    key = _get_cache_key(user_input, mode)
    cache_file = CACHE_DIR / f"{key}.json"

    try:
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump({
                "input": user_input,
                "mode": mode,
                "cached_at": datetime.utcnow().isoformat(),
                "result": result
            }, f, ensure_ascii=False, indent=2)
    except Exception:
        pass  # Cache write failure is non-fatal


def clear_cache() -> int:
    """Delete all cache files. Returns count of deleted files."""
    if not CACHE_DIR.exists():
        return 0
    count = 0
    for f in CACHE_DIR.glob("*.json"):
        f.unlink()
        count += 1
    return count
