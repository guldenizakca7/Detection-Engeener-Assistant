"""ChromaDB-backed semantic search over MITRE ATT&CK techniques."""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer

EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"
COLLECTION_NAME = "mitre_techniques"
COLLECTION_METADATA = {"hnsw:space": "cosine"}

_model: SentenceTransformer | None = None
_client = None


def _data_dir() -> Path:
    """Return the configured data directory (DATA_DIR, default ./data)."""
    return Path(os.getenv("DATA_DIR", "./data"))


def _techniques_path() -> Path:
    """Return the path to the cached technique catalog JSON file."""
    return _data_dir() / "mitre_techniques.json"


def _chroma_dir() -> Path:
    """Return the path to the persistent ChromaDB directory."""
    return _data_dir() / "chroma"


def _get_model() -> SentenceTransformer:
    """Return the process-wide SentenceTransformer instance, loading it on first use."""
    global _model
    if _model is None:
        _model = SentenceTransformer(EMBEDDING_MODEL_NAME)
    return _model


def _get_client():
    """Return the process-wide ChromaDB persistent client, creating it on first use."""
    global _client
    if _client is None:
        _chroma_dir().mkdir(parents=True, exist_ok=True)
        _client = chromadb.PersistentClient(path=str(_chroma_dir()))
    return _client


def _embedding_text(technique: dict) -> str:
    """Build the text embedded per technique: "{id} {name} {tactic} {description}"."""
    return f"{technique['id']} {technique['name']} {technique['tactic']} {technique['description']}"


def build_vector_db() -> None:
    """Embed all MITRE techniques from data/mitre_techniques.json into ChromaDB.

    Idempotent: if the collection already holds the same number of techniques
    as the source JSON, this is a no-op (skips re-embedding on every startup).
    Otherwise the collection is dropped and rebuilt from scratch, to avoid
    stale or duplicate entries from a previous partial run.

    Raises:
        RuntimeError: If data/mitre_techniques.json doesn't exist yet.
    """
    techniques_path = _techniques_path()
    if not techniques_path.exists():
        raise RuntimeError(f"{techniques_path} not found. Run download_mitre_data() first.")

    with open(techniques_path, "r", encoding="utf-8") as f:
        techniques = json.load(f)

    client = _get_client()
    collection = client.get_or_create_collection(COLLECTION_NAME, metadata=COLLECTION_METADATA)

    if collection.count() == len(techniques):
        print(f"[mitre] Vector DB already has {collection.count()} techniques, skipping rebuild.")
        return

    if collection.count() > 0:
        client.delete_collection(COLLECTION_NAME)
        collection = client.get_or_create_collection(COLLECTION_NAME, metadata=COLLECTION_METADATA)

    model = _get_model()
    ids = list(techniques.keys())
    texts = [_embedding_text(techniques[tid]) for tid in ids]
    metadatas = [
        {
            "id": techniques[tid]["id"],
            "name": techniques[tid]["name"],
            "tactic": techniques[tid]["tactic"],
            "is_subtechnique": techniques[tid]["is_subtechnique"],
        }
        for tid in ids
    ]

    print(f"[mitre] Embedding {len(ids)} techniques with {EMBEDDING_MODEL_NAME}...")
    embeddings = model.encode(texts, show_progress_bar=True).tolist()

    collection.add(ids=ids, embeddings=embeddings, documents=texts, metadatas=metadatas)
    print(f"[mitre] Vector DB built: {collection.count()} techniques stored at {_chroma_dir()}")


def search(query: str, top_k: int = 3) -> list[dict]:
    """Semantic search over the MITRE technique vector DB.

    Args:
        query: Free-text query (e.g. an LLM's reasoning + technique name, or a
            CTI report chunk).
        top_k: Maximum number of results to return.

    Returns:
        A list of {technique_id, name, tactic, similarity} dicts, sorted by
        similarity descending. similarity is in roughly [0, 1], higher = closer.
    """
    client = _get_client()
    collection = client.get_or_create_collection(COLLECTION_NAME, metadata=COLLECTION_METADATA)
    model = _get_model()

    query_embedding = model.encode([query]).tolist()
    results = collection.query(query_embeddings=query_embedding, n_results=top_k)

    ids = results.get("ids", [[]])[0]
    distances = results.get("distances", [[]])[0]
    metadatas = results.get("metadatas", [[]])[0]

    # Collections are created with metadata={"hnsw:space": "cosine"} (see
    # COLLECTION_METADATA), so ChromaDB's "distance" here is cosine distance
    # (1 - cosine similarity), not the default squared-L2 distance. That makes
    # `1 - distance` recover the cosine similarity directly -- this conversion
    # would be wrong for a collection using any other space (e.g. "l2").
    matches = [
        {
            "technique_id": technique_id,
            "name": metadata.get("name"),
            "tactic": metadata.get("tactic"),
            "similarity": 1 - distance,
        }
        for technique_id, distance, metadata in zip(ids, distances, metadatas)
    ]

    matches.sort(key=lambda m: m["similarity"], reverse=True)
    return matches


def search_in_chunks(query: str, corpus: list[str], top_k: int = 5) -> list[str]:
    """Semantic search over an ad-hoc list of text chunks (CTI context extraction).

    Builds a temporary in-memory ChromaDB collection from `corpus`, searches
    it, and deletes it before returning.

    Args:
        query: Free-text query, typically "{technique_id} {name} {tactic}".
        corpus: The text chunks to search over (e.g. a chunked CTI report).
        top_k: Maximum number of chunks to return (capped at len(corpus)).

    Returns:
        The top_k most relevant chunk strings from `corpus`, most relevant first.
    """
    client = _get_client()
    model = _get_model()

    temp_name = f"temp-{uuid.uuid4().hex}"
    temp_collection = client.create_collection(temp_name, metadata=COLLECTION_METADATA)

    try:
        ids = [str(i) for i in range(len(corpus))]
        embeddings = model.encode(corpus).tolist()
        temp_collection.add(ids=ids, embeddings=embeddings, documents=corpus)

        query_embedding = model.encode([query]).tolist()
        results = temp_collection.query(
            query_embeddings=query_embedding, n_results=min(top_k, len(corpus))
        )
        return results.get("documents", [[]])[0]
    finally:
        client.delete_collection(temp_name)
