"""Local ChromaDB — ``PersistentClient``, in-process, no HTTP server.

Each tenant gets its own collection (``threat_<tenant_id>``) so vector data is
isolated per tenant. Everything lives under ``CHROMA_PATH`` (``/app/.chroma``).

Note: Chroma's embedded client is single-writer friendly; the Celery worker is
started with ``--concurrency=1`` for that reason (see README §13).
"""
import logging
import re
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List

import chromadb
from chromadb.config import Settings as ChromaSettings

from app.core.config import settings
from app.services import embedder

logger = logging.getLogger(__name__)

_client = None
_client_lock = threading.Lock()
_SAFE = re.compile(r"[^a-zA-Z0-9_-]")
MIN_DOC_CHARS = 3


def _collection_name(tenant_id: str) -> str:
    safe = _SAFE.sub("_", tenant_id)[:48] or "default"
    # Chroma requires 3-63 chars, alphanumeric start/end.
    name = f"threat_{safe}"
    return name[:63].rstrip("_-") if len(name) >= 3 else "threat_default"


def get_client():
    global _client
    if _client is not None:
        return _client
    with _client_lock:
        if _client is None:
            settings.chroma_path.mkdir(parents=True, exist_ok=True)
            _client = chromadb.PersistentClient(
                path=str(settings.chroma_path),
                settings=ChromaSettings(anonymized_telemetry=False, allow_reset=False),
            )
            logger.info("chroma_ready path=%s", settings.chroma_path)
    return _client


def get_collection(tenant_id: str):
    client = get_client()
    return client.get_or_create_collection(
        name=_collection_name(tenant_id),
        metadata={"hnsw:space": "cosine"},
    )


def add_logs(tenant_id: str, documents: List[str], metadatas: List[Dict[str, Any]] | None = None) -> int:
    """Embed and store log documents in the tenant collection."""
    docs = [d for d in documents if d and len(d.strip()) >= MIN_DOC_CHARS]
    if not docs:
        return 0

    col = get_collection(tenant_id)
    ids = [f"{tenant_id}-{datetime.now(timezone.utc).timestamp()}-{i}" for i in range(len(docs))]
    metas = metadatas or [{"source": "parser"} for _ in docs]

    try:
        vectors = embedder.embed(docs)
    except Exception as exc:  # embedder unavailable → skip indexing, parsing continues
        logger.warning("chroma_add_skipped err=%s", exc)
        return 0

    col.add(ids=ids, documents=docs, embeddings=vectors, metadatas=metas)
    logger.info("chroma_added tenant=%s docs=%d", tenant_id, len(docs))
    return len(docs)


async def search(tenant_id: str, query: str, limit: int = 10) -> List[str]:
    """Return the ``limit`` closest historical logs (empty list on any failure)."""
    if not query or len(query.strip()) < MIN_DOC_CHARS:
        return []
    try:
        col = get_collection(tenant_id)
        if col.count() == 0:
            return []
        vector = embedder.embed_one(query[:4000])
        result = col.query(query_embeddings=[vector], n_results=min(limit, col.count()))
        docs = (result.get("documents") or [[]])[0]
        return [d for d in docs if d]
    except Exception as exc:  # never let retrieval break parsing
        logger.warning("chroma_search_failed tenant=%s err=%s", tenant_id, exc)
        return []


def count(tenant_id: str) -> int:
    try:
        return get_collection(tenant_id).count()
    except Exception:
        return -1


def health() -> str:
    try:
        get_client()
        return "ok"
    except Exception as exc:  # pragma: no cover - env dependent
        return f"error: {str(exc)[:120]}"
