"""Local embeddings for local ChromaDB.

Chroma's default embedding function downloads an ONNX MiniLM at first use. To
stay fully local and predictable we compute embeddings with
``sentence-transformers`` and hand them to Chroma explicitly.

``get_embedder()`` is lazy so importing this module never loads a model.
"""
import logging
import threading
from typing import List, Sequence

from app.core.config import settings

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_model = None
_model_error: str | None = None


def get_embedder():
    """Lazily build the local sentence-transformers model (CPU)."""
    global _model, _model_error
    if _model is not None:
        return _model
    with _lock:
        if _model is None:
            from sentence_transformers import SentenceTransformer

            try:
                _model = SentenceTransformer(settings.EMBEDDER_MODEL, device="cpu")
                _model_error = None
            except Exception as exc:  # pragma: no cover - depends on env
                _model_error = str(exc)
                logger.error("embedder_unavailable model=%s err=%s", settings.EMBEDDER_MODEL, exc)
                raise
    return _model


def embed(texts: Sequence[str]) -> List[List[float]]:
    model = get_embedder()
    vectors = model.encode(
        list(texts),
        normalize_embeddings=True,
        convert_to_numpy=True,
        show_progress_bar=False,
    )
    return [v.tolist() for v in vectors]


def embed_one(text: str) -> List[float]:
    return embed([text])[0]


def health() -> str:
    if _model is not None:
        return "ok"
    if _model_error:
        return f"error: {_model_error[:120]}"
    return "not-loaded"
