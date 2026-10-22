# apps/api/Dockerfile
#
# Build context is the REPO ROOT, not apps/api — the image needs both
# `apps/api/` sources and the repo-level `ml/` prompt/schema tree. The README
# command therefore is:
#
#   docker build -f apps/api/Dockerfile -t <user>/acti-lp-api:latest .
#
# (`docker build -t x apps/api` made `COPY ml ./ml` fail with
#  "ml: not found", which is the bug this file previously had.)
FROM python:3-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl \
    && rm -rf /var/lib/apt/lists/*

COPY apps/api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY apps/api/app ./app

# Prompt templates + versioned JSON schema live at the REPO ROOT in ml/.
# hf_outlines_svc.PROMPT_DIR resolves to /app/ml/prompts in the image.
COPY ml ./ml

# ── .env baked into the image ──
# NOTE: apps/api/.env is committed with DEVELOPMENT values (localhost Postgres/
# Redis, CHROMA_PATH=./.chroma). The two ENV lines below re-point the
# container-local paths at /app so the same file works inside the image.
# For a container deployment also set POSTGRES_HOST=actilp-postgres and
# REDIS_URL=redis://actilp-redis:6379/0 (README §4).
COPY apps/api/.env ./

# Container overrides — ENV wins over .env at runtime, so these always apply.
ENV HF_HOME=/app/.cache/huggingface
RUN mkdir -p /app/.cache/huggingface

ENV CHROMA_PATH=/app/.chroma
RUN mkdir -p /app/.chroma

# Pre-download the Qwen2.5-0.5B weights + local embedding model at build time
# so the first request does not pay the download (README §13: model download
# latency). Model ids are read from the baked .env so there is one source of
# truth — changing HF_MODEL_ID / EMBEDDER_MODEL never desyncs the build.
RUN python - <<'PY'
import os
from dotenv import dotenv_values
from transformers import AutoModelForCausalLM, AutoTokenizer
from sentence_transformers import SentenceTransformer

cfg = dotenv_values(".env")
model_id = os.environ.get("HF_MODEL_ID", cfg.get("HF_MODEL_ID", "Qwen/Qwen2.5-0.5B-Instruct"))
embedder_id = os.environ.get("EMBEDDER_MODEL", cfg.get("EMBEDDER_MODEL", "sentence-transformers/all-MiniLM-L6-v2"))

print(f"priming cache: model={model_id} embedder={embedder_id}")
AutoTokenizer.from_pretrained(model_id)
AutoModelForCausalLM.from_pretrained(model_id)
SentenceTransformer(embedder_id)
print("model cache primed", model_id, embedder_id)
PY

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -fsS http://localhost:8080/healthz || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
