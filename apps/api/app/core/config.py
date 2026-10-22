"""Application configuration.

All values are loaded from ``apps/api/.env`` which is committed and baked into
the image at build time (``COPY .env ./``). No ``--env-file`` is required at
``docker run`` time.
"""
from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # --- Database -----------------------------------------------------------
    POSTGRES_DB: str = "actilp"
    POSTGRES_USER: str = "actilp"
    POSTGRES_PASSWORD: str = "change-me"
    POSTGRES_HOST: str = "actilp-postgres"
    POSTGRES_PORT: int = 5432

    # --- Redis / Celery -----------------------------------------------------
    REDIS_URL: str = "redis://actilp-redis:6379/0"
    STREAM_NAME: str = "actilp:raw_logs"
    STREAM_GROUP: str = "actilp-workers"

    # --- Auth ---------------------------------------------------------------
    JWT_SECRET: str = "change-me-to-a-long-random-string"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_TTL_MINUTES: int = 15
    REFRESH_TOKEN_TTL_DAYS: int = 7

    # --- Local ChromaDB (in-process, no HTTP server) ------------------------
    CHROMA_PATH: str = "/app/.chroma"

    # --- Qwen2.5-0.5B-Instruct + Outlines ----------------------------------
    HF_MODEL_ID: str = "Qwen/Qwen2.5-0.5B-Instruct"
    HF_DEVICE: str = "cpu"
    HF_HOME: str = "/app/.cache/huggingface"
    HF_MAX_NEW_TOKENS: int = 512
    HF_PRELOAD_ON_STARTUP: bool = False

    # --- Embedder (local sentence-transformers, in-process) ----------------
    EMBEDDER_MODEL: str = "sentence-transformers/all-MiniLM-L6-v2"

    # --- RAG tuning --------------------------------------------------------
    # Retrieval window. Default 10: Chroma returns nearest-first so only the
    # nearest neighbours carry signal, and small models lose accuracy as the
    # prompt grows. Unvalidated starting point — not a measured optimum.
    RAG_TOP_K: int = 10
    # Max characters of history injected into the prompt (0 = module default).
    RAG_CONTEXT_MAX_CHARS: int = 0

    # --- Prompt templates (repo-root ml/ or /app/ml in the image) ----------
    # Empty means "auto-detect"; see hf_outlines_svc._resolve_prompt_dir().
    ML_PROMPT_DIR: str = ""

    # --- App ----------------------------------------------------------------
    APP_ENV: str = "production"
    LOG_LEVEL: str = "info"
    CORS_ORIGINS: str = "http://localhost:3000"
    API_PREFIX: str = "/api/v1"

    # --- Bootstrap admin ----------------------------------------------------
    BOOTSTRAP_ADMIN_EMAIL: str = "admin@actilp.local"
    BOOTSTRAP_ADMIN_PASSWORD: str = "Admin123!"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"
        case_sensitive = True

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+psycopg2://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def chroma_path(self) -> Path:
        return Path(self.CHROMA_PATH)


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
