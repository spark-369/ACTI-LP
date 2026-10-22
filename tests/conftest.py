"""Shared pytest fixtures.

Unit tests never touch PostgreSQL, Redis, Chroma or the LLM: the database is
SQLite in-memory and external services are faked.
"""
import os
import sys
from pathlib import Path

import pytest

API_ROOT = Path(__file__).resolve().parents[1] / "apps" / "api"
sys.path.insert(0, str(API_ROOT))

# Config is read at import time; pin everything that has a default.
os.environ.setdefault("JWT_SECRET", "test-secret")
os.environ.setdefault("CHROMA_PATH", "/tmp/actilp-chroma-test")
os.environ.setdefault("HF_DEVICE", "cpu")
os.environ.setdefault("APP_ENV", "test")


@pytest.fixture(scope="session")
def api_root() -> Path:
    return API_ROOT
