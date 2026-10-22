"""Pytest fixtures: SQLite-backed app with Chroma and the LLM stubbed."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.models import Tenant, User  # noqa: F401  (registers metadata)
from app.schemas import LogParseResult
from app.services import chroma_local_svc, hf_outlines_svc, parser


@pytest.fixture()
def client(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def _get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _get_db

    # Stub out Chroma writes/reads and model inference.
    monkeypatch.setattr(chroma_local_svc, "add_logs", lambda *a, **k: 1)

    async def _no_context(*_a, **_k):
        return []

    monkeypatch.setattr(chroma_local_svc, "search", _no_context)

    async def _fake_parse(raw_log, context):
        return {
            "result": hf_outlines_svc.heuristic_parse(raw_log),
            "parser_mode": "outlines",
            "model_id": "Qwen/Qwen2.5-0.5B-Instruct",
        }

    monkeypatch.setattr(hf_outlines_svc, "parse_log", _fake_parse)
    monkeypatch.setattr(parser.hf_outlines_svc, "parse_log", _fake_parse)

    from app.services import bootstrap

    monkeypatch.setattr(bootstrap, "bootstrap", lambda: None)
    from app.services import ingest

    monkeypatch.setattr(ingest, "ensure_group", lambda: None)

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def admin(client):
    """Create the bootstrap-equivalent admin in the test DB, then log in."""
    from app.core.security import hash_password

    db = next(app.dependency_overrides[get_db]())
    db.add(Tenant(id="default", name="Default"))
    db.add(
        User(
            email="admin@actilp.local",
            full_name="Admin",
            hashed_password=hash_password("Admin123!"),
            role="admin",
            tenant_id="default",
            is_active=True,
        )
    )
    db.commit()

    response = client.post(
        "/api/v1/auth/login/json",
        json={"email": "admin@actilp.local", "password": "Admin123!"},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture()
def sample_result() -> LogParseResult:
    return hf_outlines_svc.heuristic_parse("brute force failed password for invalid user")
