"""End-to-end API tests against SQLite with stubbed model + Chroma."""
MALICIOUS = (
    "fw01 kernel: DROP SRC=185.220.101.45 DST=10.0.4.12 DPT=3389 "
    "failed password attempts for invalid user administrator"
)


def test_healthz_is_public(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert set(body) >= {"env", "postgres", "redis", "chroma", "model"}


def test_healthz_is_not_under_api_prefix(client):
    """Contract the SPA depends on.

    ``systemApi.health`` used to call ``api.get('/healthz')`` through the axios
    instance whose baseURL is ``/api/v1``, so the sidebar requested
    ``/api/v1/healthz`` → 404 → it always rendered "Degraded". The SPA now
    strips the prefix and calls the app root; keep ``/healthz`` there and make
    sure nothing silently mounts a shadow copy under the API prefix.
    """
    assert client.get("/healthz").status_code == 200
    assert client.get("/api/v1/healthz").status_code == 404


def test_login_rejects_bad_password(client):
    response = client.post(
        "/api/v1/auth/login/json",
        json={"email": "nobody@actilp.local", "password": "x"},
    )
    assert response.status_code == 401


def test_login_with_malformed_email_returns_401_not_422(client):
    """Login must never 422 on shape: bad emails fall through to the auth check."""
    response = client.post(
        "/api/v1/auth/login/json",
        json={"email": "not-an-email", "password": "whatever"},
    )
    assert response.status_code == 401


def test_me_returns_current_user(client, admin):
    response = client.get("/api/v1/auth/me", headers=admin)
    assert response.status_code == 200
    assert response.json()["role"] == "admin"


def test_parse_creates_alert(client, admin):
    response = client.post("/api/v1/parse", json={"raw_log": MALICIOUS}, headers=admin)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["alert_id"]
    assert body["result"]["is_malicious"] is True
    assert body["result"]["severity"] == "high"
    # API contract keeps a numeric confidence even though the LLM schema
    # constrains it as a 0.1-step string enum.
    assert isinstance(body["result"]["confidence"], float)
    assert 0.0 <= body["result"]["confidence"] <= 1.0

    listing = client.get("/api/v1/alerts", headers=admin)
    assert listing.status_code == 200
    assert listing.json()["total"] == 1


def test_stored_alert_with_confidence_one_is_served(client, admin):
    """Regression: alert.confidence is a Float in Postgres, so a stored 1.0
    must survive being shaped into the API response (previously 500)."""
    from app.db import get_db
    from app.main import app
    from app.models import Alert

    # Simulate the LLM returning the top confidence step.
    db = next(app.dependency_overrides[get_db]())
    db.add(
        Alert(
            tenant_id="default",
            source="test",
            raw_log="sql injection attempt",
            is_malicious=True,
            attack_type="sql_injection",
            severity="high",
            mitre_tactic="TA0001 - Initial Access",
            iocs=[],
            confidence=1.0,
            summary="Stored max confidence.",
            model_id="Qwen/Qwen2.5-0.5B-Instruct",
            parser_mode="outlines",
        )
    )
    db.commit()

    listing = client.get("/api/v1/alerts", headers=admin)
    assert listing.status_code == 200
    assert listing.json()["items"][0]["confidence"] == 1.0


def test_alert_acknowledge_and_close(client, admin):
    alert_id = client.post("/api/v1/parse", json={"raw_log": MALICIOUS}, headers=admin).json()["alert_id"]

    ack = client.post(f"/api/v1/alerts/{alert_id}/acknowledge", headers=admin)
    assert ack.status_code == 200
    assert ack.json()["status"] == "acknowledged"

    closed = client.post(f"/api/v1/alerts/{alert_id}/close", headers=admin)
    assert closed.status_code == 200
    assert closed.json()["status"] == "closed"


def test_acknowledged_by_shows_identity_not_user_id(client, admin):
    """Regression: the detail panel rendered "Acknowledged by: 2".

    The JWT ``sub`` is a numeric user id, so storing it verbatim put a bare
    user id in front of analysts. The stored value must identify the person.
    """
    alert_id = client.post("/api/v1/parse", json={"raw_log": MALICIOUS}, headers=admin).json()["alert_id"]

    body = client.post(f"/api/v1/alerts/{alert_id}/acknowledge", headers=admin).json()

    assert body["acknowledged_by"] != "1", "raw user id leaked into the UI"
    assert not body["acknowledged_by"].isdigit(), body["acknowledged_by"]
    assert body["acknowledged_by"] == "admin@actilp.local"


def test_acknowledge_writes_readable_audit_actor(client, admin):
    """The audit trail must name the actor, not its database id."""
    alert_id = client.post("/api/v1/parse", json={"raw_log": MALICIOUS}, headers=admin).json()["alert_id"]
    client.post(f"/api/v1/alerts/{alert_id}/acknowledge", headers=admin)

    rows = client.get("/api/v1/audit?action=alert.acknowledge", headers=admin).json()

    assert rows, "no audit row written"
    assert rows[0]["actor"] == "admin@actilp.local"


def test_me_returns_reserved_local_domain(client, admin):
    """.local is a reserved TLD (RFC 6762); it must serialize, not 500.

    Regression: UserOut.email was EmailStr, so response validation raised
    ResponseValidationError for the bootstrap admin@actilp.local.
    """
    response = client.get("/api/v1/auth/me", headers=admin)
    assert response.status_code == 200
    assert response.json()["email"] == "admin@actilp.local"


def test_me_returns_401_not_500_for_non_numeric_sub(client):
    """A token from a stale/foreign JWT_SECRET must not crash /auth/me."""
    from app.core.security import create_access_token

    token = create_access_token("not-an-int", "admin", "default")
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert response.status_code != 500


def test_cors_preflight_allows_frontend_origin(client):
    response = client.options(
        "/api/v1/auth/me",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_tenant_isolation_hides_other_tenants_alerts(client, admin):
    client.post("/api/v1/parse", json={"raw_log": MALICIOUS}, headers=admin)

    # Forge a token for a different tenant.
    from app.core.security import create_access_token

    other = create_access_token("999", "admin", "other-tenant")
    response = client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {other}"})
    assert response.status_code == 200
    assert response.json()["total"] == 0


def test_viewer_cannot_parse(client, admin):
    from app.core.security import hash_password
    from app.main import app
    from app.db import get_db
    from app.models import User

    db = next(app.dependency_overrides[get_db]())
    db.add(
        User(
            email="viewer@actilp.local",
            full_name="Viewer",
            hashed_password=hash_password("Viewer123!"),
            role="viewer",
            tenant_id="default",
            is_active=True,
        )
    )
    db.commit()

    token = client.post(
        "/api/v1/auth/login/json",
        json={"email": "viewer@actilp.local", "password": "Viewer123!"},
    ).json()["access_token"]

    response = client.post(
        "/api/v1/parse",
        json={"raw_log": MALICIOUS},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


def test_dashboard_stats_shape(client, admin):
    client.post("/api/v1/parse", json={"raw_log": MALICIOUS}, headers=admin)
    response = client.get("/api/v1/dashboard/stats?days=3", headers=admin)
    assert response.status_code == 200
    body = response.json()
    assert body["total_alerts"] == 1
    assert len(body["by_severity"]) == 4
    assert len(body["timeline"]) == 3
