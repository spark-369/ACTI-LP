"""Schema conformance + JWT/RBAC unit tests (no DB, no model)."""
from typing import get_args

import pytest
from fastapi import HTTPException

from app.core import security
from app.schemas import AttackType, LogParseResult, ParsedAnalysis, UserCreate, UserOut


class _FakeAlert:
    """Minimal stand-in for the ORM row: confidence is a real float in the DB."""

    is_malicious = True
    attack_type = "sql_injection"
    severity = "high"
    mitre_tactic = "TA0001 - Initial Access"
    iocs = ["185.220.101.45"]
    confidence = 1.0
    summary = "SQL injection attempt."


def test_parsed_analysis_from_alert_accepts_float_confidence():
    """Regression: response building re-validated stored data against the
    LLM's string-enum schema and raised for confidence=1.0 (a float)."""
    out = ParsedAnalysis.from_alert(_FakeAlert())
    assert out.confidence == 1.0
    assert out.attack_type == "sql_injection"


def test_parsed_analysis_from_result_converts_enum_to_float():
    result = LogParseResult(
        is_malicious=True,
        attack_type="brute_force",
        severity="high",
        mitre_tactic="TA0006 - Credential Access",
        iocs=["1.2.3.4"],
        confidence="0.9",
        summary="s",
    )
    out = ParsedAnalysis.from_result(result)
    assert out.confidence == 0.9
    assert isinstance(out.confidence, float)


def test_user_out_accepts_reserved_local_domain():
    """Response schemas must not validate deliverability of stored emails."""
    from datetime import datetime, timezone

    user = UserOut(
        id=1,
        email="admin@actilp.local",
        full_name="Admin",
        role="admin",
        tenant_id="default",
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    assert user.email == "admin@actilp.local"


def test_user_create_accepts_internal_domains():
    for email in ("admin@actilp.local", "analyst@corp.internal", "a@b.io"):
        assert UserCreate(email=email, password="Password123!").email == email


def test_user_create_rejects_malformed_email():
    with pytest.raises(Exception):
        UserCreate(email="not-an-email", password="Password123!")


def test_user_create_rejects_short_password():
    with pytest.raises(Exception):
        UserCreate(email="a@b.io", password="short")


def test_log_parse_result_accepts_valid_payload():
    result = LogParseResult(
        is_malicious=True,
        attack_type="brute_force",
        severity="high",
        mitre_tactic="TA0006 - Credential Access",
        iocs=["185.220.101.45"],
        confidence="0.8",
        summary="Repeated failed RDP logins from a Tor exit node.",
    )
    assert result.severity == "high"
    assert result.iocs == ["185.220.101.45"]
    assert result.confidence == "0.8"
    assert result.confidence_value == 0.8


@pytest.mark.parametrize("severity", ["low", "medium", "high", "critical"])
def test_log_parse_result_allows_known_severities(severity):
    LogParseResult(
        is_malicious=True,
        attack_type="x",
        severity=severity,
        mitre_tactic="",
        iocs=[],
        confidence="0.1",
        summary="s",
    )


def test_log_parse_result_rejects_unknown_severity():
    with pytest.raises(Exception):
        LogParseResult(
            is_malicious=True,
            attack_type="x",
            severity="catastrophic",
            mitre_tactic="",
            iocs=[],
            confidence="0.1",
            summary="s",
        )


def test_confidence_must_be_enum_value():
    """Regression: the model emitted 100; only 0.1-step strings are allowed."""
    with pytest.raises(Exception):
        LogParseResult(
            is_malicious=True,
            attack_type="sql_injection",
            severity="high",
            mitre_tactic="",
            iocs=[],
            confidence="100",
            summary="s",
        )


def test_attack_type_is_normalized_to_snake_case():
    """The model returned 'SQL Injection'; stored values must be comparable."""
    result = LogParseResult(
        is_malicious=True,
        attack_type="SQL Injection",
        severity="high",
        mitre_tactic="TA0001 - Initial Access",
        iocs=[],
        confidence="0.7",
        summary="s",
    )
    assert result.attack_type == "sql_injection"


def test_mitre_tactic_null_is_tolerated():
    result = LogParseResult(
        is_malicious=False,
        attack_type="none",
        severity="low",
        mitre_tactic=None,
        iocs=[],
        confidence="0.3",
        summary="benign",
    )
    assert result.mitre_tactic == ""


def test_mitre_tactic_bare_code_is_canonicalised():
    """The model often emits just "TA0006"; the enum needs the full label."""
    result = LogParseResult(
        is_malicious=True,
        attack_type="brute_force",
        severity="high",
        mitre_tactic="TA0006",
        iocs=[],
        confidence="0.8",
        summary="s",
    )
    assert result.mitre_tactic == "TA0006 - Credential Access"


def test_mitre_tactic_prose_is_canonicalised():
    result = LogParseResult(
        is_malicious=True,
        attack_type="brute_force",
        severity="high",
        mitre_tactic="credential access",
        iocs=[],
        confidence="0.8",
        summary="s",
    )
    assert result.mitre_tactic == "TA0006 - Credential Access"


def test_unknown_mitre_tactic_degrades_to_empty():
    """An invented tactic must not drop the whole parse into the fallback."""
    result = LogParseResult(
        is_malicious=True,
        attack_type="malware",
        severity="high",
        mitre_tactic="TA9999 - Made Up",
        iocs=[],
        confidence="0.6",
        summary="s",
    )
    assert result.mitre_tactic == ""


def test_unknown_attack_type_degrades_to_none():
    result = LogParseResult(
        is_malicious=False,
        attack_type="totally_unknown_category",
        severity="low",
        mitre_tactic="",
        iocs=[],
        confidence="0.2",
        summary="s",
    )
    assert result.attack_type == "none"


def test_attack_type_alias_is_mapped():
    result = LogParseResult(
        is_malicious=True,
        attack_type="XSS",
        severity="medium",
        mitre_tactic="",
        iocs=[],
        confidence="0.5",
        summary="s",
    )
    assert result.attack_type == "cross_site_scripting"


def test_every_alias_targets_a_real_member():
    """An alias pointing at a removed member would silently become "none".

    The alias table is hand-written next to the enum, so it is exactly the kind
    of thing that rots when members are added or removed.
    """
    values = set(get_args(AttackType))
    from app.schemas import ATTACK_TYPE_VALUES

    assert ATTACK_TYPE_VALUES == values

    # Drive each documented abbreviation through the public schema.
    for alias, expected in [
        ("ddos", "distributed_denial_of_service"),
        ("csrf", "cross_site_request_forgery"),
        ("ssrf", "server_side_request_forgery"),
        ("xxe", "xml_external_entity"),
        ("ssti", "server_side_template_injection"),
        ("mitm", "man_in_the_middle"),
        ("rce", "command_injection"),
        ("webshell", "web_shell"),
        ("cryptojacking", "cryptominer"),
        ("exfiltration", "data_exfiltration"),
    ]:
        assert expected in values, f"alias {alias!r} targets a missing member"
        parsed = LogParseResult(
            is_malicious=True,
            attack_type=alias,
            severity="high",
            mitre_tactic="",
            iocs=[],
            confidence="0.7",
            summary="s",
        )
        assert parsed.attack_type == expected, alias


# ── attack_type vocabulary ────────────────────────────────────────────────
def test_attack_type_enum_is_100():
    """The enum is specified as exactly 100 attack types.

    Pinned because a duplicate would silently shrink the usable vocabulary and
    because hand-counting a 100-entry Literal is not a reliable review step.
    """
    values = get_args(AttackType)

    assert len(values) == 100, f"expected 100 attack types, found {len(values)}"
    assert len(set(values)) == 100, "duplicate attack_type members"
    for value in values:
        assert value == value.strip().lower(), f"non-canonical member: {value!r}"
        assert " " not in value and "-" not in value, f"not snake_case: {value!r}"


def test_attack_type_enum_keeps_original_values():
    """Alerts already stored must keep their exact value after the expansion."""
    original = {
        "none",
        "sql_injection",
        "cross_site_scripting",
        "path_traversal",
        "brute_force",
        "reverse_shell",
        "command_and_control",
        "ransomware",
        "privilege_escalation",
        "port_scan",
        "malware",
        "data_exfiltration",
    }
    assert original <= set(get_args(AttackType))


@pytest.mark.parametrize(
    "attack_type",
    [
        "credential_stuffing",
        "server_side_request_forgery",
        "kerberoasting",
        "dns_tunneling",
        "fileless_malware",
        "cloud_bucket_exposure",
    ],
)
def test_new_attack_types_are_accepted(attack_type):
    """A newly added member must validate end to end."""
    result = LogParseResult(
        is_malicious=True,
        attack_type=attack_type,
        severity="high",
        mitre_tactic="TA0006 - Credential Access",
        iocs=[],
        confidence="0.7",
        summary="s",
    )
    assert result.attack_type == attack_type


def test_ddos_alias_maps_to_ddos_not_exfiltration():
    """Regression: "ddos" used to be folded into data_exfiltration."""
    result = LogParseResult(
        is_malicious=True,
        attack_type="DDoS",
        severity="high",
        mitre_tactic="TA0040 - Impact",
        iocs=[],
        confidence="0.9",
        summary="s",
    )
    assert result.attack_type == "distributed_denial_of_service"


def test_password_hash_roundtrip():
    hashed = security.hash_password("Admin123!")
    assert hashed != "Admin123!"
    assert security.verify_password("Admin123!", hashed)
    assert not security.verify_password("wrong", hashed)


def test_access_and_refresh_tokens_are_distinct_types():
    access = security.create_access_token("1", "analyst", "default")
    refresh = security.create_refresh_token("1", "analyst", "default")

    assert security.decode_token(access, expected_type="access")["tid"] == "default"
    assert security.decode_token(refresh, expected_type="refresh")["sub"] == "1"

    with pytest.raises(HTTPException):
        security.decode_token(refresh, expected_type="access")


def test_tampered_token_is_rejected():
    token = security.create_access_token("1", "viewer", "default")
    with pytest.raises(HTTPException):
        security.decode_token(token + "x", expected_type="access")


@pytest.mark.asyncio
async def test_current_user_requires_tenant_claim():
    token = security.create_token("1", "viewer")  # no tid → legacy shape
    with pytest.raises(HTTPException) as exc_info:
        await security.current_user(token)
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_require_role_forbids_insufficient_role():
    dep = security.require_role("admin")
    with pytest.raises(HTTPException) as exc_info:
        await dep({"sub": "1", "role": "viewer", "tid": "default"})
    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_require_role_allows_matching_role():
    dep = security.require_role("admin", "analyst")
    user = await dep({"sub": "1", "role": "analyst", "tid": "default"})
    assert user["role"] == "analyst"
