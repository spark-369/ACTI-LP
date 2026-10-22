"""Pydantic schemas (request/response contracts + Outlines output schema)."""
from datetime import datetime
from typing import Literal, Optional, Union, get_args

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ── Outlines structured-output schema (mirrors ml/schemas/log_parse.schema.json)
Severity = Literal["low", "medium", "high", "critical"]

# 100 attack types. Grouped, and the original 11 come first so existing rows in
# the alerts table keep their exact stored value. Every value here is a closed
# enum member: the grammar can only emit these, which is what makes a 0.5B model
# usable at all. Ordering also nudges decoding — put the most common first.
#
# NOTE: keep in sync with ml/schemas/log_parse.schema.json and with the
# `attack_type` list in ml/prompts/system.txt (test_attack_type_enum_is_100
# enforces the count).
AttackType = Literal[
    # ── core / original set (do not reorder: stored values) ────────────────
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
    # ── injection / input validation ──────────────────────────────────────
    "nosql_injection",
    "ldap_injection",
    "xml_external_entity",
    "server_side_request_forgery",
    "template_injection",
    "command_injection",
    "header_injection",
    "deserialization_attack",
    # ── web application ───────────────────────────────────────────────────
    "cross_site_request_forgery",
    "open_redirect",
    "remote_file_inclusion",
    "local_file_inclusion",
    "web_shell",
    "directory_traversal_scan",
    "parameter_tampering",
    "session_fixation",
    "session_hijacking",
    "clickjacking",
    "http_request_smuggling",
    "host_header_injection",
    "api_abuse",
    "graphql_abuse",
    "server_side_template_injection",
    "file_upload_abuse",
    "broken_access_control",
    # ── credentials / auth ────────────────────────────────────────────────
    "credential_stuffing",
    "password_spraying",
    "credential_dumping",
    "kerberoasting",
    "pass_the_hash",
    "pass_the_ticket",
    "golden_ticket",
    "default_credentials",
    "account_takeover",
    "mfa_bypass",
    "token_theft",
    "saml_assertion_forgery",
    # ── network / transport ───────────────────────────────────────────────
    "denial_of_service",
    "distributed_denial_of_service",
    "dns_tunneling",
    "dns_spoofing",
    "arp_spoofing",
    "man_in_the_middle",
    "session_replay",
    "packet_sniffing",
    "udp_flood",
    "syn_flood",
    "ip_spoofing",
    "bgp_hijacking",
    "wifi_deauth",
    "rogue_access_point",
    "tls_downgrade",
    "protocol_anomaly",
    # ── malware families / execution ──────────────────────────────────────
    "trojan",
    "backdoor",
    "rootkit",
    "bootkit",
    "keylogger",
    "spyware",
    "adware",
    "worm",
    "virus",
    "logic_bomb",
    "dropper",
    "loader",
    "cryptominer",
    "ransomware_note",
    "wiper",
    "macro_malware",
    "malicious_document",
    "payload_delivery",
    # ── application / host behaviour ──────────────────────────────────────
    "suspicious_process",
    "suspicious_script_execution",
    "scheduled_task_abuse",
    "service_creation",
    "registry_persistence",
    "wmi_abuse",
    "dll_hijacking",
    "code_signing_bypass",
    "antivirus_evasion",
    "defense_evasion",
    "log_tampering",
    "timestamp_manipulation",
    # ── data / exfiltration / impact ──────────────────────────────────────
    "data_leak",
    "insider_threat",
    "sensitive_file_access",
    "database_dump",
    "cloud_bucket_exposure",
]

MitreTactic = Literal[
    "TA0001 - Initial Access",
    "TA0002 - Execution",
    "TA0003 - Persistence",
    "TA0004 - Privilege Escalation",
    "TA0005 - Defense Evasion",
    "TA0006 - Credential Access",
    "TA0007 - Discovery",
    "TA0008 - Lateral Movement",
    "TA0009 - Collection",
    "TA0010 - Exfiltration",
    "TA0011 - Command and Control",
    "TA0040 - Impact",
]

# Derived from the Literal so the validator can never drift from the enum.
ATTACK_TYPE_VALUES = frozenset(get_args(AttackType))
MITRE_TACTIC_VALUES = frozenset(get_args(MitreTactic))


class LogParseResult(BaseModel):
    """Schema the LLM is constrained to.

    Constrained decoding works on the JSON Schema *shape*, not on numeric
    semantics: ``ge``/``le`` become ``minimum``/``maximum`` keywords, which
    grammar backends (outlines_core / llguidance / xgrammar) do not enforce —
    the 0.5B model happily emitted ``"confidence": 100`` and Pydantic then
    rejected it, dropping every parse into the regex fallback.

    So ``confidence`` is declared as a ``str`` enum of 0.1 steps and coerced to
    ``float`` on access. That is enforceable by the grammar AND still gives the
    API/DB numeric values.

    Fields the model must always emit carry **no default** — a default makes
    them non-required in the derived schema, and the model then omits them
    (observed: missing ``mitre_tactic`` and ``iocs``).
    """

    is_malicious: bool
    attack_type: AttackType
    severity: Severity
    # Not a bare Literal: "" (nothing to report) must also be expressible, and
    # a nullable field makes the model omit it entirely (see docstring).
    mitre_tactic: Union[MitreTactic, Literal[""]]
    iocs: list[str]
    confidence: Literal[
        "0.1", "0.2", "0.3", "0.4", "0.5", "0.6", "0.7", "0.8", "0.9", "1.0"
    ]
    summary: str

    @property
    def confidence_value(self) -> float:
        """Numeric confidence for API responses and the alerts table."""
        return float(self.confidence)

    @field_validator("mitre_tactic", mode="before")
    @classmethod
    def _tactic_to_str(cls, value):
        """Tolerate null / malformed tactics instead of failing the whole parse.

        ``mitre_tactic`` is a ``Literal``, so the model emitting an unknown
        tactic (or the prose spelling "Credential Access") would raise and drop
        the parse into the regex fallback. Normalise what we can, else "".
        """
        if value is None:
            return ""
        if not isinstance(value, str):
            return ""
        text = value.strip()
        if not text:
            return ""
        if text in MITRE_TACTIC_VALUES:
            return text
        # "TA0006" or "credential access" → canonical "TA0006 - Credential Access"
        low = text.lower()
        for tactic in MITRE_TACTIC_VALUES:
            code, _, name = tactic.partition(" - ")
            if low == code.lower() or low == name.lower():
                return tactic
        return ""

    @field_validator("attack_type", mode="before")
    @classmethod
    def _normalize_attack_type(cls, value):
        """'SQL Injection' → 'sql_injection' so stored values are comparable.

        Runs in ``before`` mode because ``attack_type`` is now a ``Literal``:
        an ``after`` validator would only ever see an already-validated member,
        so a model emitting ``"SQL Injection"`` would fail validation instead of
        being normalised. Unmapped values fall back to ``"none"`` when the log
        is benign, else to the most generic category, so one odd label can never
        drop an entire parse into the regex fallback.
        """
        if not isinstance(value, str):
            return "none"
        slug = value.strip().lower().replace(" ", "_").replace("-", "_")
        if slug in ATTACK_TYPE_VALUES:
            return slug
        # Common model spellings that are not in the enum.
        aliases = {
            # abbreviations
            "xss": "cross_site_scripting",
            "sqli": "sql_injection",
            "csrf": "cross_site_request_forgery",
            "ssrf": "server_side_request_forgery",
            "xxe": "xml_external_entity",
            "lfi": "local_file_inclusion",
            "rfi": "remote_file_inclusion",
            "ssti": "server_side_template_injection",
            "dos": "denial_of_service",
            "ddos": "distributed_denial_of_service",
            "mitm": "man_in_the_middle",
            "rce": "command_injection",
            "rce_remote_code_execution": "command_injection",
            "lolbin": "suspicious_script_execution",
            # was mapped to data_exfiltration, which is a different thing
            "c2": "command_and_control",
            "cnc": "command_and_control",
            "beaconing": "command_and_control",
            # generic words the model falls back to
            "attack": "malware",
            "suspicious": "malware",
            "unknown": "none",
            "benign": "none",
            "normal": "none",
            "no_attack": "none",
            # families -> canonical bucket
            "ransom": "ransomware",
            "crypto_miner": "cryptominer",
            "cryptojacking": "cryptominer",
            "key_logger": "keylogger",
            "shell": "web_shell",
            "webshell": "web_shell",
            "exploit": "payload_delivery",
            "malicious_file": "malicious_document",
            "phishing": "payload_delivery",
            "insider": "insider_threat",
            "data_breach": "data_leak",
            "exfiltration": "data_exfiltration",
        }
        return aliases.get(slug, "none")


# ── Auth
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    role: str


class RefreshRequest(BaseModel):
    refresh_token: str


class LoginRequest(BaseModel):
    """Deliberately lenient: malformed input should yield a clean 401 from the
    auth flow, not a 422 from schema validation (which leaks field-level
    detail and is harder for the UI to display)."""

    email: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=128)


# ── Users
class UserCreate(BaseModel):
    """Inbound user creation.

    Uses a permissive syntactic check instead of ``EmailStr`` so internal
    domains (``*.local``, ``*.internal``) are accepted; those are exactly what
    this deployment bootstraps with.
    """

    email: str = Field(min_length=3, max_length=255, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(min_length=8, max_length=128)
    full_name: str = ""
    role: Literal["admin", "analyst", "viewer"] = "viewer"
    tenant_id: Optional[str] = None


class UserOut(BaseModel):
    """Outbound user representation.

    ``email`` is plain ``str`` on purpose: output schemas must not run
    email-validator. Internal deployments legitimately use reserved TLDs such
    as ``admin@actilp.local`` (RFC 6762), which EmailStr rejects — that would
    turn every read into a 500 ResponseValidationError.
    """

    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    full_name: str
    role: str
    tenant_id: str
    is_active: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None


# ── Alerts
class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: str
    source: str
    raw_log: str
    is_malicious: bool
    attack_type: str
    severity: str
    mitre_tactic: Optional[str] = None
    iocs: list[str] = []
    confidence: float
    summary: str
    status: str
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    model_id: str = ""
    parser_mode: str = "outlines"
    celery_task_id: Optional[str] = None
    created_at: datetime

    @field_validator("iocs", mode="before")
    @classmethod
    def _default_iocs(cls, value):
        return value or []


class AlertList(BaseModel):
    items: list[AlertOut]
    total: int
    limit: int
    offset: int


# ── Parsing
class ParseRequest(BaseModel):
    raw_log: str = Field(min_length=1, max_length=20000)
    source: str = Field(default="manual", max_length=64)
    async_mode: bool = False


class ParsedAnalysis(BaseModel):
    """API/response view of an analysis.

    Distinct from ``LogParseResult`` on purpose: that model is the schema the
    LLM is *constrained to* (so ``confidence`` must be a string enum a grammar
    can enforce), while the API and the database use a plain float. Keeping
    them separate stops the response layer from re-validating stored data
    against decoder constraints.
    """

    is_malicious: bool
    attack_type: str
    severity: str
    mitre_tactic: Optional[str] = None
    iocs: list[str] = []
    confidence: float
    summary: str

    @classmethod
    def from_alert(cls, alert) -> "ParsedAnalysis":
        return cls(
            is_malicious=alert.is_malicious,
            attack_type=alert.attack_type,
            severity=alert.severity,
            mitre_tactic=alert.mitre_tactic,
            iocs=list(alert.iocs or []),
            confidence=float(alert.confidence),
            summary=alert.summary,
        )

    @classmethod
    def from_result(cls, result: LogParseResult) -> "ParsedAnalysis":
        return cls(
            is_malicious=result.is_malicious,
            attack_type=result.attack_type,
            severity=result.severity,
            mitre_tactic=result.mitre_tactic,
            iocs=list(result.iocs),
            confidence=result.confidence_value,
            summary=result.summary,
        )


class ParseResponse(BaseModel):
    alert_id: Optional[int] = None
    task_id: Optional[str] = None
    result: ParsedAnalysis
    retrieved_context: list[str] = []
    parser_mode: str = "outlines"
    model_id: str = ""


class BatchParseRequest(BaseModel):
    logs: list[str] = Field(min_length=1, max_length=100)
    source: str = Field(default="batch", max_length=64)


# ── Dashboard
class SeverityBucket(BaseModel):
    severity: str
    count: int


class DashboardStats(BaseModel):
    total_alerts: int
    malicious: int
    benign: int
    open_alerts: int
    critical_open: int
    by_severity: list[SeverityBucket]
    by_attack_type: list[dict]
    timeline: list[dict]


# ── Audit
class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: str
    actor: str
    action: str
    resource: str
    resource_id: str
    detail: dict
    created_at: datetime


# ── Health
class HealthOut(BaseModel):
    status: str
    env: str
    postgres: str
    redis: str
    chroma: str
    model: str
