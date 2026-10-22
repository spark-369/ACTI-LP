"""Append-only audit trail (PostgreSQL)."""
import logging

from sqlalchemy.orm import Session

from app.models import AuditLog

logger = logging.getLogger(__name__)


def actor_label(db: Session, user: dict) -> str:
    """Human-readable identity for audit and acknowledgement records.

    The JWT ``sub`` claim is a numeric user id, so storing it verbatim produced
    audit rows reading ``actor = "2"`` — meaningless to anyone reading the trail.
    Resolve it to the user's email, falling back to the raw subject when the
    account has since been removed.
    """
    sub = user.get("sub")
    if sub is None:
        return "system"

    # /auth/me already carries the email; use it without a query when present.
    email = user.get("email")
    if isinstance(email, str) and email:
        return email

    try:
        user_id = int(sub)
    except (TypeError, ValueError):
        return str(sub)

    from app.models import User  # local import keeps the module import graph flat

    record = db.query(User).filter(User.id == user_id).one_or_none()
    return record.email if record is not None else str(sub)


def record(
    db: Session,
    tenant_id: str,
    actor: str,
    action: str,
    resource: str = "",
    resource_id: str | int = "",
    detail: dict | None = None,
    commit: bool = True,
) -> AuditLog:
    """Insert one immutable audit row. There is intentionally no update/delete."""
    entry = AuditLog(
        tenant_id=tenant_id or "unknown",
        actor=actor or "system",
        action=action,
        resource=resource,
        resource_id=str(resource_id or ""),
        detail=detail or {},
    )
    db.add(entry)
    if commit:
        db.commit()
        db.refresh(entry)
    return entry


def record_safe(db: Session, **kwargs) -> None:
    """Audit failures must never break the request path."""
    try:
        record(db, **kwargs)
    except Exception as exc:  # pragma: no cover
        logger.error("audit_write_failed err=%s", exc)
