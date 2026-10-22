"""Startup bootstrap: create tables, seed tenant/roles/admin, lock audit table.

Runs inside ``lifespan`` of the API. Safe to call repeatedly.
"""
import logging

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.core.security import hash_password
from app.db import Base, SessionLocal, engine
from app.models import Tenant, User

logger = logging.getLogger(__name__)

DEFAULT_TENANT = "default"

APPEND_ONLY_RULE = """
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_rules WHERE rulename = 'audit_log_append_only'
    ) THEN
        CREATE RULE audit_log_append_only AS
            ON UPDATE TO audit_log DO INSTEAD NOTHING;
        CREATE RULE audit_log_no_delete AS
            ON DELETE TO audit_log DO INSTEAD NOTHING;
    END IF;
END
$$;
"""


def create_schema() -> None:
    Base.metadata.create_all(bind=engine)
    logger.info("schema_ready tables=%s", sorted(Base.metadata.tables))


def enforce_append_only() -> None:
    try:
        with engine.begin() as conn:
            conn.execute(text(APPEND_ONLY_RULE))
        logger.info("audit_append_only_enforced")
    except Exception as exc:  # non-fatal (e.g. restricted role)
        logger.warning("audit_append_only_skipped err=%s", exc)


def seed() -> None:
    db = SessionLocal()
    try:
        if db.get(Tenant, DEFAULT_TENANT) is None:
            db.add(Tenant(id=DEFAULT_TENANT, name="Default Tenant"))
            db.commit()

        admin_email = settings.BOOTSTRAP_ADMIN_EMAIL.lower().strip()
        exists = db.query(User).filter(User.email == admin_email).one_or_none()
        if exists is None:
            db.add(
                User(
                    email=admin_email,
                    full_name="ACTI-LP Admin",
                    hashed_password=hash_password(settings.BOOTSTRAP_ADMIN_PASSWORD),
                    role="admin",
                    tenant_id=DEFAULT_TENANT,
                    is_active=True,
                )
            )
            try:
                db.commit()
                logger.info("admin_seeded email=%s", admin_email)
            except IntegrityError:
                db.rollback()
    finally:
        db.close()


def bootstrap() -> None:
    try:
        create_schema()
        seed()
        enforce_append_only()
    except Exception as exc:  # allow API to boot for /healthz diagnostics
        logger.error("bootstrap_failed err=%s", exc)
