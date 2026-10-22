"""Celery tasks: background log parsing + Redis Streams consumer."""
import asyncio
import logging
from datetime import datetime, timedelta, timezone

from app.db import SessionLocal
from app.models import Alert
from app.services import audit, ingest, parser
from app.workers import celery_app

logger = logging.getLogger(__name__)


def _run(coro):
    """Run an async coroutine from a sync Celery task."""
    return asyncio.run(coro)


@celery_app.task(name="app.workers.tasks.parse_log_task", bind=True)
def parse_log_task(self, raw_log: str, tenant_id: str, source: str = "api") -> dict:
    db = SessionLocal()
    try:
        alert = _run(
            parser.parse_and_persist(
                raw_log=raw_log,
                tenant_id=tenant_id,
                source=source,
                db=db,
                celery_task_id=self.request.id,
            )
        )
        audit.record_safe(
            db,
            tenant_id=tenant_id,
            actor="celery-worker",
            action="alert.parse",
            resource="alert",
            resource_id=alert.id,
            detail={"severity": alert.severity, "parser_mode": alert.parser_mode},
        )
        return {
            "alert_id": alert.id,
            "status": "done",
            "is_malicious": alert.is_malicious,
            "severity": alert.severity,
            "task_id": self.request.id,
        }
    except Exception as exc:
        db.rollback()
        logger.error("parse_log_task_failed err=%s", exc, exc_info=True)
        return {"status": "error", "error": str(exc), "task_id": self.request.id}
    finally:
        db.close()


@celery_app.task(name="app.workers.tasks.consume_stream")
def consume_stream(batch: int = 10) -> dict:
    """Read new entries from the Redis Stream and enqueue parsing tasks."""
    ingest.ensure_group()
    entries = ingest.read_batch(count=batch, block_ms=100)
    queued = 0
    for entry in entries:
        if not entry.get("raw_log"):
            ingest.ack(entry["id"])
            continue
        parse_log_task.delay(
            entry["raw_log"],
            entry.get("tenant_id", "default"),
            entry.get("source", "stream"),
        )
        ingest.ack(entry["id"])
        queued += 1
    if queued:
        logger.info("stream_consumed queued=%d", queued)
    return {"queued": queued}


@celery_app.task(name="app.workers.tasks.expire_stale_alerts")
def expire_stale_alerts(days: int = 30) -> dict:
    """Close low-severity alerts that nobody acknowledged."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    db = SessionLocal()
    try:
        stale = (
            db.query(Alert)
            .filter(Alert.status == "new", Alert.severity == "low", Alert.created_at < cutoff)
            .all()
        )
        for alert in stale:
            alert.status = "closed"
        db.commit()
        return {"closed": len(stale)}
    finally:
        db.close()
