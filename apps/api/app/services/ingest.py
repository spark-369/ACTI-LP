"""Redis Streams ingestion (Filebeat / Fluent Bit / syslog-ng → Redis).

Producers ``XADD`` to ``STREAM_NAME``; the Celery worker consumes via a consumer
group and enqueues a parse task per message.
"""
import json
import logging
from typing import List

import redis

from app.core.config import settings

logger = logging.getLogger(__name__)


def get_redis() -> redis.Redis:
    return redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)


def publish(raw_log: str, tenant_id: str = "default", source: str = "stream") -> str:
    """Push one raw log line onto the stream. Returns the stream entry id."""
    client = get_redis()
    return client.xadd(
        settings.STREAM_NAME,
        {"raw_log": raw_log, "tenant_id": tenant_id, "source": source},
        maxlen=100_000,
        approximate=True,
    )


def ensure_group() -> None:
    client = get_redis()
    try:
        client.xgroup_create(settings.STREAM_NAME, settings.STREAM_GROUP, id="0", mkstream=True)
        logger.info("stream_group_created stream=%s group=%s", settings.STREAM_NAME, settings.STREAM_GROUP)
    except redis.ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise


def read_batch(count: int = 10, block_ms: int = 2000) -> List[dict]:
    """Blocking read for the worker loop new-messages (``>``) cursor."""
    client = get_redis()
    resp = client.xreadgroup(
        settings.STREAM_GROUP,
        "consumer-1",
        {settings.STREAM_NAME: ">"},
        count=count,
        block=block_ms,
    )
    out: List[dict] = []
    for _, entries in resp or []:
        for entry_id, fields in entries:
            payload = {
                "id": entry_id,
                "raw_log": fields.get("raw_log", ""),
                "tenant_id": fields.get("tenant_id", "default"),
                "source": fields.get("source", "stream"),
            }
            if isinstance(fields.get("payload"), str):
                try:
                    payload.update(json.loads(fields["payload"]))
                except json.JSONDecodeError:
                    pass
            out.append(payload)
    return out


def ack(entry_id: str) -> None:
    get_redis().xack(settings.STREAM_NAME, settings.STREAM_GROUP, entry_id)


def health() -> str:
    try:
        return "ok" if get_redis().ping() else "error"
    except Exception as exc:  # pragma: no cover
        return f"error: {str(exc)[:120]}"
