"""Parser orchestrator: local Chroma retrieval → Qwen0.5B + Outlines → DB."""
import logging
from typing import List

from sqlalchemy.orm import Session

from app.models import Alert
from app.schemas import LogParseResult
from app.services import chroma_local_svc, hf_outlines_svc

logger = logging.getLogger(__name__)


async def parse_log(raw_log: str, tenant_id: str) -> dict:
    """Retrieve similar historical logs, then run schema-constrained inference."""
    context = await chroma_local_svc.search(
        tenant_id, raw_log, limit=hf_outlines_svc.RAG_TOP_K
    )
    return await hf_outlines_svc.parse_log(raw_log, context)


async def parse_and_persist(
    raw_log: str,
    tenant_id: str,
    source: str,
    db: Session,
    celery_task_id: str | None = None,
    context: List[str] | None = None,
) -> Alert:
    """Full pipeline used by the REST API and the Celery worker."""
    if context is None:
        context = await chroma_local_svc.search(
            tenant_id, raw_log, limit=hf_outlines_svc.RAG_TOP_K
        )

    output = await hf_outlines_svc.parse_log(raw_log, context)
    result: LogParseResult = output["result"]

    alert = Alert(
        tenant_id=tenant_id,
        source=source,
        raw_log=raw_log,
        is_malicious=result.is_malicious,
        attack_type=result.attack_type or "none",
        severity=result.severity,
        mitre_tactic=result.mitre_tactic,
        iocs=list(result.iocs),
        confidence=result.confidence_value,
        summary=result.summary,
        model_id=output["model_id"],
        parser_mode=output["parser_mode"],
        celery_task_id=celery_task_id,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    chroma_local_svc.add_logs(
        tenant_id,
        [raw_log],
        [{"alert_id": alert.id, "source": source, "severity": alert.severity}],
    )
    logger.info(
        "alert_created id=%s tenant=%s malicious=%s severity=%s mode=%s",
        alert.id,
        tenant_id,
        alert.is_malicious,
        alert.severity,
        alert.parser_mode,
    )
    return alert


def normalize_log_line(line: str) -> str:
    """Light normalizer for stream/filebeat style ingestion."""
    return " ".join((line or "").split())[:20000]


def split_targets(payload: str) -> List[str]:
    return [normalize_log_line(p) for p in (payload or "").splitlines() if p.strip()]
