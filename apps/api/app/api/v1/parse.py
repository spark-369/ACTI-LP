"""Parse endpoints: synchronous (Outlines) and asynchronous (Celery)."""
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.security import require_role
from app.db import get_db
from app.schemas import BatchParseRequest, ParsedAnalysis, ParseRequest, ParseResponse
from app.services import audit, chroma_local_svc, hf_outlines_svc, parser
from app.workers.tasks import parse_log_task

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/parse", tags=["parse"])


@router.post("", response_model=ParseResponse, summary="Parse a single log line")
async def parse_single(
    payload: ParseRequest,
    user: dict = Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
) -> ParseResponse:
    tenant_id = user["tid"]

    if payload.async_mode:
        task = parse_log_task.delay(payload.raw_log, tenant_id, payload.source)
        audit.record(
            db,
            tenant_id=tenant_id,
            actor=user.get("email") or str(user.get("sub")),
            action="log.parse.enqueued",
            resource="log",
            resource_id=task.id,
            detail={"source": payload.source, "chars": len(payload.raw_log)},
        )
        return ParseResponse(
            task_id=task.id,
            result=ParsedAnalysis(
                is_malicious=False,
                attack_type="pending",
                severity="low",
                mitre_tactic=None,
                iocs=[],
                confidence=0.0,
                summary="Queued for background analysis.",
            ),
            retrieved_context=[],
            parser_mode="celery",
            model_id="",
        )

    context = await chroma_local_svc.search(
        tenant_id, payload.raw_log, limit=hf_outlines_svc.RAG_TOP_K
    )
    alert = await parser.parse_and_persist(
        raw_log=payload.raw_log,
        tenant_id=tenant_id,
        source=payload.source,
        db=db,
        context=context,
    )
    audit.record(
        db,
        tenant_id=tenant_id,
        actor=user.get("email") or str(user.get("sub")),
        action="log.parse",
        resource="alert",
        resource_id=alert.id,
        detail={"mode": alert.parser_mode, "severity": alert.severity},
    )

    return ParseResponse(
        alert_id=alert.id,
        result=ParsedAnalysis.from_alert(alert),
        retrieved_context=context,
        parser_mode=alert.parser_mode,
        model_id=alert.model_id,
    )


@router.post("/batch", summary="Parse up to 100 log lines")
async def parse_batch(
    payload: BatchParseRequest,
    user: dict = Depends(require_role("admin", "analyst")),
) -> dict:
    tenant_id = user["tid"]
    task_ids = []
    for line in payload.logs:
        if line.strip():
            task = parse_log_task.delay(line, tenant_id, payload.source)
            task_ids.append(task.id)

    if not task_ids:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "No non-empty log lines")

    logger.info("batch_enqueued tenant=%s count=%d", tenant_id, len(task_ids))
    return {"queued": len(task_ids), "task_ids": task_ids}


@router.get("/context", summary="Retrieve similar historical logs")
async def retrieve_context(
    q: str,
    limit: int = hf_outlines_svc.RAG_TOP_K,
    user: dict = Depends(require_role("admin", "analyst", "viewer")),
) -> dict:
    docs = await chroma_local_svc.search(
        user["tid"], q, limit=max(1, min(limit, hf_outlines_svc.RAG_TOP_K))
    )
    return {"query": q, "count": len(docs), "documents": docs}
