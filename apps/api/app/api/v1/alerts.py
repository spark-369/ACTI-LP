"""Alert listing, detail, acknowledgement and resolution (tenant-scoped)."""
from datetime import datetime, timezone
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.security import require_role
from app.db import get_db
from app.models import Alert
from app.schemas import AlertList, AlertOut
from app.services import audit, hf_outlines_svc

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _tenant_scoped(db: Session, tenant_id: str):
    return db.query(Alert).filter(Alert.tenant_id == tenant_id)


def _with_tactic(alert: Alert) -> Alert:
    """Backfill ``mitre_tactic`` on read for rows written before the fix.

    Alerts parsed while the model returned "" are already in the database, so
    fixing new parses alone would leave the MITRE column empty for all existing
    history. Derive the tactic from the stored ``attack_type`` without touching
    the row — the value is a pure function of data already present.
    """
    if alert.is_malicious and not alert.mitre_tactic:
        alert.mitre_tactic = hf_outlines_svc.ATTACK_TYPE_TO_TACTIC.get(
            alert.attack_type, hf_outlines_svc.DEFAULT_TACTIC
        )
    return alert


@router.get("", response_model=AlertList, summary="List alerts")
async def list_alerts(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    severity: Optional[str] = Query(default=None, pattern="^(low|medium|high|critical)$"),
    status_: Optional[Literal["new", "acknowledged", "closed"]] = Query(default=None, alias="status"),
    malicious: Optional[bool] = None,
    search: Optional[str] = Query(default=None, max_length=200),
    user: dict = Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
) -> AlertList:
    query = _tenant_scoped(db, user["tid"])
    if severity:
        query = query.filter(Alert.severity == severity)
    if status_:
        query = query.filter(Alert.status == status_)
    if malicious is not None:
        query = query.filter(Alert.is_malicious.is_(malicious))
    if search:
        like = f"%{search}%"
        query = query.filter(
            or_(
                Alert.raw_log.ilike(like),
                Alert.summary.ilike(like),
                Alert.attack_type.ilike(like),
            )
        )

    total = query.count()
    items = query.order_by(Alert.created_at.desc()).offset(offset).limit(limit).all()
    return AlertList(
        items=[_with_tactic(item) for item in items], total=total, limit=limit, offset=offset
    )


@router.get("/{alert_id}", response_model=AlertOut, summary="Alert detail")
async def get_alert(
    alert_id: int,
    user: dict = Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
) -> Alert:
    alert = _tenant_scoped(db, user["tid"]).filter(Alert.id == alert_id).one_or_none()
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    return _with_tactic(alert)


@router.post("/{alert_id}/acknowledge", response_model=AlertOut, summary="Acknowledge alert")
async def acknowledge_alert(
    alert_id: int,
    user: dict = Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
) -> Alert:
    alert = _tenant_scoped(db, user["tid"]).filter(Alert.id == alert_id).one_or_none()
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    if alert.status == "closed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Alert already closed")

    alert.status = "acknowledged"
    alert.acknowledged_by = audit.actor_label(db, user)
    alert.acknowledged_at = datetime.now(timezone.utc)
    audit.record(
        db,
        tenant_id=user["tid"],
        actor=audit.actor_label(db, user),
        action="alert.acknowledge",
        resource="alert",
        resource_id=alert.id,
        commit=False,
    )
    db.commit()
    db.refresh(alert)
    return _with_tactic(alert)


@router.post("/{alert_id}/close", response_model=AlertOut, summary="Close alert")
async def close_alert(
    alert_id: int,
    user: dict = Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
) -> Alert:
    alert = _tenant_scoped(db, user["tid"]).filter(Alert.id == alert_id).one_or_none()
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")

    alert.status = "closed"
    audit.record(
        db,
        tenant_id=user["tid"],
        actor=audit.actor_label(db, user),
        action="alert.close",
        resource="alert",
        resource_id=alert.id,
        commit=False,
    )
    db.commit()
    db.refresh(alert)
    return _with_tactic(alert)
