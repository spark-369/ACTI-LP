"""Read-only audit trail (append-only; there is no write endpoint)."""
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.security import require_role
from app.db import get_db
from app.models import AuditLog
from app.schemas import AuditOut

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=list[AuditOut], summary="List audit entries")
async def list_audit(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    action: Optional[str] = Query(default=None, max_length=64),
    user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> list[AuditLog]:
    query = db.query(AuditLog).filter(AuditLog.tenant_id == user["tid"])
    if action:
        query = query.filter(AuditLog.action == action)
    return query.order_by(AuditLog.id.desc()).offset(offset).limit(limit).all()
