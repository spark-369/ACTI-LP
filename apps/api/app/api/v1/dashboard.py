"""Dashboard aggregates for the React/Recharts views (tenant-scoped)."""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.security import require_role
from app.db import get_db
from app.models import Alert
from app.schemas import DashboardStats, SeverityBucket

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

SEVERITIES = ["critical", "high", "medium", "low"]


@router.get("/stats", response_model=DashboardStats, summary="Aggregate alert metrics")
async def stats(
    days: int = Query(default=7, ge=1, le=90),
    user: dict = Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
) -> DashboardStats:
    tenant = user["tid"]
    base = db.query(Alert).filter(Alert.tenant_id == tenant)
    now = datetime.now(timezone.utc)

    total = base.count()
    malicious = base.filter(Alert.is_malicious.is_(True)).count()
    open_alerts = base.filter(Alert.status == "new").count()
    critical_open = base.filter(Alert.status == "new", Alert.severity == "critical").count()

    sev_rows = (
        db.query(Alert.severity, func.count(Alert.id))
        .filter(Alert.tenant_id == tenant)
        .group_by(Alert.severity)
        .all()
    )
    sev_map = {s: c for s, c in sev_rows}
    by_severity = [SeverityBucket(severity=s, count=int(sev_map.get(s, 0))) for s in SEVERITIES]

    atk_rows = (
        db.query(Alert.attack_type, func.count(Alert.id))
        .filter(Alert.tenant_id == tenant, Alert.is_malicious.is_(True))
        .group_by(Alert.attack_type)
        .order_by(func.count(Alert.id).desc())
        .limit(100)
        .all()
    )
    by_attack_type = [{"attack_type": a, "count": int(c)} for a, c in atk_rows]

    since = now - timedelta(days=days)
    dialect = db.bind.dialect.name if db.bind is not None else "postgresql"
    if dialect == "sqlite":
        # Fine-grained test/dev SQLite: aggregate in Python instead of date_trunc.
        recent = (
            db.query(func.date(Alert.created_at), func.count(Alert.id))
            .filter(Alert.tenant_id == tenant, Alert.created_at >= since)
            .group_by(func.date(Alert.created_at))
            .order_by(func.date(Alert.created_at))
            .all()
        )
        buckets = {str(row[0]): int(row[1]) for row in recent if row[0]}
    else:
        timeline_rows = (
            db.query(func.date_trunc("day", Alert.created_at).label("day"), func.count(Alert.id))
            .filter(Alert.tenant_id == tenant, Alert.created_at >= since)
            .group_by("day")
            .order_by("day")
            .all()
        )
        buckets = {row[0].date().isoformat(): int(row[1]) for row in timeline_rows if row[0]}

    timeline = []
    for i in range(days):
        day = (since + timedelta(days=i + 1)).date().isoformat()
        timeline.append({"date": day, "count": buckets.get(day, 0)})

    return DashboardStats(
        total_alerts=total,
        malicious=malicious,
        benign=max(total - malicious, 0),
        open_alerts=open_alerts,
        critical_open=critical_open,
        by_severity=by_severity,
        by_attack_type=by_attack_type,
        timeline=timeline,
    )
