"""User management — DB-driven RBAC, admin only (tenant-scoped)."""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.security import hash_password, require_role
from app.db import get_db
from app.models import User
from app.schemas import UserCreate, UserOut
from app.services import audit

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserOut], summary="List users in tenant")
async def list_users(
    limit: int = Query(default=50, ge=1, le=200),
    user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> list[User]:
    return (
        db.query(User)
        .filter(User.tenant_id == user["tid"])
        .order_by(User.created_at.desc())
        .limit(limit)
        .all()
    )


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED, summary="Create user")
async def create_user(
    payload: UserCreate,
    user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> User:
    email = str(payload.email).lower().strip()
    if db.query(User).filter(User.email == email).one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")

    if payload.tenant_id and payload.tenant_id != user["tid"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cannot create users in another tenant")

    record = User(
        email=email,
        full_name=payload.full_name or email.split("@")[0],
        hashed_password=hash_password(payload.password),
        role=payload.role,
        tenant_id=user["tid"],
        is_active=True,
    )
    db.add(record)
    audit.record(
        db,
        tenant_id=user["tid"],
        actor=audit.actor_label(db, user),
        action="user.create",
        resource="user",
        resource_id=email,
        detail={"role": payload.role},
        commit=False,
    )
    db.commit()
    db.refresh(record)
    return record


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Deactivate user")
async def deactivate_user(
    user_id: int,
    user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> None:
    if str(user_id) == str(user.get("sub")):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Cannot deactivate yourself")

    record = (
        db.query(User)
        .filter(User.id == user_id, User.tenant_id == user["tid"])
        .one_or_none()
    )
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    record.is_active = False
    audit.record(
        db,
        tenant_id=user["tid"],
        actor=audit.actor_label(db, user),
        action="user.deactivate",
        resource="user",
        resource_id=user_id,
        commit=False,
    )
    db.commit()
