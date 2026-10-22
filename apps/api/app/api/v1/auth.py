"""Auth endpoints: login (form + JSON), refresh rotation, me."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.core.security import (
    ACCESS_TTL,
    create_access_token,
    create_refresh_token,
    decode_token,
    oauth2,
    verify_password,
)
from app.db import get_db
from app.models import User
from app.schemas import LoginRequest, RefreshRequest, Token, UserOut
from app.services import audit

router = APIRouter(prefix="/auth", tags=["auth"])


def _issue(user: User) -> Token:
    return Token(
        access_token=create_access_token(str(user.id), user.role, user.tenant_id),
        refresh_token=create_refresh_token(str(user.id), user.role, user.tenant_id),
        expires_in=int(ACCESS_TTL.total_seconds()),
        role=user.role,
    )


def _authenticate(db: Session, email: str, password: str) -> User:
    user = db.query(User).filter(User.email == email.lower().strip()).one_or_none()
    if user is None or not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is disabled")

    user.last_login_at = datetime.now(timezone.utc)
    audit.record(
        db,
        tenant_id=user.tenant_id,
        actor=user.email,
        action="auth.login",
        resource="user",
        resource_id=user.id,
        commit=False,
    )
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=Token, summary="OAuth2 password form login")
async def login_form(
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
) -> Token:
    """Form-encoded login — used by Swagger UI and the frontend."""
    user = _authenticate(db, form.username, form.password)
    return _issue(user)


@router.post("/login/json", response_model=Token, summary="JSON login")
async def login_json(payload: LoginRequest, db: Session = Depends(get_db)) -> Token:
    user = _authenticate(db, str(payload.email), payload.password)
    return _issue(user)


@router.post("/refresh", response_model=Token, summary="Rotate refresh token")
async def refresh(payload: RefreshRequest, db: Session = Depends(get_db)) -> Token:
    claims = decode_token(payload.refresh_token, expected_type="refresh")
    try:
        user_id = int(claims["sub"])
    except (KeyError, TypeError, ValueError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token payload") from None

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User no longer valid")
    return _issue(user)


@router.get("/me", response_model=UserOut, summary="Current user")
async def me(
    token: str = Depends(oauth2),
    db: Session = Depends(get_db),
) -> User:
    claims = decode_token(token, expected_type="access")
    try:
        user_id = int(claims["sub"])
    except (KeyError, TypeError, ValueError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token payload") from None

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")
    return user
