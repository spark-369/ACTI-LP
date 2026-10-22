"""Built-in JWT auth (FastAPI-native) + bcrypt password hashing + RBAC."""
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

ALGORITHM = settings.JWT_ALGORITHM or "HS256"
ACCESS_TTL = timedelta(minutes=settings.ACCESS_TOKEN_TTL_MINUTES)
REFRESH_TTL = timedelta(days=settings.REFRESH_TOKEN_TTL_DAYS)

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2 = OAuth2PasswordBearer(tokenUrl=f"{settings.API_PREFIX}/auth/login")

ACCESS = "access"
REFRESH = "refresh"


def hash_password(raw: str) -> str:
    return pwd_ctx.hash(raw)


def verify_password(raw: str, hashed: str) -> bool:
    try:
        return pwd_ctx.verify(raw, hashed)
    except ValueError:
        return False


def _encode(sub: str, role: str, ttl: timedelta, token_type: str, **extra) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": sub,
        "role": role,
        "type": token_type,
        "iat": int(now.timestamp()),
        "exp": int((now + ttl).timestamp()),
        **extra,
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=ALGORITHM)


def create_token(sub: str, role: str, ttl: timedelta = ACCESS_TTL, **extra) -> str:
    """Backwards-compatible helper: create an access token."""
    return _encode(sub, role, ttl, ACCESS, **extra)


def create_access_token(sub: str, role: str, tenant_id: str) -> str:
    return _encode(sub, role, ACCESS_TTL, ACCESS, tid=tenant_id)


def create_refresh_token(sub: str, role: str, tenant_id: str) -> str:
    return _encode(sub, role, REFRESH_TTL, REFRESH, tid=tenant_id)


def decode_token(token: str, expected_type: Optional[str] = None) -> dict:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[ALGORITHM])
    except JWTError as exc:  # expired / tampered / malformed
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    if expected_type and payload.get("type") != expected_type:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Expected a {expected_type} token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


async def current_user(token: str = Depends(oauth2)) -> dict:
    payload = decode_token(token, expected_type=ACCESS)
    if not payload.get("sub"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token payload")
    if not payload.get("tid"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing tenant claim")
    return payload


def require_role(*roles: Iterable[str]):
    allowed: List[str] = list(roles)

    async def _dep(user: dict = Depends(current_user)) -> dict:
        if user.get("role") not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role",
            )
        return user

    return _dep
