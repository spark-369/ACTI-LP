"""v1 router aggregation."""
from fastapi import APIRouter

from app.api.v1 import alerts, audit, auth, dashboard, parse, users

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(alerts.router)
api_router.include_router(parse.router)
api_router.include_router(dashboard.router)
api_router.include_router(users.router)
api_router.include_router(audit.router)
