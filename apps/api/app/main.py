"""FastAPI application entrypoint for ACTI-LP."""
import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.logging import configure_logging
from app.db import engine
from app.schemas import HealthOut
from app.services import bootstrap, chroma_local_svc, embedder, hf_outlines_svc, ingest

configure_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    logger.info("startup env=%s model=%s chroma=%s", settings.APP_ENV, settings.HF_MODEL_ID, settings.CHROMA_PATH)
    bootstrap.bootstrap()
    try:
        ingest.ensure_group()
    except Exception as exc:
        logger.warning("stream_group_bootstrap_skipped err=%s", exc)
    if settings.HF_PRELOAD_ON_STARTUP:
        hf_outlines_svc.preload()
    yield
    logger.info("shutdown")


app = FastAPI(
    title="ACTI-LP API",
    description="Automated Cyber Threat Intelligence & Log Parser (Qwen2.5-0.5B + Outlines + local ChromaDB)",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_context(request: Request, call_next):
    """Attach a request id and emit one structured access-log line.

    Must never raise: this middleware wraps the app, so any exception here
    escapes CORS and the browser reports a misleading CORS error.
    """
    request_id = request.headers.get("x-request-id", uuid.uuid4().hex[:12])
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception as exc:  # let the 500 handler + CORS deal with the body
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        logger.error(
            "http_request_failed request_id=%s path=%s err=%s duration_ms=%s",
            request_id,
            request.url.path,
            exc,
            duration_ms,
        )
        raise

    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    try:
        response.headers["x-request-id"] = request_id
        logger.info(
            "http_request request_id=%s method=%s path=%s status=%s duration_ms=%s",
            request_id,
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
        )
    except Exception:  # logging/headers are best-effort only
        logger.debug("request_context_logging_failed", exc_info=True)
    return response


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Last-resort 500 handler.

    Starlette renders this via ``ServerErrorMiddleware``, which sits OUTSIDE
    ``CORSMiddleware`` — so a plain JSONResponse here reaches the browser with
    no ``Access-Control-Allow-Origin`` and shows up as a CORS error instead of
    a 500. Re-apply the CORS headers so the real status is visible to the SPA.
    """
    logger.error("unhandled_error path=%s err=%s", request.url.path, exc, exc_info=True)

    headers = {}
    origin = request.headers.get("origin")
    if origin and origin in settings.cors_origins_list:
        headers["Access-Control-Allow-Origin"] = origin
        headers["Access-Control-Allow-Credentials"] = "true"
        headers["Vary"] = "Origin"

    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "path": request.url.path},
        headers=headers,
    )


@app.get("/healthz", response_model=HealthOut, tags=["system"])
async def healthz() -> HealthOut:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        pg = "ok"
    except Exception as exc:
        pg = f"error: {str(exc)[:120]}"

    return HealthOut(
        status="ok",
        env=settings.APP_ENV,
        postgres=pg,
        redis=ingest.health(),
        chroma=chroma_local_svc.health(),
        model=hf_outlines_svc.health(),
    )


@app.get("/healthz/ready", tags=["system"])
async def ready() -> dict:
    return {
        "ready": True,
        "embedder": embedder.health(),
        "chroma": chroma_local_svc.health(),
        "model": hf_outlines_svc.health(),
    }


app.include_router(api_router, prefix=settings.API_PREFIX)
