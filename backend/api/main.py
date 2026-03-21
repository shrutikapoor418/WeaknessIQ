"""
WeaknessIQ — FastAPI Application
==================================
Security decisions:
- CWE-942: CORS restricted to explicit allowlist
- CWE-16:  Security headers on every response
- CWE-307: Rate limiting on all endpoints
- CWE-209: Safe error handling (no stack traces exposed)
- CWE-20:  Input validation before DB access
"""

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.database import create_tables, get_session, init_engine
from backend.db.loader import load_cwe_data
from backend.parser.cwe_parser import CWEParser, SecurityError, ParseError
from backend.analysis import insights

logger = logging.getLogger("weaknessiq.api")

# ── Rate Limiter ─────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ── Lifespan (startup / shutdown) ────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("WeaknessIQ starting up...")

    init_engine()
    await create_tables()

    # Load CWE XML
    xml_path = Path(__file__).parent.parent.parent / "data" / "cwec_latest.xml"

    if xml_path.exists():
        try:
            parser = CWEParser(xml_path)
            result = parser.parse()

            async for session in get_session():
                await load_cwe_data(session, result.entries)
                break

            logger.info(f"CWE data loaded: {result.total_count} entries")

        except (SecurityError, ParseError) as e:
            logger.error(f"Failed to load CWE data: {e}")

    else:
        logger.warning(
            f"CWE XML not found at {xml_path}. "
            "Run: python backend/parser/downloader.py --register"
        )

    yield
    logger.info("WeaknessIQ shutting down...")


# ── FastAPI App ─────────────────────────────────────────────
app = FastAPI(
    title="WeaknessIQ",
    description="CWE analysis API — security threat insights",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if os.getenv("APP_ENV", "development") == "development" else None,
    redoc_url=None,
    openapi_url="/openapi.json" if os.getenv("APP_ENV") != "production" else None,
)

# Attach limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS ─────────────────────────────────────────────────────
allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in allowed_origins],
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["Content-Type"],
)

# ── Security Headers Middleware ─────────────────────────────
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"

    if os.getenv("APP_ENV") == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"

    # Remove server header safely
    if "server" in response.headers:
        del response.headers["server"]

    return response


# ── Global Error Handler ─────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.url.path}: {exc}", exc_info=True)

    return JSONResponse(
        status_code=500,
        content={"error": "An internal error occurred. Please try again later."}
    )


# ── Routes ───────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "WeaknessIQ"}


@app.get("/api/v1/summary")
@limiter.limit("30/minute")
async def get_summary(request: Request, session: AsyncSession = Depends(get_session)):
    try:
        return await insights.get_catalogue_summary(session)
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to retrieve summary")


@app.get("/api/v1/cwe/{cwe_id}")
@limiter.limit("60/minute")
async def get_cwe(request: Request, cwe_id: str, session: AsyncSession = Depends(get_session)):
    try:
        entry = await insights.get_cwe_by_id(session, cwe_id)
        if not entry:
            raise HTTPException(status_code=404, detail=f"CWE-{cwe_id} not found")
        return entry
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/analysis/top-weaknesses")
@limiter.limit("20/minute")
async def top_weaknesses(request: Request, abstraction: str | None = None, limit: int = 20,
                         session: AsyncSession = Depends(get_session)):
    try:
        return await insights.get_top_weaknesses(session, abstraction, limit)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/analysis/exploit-likelihood")
@limiter.limit("20/minute")
async def exploit_likelihood(request: Request, session: AsyncSession = Depends(get_session)):
    return await insights.get_exploit_likelihood_distribution(session)


@app.get("/api/v1/analysis/language-risk")
@limiter.limit("20/minute")
async def language_risk(request: Request, session: AsyncSession = Depends(get_session)):
    return await insights.get_language_risk_profiles(session)


@app.get("/api/v1/analysis/relationships/{cwe_id}")
@limiter.limit("20/minute")
async def relationship_chains(request: Request, cwe_id: str, depth: int = 3,
                              session: AsyncSession = Depends(get_session)):
    try:
        return await insights.get_relationship_chains(session, cwe_id, depth)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/analysis/detection-gaps")
@limiter.limit("10/minute")
async def detection_gaps(request: Request, session: AsyncSession = Depends(get_session)):
    return await insights.get_detection_gaps(session)