"""
WeaknessIQ — FastAPI Application
==================================
Security decisions:
- CWE-942: CORS restricted to explicit allowlist, never wildcard in production
- CWE-16:  Security headers on every response (CSP, HSTS, X-Frame-Options etc.)
- CWE-307: Rate limiting on all endpoints — prevents brute force / DoS
- CWE-209: Error handlers return safe messages — no stack traces to client
- CWE-20:  All path parameters validated before reaching DB layer
"""

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException, Request, status
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

# ── Rate limiter (CWE-307: prevents DoS / brute force) ───────────────────────
limiter = Limiter(key_func=get_remote_address)

# ── Lifespan: startup / shutdown ──────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise DB and load CWE data on startup."""
    logger.info("WeaknessIQ starting up...")
    init_engine()
    await create_tables()

    # Load CWE data if DB is empty
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


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="WeaknessIQ",
    description="CWE analysis API — security threat landscape insights",
    version="1.0.0",
    lifespan=lifespan,
    # Disable default docs in production (information disclosure)
    docs_url="/docs" if os.getenv("APP_ENV", "development") == "development" else None,
    redoc_url=None,
    openapi_url="/openapi.json" if os.getenv("APP_ENV") != "production" else None,
)

# Attach rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS (CWE-942: explicit allowlist, never *) ───────────────────────────────
allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in allowed_origins],
    allow_credentials=False,      # No cookies — reduces CSRF surface
    allow_methods=["GET"],        # Read-only API — no POST/PUT/DELETE needed
    allow_headers=["Content-Type"],
)

# ── Security Headers Middleware ───────────────────────────────────────────────
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """
    Add security headers to every response.
    These are a defence-in-depth layer — even if app logic has a flaw,
    these headers limit what an attacker can do with it.
    """
    response = await call_next(request)

    # Prevent MIME sniffing (CWE-430)
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Prevent clickjacking (CWE-1021)
    response.headers["X-Frame-Options"] = "DENY"

    # XSS protection for older browsers
    response.headers["X-XSS-Protection"] = "1; mode=block"

    # HSTS — force HTTPS for 1 year (production only)
    if os.getenv("APP_ENV") == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    # CSP — restrict what can load in browser context
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"

    # Remove server fingerprinting info (CWE-200)
    response.headers.pop("server", None)

    return response


# ── Safe Global Error Handler (CWE-209) ──────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Catch-all handler — never return stack traces or internal details to client.
    Log full details server-side for debugging.
    """
    logger.error(f"Unhandled exception on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "An internal error occurred. Please try again later."}
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    """Health check endpoint — used by Docker HEALTHCHECK and monitoring."""
    return {"status": "ok", "service": "WeaknessIQ"}


@app.get("/api/v1/summary")
@limiter.limit("30/minute")
async def get_summary(request: Request, session: AsyncSession = Depends(get_session)):
    """Catalogue-level summary statistics."""
    try:
        return await insights.get_catalogue_summary(session)
    except Exception as e:
        logger.error(f"Summary error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve summary")


@app.get("/api/v1/cwe/{cwe_id}")
@limiter.limit("60/minute")
async def get_cwe(
    request: Request,
    cwe_id: str,
    session: AsyncSession = Depends(get_session)
):
    """
    Lookup a specific CWE by ID.
    Input validated in analysis layer — numeric IDs only (CWE-20).
    """
    try:
        entry = await insights.get_cwe_by_id(session, cwe_id)
        if not entry:
            raise HTTPException(status_code=404, detail=f"CWE-{cwe_id} not found")
        return entry
    except ValueError as e:
        # Safe to return — validation error, not internal detail
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/analysis/top-weaknesses")
@limiter.limit("20/minute")
async def top_weaknesses(
    request: Request,
    abstraction: str | None = None,
    limit: int = 20,
    session: AsyncSession = Depends(get_session)
):
    """
    Most prevalent weakness consequence types across the catalogue.
    Filter by abstraction level: Pillar | Class | Base | Variant
    """
    try:
        return await insights.get_top_weaknesses(session, abstraction, limit)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/analysis/exploit-likelihood")
@limiter.limit("20/minute")
async def exploit_likelihood(
    request: Request,
    session: AsyncSession = Depends(get_session)
):
    """Distribution of exploit likelihood across the entire CWE catalogue."""
    return await insights.get_exploit_likelihood_distribution(session)


@app.get("/api/v1/analysis/language-risk")
@limiter.limit("20/minute")
async def language_risk(
    request: Request,
    session: AsyncSession = Depends(get_session)
):
    """
    Risk profiles per programming language.
    Shows which languages carry the most CWEs and at what exploit likelihood.
    """
    return await insights.get_language_risk_profiles(session)


@app.get("/api/v1/analysis/relationships/{cwe_id}")
@limiter.limit("20/minute")
async def relationship_chains(
    request: Request,
    cwe_id: str,
    depth: int = 3,
    session: AsyncSession = Depends(get_session)
):
    """
    Trace parent/child/peer relationship chains for a CWE up to N levels deep.
    Reveals cascading vulnerability paths.
    depth capped at 5 (DoS prevention — CWE-400).
    """
    try:
        return await insights.get_relationship_chains(session, cwe_id, depth)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/analysis/detection-gaps")
@limiter.limit("10/minute")
async def detection_gaps(
    request: Request,
    session: AsyncSession = Depends(get_session)
):
    """
    Identifies weaknesses with no documented detection methods.
    High-likelihood weaknesses with no detection = critical blind spots.
    """
    return await insights.get_detection_gaps(session)
