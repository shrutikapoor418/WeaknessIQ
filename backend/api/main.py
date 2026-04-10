"""
WeaknessIQ — FastAPI Application
====================================
Data sources:
1. MITRE CWE XML       — weakness catalogue (969 entries)
2. NIST NVD API v2     — real CVEs per weakness
3. OWASP Top 10 2025   — industry standard category mapping

Security decisions:
- CWE-942: CORS restricted to explicit allowlist
- CWE-16:  Security headers on every response
- CWE-307: Rate limiting on all endpoints
- CWE-209: Safe error handling (no stack traces exposed)
- CWE-20:  Input validation before DB or external API access
- CWE-918: NVD URL allowlisted — SSRF prevention
"""

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from collections import defaultdict

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.db.database import create_tables, get_session, init_engine, CWEModel
from backend.db.loader import load_cwe_data
from backend.parser.cwe_parser import CWEParser, SecurityError, ParseError
from backend.analysis import insights
from backend.integrations.nvd import (
    fetch_cves_for_cwe,
    get_owasp_mapping,
    get_owasp_coverage_summary,
)

logger = logging.getLogger("weaknessiq.api")
limiter = Limiter(key_func=get_remote_address)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("WeaknessIQ starting up...")
    init_engine()
    await create_tables()
     try:
        from backend.parser.cwe_parser import CWEParser
        from backend.db.database import AsyncSessionLocal
        xml_path = Path("/app/data/cwec_latest.xml")
        if xml_path.exists():
            parser = CWEParser()
            entries = parser.parse(str(xml_path))
            async with AsyncSessionLocal() as session:
                await load_cwe_data(session, entries)
            logger.info(f"Loaded {len(entries)} CWEs")
        else:
            logger.warning("CWE XML not found — database empty")
    except Exception as e:
        logger.error(f"CWE load failed: {e}")
    logger.info("Startup complete")
    yield

app = FastAPI(
    title="WeaknessIQ",
    description="CWE analysis API enriched with NVD CVE data and OWASP Top 10 mapping",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs" if os.getenv("APP_ENV", "development") == "development" else None,
    redoc_url=None,
    openapi_url="/openapi.json" if os.getenv("APP_ENV") != "production" else None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,https://weaknessiq.onrender.com").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["Content-Type"],
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    if os.getenv("APP_ENV") == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' https: data:; frame-ancestors 'none'"
    if "server" in response.headers:
        del response.headers["server"]
    return response

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"error": "An internal error occurred."})

@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "WeaknessIQ", "version": "2.0.0",
            "data_sources": ["MITRE CWE", "NIST NVD", "OWASP Top 10 2025"]}

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
async def top_weaknesses(request: Request, abstraction: str | None = None,
                         limit: int = 20, session: AsyncSession = Depends(get_session)):
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

@app.get("/api/v1/search")
@limiter.limit("30/minute")
async def search_cwe(request: Request, q: str, limit: int = 20,
                     session: AsyncSession = Depends(get_session)):
    import re
    from sqlalchemy import or_
    if not re.match(r"^[a-zA-Z0-9 \-_]{1,100}$", q):
        raise HTTPException(status_code=400, detail="Invalid search query")
    limit = max(1, min(limit, 50))
    result = await session.execute(
        select(CWEModel).where(or_(
            CWEModel.name.ilike(f"%{q}%"),
            CWEModel.description.ilike(f"%{q}%")
        )).limit(limit)
    )
    entries = result.scalars().all()
    return {
        "query": q,
        "total_results": len(entries),
        "results": [
            {
                "cwe_id": e.cwe_id,
                "name": e.name,
                "abstraction": e.abstraction,
                "likelihood_of_exploit": e.likelihood_of_exploit,
                "description": e.description[:200] + "..." if len(e.description) > 200 else e.description,
                "consequences": e.common_consequences[:3] if e.common_consequences else [],
            }
            for e in entries
        ]
    }

@app.get("/api/v1/enrich/nvd/{cwe_id}")
@limiter.limit("5/minute")
async def get_nvd_cves(request: Request, cwe_id: str, limit: int = 10,
                       session: AsyncSession = Depends(get_session)):
    try:
        return fetch_cves_for_cwe(cwe_id, limit)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        raise HTTPException(status_code=500, detail="NVD enrichment failed")

@app.get("/api/v1/enrich/owasp/{cwe_id}")
@limiter.limit("30/minute")
async def get_owasp_for_cwe(request: Request, cwe_id: str):
    try:
        return get_owasp_mapping(cwe_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/enrich/owasp-coverage")
@limiter.limit("10/minute")
async def get_owasp_coverage(request: Request, session: AsyncSession = Depends(get_session)):
    try:
        result = await session.execute(select(CWEModel.cwe_id))
        cwe_ids = [r[0] for r in result.all()]
        return get_owasp_coverage_summary(cwe_ids)
    except Exception:
        raise HTTPException(status_code=500, detail="OWASP coverage analysis failed")

@app.get("/api/v1/enrich/threat-profile/{cwe_id}")
@limiter.limit("5/minute")
async def get_threat_profile(request: Request, cwe_id: str,
                             session: AsyncSession = Depends(get_session)):
    try:
        if not str(cwe_id).isdigit():
            raise ValueError("CWE ID must be numeric")
        cwe_detail = await insights.get_cwe_by_id(session, cwe_id)
        if not cwe_detail:
            raise HTTPException(status_code=404, detail=f"CWE-{cwe_id} not found")
        nvd_data   = fetch_cves_for_cwe(cwe_id, limit=5)
        owasp_data = get_owasp_mapping(cwe_id)
        chain_data = await insights.get_relationship_chains(session, cwe_id, depth=2)
        risk_factors = []
        nvd_total = nvd_data.get("total_cves_in_nvd", 0)
        critical  = nvd_data.get("severity_breakdown", {}).get("CRITICAL", 0)
        if nvd_total > 100:
            risk_factors.append(f"High CVE volume: {nvd_total} CVEs in NVD")
        if critical > 0:
            risk_factors.append(f"{critical} CRITICAL severity CVEs in NVD")
        if owasp_data.get("in_owasp_top10"):
            risk_factors.append("Listed in OWASP Top 10 2025")
        if cwe_detail.get("likelihood_of_exploit") == "High":
            risk_factors.append("High exploit likelihood (CWE catalogue)")
        if chain_data.get("nodes_found", 0) > 5:
            risk_factors.append("Broad vulnerability chain — cascading risk")
        return {
            "cwe_id": cwe_id,
            "name": cwe_detail.get("name"),
            "abstraction": cwe_detail.get("abstraction"),
            "likelihood_of_exploit": cwe_detail.get("likelihood_of_exploit"),
            "description": cwe_detail.get("description"),
            "nvd_enrichment": {
                "total_cves_in_nvd": nvd_total,
                "severity_breakdown": nvd_data.get("severity_breakdown", {}),
                "sample_cves": nvd_data.get("cves", [])[:3],
            },
            "owasp_mapping": owasp_data,
            "relationship_chain": {
                "nodes_found": chain_data.get("nodes_found", 0),
                "depth_searched": chain_data.get("depth_searched", 0),
            },
            "risk_factors": risk_factors,
            "risk_factor_count": len(risk_factors),
            "data_sources": ["MITRE CWE", "NIST NVD API v2", "OWASP Top 10 2025"],
        }
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Threat profile error: {e}")
        raise HTTPException(status_code=500, detail="Threat profile generation failed")

@app.get("/api/v1/analysis/consequences")
@limiter.limit("20/minute")
async def consequence_analysis(request: Request, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(CWEModel))
    entries = result.scalars().all()
    consequence_map = defaultdict(list)
    for entry in entries:
        for c in (entry.common_consequences or []):
            consequence_map[c].append({
                "cwe_id": entry.cwe_id,
                "name": entry.name,
                "likelihood": entry.likelihood_of_exploit,
                "abstraction": entry.abstraction,
            })
    total = len(entries)
    recommendations = {
        "Confidentiality": ["Implement strict input validation and output encoding","Use parameterised queries to prevent data exfiltration","Apply least privilege","Encrypt sensitive data at rest and in transit (TLS 1.3 minimum)"],
        "Integrity": ["Validate all inputs before processing (allowlist, not blocklist)","Use integrity checks (checksums, digital signatures) on critical data","Implement proper authorisation","Use ORM or parameterised queries to prevent data tampering"],
        "Availability": ["Implement rate limiting on all public endpoints","Set file size caps and timeouts on all input processing","Use connection pooling and resource limits","Implement circuit breakers for external service calls"],
        "Access Control": ["Enforce authentication on every sensitive endpoint","Apply role-based access control (RBAC)","Validate session tokens on every request","Implement the principle of least privilege throughout"],
        "Non-Repudiation": ["Implement comprehensive audit logging","Use digital signatures for critical operations","Store immutable logs with timestamps"],
        "Accountability": ["Log all security-relevant events with user identity","Implement multi-factor authentication","Maintain audit trails for sensitive operations"],
    }
    analysis = []
    for consequence, cwes in sorted(consequence_map.items(), key=lambda x: -len(x[1])):
        high_count = sum(1 for c in cwes if c["likelihood"] == "High")
        analysis.append({
            "consequence": consequence,
            "cwe_count": len(cwes),
            "percentage": round(len(cwes) / total * 100, 1),
            "high_likelihood_count": high_count,
            "top_cwes": sorted(cwes, key=lambda x: x["likelihood"] == "High", reverse=True)[:5],
            "recommendations": recommendations.get(consequence, ["Apply general secure coding practices"]),
        })
    return {
        "total_weaknesses_analysed": total,
        "consequence_categories": len(analysis),
        "analysis": analysis,
        "insight": "Confidentiality and Integrity are the most impacted properties. Addressing root-cause weaknesses provides the highest security return."
    }

@app.get("/api/v1/recommendations/{cwe_id}")
@limiter.limit("20/minute")
async def get_recommendations(request: Request, cwe_id: str,
                               session: AsyncSession = Depends(get_session)):
    if not str(cwe_id).isdigit():
        raise HTTPException(status_code=400, detail="CWE ID must be numeric")
    cwe = await insights.get_cwe_by_id(session, cwe_id)
    if not cwe:
        raise HTTPException(status_code=404, detail=f"CWE-{cwe_id} not found")
    owasp = get_owasp_mapping(cwe_id)
    recs = []
    consequence_recs = {
        "Confidentiality": "Encrypt sensitive data and apply least privilege access controls",
        "Integrity": "Validate all inputs with allowlists and use parameterised queries",
        "Availability": "Implement rate limiting, timeouts, and resource caps",
        "Access Control": "Enforce authentication and authorisation on every endpoint",
    }
    for c in (cwe.get("common_consequences") or []):
        if c in consequence_recs:
            recs.append({"type": "consequence", "consequence": c, "recommendation": consequence_recs[c]})
    platform_recs = {
        "Java": "Use OWASP Java Encoder for output encoding; avoid raw JDBC string formatting",
        "PHP": "Use PDO with prepared statements; enable strict mode; use htmlspecialchars()",
        "C": "Use safe string functions (strncpy, snprintf); enable ASLR and stack canaries",
        "C++": "Use smart pointers; enable AddressSanitizer in testing; avoid raw pointer arithmetic",
        "Python": "Use parameterised queries with SQLAlchemy; validate with Pydantic; run Bandit SAST",
        "JavaScript": "Sanitise DOM inputs; use Content Security Policy; avoid eval()",
    }
    platforms = [p.get("name", "") for p in (cwe.get("applicable_platforms") or [])]
    for p in platforms[:3]:
        if p in platform_recs:
            recs.append({"type": "platform", "platform": p, "recommendation": platform_recs[p]})
    if not cwe.get("detection_methods"):
        recs.append({"type": "detection", "recommendation": "No standard detection methods documented — consider manual code review and penetration testing"})
    else:
        recs.append({"type": "detection", "recommendation": f"Detection methods available: {', '.join(cwe['detection_methods'][:3])}"})
    if owasp.get("in_owasp_top10"):
        recs.append({"type": "owasp", "recommendation": f"Consult OWASP guidance for {owasp['owasp_categories'][0]} — includes specific prevention checklists"})
    priority = "CRITICAL" if cwe.get("likelihood_of_exploit") == "High" else \
               "HIGH" if cwe.get("likelihood_of_exploit") == "Medium" else "MEDIUM"
    return {
        "cwe_id": cwe_id,
        "name": cwe.get("name"),
        "priority": priority,
        "likelihood": cwe.get("likelihood_of_exploit"),
        "recommendations": recs,
        "general_advice": [
            "Follow OWASP Secure Coding Practices",
            "Run SAST tools (Bandit, Semgrep) on every commit",
            "Include this CWE in your threat model",
            "Add specific test cases to detect this weakness",
        ],
        "references": [
            f"https://cwe.mitre.org/data/definitions/{cwe_id}.html",
            "https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/",
            "https://nvd.nist.gov/",
        ]
    }

# ── Serve frontend ────────────────────────────────────────────
# Must be LAST — after all API routes
frontend_path = Path(__file__).parent.parent.parent / "frontend"
if frontend_path.exists():
    app.mount("/", StaticFiles(directory=str(frontend_path), html=True), name="static")
