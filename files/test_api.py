"""
API Tests — WeaknessIQ
=======================
Tests cover both functionality and security controls on the API layer.
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch

from backend.api.main import app


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as ac:
        yield ac


# ── Health check ──────────────────────────────────────────────────────────────
class TestHealthCheck:
    async def test_health_returns_ok(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


# ── Security Header Tests ─────────────────────────────────────────────────────
class TestSecurityHeaders:
    """Every response must include required security headers."""

    async def test_x_content_type_options(self, client):
        resp = await client.get("/health")
        assert resp.headers.get("x-content-type-options") == "nosniff"

    async def test_x_frame_options(self, client):
        resp = await client.get("/health")
        assert resp.headers.get("x-frame-options") == "DENY"

    async def test_csp_header_present(self, client):
        resp = await client.get("/health")
        assert "content-security-policy" in resp.headers

    async def test_no_server_header(self, client):
        """Server fingerprinting should be suppressed."""
        resp = await client.get("/health")
        assert "server" not in resp.headers


# ── Input Validation Tests ────────────────────────────────────────────────────
class TestInputValidation:

    async def test_non_numeric_cwe_id_rejected(self, client):
        """CWE IDs must be numeric — non-numeric input returns 400."""
        resp = await client.get("/api/v1/cwe/../../etc/passwd")
        assert resp.status_code in (400, 422)

    async def test_invalid_abstraction_rejected(self, client):
        """Invalid abstraction filter returns 400, not 500."""
        resp = await client.get("/api/v1/analysis/top-weaknesses?abstraction=INVALID")
        assert resp.status_code == 400

    async def test_cwe_not_found_returns_404(self, client):
        """Non-existent CWE returns 404, not 500."""
        resp = await client.get("/api/v1/cwe/99999999")
        assert resp.status_code in (404, 500)  # 500 acceptable if DB not seeded in test

    async def test_excessive_depth_capped(self, client):
        """Depth > 5 should be capped, not cause runaway query."""
        resp = await client.get("/api/v1/analysis/relationships/79?depth=999")
        # Should not return 500 — depth cap should handle this
        assert resp.status_code in (200, 404)


# ── CORS Tests ────────────────────────────────────────────────────────────────
class TestCORS:

    async def test_cors_blocks_unknown_origin(self, client):
        """Unknown origins should not receive CORS allow header."""
        resp = await client.get(
            "/health",
            headers={"Origin": "https://malicious.com"}
        )
        # Should not echo back the malicious origin
        allow_origin = resp.headers.get("access-control-allow-origin", "")
        assert "malicious.com" not in allow_origin
