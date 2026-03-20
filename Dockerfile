# ============================================================
# Dockerfile — Hardened Python container
# ============================================================
# Security decisions documented inline.
# ============================================================

# Pin to specific digest, not just tag, to prevent image substitution
# (supply chain protection — update digest intentionally, not automatically)
FROM python:3.11-slim@sha256:3be54ded5fa864f36d4a4a9d2b9f03e6dc8c4c03f4a2ad2b3d36b85427fc9b85

# ── Metadata ─────────────────────────────────────────────────
LABEL maintainer="PureSecure" \
      description="CWE Analyser — secure prototype"

# ── Non-root user (least privilege — CWE-250) ────────────────
# Running as root in a container means a container escape gives
# full host access. Non-root limits blast radius.
RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --shell /bin/false --no-create-home appuser

# ── System hardening ─────────────────────────────────────────
# Update base image packages to patch known CVEs
# Clean up apt cache to reduce image size and attack surface
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# ── Working directory ─────────────────────────────────────────
WORKDIR /app

# ── Install dependencies as root, then drop privileges ───────
# Separate COPY of requirements first — Docker cache layer optimisation
# If code changes but requirements don't, this layer is cached
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip==24.0 && \
    pip install --no-cache-dir -r requirements.txt

# ── Copy application code ─────────────────────────────────────
COPY --chown=appuser:appgroup backend/ ./backend/
COPY --chown=appuser:appgroup data/ ./data/

# ── Drop to non-root ──────────────────────────────────────────
USER appuser

# ── Read-only filesystem where possible ──────────────────────
# Volumes for data that needs to change; everything else is read-only
# (configured at runtime with --read-only flag + tmpfs for /tmp)

# ── Health check ─────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# ── Expose only the required port ────────────────────────────
EXPOSE 8000

# ── No shell in entrypoint (prevents shell injection) ────────
ENTRYPOINT ["python", "-m", "uvicorn", "backend.api.main:app"]
CMD ["--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
