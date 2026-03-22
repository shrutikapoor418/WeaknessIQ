# CWE Analyser — PureSecure Prototype

A secure prototype system that ingests MITRE CWE XML data and surfaces
analytical insights into the software vulnerability landscape.

## Security-First Setup

### 1. Clone and configure secrets

```bash
git clone <your-gitlab-repo>
cd cwe-analyser
cp .env.example .env
# Edit .env — fill in APP_SECRET_KEY and any other values
```

**Never commit `.env`** — it is blocked by `.gitignore`.

### 2. Install dependencies

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt   # Dev/test tools
```

### 3. Download CWE data securely

```bash
# Downloads from official MITRE source over verified TLS
# --register flag saves SHA-256 checksum for future integrity checks
python backend/parser/downloader.py --register
```

After running, copy the printed checksum into `KNOWN_CHECKSUMS` in
`backend/parser/cwe_parser.py`. All subsequent downloads will be verified
against this value.

### 4. Run the parser (verify it works)

```bash
python backend/parser/cwe_parser.py data/cwec_latest.xml
```

### 5. Run security checks locally (before committing)

```bash
bandit -r backend/ -ll              # SAST
safety check                        # CVE dependency check
semgrep --config=p/owasp-top-ten backend/
```

### 6. Run tests

```bash
pytest tests/ --cov=backend -v
```

## Project Structure

```
cwe-analyser/
├── backend/
│   ├── parser/
│   │   ├── cwe_parser.py      # Secure XML parser (CWE-611, CWE-400 mitigated)
│   │   └── downloader.py      # TLS-verified downloader (CWE-295, CWE-918)
│   ├── api/                   # FastAPI application (Phase 2)
│   ├── db/                    # Database layer (Phase 2)
│   └── utils/
├── data/                      # CWE XML data (gitignored — fetched at runtime)
├── tests/                     # Test suite
├── .gitlab-ci.yml             # CI/CD pipeline with SAST, secret detection
├── .gitignore                 # Prevents accidental secret commits
├── .env.example               # Secret template (never commit .env)
├── Dockerfile                 # Hardened container (non-root, pinned base)
├── requirements.txt           # Pinned production dependencies
└── requirements-dev.txt       # Pinned dev/test dependencies
```

## Security Controls Summary

| Control | Implementation | CWE Mitigated |
|---|---|---|
| XXE Prevention | stdlib ET parser (no external entities) | CWE-611 |
| DoS Prevention | File size cap before parsing | CWE-400 |
| Path Traversal | Resolve + restrict to data dir | CWE-22 |
| Supply Chain | Pinned deps + SHA-256 file verification | CWE-494 |
| TLS Verification | `verify=True` explicit in all requests | CWE-295 |
| SSRF Prevention | URL allowlist before any HTTP request | CWE-918 |
| Secret Management | Env vars only, never hardcoded | CWE-798 |
| Least Privilege | Non-root Docker user | CWE-250 |
| Error Safety | Safe exceptions, no stack trace leaks | CWE-703 |
| SAST | Bandit + Semgrep on every commit | Multiple |

## GitLab CI Pipeline

Every commit triggers:
1. **Secret detection** — blocks merge if credentials detected
2. **Bandit SAST** — Python security linting
3. **Semgrep** — OWASP Top 10 rule set
4. **Safety** — dependency CVE check
5. **Unit tests** — with coverage reporting
6. **Trivy** — container image scan (on main branch)
