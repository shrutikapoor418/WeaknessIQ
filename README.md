# WeaknessIQ — Security Intelligence Dashboard

A secure web-based threat intelligence platform that analyses the MITRE CWE catalogue
and enriches it with real CVE data from NIST NVD and OWASP Top 10 2021 mappings.

**ELE8094 Software Assurance — Assignment 2 | PureSecure Consultancy Prototype**

---

## What It Does

- Ingests 969 CWE weakness definitions from MITRE XML
- Links each CWE to real CVEs from the NIST National Vulnerability Database
- Maps weaknesses to OWASP Top 10 2021 categories
- Provides a live dashboard with exploit likelihood charts, language risk profiles,
  detection gap analysis, and enriched threat profiles

---

## Requirements

- Python 3.11 or higher
- Git

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://gitlab.eeecs.qub.ac.uk/40472240/WeaknessIQ.git
cd WeaknessIQ
```

### 2. Install dependencies

```bash
pip install fastapi uvicorn sqlalchemy aiosqlite slowapi python-dotenv requests certifi
```

### 3. Download CWE data from MITRE

```bash
python3 backend/parser/downloader.py
```

This downloads the official CWE XML from `cwe.mitre.org` over verified TLS.
The file is saved to `data/cwec_latest.xml`.

### 4. Start the API (Terminal 1)

```bash
python3 -m uvicorn backend.api.main:app --reload
```

The API starts at `http://localhost:8000`.
On first run it automatically parses the CWE XML and loads 969 entries into the database.

### 5. Start the frontend (Terminal 2)

```bash
cd frontend
python3 -m http.server 3000
```

### 6. Open the dashboard

```
http://localhost:3000
```

---

## API Endpoints

| Endpoint | Description |
|---|---|
| `GET /health` | Health check |
| `GET /api/v1/summary` | Catalogue statistics |
| `GET /api/v1/cwe/{id}` | Single CWE lookup |
| `GET /api/v1/analysis/exploit-likelihood` | Likelihood distribution |
| `GET /api/v1/analysis/language-risk` | Language risk profiles |
| `GET /api/v1/analysis/detection-gaps` | Detection blind spots |
| `GET /api/v1/analysis/relationships/{id}` | Relationship chain traversal |
| `GET /api/v1/enrich/nvd/{id}` | Real CVEs from NIST NVD |
| `GET /api/v1/enrich/owasp/{id}` | OWASP Top 10 mapping |
| `GET /api/v1/enrich/owasp-coverage` | Catalogue-wide OWASP coverage |
| `GET /api/v1/enrich/threat-profile/{id}` | Full enriched threat profile |

Interactive API docs available at `http://localhost:8000/docs`

---

## Project Structure

```
WeaknessIQ/
├── backend/
│   ├── api/
│   │   └── main.py          # FastAPI application + security headers
│   ├── analysis/
│   │   └── insights.py      # Analysis engine (6 insight types)
│   ├── db/
│   │   ├── database.py      # SQLite + SQLAlchemy ORM
│   │   └── loader.py        # CWE data loader
│   ├── integrations/
│   │   └── nvd.py           # NIST NVD + OWASP integration
│   └── parser/
│       ├── cwe_parser.py    # Secure XML parser (XXE prevention)
│       └── downloader.py    # TLS-verified CWE downloader
├── frontend/
│   └── index.html           # Dashboard (HTML/JS)
├── tests/
│   ├── test_parser.py       # Parser security tests
│   └── test_api.py          # API security tests
├── data/                    # CWE XML data (gitignored)
├── .gitlab-ci.yml           # CI/CD pipeline
├── Dockerfile               # Hardened container
└── requirements.txt         # Pinned dependencies
```

---

## Security Controls

| Control | Implementation | CWE Mitigated |
|---|---|---|
| XXE prevention | stdlib ET parser, no external entities | CWE-611 |
| Path traversal | Path resolve + /data/ boundary check | CWE-22 |
| DoS prevention | 50MB file size cap before parsing | CWE-400 |
| Integrity check | SHA-256 verification of CWE XML | CWE-494 |
| SQL injection | SQLAlchemy ORM, no raw SQL | CWE-89 |
| SSRF prevention | URL allowlist for external requests | CWE-918 |
| Rate limiting | slowapi on all endpoints | CWE-307 |
| Secret management | Environment variables only | CWE-798 |
| Security headers | CSP, HSTS, X-Frame-Options on all responses | CWE-16 |

---

## Data Sources

- **MITRE CWE** — https://cwe.mitre.org
- **NIST NVD API v2** — https://nvd.nist.gov/developers/vulnerabilities
- **OWASP Top 10 2021** — https://owasp.org/Top10/

---

## Running Tests

```bash
pip install pytest pytest-asyncio httpx
pytest tests/ -v
```
