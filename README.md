# WeaknessIQ — Security Intelligence Dashboard

A secure web-based threat intelligence platform that analyses the MITRE CWE catalogue and enriches it with real CVE data from NIST NVD and OWASP Top 10 2025 mappings.

**ELE8094 Software Assurance — Assignment 2 | PureSecure Consultancy Prototype**

**Developed by:** Shruti Kapoor | Student ID: 40472240 | Queen's University Belfast

---

## What It Does

- Ingests 969 CWE weakness definitions from MITRE XML
- Links each CWE to real CVEs from the NIST National Vulnerability Database
- Maps weaknesses to OWASP Top 10 2025 categories
- Search vulnerabilities by name or keyword (e.g. "buffer overflow", "injection")
- Compare two CWEs side by side with consequence analysis and fix recommendations
- Calculate composite risk scores (0-100) based on 5 weighted factors
- Rank top 10 most dangerous CWEs by composite danger score
- Plan fix priority for up to 8 CWEs ranked by urgency
- Generate downloadable PDF security reports per CWE
- Live dashboard with 9 pages: Dashboard, Search, Threat Profile, Consequences, OWASP, Top 10 Dangerous, Risk Score, Fix Priority, PDF Report

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

### 4. Start the API (Terminal 1)

```bash
python3 -m uvicorn backend.api.main:app --reload
```

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
| `GET /api/v1/search?q=...` | Search CWEs by name or keyword |
| `GET /api/v1/analysis/exploit-likelihood` | Likelihood distribution |
| `GET /api/v1/analysis/language-risk` | Language risk profiles |
| `GET /api/v1/analysis/detection-gaps` | Detection blind spots |
| `GET /api/v1/analysis/relationships/{id}` | Relationship chain traversal |
| `GET /api/v1/analysis/consequences` | Consequence category analysis |
| `GET /api/v1/enrich/nvd/{id}` | Real CVEs from NIST NVD |
| `GET /api/v1/enrich/owasp/{id}` | OWASP Top 10 2025 mapping |
| `GET /api/v1/enrich/owasp-coverage` | Catalogue-wide OWASP coverage |
| `GET /api/v1/enrich/threat-profile/{id}` | Full enriched threat profile |
| `GET /api/v1/recommendations/{id}` | Actionable fix recommendations |

Interactive API docs: `http://localhost:8000/docs`

---

## Dashboard Pages

| Page | What It Shows |
|---|---|
| **Dashboard** | Stat cards, exploit likelihood, language risk, abstraction breakdown, blind spots |
| **Search** | Search by name/keyword or CWE ID with CVE, MITRE, OWASP tabs |
| **Threat Profile** | Enriched profile combining MITRE + NVD + OWASP in one view |
| **Consequences** | Compare two CWEs side by side — consequences, CVEs, fix recommendations |
| **OWASP** | Clickable OWASP Top 10 2025 categories showing all mapped CWEs |
| **Top 10 Dangerous** | Top 10 most dangerous CWEs ranked by composite danger score |
| **Risk Score** | 5-factor composite risk score calculator (0-100) per CWE |
| **Fix Priority** | Rank up to 8 CWEs by danger score with Fix Immediately/This Week/When Possible labels |
| **PDF Report** | Generate downloadable security report for any CWE |

---

## Project Structure

```
WeaknessIQ/
├── backend/
│   ├── api/
│   │   └── main.py              # FastAPI app — 14 endpoints, security headers
│   ├── analysis/
│   │   └── insights.py          # Analysis engine (7 insight types)
│   ├── db/
│   │   ├── database.py          # SQLite + SQLAlchemy ORM
│   │   └── loader.py            # CWE data loader
│   ├── integrations/
│   │   └── nvd.py               # NIST NVD + OWASP 2025 integration
│   └── parser/
│       ├── cwe_parser.py        # Secure XML parser (XXE prevention)
│       └── downloader.py        # TLS-verified CWE downloader
├── frontend/
│   └── index.html               # Dashboard (HTML/JS — 9 pages)
├── tests/
│   ├── test_parser.py           # Parser security tests
│   └── test_api.py              # API security tests
├── data/                        # CWE XML data (gitignored)
├── .gitlab-ci.yml               # CI/CD pipeline with SAST
├── Dockerfile                   # Hardened container (non-root)
└── requirements.txt             # Dependencies
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
| Input validation | Regex + allowlist on all user inputs | CWE-20 |

---

## Data Sources

- **MITRE CWE** — https://cwe.mitre.org
- **NIST NVD API v2** — https://nvd.nist.gov/developers/vulnerabilities
- **OWASP Top 10 2025** — https://owasp.org/Top10/2025/

---

## CI/CD Pipeline

Every commit triggers:

1. Secret detection — blocks merge if credentials detected
2. Bandit SAST — Python security linting
3. Semgrep — OWASP Top 10 rule set
4. Safety — dependency CVE check
5. Unit tests — with coverage reporting
6. Trivy — container image scan (main branch)

---

## Running Tests

```bash
pip install pytest pytest-asyncio httpx
pytest tests/ -v
```
