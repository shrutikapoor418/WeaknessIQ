"""
NVD (National Vulnerability Database) Integration
===================================================
Fetches real CVE data from the US NIST NVD API and links
vulnerabilities back to CWE weakness categories.

This enriches WeaknessIQ beyond the CWE catalogue alone —
showing REAL exploited vulnerabilities per weakness type.

Security decisions:
- CWE-918: URL allowlist — only NVD API host permitted
- CWE-295: TLS verify=True always enforced
- CWE-400: Rate limiting respected (NVD allows 5 req/30s without key)
- CWE-20:  All inputs validated before use in API calls
- CWE-703: Safe error handling — API failures degrade gracefully

NVD API Docs: https://nvd.nist.gov/developers/vulnerabilities
"""

import time
import logging
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
import json

logger = logging.getLogger("weaknessiq.nvd")

# ── Constants ─────────────────────────────────────────────────────────────────
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ALLOWED_HOST = "services.nvd.nist.gov"          # CWE-918: allowlist
CACHE_DIR = Path(__file__).parent.parent.parent / "data" / "nvd_cache"
CACHE_TTL_HOURS = 24                             # Refresh cache daily
MAX_RESULTS_PER_REQUEST = 20                     # Keep responses small
NVD_RATE_LIMIT_DELAY = 6                         # Seconds between requests (no API key)


# ── URL Validation (CWE-918: SSRF prevention) ────────────────────────────────
def _validate_nvd_url(url: str) -> None:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("Only HTTPS permitted")
    if parsed.hostname != ALLOWED_HOST:
        raise ValueError(f"Host not in allowlist: {parsed.hostname}")


# ── Cache helpers ─────────────────────────────────────────────────────────────
def _cache_path(key: str) -> Path:
    safe_key = hashlib.md5(key.encode()).hexdigest()
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / f"{safe_key}.json"


def _cache_get(key: str) -> dict | None:
    path = _cache_path(key)
    if not path.exists():
        return None
    age = datetime.now() - datetime.fromtimestamp(path.stat().st_mtime)
    if age > timedelta(hours=CACHE_TTL_HOURS):
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def _cache_set(key: str, data: dict) -> None:
    try:
        _cache_path(key).write_text(json.dumps(data))
    except Exception as e:
        logger.warning(f"Cache write failed: {e}")


# ── Core NVD Fetcher ──────────────────────────────────────────────────────────
def fetch_cves_for_cwe(cwe_id: str, limit: int = 10) -> dict:
    """
    Fetch real CVEs from NVD that are linked to a specific CWE.
    Results are cached for 24 hours to respect NVD rate limits.

    Returns structured data including severity, CVSS scores, and descriptions.
    """
    # CWE-20: Validate input
    if not str(cwe_id).isdigit():
        raise ValueError("CWE ID must be numeric")
    limit = max(1, min(limit, 20))

    cache_key = f"cwe_{cwe_id}_limit_{limit}"
    cached = _cache_get(cache_key)
    if cached:
        logger.info(f"NVD cache hit for CWE-{cwe_id}")
        return cached

    try:
        import requests
    except ImportError:
        return _empty_result(cwe_id, "requests library not installed")

    # Build URL — NVD API v2 CWE filter
    url = f"{NVD_API_BASE}?cweId=CWE-{cwe_id}&resultsPerPage={limit}"
    _validate_nvd_url(url)   # CWE-918

    logger.info(f"Fetching NVD CVEs for CWE-{cwe_id}...")

    try:
        # CWE-295: verify=True enforced explicitly
        response = requests.get(
            url,
            verify=True,
            timeout=15,
            headers={"User-Agent": "WeaknessIQ-Research/1.0"}
        )
        response.raise_for_status()
        raw = response.json()

        result = _parse_nvd_response(cwe_id, raw)
        _cache_set(cache_key, result)

        # Respect NVD rate limit
        time.sleep(NVD_RATE_LIMIT_DELAY)

        return result

    except requests.exceptions.SSLError:
        logger.error("TLS verification failed for NVD API")
        return _empty_result(cwe_id, "TLS verification failed")
    except requests.exceptions.Timeout:
        logger.error("NVD API request timed out")
        return _empty_result(cwe_id, "Request timed out")
    except requests.exceptions.RequestException as e:
        logger.error(f"NVD API error: {type(e).__name__}")
        return _empty_result(cwe_id, "NVD API unavailable")
    except Exception as e:
        logger.error(f"Unexpected error fetching NVD data: {type(e).__name__}")
        return _empty_result(cwe_id, "Unexpected error")


def _parse_nvd_response(cwe_id: str, raw: dict) -> dict:
    """Parse NVD API v2 response into clean structured data."""
    vulnerabilities = raw.get("vulnerabilities", [])
    total_results = raw.get("totalResults", 0)

    cves = []
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

    for item in vulnerabilities:
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "")

        # Extract description (English only)
        descriptions = cve_data.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available"
        )

        # Extract CVSS score (prefer v3.1, fallback to v3.0, then v2)
        metrics = cve_data.get("metrics", {})
        cvss_score = None
        cvss_severity = "UNKNOWN"
        cvss_vector = None

        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(version, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = (
                    metric_list[0].get("baseSeverity") or
                    cvss_data.get("baseSeverity", "UNKNOWN")
                ).upper()
                cvss_vector = cvss_data.get("vectorString")
                break

        severity_counts[cvss_severity] = severity_counts.get(cvss_severity, 0) + 1

        # Published date
        published = cve_data.get("published", "")[:10]  # YYYY-MM-DD only

        cves.append({
            "cve_id": cve_id,
            "description": description[:300] + "..." if len(description) > 300 else description,
            "cvss_score": cvss_score,
            "severity": cvss_severity,
            "cvss_vector": cvss_vector,
            "published": published,
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })

    return {
        "cwe_id": cwe_id,
        "total_cves_in_nvd": total_results,
        "returned": len(cves),
        "severity_breakdown": severity_counts,
        "cves": cves,
        "data_source": "NIST NVD API v2",
        "cached": False,
    }


def _empty_result(cwe_id: str, reason: str) -> dict:
    """Safe empty result when NVD is unavailable — degrades gracefully."""
    return {
        "cwe_id": cwe_id,
        "total_cves_in_nvd": 0,
        "returned": 0,
        "severity_breakdown": {},
        "cves": [],
        "data_source": "NVD unavailable",
        "error": reason,
        "cached": False,
    }


# ── OWASP Top 10 Mapping ──────────────────────────────────────────────────────
# Static mapping — OWASP Top 10 2025 to CWE IDs
# Updated from 2021 to 2025 — two new categories, one consolidation:
#   NEW: A03:2025 Software Supply Chain Failures
#   NEW: A10:2025 Mishandling of Exceptional Conditions
#   REMOVED: A10:2021 SSRF — rolled into A01:2025 Broken Access Control
#   MOVED:   Security Misconfiguration A05→A02, Injection A03→A05
# Source: https://owasp.org/Top10/2025/
OWASP_TOP10_2025 = {
    "A01:2025 — Broken Access Control": [
        # Broken Access Control (same as 2021) + SSRF now rolled in (CWE-918)
        "22", "23", "35", "59", "200", "201", "219", "264", "275",
        "276", "284", "285", "352", "359", "377", "402", "425", "441",
        "497", "538", "566", "601", "639", "651", "668", "706", "862",
        "863", "913", "918", "922", "1275"
    ],
    "A02:2025 — Security Misconfiguration": [
        # Was A05:2021 — moved up to #2 in 2025
        "2", "5", "11", "13", "15", "16", "260", "315", "520", "526",
        "537", "541", "547", "611", "614", "756", "776", "942", "1021", "1173"
    ],
    "A03:2025 — Software Supply Chain Failures": [
        # NEW in 2025 — expanded from A06:2021 Vulnerable Components
        # Covers full supply chain: dependencies, build systems, CI/CD, distribution
        "494", "829", "830", "937", "1035", "1104"
    ],
    "A04:2025 — Cryptographic Failures": [
        # Was A02:2021 — moved down to #4
        "261", "296", "310", "319", "321", "322", "323", "324", "325",
        "326", "327", "328", "329", "330", "331", "335", "336", "337",
        "338", "340", "347", "523", "720", "757", "759", "760", "780",
        "818", "916"
    ],
    "A05:2025 — Injection": [
        # Was A03:2021 — moved down to #5
        "20", "74", "75", "77", "78", "79", "80", "83", "87", "88",
        "89", "90", "91", "93", "94", "95", "96", "97", "98", "99",
        "116", "138", "184", "470", "471", "564", "610", "643", "644",
        "652", "917"
    ],
    "A06:2025 — Insecure Design": [
        # Was A04:2021 — moved down to #6
        "73", "183", "213", "235", "256", "257", "266", "269",
        "280", "311", "312", "313", "316", "419", "430", "434", "444",
        "451", "472", "501", "522", "525", "539", "579", "598", "602",
        "620", "636", "645", "650", "653", "656", "657", "799"
    ],
    "A07:2025 — Authentication Failures": [
        # Same position as A07:2021
        "255", "259", "287", "288", "290", "294", "295", "297", "300",
        "302", "304", "306", "307", "346", "384", "521", "613", "620",
        "640", "798", "940", "1216"
    ],
    "A08:2025 — Software or Data Integrity Failures": [
        # Same as A08:2021 — slight rename
        "345", "353", "426", "502", "565", "784", "829", "830", "915"
    ],
    "A09:2025 — Security Logging and Alerting Failures": [
        # Was A09:2021 — renamed to emphasise alerting not just logging
        "117", "223", "532", "778"
    ],
    "A10:2025 — Mishandling of Exceptional Conditions": [
        # NEW in 2025 — improper error handling, logical errors, failing open
        # Includes CWE-209 (error message info disclosure) and CWE-918 (SSRF)
        "209", "390", "391", "392", "393", "394", "395", "396", "397",
        "476", "544", "636", "703", "754", "755", "756", "957"
    ],
}

# Reverse lookup: CWE ID → OWASP 2025 categories
CWE_TO_OWASP: dict[str, list[str]] = {}
for category, cwe_list in OWASP_TOP10_2025.items():
    for cwe in cwe_list:
        if cwe not in CWE_TO_OWASP:
            CWE_TO_OWASP[cwe] = []
        CWE_TO_OWASP[cwe].append(category)


def get_owasp_mapping(cwe_id: str) -> dict:
    """Return OWASP Top 10 2025 categories for a given CWE."""
    if not str(cwe_id).isdigit():
        raise ValueError("CWE ID must be numeric")

    categories = CWE_TO_OWASP.get(str(cwe_id), [])
    return {
        "cwe_id": cwe_id,
        "owasp_categories": categories,
        "in_owasp_top10": len(categories) > 0,
        "owasp_version": "OWASP Top 10 2025",
        "source": "https://owasp.org/Top10/2025/",
    }


def get_owasp_coverage_summary(cwe_ids: list[str]) -> dict:
    """
    For a list of CWE IDs, show how many map to each OWASP 2025 category.
    Gives a portfolio-level view of OWASP Top 10 2025 coverage.
    """
    category_counts: dict[str, int] = {cat: 0 for cat in OWASP_TOP10_2025}

    covered = 0
    for cwe_id in cwe_ids:
        categories = CWE_TO_OWASP.get(str(cwe_id), [])
        if categories:
            covered += 1
        for cat in categories:
            category_counts[cat] = category_counts.get(cat, 0) + 1

    return {
        "total_cwes_analysed": len(cwe_ids),
        "cwes_in_owasp_top10": covered,
        "coverage_percentage": round(covered / len(cwe_ids) * 100, 1) if cwe_ids else 0,
        "by_category": [
            {"category": cat, "cwe_count": count}
            for cat, count in sorted(category_counts.items(),
                                     key=lambda x: x[1], reverse=True)
            if count > 0
        ],
        "owasp_version": "OWASP Top 10 2025",
        "source": "https://owasp.org/Top10/2025/",
    }
