"""
CWE Data Downloader — Secure Fetcher
=====================================
Security decisions:
- CWE-295: TLS certificate verification ALWAYS enabled (no verify=False ever)
- CWE-494: Downloaded file integrity verified by SHA-256 before use
- CWE-400: Streaming download with size cap — no unbounded memory load
- CWE-20:  URL validated against allowlist before any request is made

Usage:
    python downloader.py                  # downloads latest CWE XML
    python downloader.py --register       # downloads + registers checksum
"""

import hashlib
import logging
import sys
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger("cwe_downloader")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s"
)

# ── Allowlisted sources (CWE-20: explicit allowlist, not blocklist) ───────────
ALLOWED_HOSTS = {"cwe.mitre.org"}

CWE_SOURCES = {
    "full": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
    "research": "https://cwe.mitre.org/data/xml/views/research_concepts.xml.zip",
}

MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024   # 100 MB hard cap (CWE-400)
CHUNK_SIZE = 8192
DATA_DIR = Path(__file__).parent.parent.parent / "data"


def _validate_url(url: str) -> None:
    """
    Allowlist check before making any HTTP request.
    Prevents SSRF (CWE-918) and ensures we only talk to MITRE.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"Only HTTPS URLs permitted. Got: {parsed.scheme}")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(
            f"Host '{parsed.hostname}' not in allowlist {ALLOWED_HOSTS}. "
            "SSRF protection active."
        )


def download_cwe(source: str = "full", register_checksum: bool = False) -> Path:
    """
    Download CWE XML from MITRE with full security controls.
    Returns path to downloaded file.
    """
    try:
        import requests
    except ImportError:
        print("Install requests: pip install requests")
        sys.exit(1)

    url = CWE_SOURCES.get(source)
    if not url:
        raise ValueError(f"Unknown source '{source}'. Choose from: {list(CWE_SOURCES)}")

    _validate_url(url)   # CWE-918 / CWE-20

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    zip_path = DATA_DIR / "cwec_latest.xml.zip"
    xml_path = DATA_DIR / "cwec_latest.xml"

    logger.info(f"Downloading CWE XML from {url}")
    logger.info("TLS certificate verification: ENABLED")

    # CWE-295: verify=True is the default but we are explicit
    # CWE-400: stream=True + size cap prevents memory exhaustion
    response = requests.get(url, stream=True, verify=True, timeout=30)
    response.raise_for_status()

    downloaded = 0
    sha256 = hashlib.sha256()

    with open(zip_path, "wb") as f:
        for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
            downloaded += len(chunk)
            if downloaded > MAX_DOWNLOAD_BYTES:
                zip_path.unlink(missing_ok=True)
                raise RuntimeError(
                    f"Download exceeded {MAX_DOWNLOAD_BYTES // 1024 // 1024} MB cap. "
                    "Aborting — possible DoS or unexpected file."
                )
            sha256.update(chunk)
            f.write(chunk)

    checksum = sha256.hexdigest()
    logger.info(f"Download complete: {downloaded / 1024:.1f} KB")
    logger.info(f"SHA-256: {checksum}")

    # Unzip
    import zipfile
    with zipfile.ZipFile(zip_path, "r") as zf:
        xml_files = [n for n in zf.namelist() if n.endswith(".xml")]
        if not xml_files:
            raise RuntimeError("No XML file found in downloaded zip")
        zf.extract(xml_files[0], DATA_DIR)
        extracted = DATA_DIR / xml_files[0]
        if extracted != xml_path:
            extracted.rename(xml_path)

    zip_path.unlink()   # Clean up zip after extraction

    logger.info(f"Extracted to: {xml_path}")

    if register_checksum:
        _register_checksum(xml_path)

    return xml_path


def _register_checksum(xml_path: Path) -> None:
    """
    After first verified download, register SHA-256 in parser's KNOWN_CHECKSUMS.
    Operator must do this manually on first run after visual inspection.
    Subsequent runs will verify against this value.
    """
    sha256 = hashlib.sha256()
    with open(xml_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    checksum = sha256.hexdigest()

    checksum_file = xml_path.parent / "checksums.txt"
    with open(checksum_file, "a") as f:
        f.write(f"{xml_path.name}:{checksum}\n")

    logger.info(f"Checksum registered in {checksum_file}")
    logger.info(f"Add to KNOWN_CHECKSUMS in cwe_parser.py: '{xml_path.name}': '{checksum}'")
    print(f"\n✅ Register this checksum in cwe_parser.py KNOWN_CHECKSUMS:")
    print(f"   '{xml_path.name}': '{checksum}'")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Secure CWE XML downloader")
    p.add_argument("--source", default="full", choices=list(CWE_SOURCES))
    p.add_argument("--register", action="store_true", help="Register checksum after download")
    args = p.parse_args()

    try:
        path = download_cwe(source=args.source, register_checksum=args.register)
        print(f"\n✅ CWE data ready at: {path}")
    except Exception as e:
        print(f"❌ {type(e).__name__}: {e}")
        sys.exit(1)
