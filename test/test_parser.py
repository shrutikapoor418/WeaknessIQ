"""
Tests for CWE Parser — Security-focused test suite
====================================================
Tests verify both functionality AND security controls.
A security control that isn't tested is a control you
can't rely on.
"""

import hashlib
import os
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch

# Adjust import path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.parser.cwe_parser import (
    CWEParser,
    ParseResult,
    SecurityError,
    ParseError,
    _compute_sha256,
    _validate_file,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

MINIMAL_CWE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog
    xmlns="http://cwe.mitre.org/cwe-7"
    Name="CWE" Version="4.14">
  <Weaknesses>
    <Weakness ID="79" Name="Cross-site Scripting" Abstraction="Base" Status="Stable">
      <Description>Improper Neutralization of Input During Web Page Generation.</Description>
      <Extended_Description>XSS allows attackers to inject scripts.</Extended_Description>
      <Likelihood_Of_Exploit>High</Likelihood_Of_Exploit>
      <Common_Consequences>
        <Consequence>
          <Scope>Confidentiality</Scope>
        </Consequence>
      </Common_Consequences>
      <Applicable_Platforms>
        <Language Name="JavaScript" Prevalence="Often"/>
      </Applicable_Platforms>
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="74" View_ID="1000"/>
      </Related_Weaknesses>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>
"""

XXE_PAYLOAD_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7">
  <Weaknesses>
    <Weakness ID="1" Name="&xxe;" Abstraction="Class" Status="Draft">
      <Description>XXE test</Description>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>
"""


def _write_temp_xml(content: str, suffix: str = ".xml") -> Path:
    """Write XML content to a temp file in the data directory and return path."""
    data_dir = Path(__file__).parent.parent / "data"
    data_dir.mkdir(exist_ok=True)
    fd, path = tempfile.mkstemp(suffix=suffix, dir=data_dir)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return Path(path)


# ── Functional Tests ──────────────────────────────────────────────────────────

class TestCWEParserFunctionality:

    def test_parses_valid_xml(self):
        path = _write_temp_xml(MINIMAL_CWE_XML)
        try:
            result = CWEParser(path).parse()
            assert isinstance(result, ParseResult)
            assert result.total_count == 1
            assert result.entries[0].cwe_id == "79"
            assert result.entries[0].name == "Cross-site Scripting"
        finally:
            path.unlink(missing_ok=True)

    def test_extracts_abstraction(self):
        path = _write_temp_xml(MINIMAL_CWE_XML)
        try:
            result = CWEParser(path).parse()
            assert result.entries[0].abstraction == "Base"
        finally:
            path.unlink(missing_ok=True)

    def test_extracts_related_weaknesses(self):
        path = _write_temp_xml(MINIMAL_CWE_XML)
        try:
            result = CWEParser(path).parse()
            rw = result.entries[0].related_weaknesses
            assert len(rw) == 1
            assert rw[0]["nature"] == "ChildOf"
            assert rw[0]["cwe_id"] == "74"
        finally:
            path.unlink(missing_ok=True)

    def test_extracts_platforms(self):
        path = _write_temp_xml(MINIMAL_CWE_XML)
        try:
            result = CWEParser(path).parse()
            platforms = result.entries[0].applicable_platforms
            assert any(p["name"] == "JavaScript" for p in platforms)
        finally:
            path.unlink(missing_ok=True)

    def test_checksum_in_result(self):
        path = _write_temp_xml(MINIMAL_CWE_XML)
        try:
            result = CWEParser(path).parse()
            assert len(result.checksum_sha256) == 64   # SHA-256 hex = 64 chars
        finally:
            path.unlink(missing_ok=True)


# ── Security Tests — these are as important as functional tests ───────────────

class TestSecurityControls:

    def test_xxe_injection_blocked(self):
        """
        CWE-611: XXE payload must NOT resolve to file contents.
        If the parser is misconfigured, &xxe; would expand to /etc/passwd contents.
        A safe parser raises ParseError or returns the literal string.
        """
        path = _write_temp_xml(XXE_PAYLOAD_XML)
        try:
            # Either raises ParseError (safe) or parses without resolving entity (safe)
            # It must NOT return /etc/passwd contents in any field
            try:
                result = CWEParser(path).parse()
                for entry in result.entries:
                    assert "root:" not in entry.name, "XXE resolved — CRITICAL VULNERABILITY"
                    assert "root:" not in entry.description, "XXE resolved — CRITICAL VULNERABILITY"
            except ParseError:
                pass   # ParseError is the safest outcome — entity rejected entirely
        finally:
            path.unlink(missing_ok=True)

    def test_path_traversal_rejected(self):
        """CWE-22: Paths outside the data directory must be rejected."""
        with pytest.raises(SecurityError, match="Path traversal"):
            _validate_file(Path("/etc/passwd"))

    def test_oversized_file_rejected(self):
        """CWE-400: Files over the size cap must be rejected before parsing."""
        data_dir = Path(__file__).parent.parent / "data"
        data_dir.mkdir(exist_ok=True)
        path = data_dir / "oversized_test.xml"
        try:
            # Write a file larger than MAX_FILE_SIZE_BYTES
            with open(path, "wb") as f:
                f.write(b"X" * (51 * 1024 * 1024))   # 51 MB
            with pytest.raises(SecurityError, match="max allowed size"):
                _validate_file(path)
        finally:
            path.unlink(missing_ok=True)

    def test_non_xml_extension_rejected(self):
        """Only .xml files should be accepted."""
        data_dir = Path(__file__).parent.parent / "data"
        data_dir.mkdir(exist_ok=True)
        path = data_dir / "test.json"
        path.write_text("{}")
        try:
            with pytest.raises(ValueError, match="Expected .xml"):
                _validate_file(path)
        finally:
            path.unlink(missing_ok=True)

    def test_malformed_xml_raises_safe_error(self):
        """CWE-703: Malformed XML must raise ParseError, not leak internal details."""
        path = _write_temp_xml("<broken xml >>>")
        try:
            with pytest.raises(ParseError):
                CWEParser(path).parse()
        finally:
            path.unlink(missing_ok=True)

    def test_checksum_computed_consistently(self):
        """SHA-256 of same content must always be identical."""
        path = _write_temp_xml(MINIMAL_CWE_XML)
        try:
            h1 = _compute_sha256(path)
            h2 = _compute_sha256(path)
            assert h1 == h2
            assert len(h1) == 64
        finally:
            path.unlink(missing_ok=True)

    def test_checksum_detects_tampering(self):
        """A modified file must produce a different checksum."""
        path = _write_temp_xml(MINIMAL_CWE_XML)
        try:
            original_hash = _compute_sha256(path)
            # Tamper with the file
            with open(path, "a") as f:
                f.write("<!-- tampered -->")
            tampered_hash = _compute_sha256(path)
            assert original_hash != tampered_hash
        finally:
            path.unlink(missing_ok=True)
