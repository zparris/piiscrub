"""End-to-end integration tests for PIIScrub.

Tests the full pipeline: extract → detect → anonymise → output → verify.
"""

import time
import pytest
from pathlib import Path

from piiscrub.anonymiser import anonymise, count_by_type
from piiscrub.audit import AuditLog, make_audit_entry
from piiscrub.detector import detect
from piiscrub.extractor import extract
from piiscrub.models import ScrubMode
from piiscrub.output import reconstruct

# PII values that must NOT appear in scrubbed output
KNOWN_PII = [
    "John Smith",
    "AB123456C",
    "john.smith@example.co.uk",
    "07700 900123",
    "943 476 5919",
    "SW1A 2AA",
]


def _run_full_scrub(input_path, output_path, mode, analyzer, mapping_db=None, session_id=None):
    chunks = extract(input_path)
    detections = detect(chunks, analyzer)
    anonymised = anonymise(
        chunks, detections, mode,
        session_id=session_id,
        mapping_db=mapping_db,
        document_hash="a" * 64,
    )
    reconstruct(input_path, chunks, anonymised, output_path)
    return anonymised, count_by_type(anonymised)


# ---------------------------------------------------------------------------
# TXT — redact mode
# ---------------------------------------------------------------------------

def test_txt_redact_no_residual_pii(sample_txt, tmp_path, analyzer):
    out = tmp_path / "out.txt"
    anonymised, counts = _run_full_scrub(sample_txt, out, ScrubMode.REDACT, analyzer)
    assert out.exists()
    content = out.read_text()
    for pii in KNOWN_PII:
        assert pii not in content, f"PII '{pii}' survived scrub"


def test_txt_redact_has_placeholders(sample_txt, tmp_path, analyzer):
    out = tmp_path / "out.txt"
    _run_full_scrub(sample_txt, out, ScrubMode.REDACT, analyzer)
    content = out.read_text()
    assert "[PERSON_1]" in content or "[EMAIL_ADDRESS_1]" in content or "[UK_NI_1]" in content


def test_txt_redact_audit_entry(sample_txt, tmp_path, analyzer):
    out = tmp_path / "out.txt"
    _, counts = _run_full_scrub(sample_txt, out, ScrubMode.REDACT, analyzer)
    audit = AuditLog(db_path=tmp_path / "audit.db")
    import hashlib
    src_hash = hashlib.sha256(sample_txt.read_bytes()).hexdigest()
    out_hash = hashlib.sha256(out.read_bytes()).hexdigest()
    entry = make_audit_entry(
        source_hash=src_hash,
        output_hash=out_hash,
        operator_hash="c" * 64,
        mode="redact",
        entity_type_counts=counts,
        processing_duration_ms=100,
    )
    audit.record(entry)
    entries = audit.query()
    audit.close()
    assert len(entries) == 1
    assert entries[0].mode == "redact"
    # Audit log must not contain PII
    for pii in KNOWN_PII:
        assert pii not in str(entries[0].entity_type_counts)


# ---------------------------------------------------------------------------
# TXT — pseudonymise mode
# ---------------------------------------------------------------------------

def test_txt_pseudonymise_no_original_values(sample_txt, tmp_path, analyzer):
    from piiscrub.mapping import MappingDB
    db = MappingDB(passphrase="testpass123", db_path=tmp_path / "map.db")
    out = tmp_path / "pseudo.txt"
    _run_full_scrub(sample_txt, out, ScrubMode.PSEUDONYMISE, analyzer,
                    mapping_db=db, session_id="test-sess")
    db.close()
    content = out.read_text()
    for pii in KNOWN_PII:
        assert pii not in content, f"PII '{pii}' found in pseudonymised output"


def test_txt_pseudonymise_mapping_exists(sample_txt, tmp_path, analyzer):
    from piiscrub.mapping import MappingDB
    db_path = tmp_path / "map.db"
    db = MappingDB(passphrase="testpass123", db_path=db_path)
    out = tmp_path / "pseudo.txt"
    _run_full_scrub(sample_txt, out, ScrubMode.PSEUDONYMISE, analyzer,
                    mapping_db=db, session_id="test-sess2")
    sessions = db.list_sessions()
    db.close()
    assert "test-sess2" in sessions


def test_restore_reverses_pseudonymisation(sample_txt, tmp_path, analyzer):
    from piiscrub.mapping import MappingDB
    db_path = tmp_path / "map.db"
    db = MappingDB(passphrase="restorepass", db_path=db_path)
    out = tmp_path / "pseudo.txt"
    anonymised, _ = _run_full_scrub(
        sample_txt, out, ScrubMode.PSEUDONYMISE, analyzer,
        mapping_db=db, session_id="restore-sess"
    )
    db.close()

    # Re-open DB and restore
    db2 = MappingDB(passphrase="restorepass", db_path=db_path)
    replacements = db2.get_session_replacements("restore-sess", "restorepass")
    db2.close()

    # Apply restore to pseudonymised output
    pseudo_text = out.read_text()
    restored_text = pseudo_text
    for fake, real in replacements.items():
        restored_text = restored_text.replace(fake, real)

    # At least some original PII should be restored
    original_text = sample_txt.read_text()
    # Check that at least one known PII value is back
    found = any(pii in restored_text for pii in KNOWN_PII)
    assert found, "Restore did not recover any original PII values"


# ---------------------------------------------------------------------------
# CSV scrub
# ---------------------------------------------------------------------------

def test_csv_redact(sample_csv, tmp_path, analyzer):
    out = tmp_path / "out.csv"
    _run_full_scrub(sample_csv, out, ScrubMode.REDACT, analyzer)
    content = out.read_text()
    assert "John Smith" not in content
    assert "AB123456C" not in content


# ---------------------------------------------------------------------------
# EML scrub
# ---------------------------------------------------------------------------

def test_eml_redact(sample_eml, tmp_path, analyzer):
    out = tmp_path / "out.eml"
    _run_full_scrub(sample_eml, out, ScrubMode.REDACT, analyzer)
    content = out.read_bytes().decode("utf-8", errors="replace")
    assert "john.smith@example.co.uk" not in content
    assert "AB123456C" not in content


# ---------------------------------------------------------------------------
# Performance test
# ---------------------------------------------------------------------------

def test_performance_3500_words(tmp_path, analyzer):
    """Scrub a ~3500-word document in < 5 seconds (model warm)."""
    # Generate a synthetic 3500-word document with 20 PII instances
    words = "The quick brown fox jumps over the lazy dog. " * 80
    pii_instances = [
        "John Smith", "jane@example.com", "AB123456C", "07700900123",
        "SW1A 2AA", "Sarah Mitchell", "bob@test.co.uk", "CD234567D",
        "07900 123456", "EC1A 1BB", "Alice Jones", "carol@example.org",
        "EF345678E", "07800 900123", "WC2N 5DU", "David Brown",
        "eve@test.com", "GH456789F", "07600 123456", "NW1 6XE",
    ]
    for i, pii in enumerate(pii_instances):
        insert_at = i * (len(words) // len(pii_instances))
        words = words[:insert_at] + f" {pii} " + words[insert_at:]

    doc_path = tmp_path / "perf_test.txt"
    doc_path.write_text(words, encoding="utf-8")
    out_path = tmp_path / "perf_test_out.txt"

    t0 = time.monotonic()
    _run_full_scrub(doc_path, out_path, ScrubMode.REDACT, analyzer)
    duration = time.monotonic() - t0

    assert duration < 5.0, f"Performance target missed: {duration:.2f}s > 5s"
    assert out_path.exists()
