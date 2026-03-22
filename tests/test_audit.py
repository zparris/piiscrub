"""Tests for audit.py — GDPR accountability log."""

import os
import stat
import pytest
from pathlib import Path

from piiscrub.audit import AuditLog, make_audit_entry


@pytest.fixture
def audit(tmp_path) -> AuditLog:
    log = AuditLog(db_path=tmp_path / "test_audit.db")
    yield log
    log.close()


def _make_entry(**kwargs):
    defaults = dict(
        source_hash="a" * 64,
        output_hash="b" * 64,
        operator_hash="c" * 64,
        mode="redact",
        entity_type_counts={"PERSON": 2, "EMAIL_ADDRESS": 1},
        processing_duration_ms=450,
        spacy_model="en_core_web_lg",
        threshold=0.6,
    )
    defaults.update(kwargs)
    return make_audit_entry(**defaults)


def test_record_creates_entry(audit):
    entry = _make_entry()
    audit.record(entry)
    results = audit.query()
    assert len(results) == 1
    assert results[0].mode == "redact"
    assert results[0].entity_type_counts == {"PERSON": 2, "EMAIL_ADDRESS": 1}


def test_no_pii_in_log_entry(audit):
    """Confirm no PII values appear in log entries."""
    entry = _make_entry(entity_type_counts={"PERSON": 3})
    audit.record(entry)
    results = audit.query()
    entry = results[0]
    # Spot check: no raw PII anywhere in the entry fields
    assert "John" not in str(entry.source_hash)
    assert "smith@" not in str(entry.operator_hash)
    # entity_type_counts keys must be entity type names (uppercase with underscores)
    for key in entry.entity_type_counts:
        assert key.isupper()


def test_source_hash_must_be_64_hex(audit):
    """Passing a filename directly (not a hash) must raise ValueError."""
    import pytest
    entry = _make_entry(source_hash="myfile.docx")  # not a hash
    with pytest.raises(ValueError, match="source_hash"):
        audit.record(entry)


def test_export_csv(audit, tmp_path):
    audit.record(_make_entry())
    audit.record(_make_entry(mode="pseudonymise", entity_type_counts={"PERSON": 1}))
    out = tmp_path / "export.csv"
    count = audit.export_csv(out)
    assert count == 2
    assert out.exists()
    content = out.read_text()
    assert "event_id" in content
    assert "redact" in content
    assert "pseudonymise" in content
    # No PII should appear in export
    assert "John" not in content
    assert "smith@" not in content


def test_audit_db_permissions(tmp_path):
    db_path = tmp_path / "audit_perms.db"
    log = AuditLog(db_path=db_path)
    log.close()
    mode = oct(stat.S_IMODE(os.stat(db_path).st_mode))
    assert mode == "0o600", f"Expected 600, got {mode}"


def test_query_empty_returns_empty_list(audit):
    results = audit.query()
    assert results == []
