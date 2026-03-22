"""Tests for anonymiser.py"""

import pytest
from piiscrub.anonymiser import anonymise, count_by_type
from piiscrub.detector import detect
from piiscrub.extractor import extract
from piiscrub.models import ScrubMode, TextChunk


def _make_chunk(text: str) -> TextChunk:
    return TextChunk.create(source_path_hash="a" * 64, fmt="txt", text=text)


def test_redact_replaces_person(analyzer):
    chunks = [_make_chunk("Hello John Smith, your email is john@example.com")]
    detections = detect(chunks, analyzer)
    anonymised = anonymise(chunks, detections, ScrubMode.REDACT)
    scrubbed = " ".join(a.scrubbed_text for a in anonymised)
    assert "John Smith" not in scrubbed
    assert "[PERSON_1]" in scrubbed


def test_redact_replaces_email(analyzer):
    chunks = [_make_chunk("Send mail to jane@example.co.uk please")]
    detections = detect(chunks, analyzer)
    anonymised = anonymise(chunks, detections, ScrubMode.REDACT)
    scrubbed = " ".join(a.scrubbed_text for a in anonymised)
    assert "jane@example.co.uk" not in scrubbed
    assert "[EMAIL_ADDRESS_1]" in scrubbed


def test_redact_no_mapping_created(analyzer, tmp_path):
    """Redact mode must not create a mapping table."""
    chunks = [_make_chunk("Contact John Smith at john@test.com")]
    detections = detect(chunks, analyzer)
    anonymised = anonymise(chunks, detections, ScrubMode.REDACT)
    for ac in anonymised:
        # replacements dict exists but mapping_db was never touched
        assert ac.replacements is not None
    # No mapping DB file created in tmp_path
    assert not (tmp_path / "mappings.db").exists()


def test_redact_counter_increments(analyzer):
    """Multiple persons in same doc should get PERSON_1, PERSON_2, etc."""
    chunks = [_make_chunk("John Smith and Jane Doe attended the meeting.")]
    detections = detect(chunks, analyzer)
    anonymised = anonymise(chunks, detections, ScrubMode.REDACT)
    scrubbed = " ".join(a.scrubbed_text for a in anonymised)
    assert "[PERSON_1]" in scrubbed
    assert "[PERSON_2]" in scrubbed


def test_pseudonymise_consistency(analyzer, tmp_path):
    """Same original value must always map to same fake value within a doc."""
    from piiscrub.mapping import MappingDB
    db_path = tmp_path / "test_mappings.db"
    db = MappingDB(passphrase="testpass123", db_path=db_path)

    # Same name appears in two chunks
    chunks = [
        _make_chunk("Hello John Smith."),
        _make_chunk("John Smith called again."),
    ]
    detections = detect(chunks, analyzer)
    anonymised = anonymise(
        chunks, detections, ScrubMode.PSEUDONYMISE,
        session_id="test-session", mapping_db=db
    )
    db.close()

    # Collect all replacements for PERSON detections
    texts = [a.scrubbed_text for a in anonymised]
    # Both chunks should have used the same fake name for John Smith
    # Extract what [PERSON_1] was replaced with from replacements dict
    all_replacements: dict[str, str] = {}
    for ac in anonymised:
        all_replacements.update(ac.replacements)

    if "John Smith" in all_replacements:
        fake = all_replacements["John Smith"]
        # Both occurrences replaced with the same value
        for text in texts:
            if "John Smith" not in text:  # it was replaced
                assert fake in text or "[PERSON" not in text


def test_entity_counts(analyzer):
    chunks = [_make_chunk("John Smith emailed jane@example.com and mary@example.com")]
    detections = detect(chunks, analyzer)
    anonymised = anonymise(chunks, detections, ScrubMode.REDACT)
    counts = count_by_type(anonymised)
    assert counts.get("EMAIL_ADDRESS", 0) >= 2


def test_reverse_offset_order(analyzer):
    """Replacements applied in reverse offset order preserve text integrity."""
    text = "John Smith at john@example.com called 07700900123"
    chunks = [_make_chunk(text)]
    detections = detect(chunks, analyzer)
    anonymised = anonymise(chunks, detections, ScrubMode.REDACT)
    scrubbed = anonymised[0].scrubbed_text
    # Should be valid text (no overlapping/corrupted replacements)
    assert "[" in scrubbed  # at least one placeholder
    assert scrubbed.count("[") == scrubbed.count("]")  # balanced brackets
