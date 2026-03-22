"""Tests for detector.py"""

import pytest
import structlog
from piiscrub.detector import (
    UKIBANRecognizer,
    UKNHSRecognizer,
    UKNIRecognizer,
    UKPostcodeRecognizer,
    detect,
)
from piiscrub.extractor import extract
from piiscrub.models import TextChunk


def _make_chunk(text: str) -> TextChunk:
    return TextChunk.create(
        source_path_hash="a" * 64,
        fmt="txt",
        text=text,
    )


def test_detect_person(analyzer):
    chunks = [_make_chunk("Dear John Smith, please find attached the report.")]
    results = detect(chunks, analyzer)
    types = [r.entity_type for r in results]
    assert "PERSON" in types


def test_detect_email(analyzer):
    chunks = [_make_chunk("Contact me at jane@example.com for details.")]
    results = detect(chunks, analyzer)
    types = [r.entity_type for r in results]
    assert "EMAIL_ADDRESS" in types


def test_detect_uk_ni(analyzer):
    chunks = [_make_chunk("NI number: AB123456C")]
    results = detect(chunks, analyzer)
    types = [r.entity_type for r in results]
    assert "UK_NI" in types


def test_detect_uk_nhs(analyzer):
    # 943 476 5919 is a Modulus-11-valid NHS number
    chunks = [_make_chunk("NHS number: 943 476 5919")]
    results = detect(chunks, analyzer, score_threshold=0.3)
    types = [r.entity_type for r in results]
    assert "UK_NHS" in types


def test_detect_uk_postcode(analyzer):
    chunks = [_make_chunk("Our office is at postcode SW1A 2AA.")]
    results = detect(chunks, analyzer, score_threshold=0.5)
    types = [r.entity_type for r in results]
    assert "UK_POSTCODE" in types


def test_score_threshold_filters(analyzer):
    chunks = [_make_chunk("Dear John Smith, contact jane@example.com.")]
    high = detect(chunks, analyzer, score_threshold=0.9)
    low = detect(chunks, analyzer, score_threshold=0.1)
    # Higher threshold should return fewer or equal results
    assert len(high) <= len(low)


def test_no_pii_in_logs(analyzer, capfd):
    """Confirm PII values do not appear in log output."""
    import io
    import structlog

    log_output = io.StringIO()

    chunks = [_make_chunk("Contact jane.doe@secret.com — NI: AB123456C")]
    detect(chunks, analyzer)

    # Check stderr (structlog output)
    captured = capfd.readouterr()
    stderr = captured.err
    assert "jane.doe@secret.com" not in stderr
    assert "AB123456C" not in stderr


def test_nhs_checksum_validator():
    recogniser = UKNHSRecognizer()
    assert recogniser._nhs_checksum_valid("9434765919")   # valid
    assert not recogniser._nhs_checksum_valid("1234567890")  # invalid checksum


def test_iban_checksum_validator():
    recogniser = UKIBANRecognizer()
    assert recogniser._iban_checksum_valid("GB29NWBK60161331926819")  # valid
    assert not recogniser._iban_checksum_valid("GB00NWBK60161331926819")  # invalid


def test_detection_results_have_original_text(analyzer):
    text = "Email us at hello@test.com"
    chunks = [_make_chunk(text)]
    results = detect(chunks, analyzer)
    email_results = [r for r in results if r.entity_type == "EMAIL_ADDRESS"]
    assert len(email_results) > 0
    assert email_results[0].original_text == "hello@test.com"
