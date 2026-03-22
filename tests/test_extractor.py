"""Tests for extractor.py"""

import pytest
from pathlib import Path

from piiscrub.extractor import UnsupportedFormatError, extract
from piiscrub.models import TextChunk


def test_extract_txt(sample_txt):
    chunks = extract(sample_txt)
    assert len(chunks) > 0
    assert all(isinstance(c, TextChunk) for c in chunks)
    full_text = " ".join(c.text for c in chunks)
    assert "John Smith" in full_text
    assert "AB123456C" in full_text


def test_extract_txt_source_hash_not_filename(sample_txt):
    """source_path_hash must be sha256 of path — never the literal filename."""
    chunks = extract(sample_txt)
    for chunk in chunks:
        assert len(chunk.source_path_hash) == 64
        assert chunk.source_path_hash.lower() == chunk.source_path_hash
        # Must NOT contain the actual filename
        assert sample_txt.name not in chunk.source_path_hash


def test_extract_csv(sample_csv):
    chunks = extract(sample_csv)
    texts = [c.text for c in chunks]
    assert any("John Smith" in t for t in texts)
    assert any("AB123456C" in t for t in texts)


def test_extract_eml(sample_eml):
    chunks = extract(sample_eml)
    parts = {c.metadata.get("part") for c in chunks}
    assert "from" in parts
    assert "body" in parts
    texts = " ".join(c.text for c in chunks)
    assert "john.smith@example.co.uk" in texts


def test_extract_xlsx(sample_xlsx):
    chunks = extract(sample_xlsx)
    texts = [c.text for c in chunks]
    assert any("John Smith" in t for t in texts)
    assert any("AB123456C" in t for t in texts)
    # Check sheet/row/col metadata present
    for chunk in chunks:
        assert "sheet" in chunk.metadata
        assert "row" in chunk.metadata


def test_extract_docx(sample_docx):
    chunks = extract(sample_docx)
    assert len(chunks) > 0
    texts = " ".join(c.text for c in chunks)
    assert "John Smith" in texts


def test_unsupported_format(tmp_path):
    f = tmp_path / "test.xyz"
    f.write_text("hello")
    with pytest.raises(UnsupportedFormatError):
        extract(f)


def test_chunk_offsets_are_valid(sample_txt):
    chunks = extract(sample_txt)
    for chunk in chunks:
        assert chunk.char_offset_start >= 0
        assert chunk.char_offset_end >= chunk.char_offset_start
        assert len(chunk.text) == chunk.char_offset_end - chunk.char_offset_start


def test_pdf_extraction(sample_pdf):
    chunks = extract(sample_pdf)
    assert len(chunks) > 0
    texts = " ".join(c.text for c in chunks)
    assert "John Smith" in texts
    # PDF chunks must have page + bbox metadata
    for chunk in chunks:
        assert "page" in chunk.metadata
        assert "bbox" in chunk.metadata
