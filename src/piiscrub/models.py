"""Shared data models for PIIScrub.

All coordinate systems:
- PDF:  TextChunk.metadata contains {"page": int, "bbox": (x0, y0, x1, y1)}
        DetectionResult start/end are offsets within TextChunk.text.
        output.py uses bbox to place redaction annotations, NOT char offsets.
- DOCX: metadata contains {"para_index": int, "run_index": int}
- XLSX: metadata contains {"sheet": str, "row": int, "col": int}
- EML:  metadata contains {"part": "subject"|"from"|"to"|"cc"|"body"}
- TXT:  metadata contains {"line_start": int}

IMPORTANT: DetectionResult.original_text is EPHEMERAL.
It must never be passed to audit.py, structlog, or any persistent store.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ScrubMode(str, Enum):
    REDACT = "redact"
    PSEUDONYMISE = "pseudonymise"


class EntityType(str, Enum):
    PERSON = "PERSON"
    EMAIL_ADDRESS = "EMAIL_ADDRESS"
    PHONE_NUMBER = "PHONE_NUMBER"
    CREDIT_CARD = "CREDIT_CARD"
    IBAN_CODE = "IBAN_CODE"
    IP_ADDRESS = "IP_ADDRESS"
    LOCATION = "LOCATION"
    DATE_TIME = "DATE_TIME"
    NRP = "NRP"
    ORGANIZATION = "ORGANIZATION"
    UK_NI = "UK_NI"
    UK_NHS = "UK_NHS"
    UK_POSTCODE = "UK_POSTCODE"
    UK_PHONE = "UK_PHONE"
    UK_DRIVING_LICENCE = "UK_DRIVING_LICENCE"
    UK_IBAN = "UK_IBAN"


# All entity types to detect by default
DEFAULT_ENTITIES = [e.value for e in EntityType]


@dataclass
class TextChunk:
    """A unit of text extracted from a document, with position metadata."""
    chunk_id: str
    source_path_hash: str  # sha256(str(absolute_path)) — 64 hex chars
    format: str            # "pdf" | "docx" | "xlsx" | "csv" | "eml" | "txt"
    page_or_sheet: int | None
    char_offset_start: int
    char_offset_end: int
    text: str              # raw text — NEVER logged
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        source_path_hash: str,
        fmt: str,
        text: str,
        page_or_sheet: int | None = None,
        char_offset_start: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> "TextChunk":
        return cls(
            chunk_id=str(uuid.uuid4()),
            source_path_hash=source_path_hash,
            format=fmt,
            page_or_sheet=page_or_sheet,
            char_offset_start=char_offset_start,
            char_offset_end=char_offset_start + len(text),
            text=text,
            metadata=metadata or {},
        )


@dataclass
class DetectionResult:
    """A single PII entity detected within a TextChunk.

    WARNING: original_text is EPHEMERAL personal data.
    Never log it, persist it, or pass it to audit.py.
    """
    chunk_id: str
    entity_type: str   # EntityType value
    start: int         # offset within TextChunk.text
    end: int
    score: float
    recogniser_name: str
    original_text: str  # EPHEMERAL — used only by anonymiser.py


@dataclass
class AnonymisedChunk:
    """A TextChunk after PII replacement.

    WARNING: original_text is EPHEMERAL.
    Call del on this object and gc.collect() after output.py finishes.
    """
    chunk_id: str
    original_text: str      # EPHEMERAL
    scrubbed_text: str
    detections: list[DetectionResult]
    replacements: dict[str, str]  # original → replacement (in-memory only)


@dataclass
class AuditEntry:
    """A single GDPR accountability record.

    MUST NOT contain: PII values, original filenames, mapping contents.
    source_hash must be sha256(filename) — exactly 64 hex characters.
    """
    event_id: str
    timestamp_utc: str          # ISO 8601
    source_hash: str            # sha256(filename) — 64 hex chars
    output_hash: str            # sha256(output file) — 64 hex chars
    operator_hash: str          # sha256(hostname)
    piiscrub_version: str
    spacy_model: str
    threshold: float
    mode: str                   # "redact" | "pseudonymise"
    entity_type_counts: dict[str, int]  # {"PERSON": 3, "EMAIL_ADDRESS": 2}
    processing_duration_ms: int
    error_flag: bool
    error_message: str
    session_id: str | None = None


@dataclass
class MappingRecord:
    """A single pseudonymisation mapping entry.

    real_value_encrypted stores AES-256-GCM(nonce || ciphertext).
    The plaintext real value must never appear anywhere except
    transiently in memory during encrypt/decrypt operations.
    """
    record_id: str
    session_id: str
    entity_type: str
    original_hash: str          # sha256(original_value) — NOT the plaintext
    real_value_encrypted: bytes  # nonce(12) || ciphertext || tag(16)
    fake_value: str
    created_utc: str
    document_hash: str          # sha256(filename)
