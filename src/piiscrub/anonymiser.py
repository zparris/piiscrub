"""Anonymisation engine.

Replaces detected PII with safe placeholders or realistic fake data.

Two modes:
  REDACT       — [PERSON_1], [EMAIL_1] etc. Per-type counter, resets per document.
                 Output is GDPR-anonymous (Recital 26). No mapping stored.
  PSEUDONYMISE — Faker en_GB realistic replacements. Consistent within a document
                 (same original → same fake). Mapping persisted to encrypted SQLite
                 via mapping.py. Output is still personal data (GDPR applies).

CRITICAL: replacements applied in REVERSE offset order to preserve span validity.
CRITICAL: original_text on DetectionResult is EPHEMERAL — never log or persist it.
"""

from __future__ import annotations

import gc
import hashlib
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Optional

from faker import Faker

from piiscrub._logging import get_logger
from piiscrub.models import AnonymisedChunk, DetectionResult, EntityType, ScrubMode, TextChunk

_log = get_logger("anonymiser")

# Faker instance — reuse across calls (instantiation is slow)
_fake = Faker("en_GB")
Faker.seed(0)  # deterministic within a process; randomised per-run via session_seed


def _gen_fake_value(entity_type: str, seed: int | None = None) -> str:
    """Generate a realistic fake value for the given entity type (en_GB locale)."""
    if seed is not None:
        Faker.seed(seed)

    mapping: dict[str, str] = {
        EntityType.PERSON: _fake.name(),
        EntityType.EMAIL_ADDRESS: _fake.email(),
        EntityType.PHONE_NUMBER: _fake.phone_number(),
        EntityType.UK_PHONE: _fake.phone_number(),
        EntityType.UK_POSTCODE: _fake.postcode(),
        EntityType.LOCATION: _fake.city(),
        EntityType.DATE_TIME: _fake.date_of_birth().isoformat(),
        EntityType.IBAN_CODE: _fake.iban(),
        EntityType.UK_IBAN: _fake.iban(),
        EntityType.ORGANIZATION: _fake.company(),
        EntityType.CREDIT_CARD: _fake.credit_card_number(),
        EntityType.IP_ADDRESS: _fake.ipv4(),
        EntityType.NRP: _fake.bothify("???-####"),
        # UK-specific with custom generation
        EntityType.UK_NI: _gen_uk_ni(),
        EntityType.UK_NHS: _gen_uk_nhs(),
        EntityType.UK_DRIVING_LICENCE: _gen_uk_driving_licence(),
    }
    return mapping.get(entity_type, f"[{entity_type}_FAKE]")


def _gen_uk_ni() -> str:
    """Generate a structurally valid UK NI number (not a real one)."""
    # Valid prefix letters: A-Z excluding D, F, I, Q, U, V
    valid = "ABCEGHJKLMNOPRSTW"
    prefix = _fake.random_element(valid) + _fake.random_element(valid)
    digits = _fake.numerify("######")
    suffix = _fake.random_element("ABCD")
    return f"{prefix}{digits}{suffix}"


def _gen_uk_nhs() -> str:
    """Generate a Modulus-11-valid NHS number."""
    while True:
        digits = [int(_fake.numerify("#")) for _ in range(9)]
        weights = list(range(10, 1, -1))
        total = sum(d * w for d, w in zip(digits, weights))
        remainder = total % 11
        check = 11 - remainder
        if check == 10:
            continue  # invalid — retry
        if check == 11:
            check = 0
        all_digits = digits + [check]
        return f"{all_digits[0]}{all_digits[1]}{all_digits[2]} {all_digits[3]}{all_digits[4]}{all_digits[5]} {all_digits[6]}{all_digits[7]}{all_digits[8]}{all_digits[9]}"


def _gen_uk_driving_licence() -> str:
    """Generate a DVLA-format driving licence number (structurally valid, not real)."""
    surname = _fake.last_name()[:5].upper().ljust(5, "X")
    dob = _fake.date_of_birth(minimum_age=18, maximum_age=80)
    decade = str(dob.year)[2]
    year = str(dob.year)[3]
    month = f"{dob.month:02d}"
    day = f"{dob.day:02d}"
    initials = _fake.bothify("??").upper()
    suffix = _fake.bothify("??").upper()
    return f"{surname}{decade}{month[0]}{year}{month[1]}{day}{initials}9{suffix}"


def _hash_original(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def anonymise(
    chunks: list[TextChunk],
    detections: list[DetectionResult],
    mode: ScrubMode,
    session_id: Optional[str] = None,
    mapping_db=None,  # piiscrub.mapping.MappingDB | None
    document_hash: str = "",
) -> list[AnonymisedChunk]:
    """Apply PII replacements to each chunk.

    Args:
        chunks: TextChunk list from extractor.py
        detections: DetectionResult list from detector.py
        mode: ScrubMode.REDACT or ScrubMode.PSEUDONYMISE
        session_id: UUID for this scrub session (required for pseudonymise)
        mapping_db: MappingDB instance (required for pseudonymise)
        document_hash: sha256 of source file (for mapping records)

    Returns:
        list[AnonymisedChunk] — one per chunk, with scrubbed_text populated.
        Call gc.collect() after output.py finishes with these.

    CRITICAL: Replacements are applied in REVERSE offset order within each chunk.
    """
    if mode == ScrubMode.PSEUDONYMISE and mapping_db is None:
        raise ValueError("mapping_db is required for pseudonymise mode")
    if mode == ScrubMode.PSEUDONYMISE and session_id is None:
        session_id = str(uuid.uuid4())

    # Build lookup: chunk_id → sorted detections (we'll reverse later)
    detections_by_chunk: dict[str, list[DetectionResult]] = defaultdict(list)
    for det in detections:
        detections_by_chunk[det.chunk_id].append(det)

    # Per-type counters (reset per document, shared across all chunks)
    type_counters: dict[str, int] = defaultdict(int)

    # In-memory consistency map for pseudonymise: sha256(original) → fake
    in_memory_map: dict[str, str] = {}

    result: list[AnonymisedChunk] = []

    for chunk in chunks:
        chunk_dets = detections_by_chunk.get(chunk.chunk_id, [])

        if not chunk_dets:
            result.append(AnonymisedChunk(
                chunk_id=chunk.chunk_id,
                original_text=chunk.text,
                scrubbed_text=chunk.text,
                detections=[],
                replacements={},
            ))
            continue

        # Sort by start offset DESCENDING — apply from end of string backwards
        # so earlier offsets remain valid after each substitution
        sorted_dets = sorted(chunk_dets, key=lambda d: d.start, reverse=True)

        text = chunk.text
        replacements: dict[str, str] = {}

        for det in sorted_dets:
            original = det.original_text  # EPHEMERAL

            if mode == ScrubMode.REDACT:
                replacement = _make_redact_label(det.entity_type, type_counters)

            else:  # PSEUDONYMISE
                original_hash = _hash_original(original)

                # 1. Check in-memory map (within-document consistency)
                if original_hash in in_memory_map:
                    replacement = in_memory_map[original_hash]
                # 2. Check encrypted DB (cross-document consistency)
                elif mapping_db is not None:
                    existing = mapping_db.lookup(original_hash, session_id)
                    if existing is not None:
                        replacement = existing
                        in_memory_map[original_hash] = replacement
                    else:
                        replacement = _gen_fake_value(det.entity_type)
                        in_memory_map[original_hash] = replacement
                        mapping_db.store_raw(
                            session_id=session_id,
                            entity_type=det.entity_type,
                            original_value=original,
                            fake_value=replacement,
                            document_hash=document_hash,
                        )
                else:
                    replacement = _gen_fake_value(det.entity_type)
                    in_memory_map[original_hash] = replacement

            # Apply replacement at correct position
            text = text[: det.start] + replacement + text[det.end :]
            replacements[original] = replacement  # original key is ephemeral PII

        result.append(AnonymisedChunk(
            chunk_id=chunk.chunk_id,
            original_text=chunk.text,  # EPHEMERAL
            scrubbed_text=text,
            detections=chunk_dets,
            replacements=replacements,
        ))

    # Log counts only — never log values
    total_counts = Counter(d.entity_type for d in detections)
    _log.info(
        "anonymisation_complete",
        mode=mode.value,
        chunk_count=len(chunks),
        entity_counts=dict(total_counts),
        session_id=session_id,
    )

    gc.collect()
    return result


def _make_redact_label(entity_type: str, counters: dict[str, int]) -> str:
    """Return [ENTITY_TYPE_N] label and increment the per-type counter."""
    counters[entity_type] += 1
    return f"[{entity_type}_{counters[entity_type]}]"


def count_by_type(anonymised: list[AnonymisedChunk]) -> dict[str, int]:
    """Aggregate entity type counts across all anonymised chunks."""
    counts: dict[str, int] = defaultdict(int)
    for chunk in anonymised:
        for det in chunk.detections:
            counts[det.entity_type] += 1
    return dict(counts)
