"""PII detection engine.

Uses Microsoft Presidio with spaCy en_core_web_lg as the NLP backend,
supplemented by custom UK-specific regex recognisers.

IMPORTANT: This module MUST NOT log any PII values.
Log only entity_type names and detection counts.

Custom UK recognisers:
  - UKNIRecognizer: National Insurance numbers
  - UKNHSRecognizer: NHS numbers (Modulus 11 checksum)
  - UKPostcodeRecognizer: Royal Mail postcodes
  - UKPhoneRecognizer: UK mobile and landline numbers
  - UKDrivingLicenceRecognizer: DVLA driving licence format
  - UKIBANRecognizer: GB-prefix IBAN with checksum validation
"""

from __future__ import annotations

import re
from typing import Optional

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider

from piiscrub._logging import get_logger
from piiscrub.models import DEFAULT_ENTITIES, DetectionResult, TextChunk

_log = get_logger("detector")


# ---------------------------------------------------------------------------
# Custom UK recognisers
# ---------------------------------------------------------------------------

class UKNIRecognizer(PatternRecognizer):
    """UK National Insurance number recogniser.

    Format: two prefix letters, six digits, one suffix letter.
    Certain letter combinations are invalid as prefixes.
    """
    PATTERNS = [
        Pattern(
            name="uk_ni_standard",
            regex=r"\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b",
            score=0.85,
        )
    ]
    CONTEXT = ["national insurance", "ni number", "nino", "ni:", "n.i."]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="UK_NI",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )


class UKNHSRecognizer(PatternRecognizer):
    """UK NHS number recogniser with Modulus 11 checksum validation.

    NHS numbers are 10 digits. The 10th digit is a check digit computed
    using Modulus 11. This recogniser first matches with regex, then
    validates the checksum.
    """
    PATTERNS = [
        Pattern(
            name="uk_nhs_spaced",
            regex=r"\b\d{3}\s\d{3}\s\d{4}\b",
            score=0.5,
        ),
        Pattern(
            name="uk_nhs_compact",
            regex=r"\b\d{10}\b",
            score=0.3,
        ),
    ]
    CONTEXT = ["nhs number", "nhs no", "patient number", "nhs:", "hospital number"]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="UK_NHS",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    @staticmethod
    def _nhs_checksum_valid(number_str: str) -> bool:
        digits = [int(c) for c in number_str if c.isdigit()]
        if len(digits) != 10:
            return False
        weights = list(range(10, 1, -1))
        total = sum(d * w for d, w in zip(digits[:9], weights))
        remainder = total % 11
        check = 11 - remainder
        if check == 11:
            check = 0
        return check == digits[9] and check != 10

    def analyze(self, text: str, entities: list[str], nlp_artifacts=None) -> list[RecognizerResult]:
        results = super().analyze(text, entities, nlp_artifacts)
        validated = []
        for result in results:
            matched = text[result.start:result.end]
            if self._nhs_checksum_valid(matched):
                # Boost score when checksum validates
                result.score = min(result.score + 0.45, 0.95)
                validated.append(result)
            else:
                # Keep with low score only if context word present
                if result.score >= 0.5:
                    validated.append(result)
        return validated


class UKPostcodeRecognizer(PatternRecognizer):
    """UK Royal Mail postcode recogniser."""
    PATTERNS = [
        Pattern(
            name="uk_postcode",
            regex=(
                r"\b(?:"
                r"[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-BD-HJLNP-UW-Z]{2}"  # full postcode
                r"|[A-Z]{1,2}\d[A-Z\d]?"  # outward code only
                r")\b"
            ),
            score=0.6,
        )
    ]
    CONTEXT = ["postcode", "post code", "postal code", "zip"]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="UK_POSTCODE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )


class UKPhoneRecognizer(PatternRecognizer):
    """UK phone number recogniser (mobile and landline)."""
    PATTERNS = [
        Pattern(
            name="uk_mobile",
            regex=r"\b(?:07\d{3}[\s\-]?\d{6}|07\d{9})\b",
            score=0.75,
        ),
        Pattern(
            name="uk_landline",
            regex=r"\b(?:0\d{4}[\s\-]?\d{6}|0\d{3}[\s\-]?\d{7}|0\d{9,10})\b",
            score=0.65,
        ),
        Pattern(
            name="uk_intl",
            regex=r"\b(?:\+44[\s\-]?\d{2,4}[\s\-]?\d{3,4}[\s\-]?\d{3,4})\b",
            score=0.8,
        ),
    ]
    CONTEXT = ["phone", "telephone", "tel", "mobile", "call", "contact"]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="UK_PHONE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )


class UKDrivingLicenceRecognizer(PatternRecognizer):
    """UK DVLA driving licence number recogniser.

    Format: MORGA753116SM9IJ
    Structure: 5 chars (surname) + 6 digits (DOB encoded) + 2 chars + 2 digits + 2 chars
    """
    PATTERNS = [
        Pattern(
            name="uk_driving_licence",
            regex=r"\b[A-Z]{1,5}\d{6}[A-Z]{2}\d[A-Z]{2}\b",
            score=0.7,
        )
    ]
    CONTEXT = ["driving licence", "driving license", "dvla", "licence number", "driver"]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="UK_DRIVING_LICENCE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )


class UKIBANRecognizer(PatternRecognizer):
    """UK IBAN recogniser with checksum validation.

    UK IBANs: GB + 2 check digits + 4 bank code chars + 6 sort code digits + 8 account digits
    Format: GB29NWBK60161331926819
    """
    PATTERNS = [
        Pattern(
            name="uk_iban",
            regex=r"\bGB\d{2}[A-Z]{4}\d{14}\b",
            score=0.8,
        ),
        Pattern(
            name="uk_iban_spaced",
            regex=r"\bGB\d{2}\s?[A-Z]{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b",
            score=0.8,
        ),
    ]
    CONTEXT = ["iban", "bank account", "sort code", "bacs", "international bank"]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="UK_IBAN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    @staticmethod
    def _iban_checksum_valid(iban: str) -> bool:
        iban = iban.replace(" ", "").upper()
        if len(iban) != 22:
            return False
        rearranged = iban[4:] + iban[:4]
        numeric = "".join(
            str(ord(c) - 55) if c.isalpha() else c for c in rearranged
        )
        return int(numeric) % 97 == 1

    def analyze(self, text: str, entities: list[str], nlp_artifacts=None) -> list[RecognizerResult]:
        results = super().analyze(text, entities, nlp_artifacts)
        validated = []
        for result in results:
            matched = text[result.start:result.end].replace(" ", "")
            if self._iban_checksum_valid(matched):
                validated.append(result)
        return validated


# ---------------------------------------------------------------------------
# Analyzer factory
# ---------------------------------------------------------------------------

def build_analyzer(high_accuracy: bool = False) -> AnalyzerEngine:
    """Build and return a Presidio AnalyzerEngine.

    Called ONCE per process. The returned engine should be reused across
    all documents — do not re-instantiate per file.

    Args:
        high_accuracy: If True, uses en_core_web_trf (transformer model).
                       Significantly slower. Requires the model to be installed.
    """
    model_name = "en_core_web_trf" if high_accuracy else "en_core_web_lg"

    try:
        import spacy
        if not spacy.util.is_package(model_name):
            raise ImportError(
                f"spaCy model '{model_name}' is not installed. "
                f"Run: python -m spacy download {model_name}"
            )
    except ImportError as exc:
        raise RuntimeError(str(exc)) from exc

    provider = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": model_name}],
    })
    nlp_engine = provider.create_engine()

    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])

    # Register UK-specific recognisers
    for recogniser_cls in [
        UKNIRecognizer,
        UKNHSRecognizer,
        UKPostcodeRecognizer,
        UKPhoneRecognizer,
        UKDrivingLicenceRecognizer,
        UKIBANRecognizer,
    ]:
        analyzer.registry.add_recognizer(recogniser_cls())

    _log.info("analyzer_ready", model=model_name, uk_recognisers=6)
    return analyzer


# ---------------------------------------------------------------------------
# Detection function
# ---------------------------------------------------------------------------

def detect(
    chunks: list[TextChunk],
    analyzer: AnalyzerEngine,
    score_threshold: float = 0.6,
    entities: Optional[list[str]] = None,
    language: str = "en",
) -> list[DetectionResult]:
    """Run PII detection over a list of TextChunks.

    Returns a flat list of DetectionResult objects.
    Only results with score >= score_threshold are included.

    NEVER logs original_text — only entity_type + count.
    """
    if entities is None:
        entities = DEFAULT_ENTITIES

    results: list[DetectionResult] = []

    for chunk in chunks:
        if not chunk.text.strip():
            continue

        raw_results = analyzer.analyze(
            text=chunk.text,
            entities=entities,
            language=language,
            score_threshold=score_threshold,
        )

        for r in raw_results:
            results.append(DetectionResult(
                chunk_id=chunk.chunk_id,
                entity_type=r.entity_type,
                start=r.start,
                end=r.end,
                score=r.score,
                recogniser_name=r.recognition_metadata.get(
                    "recognizer_name", "unknown"
                ) if r.recognition_metadata else "unknown",
                original_text=chunk.text[r.start:r.end],  # EPHEMERAL
            ))

    # Log counts only — never log values
    from collections import Counter
    counts = Counter(r.entity_type for r in results)
    _log.info(
        "detection_complete",
        chunk_count=len(chunks),
        total_detections=len(results),
        entity_counts=dict(counts),
        threshold=score_threshold,
    )

    return results
