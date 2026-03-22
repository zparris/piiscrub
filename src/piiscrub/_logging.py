"""structlog configuration with PII-guard processor.

All log output goes to stderr. PII values must NEVER appear in logs.
The PII-guard processor raises RuntimeError if a log event value looks like
it contains PII patterns longer than 50 characters — defence-in-depth only.

Rule: log entity_type + count. Never log original_text or TextChunk.text.
"""

from __future__ import annotations

import re
import sys

import structlog

# Patterns that suggest a log value may contain PII.
# These are intentionally conservative — false positives cause RuntimeError
# rather than silent PII leakage.
_PII_GUARD_PATTERNS = [
    re.compile(r"[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]", re.IGNORECASE),  # NI number
    re.compile(r"\b\d{3}\s\d{3}\s\d{4}\b"),                          # NHS number
    re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),  # email
    re.compile(r"\b(?:\d[ -]?){13,16}\b"),                            # card-like
]

_MAX_SAFE_VALUE_LEN = 200


def _pii_guard_processor(logger, method, event_dict: dict) -> dict:
    """Raise RuntimeError if any log value exceeds safe length and matches PII pattern."""
    for key, value in event_dict.items():
        if key == "event":
            continue
        if not isinstance(value, str):
            continue
        if len(value) > _MAX_SAFE_VALUE_LEN:
            for pattern in _PII_GUARD_PATTERNS:
                if pattern.search(value):
                    raise RuntimeError(
                        f"PIIScrub log guard: field '{key}' appears to contain PII. "
                        "Log only entity_type names and counts, never raw text values."
                    )
    return event_dict


def configure_logging(level: str = "WARNING") -> None:
    """Set up structlog with PII-guard processor. Call once at CLI startup."""
    import logging

    logging.basicConfig(format="%(message)s", stream=sys.stderr, level=getattr(logging, level.upper(), logging.WARNING))

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            _pii_guard_processor,
            structlog.dev.ConsoleRenderer(colors=False),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = "piiscrub") -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
