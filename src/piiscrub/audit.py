"""GDPR accountability audit log.

Storage: ~/.piiscrub/audit.db (SQLite, permissions 600)
The audit log is append-only and MUST NEVER contain:
  - Actual PII values
  - Original filenames (use sha256(filename) only)
  - Mapping table contents

A CHECK constraint on source_hash enforces the 64-hex-char rule at the DB layer,
providing a last line of defence against accidental filename leakage.
"""

from __future__ import annotations

import csv
import json
import os
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    Integer,
    String,
    Text,
    create_engine,
    text,
)
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from piiscrub.models import AuditEntry

_DEFAULT_DB_PATH = Path.home() / ".piiscrub" / "audit.db"


class _Base(DeclarativeBase):
    pass


class _AuditRow(_Base):
    __tablename__ = "pii_audit_log"
    __table_args__ = {
        "sqlite_autoincrement": True,
    }
    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String, unique=True, nullable=False)
    timestamp_utc = Column(String, nullable=False)
    source_hash = Column(String, nullable=False)     # sha256(filename), 64 hex chars
    output_hash = Column(String, nullable=False)     # sha256(output file)
    operator_hash = Column(String, nullable=False)   # sha256(hostname)
    piiscrub_version = Column(String, nullable=False)
    spacy_model = Column(String, nullable=False)
    threshold = Column(String, nullable=False)       # stored as string to avoid float drift
    mode = Column(String, nullable=False)            # "redact" | "pseudonymise"
    entity_type_counts = Column(Text, nullable=False)  # JSON: {"PERSON": 3}
    processing_duration_ms = Column(Integer, nullable=False)
    error_flag = Column(Boolean, nullable=False, default=False)
    error_message = Column(Text, nullable=False, default="")
    session_id = Column(String, nullable=True)


def _ensure_db_dir(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(db_path.parent, stat.S_IRWXU)


def _create_db_file(db_path: Path) -> None:
    if not db_path.exists():
        fd = os.open(str(db_path), os.O_CREAT | os.O_WRONLY, stat.S_IRUSR | stat.S_IWUSR)
        os.close(fd)
    else:
        os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR)


def _validate_hash(value: str, field_name: str) -> None:
    """Raise ValueError if value is not a 64-char hex string (sha256 output)."""
    if len(value) != 64 or not all(c in "0123456789abcdef" for c in value.lower()):
        raise ValueError(
            f"AuditLog: {field_name} must be a 64-character hex sha256 digest. "
            f"Got: {repr(value[:20])}... — this likely means a raw filename was passed."
        )


class AuditLog:
    """Append-only GDPR accountability audit log.

    Usage:
        log = AuditLog()
        log.record(entry)
        log.export_csv(Path("audit_export.csv"))
        log.close()
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db_path = db_path or _DEFAULT_DB_PATH
        _ensure_db_dir(self._db_path)
        _create_db_file(self._db_path)

        self._engine = create_engine(
            f"sqlite:///{self._db_path}",
            connect_args={"check_same_thread": False},
        )
        with self._engine.connect() as conn:
            conn.execute(text("PRAGMA journal_mode=WAL"))
            conn.commit()

        _Base.metadata.create_all(self._engine)
        self._Session = sessionmaker(bind=self._engine)

    def record(self, entry: AuditEntry) -> None:
        """Append one audit record. Validates hashes to prevent PII leakage."""
        _validate_hash(entry.source_hash, "source_hash")
        _validate_hash(entry.output_hash, "output_hash")
        _validate_hash(entry.operator_hash, "operator_hash")

        # Validate entity_type_counts contains only known entity type keys
        for key in entry.entity_type_counts:
            if not key.isupper() or not key.replace("_", "").isalpha():
                raise ValueError(
                    f"AuditLog: entity_type_counts key {repr(key)} looks like it "
                    "may contain PII. Keys must be entity type names (e.g. 'PERSON')."
                )

        with self._Session() as session:
            row = _AuditRow(
                event_id=entry.event_id,
                timestamp_utc=entry.timestamp_utc,
                source_hash=entry.source_hash,
                output_hash=entry.output_hash,
                operator_hash=entry.operator_hash,
                piiscrub_version=entry.piiscrub_version,
                spacy_model=entry.spacy_model,
                threshold=str(entry.threshold),
                mode=entry.mode,
                entity_type_counts=json.dumps(entry.entity_type_counts),
                processing_duration_ms=entry.processing_duration_ms,
                error_flag=entry.error_flag,
                error_message=entry.error_message or "",
                session_id=entry.session_id,
            )
            session.add(row)
            session.commit()

    def query(
        self,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        session_id: Optional[str] = None,
    ) -> list[AuditEntry]:
        """Read audit entries with optional date and session filters."""
        with self._Session() as session:
            q = session.query(_AuditRow)
            if since:
                q = q.filter(_AuditRow.timestamp_utc >= since.isoformat())
            if until:
                q = q.filter(_AuditRow.timestamp_utc <= until.isoformat())
            if session_id:
                q = q.filter_by(session_id=session_id)
            rows = q.order_by(_AuditRow.timestamp_utc).all()

        return [
            AuditEntry(
                event_id=r.event_id,
                timestamp_utc=r.timestamp_utc,
                source_hash=r.source_hash,
                output_hash=r.output_hash,
                operator_hash=r.operator_hash,
                piiscrub_version=r.piiscrub_version,
                spacy_model=r.spacy_model,
                threshold=float(r.threshold),
                mode=r.mode,
                entity_type_counts=json.loads(r.entity_type_counts),
                processing_duration_ms=r.processing_duration_ms,
                error_flag=bool(r.error_flag),
                error_message=r.error_message,
                session_id=r.session_id,
            )
            for r in rows
        ]

    def export_csv(self, output_path: Path) -> int:
        """Export all audit entries to CSV. Returns row count written."""
        entries = self.query()
        if not entries:
            return 0

        fieldnames = [
            "event_id", "timestamp_utc", "source_hash", "output_hash",
            "operator_hash", "piiscrub_version", "spacy_model", "threshold",
            "mode", "entity_type_counts", "processing_duration_ms",
            "error_flag", "error_message", "session_id",
        ]

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for entry in entries:
                writer.writerow({
                    "event_id": entry.event_id,
                    "timestamp_utc": entry.timestamp_utc,
                    "source_hash": entry.source_hash,
                    "output_hash": entry.output_hash,
                    "operator_hash": entry.operator_hash,
                    "piiscrub_version": entry.piiscrub_version,
                    "spacy_model": entry.spacy_model,
                    "threshold": entry.threshold,
                    "mode": entry.mode,
                    "entity_type_counts": json.dumps(entry.entity_type_counts),
                    "processing_duration_ms": entry.processing_duration_ms,
                    "error_flag": entry.error_flag,
                    "error_message": entry.error_message,
                    "session_id": entry.session_id,
                })

        return len(entries)

    def close(self) -> None:
        self._engine.dispose()


def make_audit_entry(
    source_hash: str,
    output_hash: str,
    operator_hash: str,
    mode: str,
    entity_type_counts: dict[str, int],
    processing_duration_ms: int,
    spacy_model: str = "en_core_web_lg",
    threshold: float = 0.6,
    error_flag: bool = False,
    error_message: str = "",
    session_id: Optional[str] = None,
) -> AuditEntry:
    """Convenience factory for AuditEntry with auto-populated fields."""
    from piiscrub import __version__
    return AuditEntry(
        event_id=str(uuid.uuid4()),
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        source_hash=source_hash,
        output_hash=output_hash,
        operator_hash=operator_hash,
        piiscrub_version=__version__,
        spacy_model=spacy_model,
        threshold=threshold,
        mode=mode,
        entity_type_counts=entity_type_counts,
        processing_duration_ms=processing_duration_ms,
        error_flag=error_flag,
        error_message=error_message,
        session_id=session_id,
    )
