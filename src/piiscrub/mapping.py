"""Encrypted local mapping table for pseudonymisation sessions.

Storage: ~/.piiscrub/mappings.db (SQLite, permissions 600)
Encryption: AES-256-GCM via cryptography library
Key derivation: PBKDF2HMAC(SHA256, 600_000 iterations, random 32-byte salt per DB)
Salt is stored in the DB salt_config table; the key NEVER touches disk.

The mapping table IS personal data (enables re-identification).
Real values are encrypted at rest. Fake values are stored in plaintext
(they are synthetic and not personal data on their own).
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sqlalchemy import (
    Boolean,
    Column,
    LargeBinary,
    String,
    Text,
    create_engine,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from piiscrub.models import MappingRecord

_DEFAULT_DB_PATH = Path.home() / ".piiscrub" / "mappings.db"
_PBKDF2_ITERATIONS = 600_000
_SALT_LENGTH = 32
_NONCE_LENGTH = 12


class _Base(DeclarativeBase):
    pass


class _SaltConfig(_Base):
    __tablename__ = "salt_config"
    id = Column(String, primary_key=True, default="singleton")
    salt = Column(LargeBinary, nullable=False)


class _PiiMapping(_Base):
    __tablename__ = "pii_mappings"
    record_id = Column(String, primary_key=True)
    session_id = Column(String, nullable=False, index=True)
    entity_type = Column(String, nullable=False)
    original_hash = Column(String, nullable=False)  # sha256(original), NOT plaintext
    real_value_encrypted = Column(LargeBinary, nullable=False)  # nonce||ciphertext||tag
    fake_value = Column(Text, nullable=False)
    created_utc = Column(String, nullable=False)
    document_hash = Column(String, nullable=False)


def _ensure_db_dir(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    # Set directory permissions to 700
    os.chmod(db_path.parent, stat.S_IRWXU)


def _create_db_file(db_path: Path) -> None:
    """Create the DB file with 600 permissions before SQLAlchemy touches it."""
    if not db_path.exists():
        fd = os.open(str(db_path), os.O_CREAT | os.O_WRONLY, stat.S_IRUSR | stat.S_IWUSR)
        os.close(fd)
    else:
        os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR)


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


class MappingDB:
    """Encrypted local SQLite store for pseudonymisation mapping tables.

    Usage:
        db = MappingDB(passphrase="secret")
        db.store(record)
        fake = db.lookup(original_hash, session_id)
        db.close()
    """

    def __init__(
        self,
        passphrase: str,
        db_path: Optional[Path] = None,
    ) -> None:
        self._db_path = db_path or _DEFAULT_DB_PATH
        _ensure_db_dir(self._db_path)
        _create_db_file(self._db_path)

        self._engine = create_engine(
            f"sqlite:///{self._db_path}",
            connect_args={"check_same_thread": False},
        )
        # Enable WAL mode for concurrent reads in batch mode
        with self._engine.connect() as conn:
            conn.execute(text("PRAGMA journal_mode=WAL"))
            conn.commit()

        _Base.metadata.create_all(self._engine)
        self._Session = sessionmaker(bind=self._engine)

        # Load or create the per-DB salt
        with self._Session() as session:
            salt_row = session.get(_SaltConfig, "singleton")
            if salt_row is None:
                salt = os.urandom(_SALT_LENGTH)
                session.add(_SaltConfig(id="singleton", salt=salt))
                session.commit()
            else:
                salt = salt_row.salt

        # Derive the encryption key — it never leaves this object's memory
        self._key = _derive_key(passphrase, salt)
        self._aesgcm = AESGCM(self._key)

    def _encrypt(self, plaintext: str) -> bytes:
        nonce = os.urandom(_NONCE_LENGTH)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return nonce + ciphertext  # nonce(12) || ciphertext+tag

    def _decrypt(self, blob: bytes) -> str:
        nonce = blob[:_NONCE_LENGTH]
        ciphertext = blob[_NONCE_LENGTH:]
        return self._aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")

    @staticmethod
    def hash_original(value: str) -> str:
        """Return sha256 hex digest of a real value (for lookup without storing plaintext)."""
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def lookup(self, original_hash: str, session_id: str) -> Optional[str]:
        """Return the existing fake value for this hash+session, or None."""
        with self._Session() as session:
            row = (
                session.query(_PiiMapping)
                .filter_by(original_hash=original_hash, session_id=session_id)
                .first()
            )
            if row is None:
                return None
            return row.fake_value

    def store(self, record: MappingRecord) -> None:
        """Encrypt and persist a mapping record."""
        with self._Session() as session:
            row = _PiiMapping(
                record_id=record.record_id,
                session_id=record.session_id,
                entity_type=record.entity_type,
                original_hash=record.original_hash,
                real_value_encrypted=record.real_value_encrypted,
                fake_value=record.fake_value,
                created_utc=record.created_utc,
                document_hash=record.document_hash,
            )
            session.add(row)
            session.commit()

    def store_raw(
        self,
        session_id: str,
        entity_type: str,
        original_value: str,
        fake_value: str,
        document_hash: str,
    ) -> None:
        """Convenience method: encrypt original_value and store the mapping."""
        original_hash = self.hash_original(original_value)
        # Check if already stored (consistency)
        existing = self.lookup(original_hash, session_id)
        if existing is not None:
            return
        record = MappingRecord(
            record_id=str(uuid.uuid4()),
            session_id=session_id,
            entity_type=entity_type,
            original_hash=original_hash,
            real_value_encrypted=self._encrypt(original_value),
            fake_value=fake_value,
            created_utc=datetime.now(timezone.utc).isoformat(),
            document_hash=document_hash,
        )
        self.store(record)

    def get_session_replacements(self, session_id: str, passphrase: str) -> dict[str, str]:
        """Decrypt and return {fake_value: real_value} for a session (for restore command)."""
        # Re-derive key from passphrase to confirm it's correct before decrypting
        result: dict[str, str] = {}
        with self._Session() as session:
            rows = session.query(_PiiMapping).filter_by(session_id=session_id).all()
            for row in rows:
                real_value = self._decrypt(row.real_value_encrypted)
                result[row.fake_value] = real_value
        return result

    def purge(self, session_id: str) -> int:
        """Delete all mapping rows for a session. Returns count deleted."""
        with self._Session() as session:
            count = (
                session.query(_PiiMapping)
                .filter_by(session_id=session_id)
                .delete()
            )
            session.commit()
            return count

    def list_sessions(self) -> list[str]:
        """Return all known session IDs."""
        with self._Session() as session:
            rows = session.query(_PiiMapping.session_id).distinct().all()
            return [r[0] for r in rows]

    def close(self) -> None:
        self._engine.dispose()
        # Zero out the key from memory as best effort
        self._key = b"\x00" * 32
