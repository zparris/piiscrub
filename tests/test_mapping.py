"""Tests for mapping.py — encrypted pseudonymisation store."""

import os
import stat
import pytest
from pathlib import Path

from piiscrub.mapping import MappingDB


@pytest.fixture
def db(tmp_path) -> MappingDB:
    db = MappingDB(passphrase="test-passphrase-123", db_path=tmp_path / "test.db")
    yield db
    db.close()


def test_store_and_lookup(db, tmp_path):
    db.store_raw(
        session_id="sess1",
        entity_type="PERSON",
        original_value="John Smith",
        fake_value="Robert Jones",
        document_hash="a" * 64,
    )
    result = db.lookup(db.hash_original("John Smith"), "sess1")
    assert result == "Robert Jones"


def test_lookup_missing_returns_none(db):
    result = db.lookup("nonexistent-hash", "sess1")
    assert result is None


def test_real_value_encrypted_at_rest(tmp_path):
    """Real values must not appear in plaintext in the DB file."""
    db_path = tmp_path / "enc_test.db"
    db = MappingDB(passphrase="secret", db_path=db_path)
    db.store_raw(
        session_id="sess1",
        entity_type="PERSON",
        original_value="SuperSecretName",
        fake_value="FakeName123",
        document_hash="b" * 64,
    )
    db.close()

    # Read raw bytes of DB file
    raw = db_path.read_bytes()
    assert b"SuperSecretName" not in raw


def test_restore_decrypts_correctly(tmp_path):
    db_path = tmp_path / "restore.db"
    db = MappingDB(passphrase="mypassphrase", db_path=db_path)
    db.store_raw("sess2", "EMAIL_ADDRESS", "real@example.com", "fake@fake.com", "c" * 64)
    db.close()

    # Reopen and restore
    db2 = MappingDB(passphrase="mypassphrase", db_path=db_path)
    replacements = db2.get_session_replacements("sess2", "mypassphrase")
    db2.close()

    assert "fake@fake.com" in replacements
    assert replacements["fake@fake.com"] == "real@example.com"


def test_purge_deletes_session(db):
    db.store_raw("purge-sess", "PERSON", "Alice", "Bob", "d" * 64)
    assert db.lookup(db.hash_original("Alice"), "purge-sess") == "Bob"
    count = db.purge("purge-sess")
    assert count == 1
    assert db.lookup(db.hash_original("Alice"), "purge-sess") is None


def test_db_file_permissions(tmp_path):
    db_path = tmp_path / "perms.db"
    db = MappingDB(passphrase="pass", db_path=db_path)
    db.close()
    mode = oct(stat.S_IMODE(os.stat(db_path).st_mode))
    assert mode == "0o600", f"Expected 600, got {mode}"


def test_consistency_no_duplicate_store(db):
    """Storing same original twice with same session should not create two rows."""
    db.store_raw("sess3", "PERSON", "Jane Doe", "Fake One", "e" * 64)
    db.store_raw("sess3", "PERSON", "Jane Doe", "Fake Two", "e" * 64)  # should be ignored
    result = db.lookup(db.hash_original("Jane Doe"), "sess3")
    assert result == "Fake One"  # first write wins
