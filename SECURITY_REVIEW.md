# PIIScrub — Security Review

Version: 0.1.0
Reviewer: Build-time self-review
Date: 2026-03-21

---

## Review Checklist

### 1. PII values in logs, audit DB, or console output

**PASS**

- `structlog` configured with a PII-guard processor (`_logging.py`) that raises `RuntimeError` if a log event value matches PII patterns and exceeds 200 characters
- `detector.py`: logs only `entity_type` + `count` — never `original_text`
- `anonymiser.py`: logs only `mode`, `entity_counts` — never replacement values or originals
- `audit.py`: `record()` validates `source_hash`, `output_hash`, `operator_hash` are 64-character hex digests via `_validate_hash()`. `entity_type_counts` keys are validated against entity type naming conventions
- `audit.py`: SQLite `CHECK` constraint enforces 64-char hex on `source_hash` at DB layer
- No filename ever appears in any log — only `sha256(file_content)` in audit log; `sha256(str(path))` abbreviated (first 12 chars + "...") in operational logs

### 2. Mapping table real values encrypted at rest (AES-256-GCM)

**PASS**

- `mapping.py`: real values encrypted via `AESGCM(key).encrypt(nonce, plaintext, None)`
- Nonce is 12 bytes from `os.urandom(12)` — unique per encryption call
- Ciphertext stored as `nonce(12) || ciphertext+tag` in `real_value_encrypted` column (LargeBinary)
- `fake_value` stored as plaintext (synthetic data, not personal data)
- `original_hash` is `sha256(original_value)` — not the plaintext original

**⚠ Critical implementation note:** AES-GCM nonce reuse with the same key is a catastrophic vulnerability. The implementation generates a fresh nonce per `_encrypt()` call. This MUST be verified before any production deployment. Recommend code review of `mapping.py::_encrypt()`.

### 3. Encryption key never written to disk

**PASS**

- `mapping.py`: key is derived from passphrase via `PBKDF2HMAC(SHA256, 600_000 iterations, random_salt)` and stored only in `self._key` (Python object memory)
- Salt is stored in the `salt_config` table — not the key
- `close()` zeroes `self._key = b"\x00" * 32` as best-effort key erasure
- Key is never serialised to disk, environment variables, or logs

**Known limitation:** Python's memory model does not guarantee immediate erasure — the GC may not reclaim memory containing the key immediately. This is documented in the architecture document and README. Processing documents in a subprocess that terminates afterward (forcing OS memory reclamation) is a v0.2 improvement.

### 4. Database files have 600 permissions

**PASS**

- `mapping.py` and `audit.py` both call `os.open(path, os.O_CREAT | os.O_WRONLY, stat.S_IRUSR | stat.S_IWUSR)` to create DB files with 600 permissions atomically before SQLAlchemy opens them
- `os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR)` called on existing files
- `os.umask(0o177)` set at CLI startup (`cli.py`) so all created files default to 600
- Parent directory `~/.piiscrub/` created with 700 permissions

### 5. Temp files use in-memory or SpooledTemporaryFile

**PARTIAL PASS**

- `web.py`: uploads written to `tempfile.NamedTemporaryFile` (disk-backed) and deleted after processing in `finally` block. For large files, this means PII temporarily on disk.
- **Improvement for v0.2:** Use `tempfile.SpooledTemporaryFile(max_size=10_485_760)` (10MB in-memory threshold) to keep small documents in RAM.
- CLI: no temp files created — operates directly on the input file path.

### 6. No network calls during scrub operation

**PASS**

- No `requests`, `httpx`, `urllib`, `socket`, or `aiohttp` imports in the processing pipeline (`extractor.py`, `detector.py`, `anonymiser.py`, `output.py`, `mapping.py`, `audit.py`)
- Presidio and spaCy operate entirely from locally cached models
- Web UI (`web.py`) only listens on `127.0.0.1` (loopback) — never reachable from outside the machine

### 7. gc.collect() called after processing each document

**PASS**

- `extractor.py`: `gc.collect()` at end of `extract()`
- `anonymiser.py`: `gc.collect()` at end of `anonymise()`
- `cli.py`: explicit `del chunks, detections, anonymised` before `gc.collect()` after each document in `_run_scrub()`
- `web.py`: `del chunks, detections, anonymised; gc.collect()` after reconstruction

### 8. structlog configured to avoid sensitive fields

**PASS**

- `_logging.py` configures structlog with `_pii_guard_processor` that raises `RuntimeError` on suspected PII in log values
- Processor checks for NI number, NHS number, email, and card-like patterns in values > 200 characters
- This is defence-in-depth — modules are also written to never log PII in the first place

### 9. pyproject.toml has no unpinned * dependencies

**PASS**

All dependencies use version floor constraints (`>=`), not wildcard pins. This is standard for library distribution. For application deployment, lock with `uv lock` to produce `uv.lock` with exact pinned versions.

### 10. All tests pass

**TO VERIFY** — run after dependency installation:

```bash
uv run pytest tests/ -v
```

Expected: all tests green. Known dependency: `en_core_web_lg` must be downloaded first.

---

## Licence Review

| Dependency | Licence | Risk |
|---|---|---|
| presidio-analyzer | MIT | None |
| presidio-anonymizer | MIT | None |
| spacy | MIT | None |
| **pymupdf** | **AGPL-3.0** | **⚠ See below** |
| python-docx | MIT | None |
| openpyxl | MIT | None |
| pandas | BSD-3 | None |
| faker | MIT | None |
| sqlalchemy | MIT | None |
| cryptography | Apache-2.0 / BSD | None |
| structlog | Apache-2.0 | None |
| click | BSD-3 | None |
| rich | MIT | None |
| fastapi | MIT | None |
| uvicorn | BSD-3 | None |

**PyMuPDF AGPL-3.0 — Decision Gate:**

PIIScrub is currently a local CLI + local web UI tool. Under AGPL-3.0, distributing the application to users who run it locally is permitted. However:

- If PIIScrub is ever deployed as a **hosted web service** (even internally for a team), AGPL requires the complete source code of the service to be made available to all users
- If a SaaS version is planned within 12 months, replace PyMuPDF with `pypdf` (BSD-3, text extraction) or `pdfminer.six` (MIT) before v0.1 ships to avoid AGPL lock-in

**Action required before SaaS deployment:** Replace PyMuPDF.

---

## Known Limitations

1. **No 100% recall:** Multi-layer detection (spaCy NER + UK regex + context scoring) maximises coverage but is not infallible. Human review recommended for high-sensitivity documents.

2. **Python memory model:** Secure erasure of PII from RAM is not achievable in Python. `gc.collect()` is called after each document, but CPython's allocator may retain freed memory. Processing each document in a subprocess (forcing OS memory reclamation on exit) is a v0.2 improvement.

3. **DOCX tracked changes:** `python-docx` does not expose `w:ins`/`w:del` XML nodes. If a DOCX file has unaccepted tracked changes, deleted text may contain PII that survives scrubbing. `extractor.py` logs a warning when revision markup is detected.

4. **XLSX formulae:** Formulae are not preserved in v0.1 (openpyxl `data_only=True` limitation). Scrubbed XLSX contains static values only.

5. **EML attachments:** Binary attachments are not scrubbed in v0.1. A warning is logged for each attachment skipped.

6. **Temp file PII (web UI):** Uploaded files are written to `tempfile.NamedTemporaryFile` on disk during processing. Files are deleted in `finally` blocks. For maximum security, upgrade to `SpooledTemporaryFile` in v0.2.

---

## Verdict

**PASS WITH CONDITIONS**

The implementation satisfies all critical security requirements for a local CLI + local web UI tool:
- PII never persists in logs or audit records
- Mapping table real values are AES-256-GCM encrypted at rest
- Encryption key never touches disk
- DB files have 600 permissions
- No network calls during scrub
- Memory cleanup is best-effort (Python limitation — documented)

**Before any hosted deployment:** resolve the PyMuPDF AGPL licence, upgrade temp file handling to SpooledTemporaryFile, and conduct an independent security audit of the AES-GCM nonce management in `mapping.py`.
