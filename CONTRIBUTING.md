# Contributing to PIIScrub

Thanks for your interest in contributing! PIIScrub is a privacy-first tool — please
read through these guidelines before opening a PR or issue.

---

## Prerequisites

| Tool | Version |
|------|---------|
| Python | 3.11+ |
| [uv](https://docs.astral.sh/uv/) | latest |
| Git | any recent |

---

## Dev Setup

```bash
git clone https://github.com/zparris/piiscrub.git
cd piiscrub

# Install all dependencies including dev extras
uv sync --extra dev

# Download the spaCy language model (required for PII detection)
uv run python -m spacy download en_core_web_lg

# Confirm everything works
uv run pytest tests/ -v --tb=short
```

Expected output: **48 passed**.

---

## Running Tests

```bash
# Full suite
uv run pytest tests/ -v

# Single module
uv run pytest tests/test_detector.py -v

# With coverage
uv run pytest tests/ --cov=piiscrub --cov-report=term-missing
```

Test fixtures live in `tests/fixtures/`. The `.gitignore` excludes fixture files
to avoid accidentally committing documents that contain real PII.

---

## Code Style

This project uses [Ruff](https://docs.astral.sh/ruff/) for linting and formatting.

```bash
# Lint
uv run ruff check src/ tests/

# Format
uv run ruff format src/ tests/
```

### Privacy rules — mandatory

1. **Never log raw PII.** Log entity *types* and *counts* only.
2. **Never log file paths.** Use `sha256(path)` (see `extractor._hash_path`).
3. **Never write PII to disk** outside the encrypted mapping store.

Violating these rules will block the PR.

---

## Project Structure

```
src/piiscrub/
├── __init__.py       # Version + public API
├── _logging.py       # structlog setup (PII-safe)
├── cli.py            # Click CLI (scrub, batch commands)
├── detector.py       # Presidio wrapper + UK custom recognisers
├── extractor.py      # Document parsing (PDF/DOCX/XLSX/CSV/EML/TXT)
├── models.py         # TextChunk, DetectionResult, AnonymisedChunk
├── output.py         # Document reconstruction + get_output_extension
├── pseudonymiser.py  # AES-256-GCM mapping store
└── web.py            # FastAPI app + HTML preview
tests/
├── fixtures/         # Synthetic test documents (git-ignored)
├── test_cli.py
├── test_detector.py
├── test_extractor.py
├── test_output.py
├── test_pseudonymiser.py
└── test_web.py
```

---

## PR Process

- **Bug fixes:** Open a PR directly. Include a regression test that fails without the
  fix and passes with it.
- **New features:** Open an issue first to discuss scope. This avoids wasted effort
  on features that won't be merged.
- **Recognisers:** New entity types are welcome — follow the pattern in
  `detector.py` and add at least five test cases covering true positives and false
  positives.

All PRs must pass CI (tests + ruff) before review.

---

## Areas of Interest

These are gaps in v0.1.0 that would make great contributions:

| Area | Notes |
|------|-------|
| `.pptx` support | python-pptx extraction + reconstruction |
| OCR for scanned PDFs | pytesseract or similar; flag as separate output pass |
| Windows packaging | `pyinstaller` one-file build; fix path handling |
| Additional recognisers | Date of birth, vehicle registration, bank sort code |
| Batch progress UI | Rich progress bar or web-socket progress for large directories |
| i18n / non-English PII | spaCy multi-language model support |

---

## Security

Please report security issues privately via the [GitHub security advisory](https://github.com/zparris/piiscrub/security/advisories/new)
rather than opening a public issue. See `SECURITY_REVIEW.md` for the threat model.
