# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-03-21

### Added

- **Full PII scrubbing pipeline** — extract → detect → anonymise → reconstruct, all running locally with no data leaving the machine.
- **Six UK-tuned custom recognisers** — NHS number, National Insurance number, UK driving licence, UK passport number, UK postcode, and UK phone number (Presidio + spaCy `en_core_web_lg`).
- **Two scrubbing modes:**
  - *Redact* — replaces PII with labelled placeholders (e.g. `[PERSON_1]`). No passphrase required.
  - *Pseudonymise* — replaces PII with consistent pseudonyms and stores an AES-256-GCM encrypted mapping so replacements can be reversed with a passphrase.
- **Supported input formats:** `.pdf`, `.docx`, `.xlsx`, `.csv`, `.eml`, `.txt`.
- **Output format logic:** PDFs are converted to `.docx` (reflowable, no fixed-layout overlap issues); all other formats preserve their original extension.
- **PyMuPDF spatial redaction** — text-search-based precise redaction for PDF inputs, preserving page structure while removing only the matched PII spans.
- **PDF → DOCX conversion** — headings detected from ALL-CAPS short lines; page breaks respected; PII labels rendered in dark-red bold.
- **CLI** (`piiscrub scrub`, `piiscrub batch`) — single-file and directory-wide scrubbing with configurable mode, output directory, and passphrase.
- **Web UI** (FastAPI + uvicorn) — drag-and-drop upload, live detection preview with entity-type tags, Download and Preview buttons, full scrubbed-text HTML preview page.
- **AES-256-GCM encrypted mapping store** — pseudonym-to-original mapping persisted to `~/.piiscrub/mappings/` with PBKDF2-HMAC-SHA256 key derivation (600 000 iterations).
- **GDPR audit log** — structured JSON log (structlog) records entity types and counts without ever logging raw PII values or file paths (only SHA-256 hashes of paths).
- **HTML in-browser preview** — `/preview/{token}` endpoint renders the scrubbed document as a styled HTML page with highlighted PII labels and a Download button, compatible with all browsers and output formats.

[0.1.0]: https://github.com/zparris/piiscrub/releases/tag/v0.1.0
