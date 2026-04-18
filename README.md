# PIIScrub

**Scrub PII from documents locally before sending to cloud AI — GDPR-safe in seconds.**

---

## The problem

Every time you paste a client email, case note, or PDF into ChatGPT, Claude, or Gemini, you may be transferring personal data to a US-hosted service. Under GDPR, that triggers Article 5 (data minimisation), Article 6 (lawful basis), and Articles 44–49 (international transfer restrictions). Fines reach €20 million or 4% of annual turnover.

PIIScrub removes PII *before* the document reaches the AI. Because [GDPR Recital 26](https://www.privacy-regulation.eu/en/recital-26-GDPR.htm) exempts truly anonymous data from all GDPR obligations, **the data you send is no longer personal data** — no lawful basis required, no transfer mechanism needed.

---

## Requirements

- Python 3.11+
- A local Python environment with the package installed, or `uv`
- A one-time spaCy model download: `en_core_web_lg`

Core runtime dependencies are installed automatically with the package and include `click`, `presidio-analyzer`, `presidio-anonymizer`, `spacy`, `pymupdf`, `python-docx`, `openpyxl`, `pandas`, `faker`, `sqlalchemy`, `cryptography`, `fastapi`, and `uvicorn`.

## Install And Run

### Option 1: install from PyPI

```bash
pip install piiscrub

# Required one-time step: download the NLP model
python -m spacy download en_core_web_lg
```

Then run either:

```bash
piiscrub scrub myfile.docx
piiscrub serve
```

### Option 2: run from a GitHub checkout with `uv`

If you cloned this repository from GitHub, the `piiscrub` command is not available until you create an environment and install the project dependencies.

```bash
uv sync

# Required one-time step: download the NLP model into the environment
uv run python -m spacy download en_core_web_lg
```

Then run either:

```bash
uv run piiscrub scrub myfile.docx
uv run piiscrub serve
```

### Option 3: run from a GitHub checkout with `pip`

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .

# Required one-time step: download the NLP model
python -m spacy download en_core_web_lg
```

Then run either:

```bash
piiscrub scrub myfile.docx
piiscrub serve
```

### Option 4: one-off execution with `uvx`

```bash
uvx --with spacy --with presidio-analyzer --with presidio-anonymizer --with pymupdf --with python-docx --with openpyxl --with pandas --with faker --with sqlalchemy --with cryptography --with fastapi --with uvicorn piiscrub scrub myfile.docx
```

`uvx` is useful for quick CLI execution, but you still need the spaCy language model available locally. For repeated use, `uv sync` or `pip install -e .` is the cleaner path.

Via Homebrew *(coming soon)*:
```bash
brew install piiscrub
```

---

## Quick start — CLI

```bash
# Scrub a document (redact mode — default, GDPR-anonymous output)
piiscrub scrub client_notes.docx

# Output: client_notes_piiscrub.docx
# ✅ Scrubbed: 3 PERSON, 2 EMAIL_ADDRESS, 1 UK_NI
# Audit log updated: ~/.piiscrub/audit.db
```

---

## Quick start — Web UI

```bash
# Start the local browser interface (no data leaves your machine)
piiscrub serve

# Opens http://localhost:7890 in your browser
```

Drag in a document → choose Redact or Pseudonymise → preview the scrubbed output → download.

If you are running from a GitHub checkout instead of an installed package, prefix commands with `uv run`, for example:

```bash
uv run piiscrub scrub client_notes.docx
uv run piiscrub serve
```

---

## Terminal output example

```
┌──────────────────────────────────────────┐
│           PII Scrub Summary              │
├─────────────────┬───────┬────────────────┤
│ Entity Type     │ Count │ Action         │
├─────────────────┼───────┼────────────────┤
│ EMAIL_ADDRESS   │     2 │ Redacted       │
│ PERSON          │     3 │ Redacted       │
│ UK_NI           │     1 │ Redacted       │
│ UK_POSTCODE     │     2 │ Redacted       │
└─────────────────┴───────┴────────────────┘

✅ Saved to: client_notes_piiscrub.docx
Audit log updated: ~/.piiscrub/audit.db
```

---

## Supported formats

| Format | Extension | Notes |
|--------|-----------|-------|
| PDF | `.pdf` | Text extraction + spatial redaction via PyMuPDF |
| Word | `.docx` | Paragraphs, tables, headers/footers; comments stripped |
| Excel | `.xlsx` | Cell-by-cell scrubbing; formulae not preserved (v0.1) |
| CSV | `.csv` | Row-by-row scrubbing |
| Email | `.eml` | Headers (From, To, CC, Subject) + body |
| Plain text | `.txt` | Line-by-line scrubbing |

---

## Supported PII entity types

| Entity | Description | UK-specific |
|--------|-------------|-------------|
| `PERSON` | Names detected by spaCy NER | |
| `EMAIL_ADDRESS` | Email addresses | |
| `PHONE_NUMBER` | Generic phone numbers | |
| `UK_NI` | National Insurance numbers (e.g. AB123456C) | ✅ |
| `UK_NHS` | NHS numbers with Modulus 11 checksum | ✅ |
| `UK_POSTCODE` | Royal Mail postcodes (e.g. SW1A 2AA) | ✅ |
| `UK_PHONE` | UK mobile and landline numbers | ✅ |
| `UK_DRIVING_LICENCE` | DVLA driving licence format | ✅ |
| `UK_IBAN` | GB-prefix IBANs with checksum validation | ✅ |
| `IBAN_CODE` | Generic IBAN codes | |
| `CREDIT_CARD` | Credit/debit card numbers | |
| `IP_ADDRESS` | IPv4/IPv6 addresses | |
| `LOCATION` | Places and addresses via NER | |
| `DATE_TIME` | Dates and times | |
| `NRP` | Nationality, religion, political views | |

---

## Modes

### Redact (default — recommended)

```bash
piiscrub scrub report.docx --mode redact
```

Replaces PII with type-tagged labels: `John Smith` → `[PERSON_1]`. The output is **GDPR-anonymous** under Recital 26. No mapping table is created. No personal data persists.

### Pseudonymise

```bash
piiscrub scrub report.docx --mode pseudonymise --passphrase mysecretpassphrase
```

Replaces PII with realistic fake data using [Faker](https://faker.readthedocs.io/) (en_GB locale). `John Smith` → `Robert Davies`. The AI sees coherent, realistic text. The mapping table is encrypted locally and reversible.

> ⚠ Pseudonymised output is still personal data under GDPR. Use Redact unless you specifically need the AI to work with realistic-looking names/data.

### Restore after pseudonymisation

```bash
piiscrub restore ai_response.txt SESSION_ID --passphrase mysecretpassphrase
```

Replaces fake values in the AI's response with original values.

---

## Batch processing

```bash
piiscrub batch ./documents/ --output-dir ./scrubbed/
```

Processes all supported files in a folder with a progress bar.

---

## GDPR audit log

Every scrub operation is logged to `~/.piiscrub/audit.db`. The log records:
- Timestamp (ISO 8601)
- sha256 of source file (never the filename)
- Detection mode and entity type counts
- Processing duration
- spaCy model version and confidence threshold

**The audit log never contains PII values or filenames.**

Export for DPIA/ICO accountability evidence:
```bash
piiscrub audit export --output audit_evidence.csv
```

---

## Options reference

```
piiscrub scrub [FILE] [OPTIONS]

Options:
  --mode [redact|pseudonymise]  Default: redact
  --output, -o PATH             Output file path (default: {file}_piiscrub.{ext})
  --threshold FLOAT             Detection confidence 0.0–1.0 (default: 0.6)
  --high-accuracy               Use transformer NER model — higher recall, slower
  --formats TEXT                Comma-separated entity types (default: all)
  --no-audit                    Skip audit log entry (not recommended)
  --passphrase TEXT             Required for pseudonymise mode
  --session TEXT                Session ID for cross-document consistency
  --version                     Show version and spaCy model
```

---

## Compliance note

PIIScrub is designed to help with:

- **GDPR Recital 26** — output that passes the anonymisation test falls outside GDPR scope
- **Article 5(1)(c)** — data minimisation: only necessary data reaches cloud AI
- **Article 25** — data protection by design and by default
- **EU AI Act Article 10(5)** — anonymised data recommended before AI bias detection

> ⚠ **Important caveat:** PIIScrub reduces risk but does not guarantee 100% PII detection. Automated detection using NER and regex achieves high recall but is not infallible. Human review is recommended for high-sensitivity documents (medical records, legal proceedings, safeguarding cases). The tool provides a meaningful reduction in exposure, not absolute elimination.

---

## How it works

```
Your document (on your machine)
       ↓
  PIIScrub extracts text
       ↓
  Presidio + spaCy NER + UK regex detect PII
       ↓
  Detected spans replaced with [ENTITY_TYPE_N]
       ↓
  Scrubbed document written in original format
       ↓
  Audit log entry created locally
       ↓
  You send the clean document to ChatGPT / Claude / Gemini
```

All steps run locally. No network requests are made during processing.

---

## Contributing

Contributions welcome. Please open an issue before submitting a PR for new features.

Areas of particular interest:
- Additional UK-specific entity recognisers
- PowerPoint (`.pptx`) support
- Scanned PDF support via OCR (pytesseract)
- Desktop launcher packaging (macOS/Windows)

---

## Licence

MIT — see [LICENSE](LICENSE)

> **PyMuPDF note:** PDF processing uses PyMuPDF (AGPL-3.0). For local CLI use this is acceptable. If you are building a hosted service on top of PIIScrub, you must comply with AGPL-3.0 or replace PyMuPDF with an Apache-licensed alternative.
