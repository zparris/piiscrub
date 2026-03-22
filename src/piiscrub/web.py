"""PIIScrub local web UI — FastAPI application.

Runs at http://localhost:7890 (default). All processing happens locally.
No data is sent to any external server.

Routes:
  GET  /           → 5-step HTML UI
  POST /scrub      → multipart upload, returns JSON result + scrubbed file
  POST /scrub-text → plain text input, returns JSON result + scrubbed text
  GET  /download/{token} → download scrubbed file (token is short-lived, in-memory)
  GET  /audit      → returns audit log as JSON
"""

import gc
import hashlib
import io
import os
import socket
import tempfile
import time
import uuid
from pathlib import Path
from typing import Optional

_SCRUB_CACHE: dict[str, bytes] = {}  # token → scrubbed file bytes (in-memory, no disk)
_SCRUB_META: dict[str, dict] = {}    # token → {filename, entity_counts, mode, session_id}


def _hash_file_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_hostname() -> str:
    return hashlib.sha256(socket.gethostname().encode()).hexdigest()


def create_app(high_accuracy: bool = False):
    """Factory — creates and returns the FastAPI app with shared analyzer instance."""
    try:
        from fastapi import FastAPI, File, Form, HTTPException, UploadFile
        from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
    except ImportError:
        raise ImportError(
            "FastAPI is required for the web UI. "
            "Install with: pip install fastapi uvicorn"
        )

    from piiscrub._logging import configure_logging
    from piiscrub.anonymiser import anonymise, count_by_type
    from piiscrub.audit import AuditLog, make_audit_entry
    from piiscrub.detector import build_analyzer, detect
    from piiscrub.extractor import UnsupportedFormatError, extract
    from piiscrub.mapping import MappingDB
    from piiscrub.models import DEFAULT_ENTITIES, ScrubMode
    from piiscrub.output import get_output_extension, reconstruct

    configure_logging()

    app = FastAPI(title="PIIScrub", version="0.1.0", docs_url=None, redoc_url=None)

    # Global exception handler — ensures all errors return JSON, never plain-text 500
    from fastapi import Request as _Request

    @app.exception_handler(Exception)
    async def _global_exc_handler(_request: _Request, exc: Exception):
        return JSONResponse(status_code=500, content={"detail": str(exc)})

    # Load analyzer once at startup
    _model = "en_core_web_trf" if high_accuracy else "en_core_web_lg"
    _analyzer = build_analyzer(high_accuracy=high_accuracy)

    # ---------------------------------------------------------------------------
    # HTML UI
    # ---------------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return HTMLResponse(content=_render_html())

    # ---------------------------------------------------------------------------
    # File scrub endpoint
    # ---------------------------------------------------------------------------

    @app.post("/scrub")
    async def scrub_file(
        file: UploadFile = File(...),
        mode: str = Form("redact"),
        threshold: float = Form(0.6),
        passphrase: Optional[str] = Form(None),
        session_id: Optional[str] = Form(None),
    ):
        scrub_mode = ScrubMode(mode)
        if scrub_mode == ScrubMode.PSEUDONYMISE and not passphrase:
            raise HTTPException(status_code=400, detail="passphrase required for pseudonymise mode")

        # Write upload to temp file (in-memory via SpooledTemporaryFile)
        contents = await file.read()
        filename = file.filename or "upload.txt"
        suffix = Path(filename).suffix.lower()
        output_suffix = get_output_extension(suffix)   # .pdf → .docx, others unchanged

        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(contents)
            tmp_path = Path(tmp.name)

        output_tmp = tmp_path.with_suffix(suffix + ".out" + output_suffix)

        t_start = time.monotonic()
        source_hash = _hash_file_bytes(contents)
        entity_counts: dict[str, int] = {}
        error_flag = False
        error_message = ""
        token = str(uuid.uuid4())
        sid = session_id or str(uuid.uuid4())
        mapping_db = None

        try:
            chunks = extract(tmp_path)
            detections = detect(chunks, _analyzer, score_threshold=threshold, entities=DEFAULT_ENTITIES)

            if scrub_mode == ScrubMode.PSEUDONYMISE:
                mapping_db = MappingDB(passphrase=passphrase)

            anonymised = anonymise(
                chunks, detections, scrub_mode,
                session_id=sid,
                mapping_db=mapping_db,
                document_hash=source_hash,
            )
            reconstruct(tmp_path, chunks, anonymised, output_tmp)
            entity_counts = count_by_type(anonymised)

            # Build sanitised detection summary for UI
            detection_summary = _build_detection_summary(detections, chunks)

            # Build preview text — short version for inline card, full for preview tab
            preview_text = _build_preview(anonymised)
            full_scrubbed_text = _build_full_text(anonymised)

            # Cache scrubbed file in memory (not on disk beyond tmp)
            scrubbed_bytes = output_tmp.read_bytes()
            _SCRUB_CACHE[token] = scrubbed_bytes
            _SCRUB_META[token] = {
                "filename": f"{Path(filename).stem}_piiscrub{output_suffix}",
                "suffix": output_suffix,
                "entity_counts": entity_counts,
                "mode": mode,
                "session_id": sid,
                "full_text": full_scrubbed_text,
                "original_filename": filename,
            }

            del chunks, detections, anonymised
            gc.collect()

        except UnsupportedFormatError as exc:
            error_flag = True
            error_message = str(exc)
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:
            error_flag = True
            error_message = str(exc)
            raise HTTPException(status_code=500, detail=str(exc))
        finally:
            duration_ms = int((time.monotonic() - t_start) * 1000)
            output_hash = _hash_file_bytes(output_tmp.read_bytes()) if output_tmp.exists() else _hash_file_bytes(b"")

            # Write audit log
            try:
                audit_log = AuditLog()
                entry = make_audit_entry(
                    source_hash=source_hash,
                    output_hash=output_hash,
                    operator_hash=_hash_hostname(),
                    mode=mode,
                    entity_type_counts=entity_counts,
                    processing_duration_ms=duration_ms,
                    spacy_model=_model,
                    threshold=threshold,
                    error_flag=error_flag,
                    error_message=error_message,
                    session_id=sid,
                )
                audit_log.record(entry)
                audit_log.close()
            except Exception:
                pass

            if mapping_db:
                mapping_db.close()

            # Clean up temp files
            try:
                tmp_path.unlink(missing_ok=True)
                output_tmp.unlink(missing_ok=True)
            except Exception:
                pass

        return JSONResponse({
            "token": token,
            "entity_counts": entity_counts,
            "detection_summary": detection_summary,
            "preview": preview_text,
            "session_id": sid if scrub_mode == ScrubMode.PSEUDONYMISE else None,
            "duration_ms": duration_ms,
        })

    # ---------------------------------------------------------------------------
    # Text scrub endpoint
    # ---------------------------------------------------------------------------

    @app.post("/scrub-text")
    async def scrub_text(
        text: str = Form(...),
        mode: str = Form("redact"),
        threshold: float = Form(0.6),
        passphrase: Optional[str] = Form(None),
        session_id: Optional[str] = Form(None),
    ):
        scrub_mode = ScrubMode(mode)
        if scrub_mode == ScrubMode.PSEUDONYMISE and not passphrase:
            raise HTTPException(status_code=400, detail="passphrase required for pseudonymise mode")

        # Write text to temp .txt file
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w", encoding="utf-8") as tmp:
            tmp.write(text)
            tmp_path = Path(tmp.name)

        output_tmp = tmp_path.with_suffix(".out.txt")
        t_start = time.monotonic()
        source_hash = hashlib.sha256(text.encode()).hexdigest()
        entity_counts: dict[str, int] = {}
        sid = session_id or str(uuid.uuid4())
        mapping_db = None

        try:
            chunks = extract(tmp_path)
            detections = detect(chunks, _analyzer, score_threshold=threshold, entities=DEFAULT_ENTITIES)

            if scrub_mode == ScrubMode.PSEUDONYMISE:
                mapping_db = MappingDB(passphrase=passphrase)

            anonymised = anonymise(chunks, detections, scrub_mode, session_id=sid, mapping_db=mapping_db, document_hash=source_hash)
            reconstruct(tmp_path, chunks, anonymised, output_tmp)
            entity_counts = count_by_type(anonymised)

            scrubbed_text = output_tmp.read_text(encoding="utf-8")
            detection_summary = _build_detection_summary(detections, chunks)
            preview_text = scrubbed_text[:800]

            del chunks, detections, anonymised
            gc.collect()

        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))
        finally:
            if mapping_db:
                mapping_db.close()
            tmp_path.unlink(missing_ok=True)
            output_tmp.unlink(missing_ok=True)

        return JSONResponse({
            "scrubbed_text": scrubbed_text,
            "entity_counts": entity_counts,
            "detection_summary": detection_summary,
            "preview": preview_text,
            "session_id": sid if scrub_mode == ScrubMode.PSEUDONYMISE else None,
            "duration_ms": int((time.monotonic() - t_start) * 1000),
        })

    # ---------------------------------------------------------------------------
    # Download endpoint
    # ---------------------------------------------------------------------------

    @app.get("/preview/{token}", response_class=HTMLResponse)
    async def preview(token: str):
        """Serve an HTML preview of the scrubbed document — works for all formats.

        Browsers cannot render DOCX/XLSX/EML inline, so serving raw bytes with
        Content-Disposition: inline just triggers a download. Instead we render
        the scrubbed text as a styled HTML page with PII labels highlighted and
        a Download button. Does NOT consume the token.
        """
        if token not in _SCRUB_CACHE:
            return HTMLResponse(content=_render_preview_error(), status_code=404)
        meta = _SCRUB_META.get(token, {})
        return HTMLResponse(content=_render_preview_page(token, meta))

    @app.get("/download/{token}")
    async def download(token: str):
        if token not in _SCRUB_CACHE:
            raise HTTPException(status_code=404, detail="Token expired or not found")
        data = _SCRUB_CACHE.pop(token)
        meta = _SCRUB_META.pop(token, {})
        filename = meta.get("filename", "piiscrub_output.txt")
        return Response(
            content=data,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # ---------------------------------------------------------------------------
    # Audit log endpoint
    # ---------------------------------------------------------------------------

    @app.get("/audit")
    async def get_audit():
        import json
        audit_log = AuditLog()
        entries = audit_log.query()
        audit_log.close()
        return JSONResponse([
            {
                "event_id": e.event_id,
                "timestamp_utc": e.timestamp_utc,
                "mode": e.mode,
                "entity_type_counts": e.entity_type_counts,
                "processing_duration_ms": e.processing_duration_ms,
                "error_flag": e.error_flag,
            }
            for e in entries
        ])

    return app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_detection_summary(detections, chunks) -> list[dict]:
    """Build sanitised detection summary for UI (no full PII values)."""
    from collections import defaultdict
    chunk_map = {c.chunk_id: c for c in chunks}
    by_type: dict[str, list[str]] = defaultdict(list)

    for det in detections:
        original = det.original_text
        # Show first 3 chars + *** (never full value)
        if len(original) > 3:
            sanitised = original[:3] + "***"
        else:
            sanitised = "***"
        by_type[det.entity_type].append(sanitised)

    return [
        {
            "entity_type": entity_type,
            "count": len(examples),
            "example": examples[0] if examples else "***",
        }
        for entity_type, examples in sorted(by_type.items())
    ]


def _build_preview(anonymised_chunks) -> str:
    """Build inline preview of scrubbed text (first ~600 chars)."""
    parts = []
    total = 0
    for chunk in anonymised_chunks:
        if total >= 600:
            parts.append("…")
            break
        parts.append(chunk.scrubbed_text)
        total += len(chunk.scrubbed_text)
    return " ".join(parts)[:600]


def _build_full_text(anonymised_chunks) -> str:
    """Build the complete scrubbed text from all chunks (for HTML preview page)."""
    return "\n".join(chunk.scrubbed_text for chunk in anonymised_chunks)


def _render_preview_page(token: str, meta: dict) -> str:
    """Render a standalone HTML preview page for the scrubbed document."""
    import html as _html
    import re

    filename = meta.get("original_filename", "document")
    output_filename = meta.get("filename", "piiscrub_output")
    full_text = meta.get("full_text", "(No preview available)")
    char_count = len(full_text)

    # Escape HTML, then highlight [TYPE_N] placeholders in red
    escaped = _html.escape(full_text)
    highlighted = re.sub(
        r'\[([A-Z_]+_\d+)\]',
        r'<mark class="pii">[\1]</mark>',
        escaped,
    )
    # Preserve line breaks
    highlighted = highlighted.replace("\n", "<br>")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Preview — {_html.escape(output_filename)}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: system-ui, -apple-system, sans-serif; background: #f5f5f5; color: #222; }}
  .header {{ border-bottom: 2px solid #222; padding: 14px 32px; display: flex;
             justify-content: space-between; align-items: center; background: #fff; }}
  .logo {{ font-size: 16px; font-weight: 700; letter-spacing: -0.5px; }}
  .logo span {{ font-weight: 300; }}
  .meta {{ font-size: 12px; color: #888; }}
  .container {{ max-width: 860px; margin: 28px auto; padding: 0 20px 60px; }}
  .toolbar {{ display: flex; justify-content: space-between; align-items: center;
              margin-bottom: 16px; }}
  .doc-title {{ font-size: 15px; font-weight: 600; }}
  .char-count {{ font-size: 12px; color: #aaa; }}
  .btn-download {{ background: #222; color: #fff; border: none; border-radius: 6px;
                   padding: 10px 20px; font-size: 13px; font-weight: 600;
                   cursor: pointer; text-decoration: none; display: inline-block; }}
  .btn-download:hover {{ background: #444; }}
  .doc-body {{ background: #fff; border: 1px solid #ddd; border-radius: 8px;
               padding: 32px 40px; font-size: 13px; line-height: 1.9;
               font-family: Georgia, 'Times New Roman', serif; white-space: pre-wrap; }}
  mark.pii {{ background: #fdf0ed; color: #c0392b; font-weight: 700;
              border-radius: 3px; padding: 1px 3px; font-family: monospace;
              font-size: 12px; }}
  .legend {{ margin-top: 20px; font-size: 11px; color: #aaa; text-align: center; }}
</style>
</head>
<body>
<div class="header">
  <div class="logo">PII<span>Scrub</span> — Preview</div>
  <div class="meta">Running locally &mdash; no data leaves your machine</div>
</div>
<div class="container">
  <div class="toolbar">
    <div>
      <div class="doc-title">{_html.escape(filename)}</div>
      <div class="char-count">{char_count:,} characters</div>
    </div>
    <a href="/download/{token}" class="btn-download">⬇ Download Scrubbed Document</a>
  </div>
  <div class="doc-body">{highlighted}</div>
  <div class="legend">
    <mark class="pii" style="font-size:11px">[LABELS]</mark> indicate redacted PII.
    Download the document to get the full formatted version.<br>
    ⚠ Automated detection — human review recommended before sharing sensitive documents.
  </div>
</div>
</body>
</html>"""


def _render_preview_error() -> str:
    return """<!DOCTYPE html><html><body style="font-family:system-ui;padding:40px;color:#c00">
    <h2>Preview expired</h2><p>This preview link has expired. Please re-upload and scrub your document.</p>
    </body></html>"""


# ---------------------------------------------------------------------------
# HTML template
# ---------------------------------------------------------------------------

def _render_html() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PIIScrub — Local PII Scrubbing</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, sans-serif; background: #f5f5f5; color: #222; }
  .header { border-bottom: 2px solid #222; padding: 16px 32px; display: flex; justify-content: space-between; align-items: center; background: #fff; }
  .logo { font-size: 20px; font-weight: 700; letter-spacing: -0.5px; }
  .logo span { font-weight: 300; }
  .badge { font-size: 11px; border: 1px solid #aaa; padding: 3px 10px; border-radius: 10px; color: #555; }
  .container { max-width: 700px; margin: 32px auto; padding: 0 16px; }
  .section-label { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: #aaa; margin-bottom: 8px; }
  .card { background: #fff; border: 1px solid #ddd; border-radius: 8px; margin-bottom: 20px; overflow: hidden; }
  .tabs { display: flex; border-bottom: 1px solid #ddd; }
  .tab { flex: 1; padding: 12px; text-align: center; font-size: 13px; font-weight: 600; cursor: pointer; background: #f8f8f8; border-right: 1px solid #ddd; transition: background 0.15s; }
  .tab:last-child { border-right: none; }
  .tab.active { background: #fff; }
  .dropzone { padding: 40px 24px; text-align: center; cursor: pointer; border: 2px dashed transparent; transition: border-color 0.15s, background 0.15s; }
  .dropzone.drag-over { border-color: #222; background: #f9f9f9; }
  .dropzone.has-file { background: #f0f7f0; border-color: #6aad6a; }
  .dropzone .icon { font-size: 32px; margin-bottom: 10px; }
  .dropzone .label { font-size: 15px; font-weight: 600; margin-bottom: 4px; }
  .dropzone .sub { font-size: 13px; color: #888; }
  .formats { font-size: 11px; color: #aaa; margin-top: 10px; background: #f5f5f5; display: inline-block; padding: 3px 12px; border-radius: 4px; }
  #file-input { display: none; }
  .paste-area { display: none; padding: 0; }
  .paste-area textarea { width: 100%; height: 140px; border: none; padding: 16px; font-size: 13px; font-family: inherit; resize: vertical; outline: none; }
  .mode-row { display: flex; gap: 12px; padding: 16px; }
  .mode-card { flex: 1; border: 1px solid #ddd; border-radius: 6px; padding: 12px; cursor: pointer; transition: border-color 0.15s; }
  .mode-card.selected { border-color: #222; border-width: 2px; }
  .mode-label { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 3px; }
  .mode-desc { font-size: 12px; color: #666; line-height: 1.4; }
  #passphrase-field { display: none; padding: 0 16px 16px; }
  #passphrase-field input { width: 100%; border: 1px solid #ddd; border-radius: 6px; padding: 10px 12px; font-size: 13px; font-family: inherit; outline: none; }
  #passphrase-field input:focus { border-color: #222; }
  #passphrase-field .hint { font-size: 12px; color: #888; margin-top: 8px; line-height: 1.6; }
  .btn-primary { width: 100%; background: #222; color: #fff; border: none; border-radius: 6px; padding: 14px; font-size: 14px; font-weight: 600; cursor: pointer; margin-top: 4px; }
  .btn-primary:disabled { background: #aaa; cursor: not-allowed; }
  .btn-secondary { width: 100%; background: #fff; color: #555; border: 1px solid #ddd; border-radius: 6px; padding: 12px; font-size: 13px; cursor: pointer; margin-top: 8px; }
  #status { display: none; padding: 16px; text-align: center; font-size: 13px; color: #555; }
  #results { display: none; }
  .results-header { background: #f5f5f5; padding: 12px 16px; font-size: 13px; font-weight: 600; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; }
  .entity-row { display: flex; align-items: center; padding: 10px 16px; border-bottom: 1px solid #f5f5f5; font-size: 13px; }
  .entity-tag { font-size: 10px; font-weight: 700; border: 1px solid #ddd; padding: 2px 8px; border-radius: 3px; background: #fafafa; min-width: 130px; text-align: center; font-family: monospace; }
  .entity-example { color: #aaa; font-size: 11px; margin-left: 10px; font-style: italic; }
  .entity-count { margin-left: auto; font-size: 12px; color: #555; }
  .preview-body { padding: 16px; font-size: 13px; line-height: 1.8; color: #444; background: #fdfdfd; font-family: monospace; max-height: 200px; overflow-y: auto; }
  .placeholder { color: #c0392b; font-weight: 700; background: #fdf0ed; padding: 1px 3px; border-radius: 2px; }
  .download-section { padding: 16px; }
  #session-info { display: none; background: #fffbf0; border: 1px solid #f0d060; border-radius: 6px; padding: 12px; margin-bottom: 12px; font-size: 12px; color: #555; }
  #session-info strong { color: #333; }
  .review-notice { font-size: 12px; color: #7a5c00; background: #fffbeb; border: 1px solid #f0d060; border-radius: 6px; padding: 8px 12px; margin-bottom: 12px; }
  .footer { text-align: center; font-size: 11px; color: #aaa; margin-top: 32px; padding-bottom: 32px; line-height: 1.8; }
  .footer strong { color: #888; }
  .error-msg { background: #fef0f0; border: 1px solid #f0c0c0; border-radius: 6px; padding: 12px 16px; color: #c00; font-size: 13px; margin-top: 12px; display: none; }
  .spinner { display: inline-block; width: 16px; height: 16px; border: 2px solid #ddd; border-top-color: #222; border-radius: 50%; animation: spin 0.8s linear infinite; vertical-align: middle; margin-right: 8px; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>

<div class="header">
  <div class="logo">PII<span>Scrub</span></div>
  <div class="badge">● Running locally &mdash; no data leaves your machine</div>
</div>

<div class="container">

  <!-- Step 1: Input -->
  <div class="section-label">Step 1 &mdash; Add your document or text</div>
  <div class="card">
    <div class="tabs">
      <div class="tab active" onclick="switchTab('file')">⬆ Upload file</div>
      <div class="tab" onclick="switchTab('paste')">✎ Paste text</div>
    </div>

    <!-- File tab -->
    <div id="file-tab">
      <div class="dropzone" id="dropzone" onclick="document.getElementById('file-input').click()"
           ondragover="handleDragOver(event)" ondragleave="handleDragLeave(event)" ondrop="handleDrop(event)">
        <div class="icon">⬆</div>
        <div class="label" id="drop-label">Drop your document here</div>
        <div class="sub" id="drop-sub">or click to browse files</div>
        <div class="formats">PDF · DOCX · XLSX · CSV · EML · TXT</div>
      </div>
      <input type="file" id="file-input" accept=".pdf,.docx,.txt,.csv,.xlsx,.eml"
             onchange="handleFileSelect(event)">
    </div>

    <!-- Paste tab -->
    <div class="paste-area" id="paste-tab">
      <textarea id="paste-input" placeholder="Paste any text here — emails, case notes, letters, meeting notes..."></textarea>
    </div>
  </div>

  <!-- Step 2: Mode -->
  <div class="section-label">Step 2 &mdash; Choose what to do with PII</div>
  <div class="card">
    <div class="mode-row">
      <div class="mode-card selected" id="mode-redact" onclick="selectMode('redact')">
        <div class="mode-label">✓ Redact <span style="font-weight:400;color:#888">(Recommended)</span></div>
        <div class="mode-desc">Replace PII with [PERSON_1], [EMAIL_1] etc. Fully anonymous. Safe to send anywhere.</div>
      </div>
      <div class="mode-card" id="mode-pseudo" onclick="selectMode('pseudonymise')">
        <div class="mode-label">Pseudonymise</div>
        <div class="mode-desc">Replace with realistic fake data. Reversible with a passphrase. AI sees fake names.</div>
      </div>
    </div>
    <div id="passphrase-field">
      <input type="password" id="passphrase" placeholder="Enter passphrase (min 8 characters)" minlength="8">
      <div class="hint">
        🔐 <strong>Why a passphrase?</strong> Pseudonymise replaces real names and IDs with realistic fakes
        (e.g. "James Hargreaves" → "Oliver Bennett") so you can send the document to an AI safely.
        The original→fake mapping is saved to your machine, encrypted with this passphrase.
        To swap the AI's response back to real names, run
        <code style="background:#f5f5f5;padding:1px 4px;border-radius:3px">piiscrub restore</code> with the same passphrase.
        If you just want to permanently remove PII with no reversal, use <strong>Redact</strong> instead — no passphrase needed.
      </div>
    </div>
  </div>

  <!-- Scrub button -->
  <button class="btn-primary" id="scrub-btn" onclick="runScrub()" disabled>Scrub Document</button>
  <div id="status"></div>
  <div class="error-msg" id="error-msg"></div>

  <!-- Step 3 + 4: Results (hidden until scrub completes) -->
  <div id="results">
    <br>
    <div class="section-label">Step 3 &mdash; What was found</div>
    <div class="card">
      <div class="results-header">
        <span id="results-title">Detection results</span>
        <span id="results-count" style="color:#888;font-size:12px;font-weight:400"></span>
      </div>
      <div id="entity-rows"></div>
    </div>

    <div class="section-label">Step 4 &mdash; Preview scrubbed output</div>
    <div class="card">
      <div class="results-header"><span>Scrubbed output preview</span></div>
      <div class="preview-body" id="preview-body"></div>
    </div>

    <div class="card download-section">
      <div id="session-info"></div>
      <div class="review-notice">⚠ Automated detection — review the output before sharing sensitive documents.</div>
      <div id="download-area"></div>
      <button class="btn-secondary" onclick="resetUI()">↺ Scrub Another Document</button>
    </div>
  </div>

  <div class="footer">
    <strong>Your privacy is absolute.</strong><br>
    Processed entirely on your computer &middot; No data sent to any server<br>
    Audit log saved to ~/.piiscrub/audit.db &middot; GDPR Recital 26 compliant &middot; PIIScrub v0.1.0
  </div>
</div>

<script>
let selectedFile = null;
let selectedMode = 'redact';
let inputType = 'file';

function switchTab(tab) {
  inputType = tab;
  document.querySelectorAll('.tab').forEach((t, i) => {
    t.classList.toggle('active', (tab === 'file' && i === 0) || (tab === 'paste' && i === 1));
  });
  document.getElementById('file-tab').style.display = tab === 'file' ? 'block' : 'none';
  document.getElementById('paste-tab').style.display = tab === 'paste' ? 'block' : 'none';
  updateScrubBtn();
}

function handleDragOver(e) {
  e.preventDefault();
  document.getElementById('dropzone').classList.add('drag-over');
}
function handleDragLeave(e) {
  document.getElementById('dropzone').classList.remove('drag-over');
}
function handleDrop(e) {
  e.preventDefault();
  document.getElementById('dropzone').classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) setFile(file);
}
function handleFileSelect(e) {
  const file = e.target.files[0];
  if (file) setFile(file);
}
function setFile(file) {
  selectedFile = file;
  document.getElementById('drop-label').textContent = file.name;
  document.getElementById('drop-sub').textContent = (file.size / 1024).toFixed(1) + ' KB';
  document.getElementById('dropzone').classList.add('has-file');
  updateScrubBtn();
}

function selectMode(mode) {
  selectedMode = mode;
  document.getElementById('mode-redact').classList.toggle('selected', mode === 'redact');
  document.getElementById('mode-pseudo').classList.toggle('selected', mode === 'pseudonymise');
  document.getElementById('passphrase-field').style.display = mode === 'pseudonymise' ? 'block' : 'none';
  updateScrubBtn();
}

function updateScrubBtn() {
  const hasInput = inputType === 'file' ? !!selectedFile
    : document.getElementById('paste-input').value.trim().length > 0;
  const hasPass = selectedMode !== 'pseudonymise'
    || document.getElementById('passphrase').value.length >= 8;
  document.getElementById('scrub-btn').disabled = !(hasInput && hasPass);
}

document.getElementById('paste-input').addEventListener('input', updateScrubBtn);
document.getElementById('passphrase').addEventListener('input', updateScrubBtn);

async function runScrub() {
  document.getElementById('scrub-btn').disabled = true;
  document.getElementById('error-msg').style.display = 'none';
  document.getElementById('results').style.display = 'none';
  const status = document.getElementById('status');
  status.style.display = 'block';
  status.innerHTML = '<span class="spinner"></span>Detecting PII…';

  try {
    let resp;
    if (inputType === 'file') {
      const fd = new FormData();
      fd.append('file', selectedFile);
      fd.append('mode', selectedMode);
      if (selectedMode === 'pseudonymise') fd.append('passphrase', document.getElementById('passphrase').value);
      resp = await fetch('/scrub', { method: 'POST', body: fd });
    } else {
      const fd = new FormData();
      fd.append('text', document.getElementById('paste-input').value);
      fd.append('mode', selectedMode);
      if (selectedMode === 'pseudonymise') fd.append('passphrase', document.getElementById('passphrase').value);
      resp = await fetch('/scrub-text', { method: 'POST', body: fd });
    }

    let data;
    const ct = resp.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      data = await resp.json();
    } else {
      const txt = await resp.text();
      throw new Error('Server error: ' + txt.slice(0, 200));
    }
    if (!resp.ok) throw new Error(data.detail || 'Scrub failed');

    status.style.display = 'none';
    renderResults(data);

  } catch (err) {
    status.style.display = 'none';
    const errEl = document.getElementById('error-msg');
    errEl.textContent = '✗ ' + err.message;
    errEl.style.display = 'block';
    document.getElementById('scrub-btn').disabled = false;
  }
}

function renderResults(data) {
  const total = Object.values(data.entity_counts).reduce((a, b) => a + b, 0);
  document.getElementById('results-title').textContent = total === 0
    ? 'No PII detected' : `${total} items detected`;
  document.getElementById('results-count').textContent = data.duration_ms + 'ms';

  const rows = document.getElementById('entity-rows');
  rows.innerHTML = '';
  if (data.detection_summary.length === 0) {
    rows.innerHTML = '<div style="padding:16px;color:#888;font-size:13px">No PII found — document is clean.</div>';
  } else {
    data.detection_summary.forEach(d => {
      rows.innerHTML += `<div class="entity-row">
        <div class="entity-tag">${d.entity_type}</div>
        <span>${d.count} instance${d.count !== 1 ? 's' : ''}</span>
        <span class="entity-example">${d.example}</span>
        <span class="entity-count">${data.entity_counts[d.entity_type] || 0}</span>
      </div>`;
    });
  }

  // Preview with highlighted placeholders + truncation notice
  const preview = document.getElementById('preview-body');
  const escaped = (data.preview || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const highlighted = escaped.replace(/\[([\w_]+_\d+)\]/g, '<span class="placeholder">[$1]</span>');
  const fullLen = data.scrubbed_text ? data.scrubbed_text.length : (data.preview ? data.preview.length : 0);
  const previewLen = data.preview ? data.preview.length : 0;
  const truncated = fullLen > previewLen;
  const charNote = truncated
    ? `<div style="font-size:11px;color:#aaa;margin-bottom:6px">Preview — first ${previewLen.toLocaleString()} of ${fullLen.toLocaleString()} characters. Use Copy or Download for the full text.</div>`
    : '';
  preview.innerHTML = charNote + (highlighted || '<em style="color:#aaa">No preview available.</em>');

  // Session info for pseudonymise
  const sessionDiv = document.getElementById('session-info');
  if (data.session_id) {
    sessionDiv.style.display = 'block';
    sessionDiv.innerHTML = `<strong>🔑 Session ID:</strong> ${data.session_id}<br>
      <span>Keep this to restore original values after AI processing:<br>
      <code>piiscrub restore [file] ${data.session_id} --passphrase ...</code></span>`;
  } else {
    sessionDiv.style.display = 'none';
  }

  // Download / copy section
  const dlArea = document.getElementById('download-area');
  if (data.token) {
    // File mode: preview in new tab + download
    dlArea.innerHTML = `
      <a href="/preview/${data.token}" target="_blank" style="display:block;margin-bottom:8px">
        <button class="btn-secondary" style="width:100%">👁 Preview in New Tab</button></a>
      <a href="/download/${data.token}" download>
        <button class="btn-primary">⬇ Download Scrubbed Document</button></a>`;
  } else {
    // Text mode — copy to clipboard + download as .txt
    window._scrubbedText = data.scrubbed_text;
    dlArea.innerHTML = `
      <button class="btn-primary" onclick="copyToClipboard()" style="margin-bottom:8px">📋 Copy Scrubbed Text</button>
      <button class="btn-secondary" onclick="downloadTxt()">⬇ Download as .txt</button>`;
  }

  document.getElementById('results').style.display = 'block';
}

function copyToClipboard() {
  navigator.clipboard.writeText(window._scrubbedText || '').then(() => {
    const btn = document.querySelector('#download-area .btn-primary');
    btn.textContent = '✅ Copied!';
    setTimeout(() => { btn.textContent = '📋 Copy Scrubbed Text'; }, 2000);
  });
}

function downloadTxt() {
  const text = window._scrubbedText || '';
  const blob = new Blob([text], {type: 'text/plain'});
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement('a'), {href: url, download: 'scrubbed.txt'});
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function resetUI() {
  selectedFile = null;
  document.getElementById('drop-label').textContent = 'Drop your document here';
  document.getElementById('drop-sub').textContent = 'or click to browse files';
  document.getElementById('file-input').value = '';
  document.getElementById('paste-input').value = '';
  document.getElementById('dropzone').classList.remove('has-file');
  document.getElementById('results').style.display = 'none';
  document.getElementById('error-msg').style.display = 'none';
  document.getElementById('scrub-btn').disabled = true;
}
</script>
</body>
</html>"""
