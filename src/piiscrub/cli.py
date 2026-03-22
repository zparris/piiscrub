"""PIIScrub CLI — Click-based interface with Rich terminal output.

Commands:
  piiscrub scrub [FILE]     Scrub a single document
  piiscrub batch [FOLDER]   Scrub all supported files in a folder
  piiscrub restore [FILE]   Restore pseudonymised output using mapping table
  piiscrub audit export     Export GDPR audit log to CSV
  piiscrub serve            Start local web UI at http://localhost:7890
  piiscrub --version        Show version info

Security:
  - os.umask(0o177) at startup → DB files created with 600 permissions
  - AnalyzerEngine instantiated ONCE per process (2-4s spaCy model load)
  - MappingDB instantiated ONCE per invocation, passed through
  - gc.collect() after each document processed
"""

from __future__ import annotations

import gc
import hashlib
import os
import socket
import stat
import time
import uuid
from pathlib import Path
from typing import Optional

import click
import spacy
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from piiscrub import __version__
from piiscrub._logging import configure_logging, get_logger
from piiscrub.audit import AuditLog, make_audit_entry
from piiscrub.extractor import UnsupportedFormatError, extract
from piiscrub.models import DEFAULT_ENTITIES, ScrubMode

console = Console()
_log = get_logger("cli")

_SUPPORTED_EXTENSIONS = {".pdf", ".docx", ".txt", ".csv", ".xlsx", ".eml"}
_DEFAULT_SPACY_MODEL = "en_core_web_lg"
_DEFAULT_PORT = 7890


def _hash_file(path: Path) -> str:
    """sha256 of file content — used for audit log source_hash."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _hash_hostname() -> str:
    return hashlib.sha256(socket.gethostname().encode("utf-8")).hexdigest()


def _check_spacy_model(model_name: str) -> None:
    """Check spaCy model is installed; print helpful error if not."""
    if not spacy.util.is_package(model_name):
        console.print(f"\n[bold red]✗ spaCy model '{model_name}' is not installed.[/bold red]")
        console.print(f"  Run: [cyan]python -m spacy download {model_name}[/cyan]\n")
        raise SystemExit(1)


def _build_analyzer(high_accuracy: bool):
    """Build AnalyzerEngine. Called once per CLI invocation."""
    from piiscrub.detector import build_analyzer
    model = "en_core_web_trf" if high_accuracy else _DEFAULT_SPACY_MODEL
    if high_accuracy:
        console.print(
            "[yellow]⚠ High-accuracy mode uses a transformer model — "
            "processing will be significantly slower.[/yellow]"
        )
    _check_spacy_model(model)
    return build_analyzer(high_accuracy=high_accuracy), model


def _run_scrub(
    input_path: Path,
    output_path: Path,
    mode: ScrubMode,
    analyzer,
    audit_log: Optional[AuditLog],
    threshold: float,
    entities: list[str],
    spacy_model: str,
    session_id: Optional[str] = None,
    mapping_db=None,
    passphrase: Optional[str] = None,
) -> dict[str, int]:
    """Core scrub pipeline. Returns entity_type_counts."""
    from piiscrub.anonymiser import anonymise, count_by_type
    from piiscrub.detector import detect
    from piiscrub.output import get_output_extension, reconstruct

    t_start = time.monotonic()
    source_hash = _hash_file(input_path)
    error_flag = False
    error_message = ""
    entity_counts: dict[str, int] = {}

    try:
        chunks = extract(input_path)
        detections = detect(chunks, analyzer, score_threshold=threshold, entities=entities)
        anonymised = anonymise(
            chunks, detections, mode,
            session_id=session_id,
            mapping_db=mapping_db,
            document_hash=source_hash,
        )
        reconstruct(input_path, chunks, anonymised, output_path)
        entity_counts = count_by_type(anonymised)

        del chunks, detections, anonymised
        gc.collect()

    except Exception as exc:
        error_flag = True
        error_message = str(exc)
        raise
    finally:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        output_hash = _hash_file(output_path) if output_path.exists() else _hash_text("")

        if audit_log is not None:
            try:
                entry = make_audit_entry(
                    source_hash=source_hash,
                    output_hash=output_hash,
                    operator_hash=_hash_hostname(),
                    mode=mode.value,
                    entity_type_counts=entity_counts,
                    processing_duration_ms=duration_ms,
                    spacy_model=spacy_model,
                    threshold=threshold,
                    error_flag=error_flag,
                    error_message=error_message,
                    session_id=session_id,
                )
                audit_log.record(entry)
            except Exception as audit_exc:
                _log.warning("audit_write_failed", error=str(audit_exc))

    return entity_counts


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(
    version=__version__,
    prog_name="PIIScrub",
    message=f"PIIScrub %(version)s | spaCy model: {_DEFAULT_SPACY_MODEL}",
)
def cli() -> None:
    """PIIScrub — scrub PII from documents locally before sending to cloud AI.

    Data never leaves your machine. GDPR Recital 26 compliant.
    """
    # Set umask so all created files default to 600
    os.umask(0o177)
    configure_logging()


# ---------------------------------------------------------------------------
# scrub command
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--mode", type=click.Choice(["redact", "pseudonymise"]), default="redact",
              show_default=True, help="Redaction mode")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Output file path (default: {filename}_piiscrub.{ext})")
@click.option("--threshold", type=float, default=0.6, show_default=True,
              help="Detection confidence threshold (0.0–1.0)")
@click.option("--high-accuracy", is_flag=True, default=False,
              help="Use transformer NER model (slower, higher recall)")
@click.option("--formats", default=None,
              help="Comma-separated entity types to detect (default: all)")
@click.option("--no-audit", is_flag=True, default=False,
              help="Skip audit log entry (not recommended for GDPR accountability)")
@click.option("--passphrase", envvar="PIISCRUB_PASSPHRASE", default=None,
              help="Passphrase for pseudonymise mode (or set PIISCRUB_PASSPHRASE env var)")
@click.option("--session", default=None,
              help="Session ID for cross-document pseudonymisation consistency")
def scrub(
    file: Path,
    mode: str,
    output: Optional[Path],
    threshold: float,
    high_accuracy: bool,
    formats: Optional[str],
    no_audit: bool,
    passphrase: Optional[str],
    session: Optional[str],
) -> None:
    """Scrub PII from a single document."""
    from piiscrub.output import get_output_extension
    scrub_mode = ScrubMode(mode)

    # Passphrase required for pseudonymise
    if scrub_mode == ScrubMode.PSEUDONYMISE and not passphrase:
        passphrase = click.prompt(
            "Passphrase for pseudonymisation mapping",
            hide_input=True,
        )

    # Default output path — PDFs output as DOCX for reflowable layout
    if output is None:
        out_ext = get_output_extension(file.suffix)
        output = file.parent / f"{file.stem}_piiscrub{out_ext}"

    entities = formats.split(",") if formats else DEFAULT_ENTITIES

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Loading detection engine…", total=None)
        analyzer, spacy_model = _build_analyzer(high_accuracy)

    mapping_db = None
    session_id = session or str(uuid.uuid4())

    if scrub_mode == ScrubMode.PSEUDONYMISE:
        from piiscrub.mapping import MappingDB
        mapping_db = MappingDB(passphrase=passphrase)

    audit_log = None if no_audit else AuditLog()

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task(f"Scrubbing {file.name}…", total=None)
            entity_counts = _run_scrub(
                input_path=file,
                output_path=output,
                mode=scrub_mode,
                analyzer=analyzer,
                audit_log=audit_log,
                threshold=threshold,
                entities=entities,
                spacy_model=spacy_model,
                session_id=session_id,
                mapping_db=mapping_db,
                passphrase=passphrase,
            )

    except UnsupportedFormatError as exc:
        console.print(f"\n[bold red]✗ {exc}[/bold red]")
        raise SystemExit(1)
    except FileNotFoundError:
        console.print(f"\n[bold red]✗ File not found: {file}[/bold red]")
        raise SystemExit(1)
    except Exception as exc:
        console.print(f"\n[bold red]✗ Error: {exc}[/bold red]")
        raise SystemExit(1)
    finally:
        if mapping_db:
            mapping_db.close()
        if audit_log:
            audit_log.close()

    # Success output
    _print_summary(entity_counts, output, scrub_mode, session_id if scrub_mode == ScrubMode.PSEUDONYMISE else None)


def _print_summary(
    entity_counts: dict[str, int],
    output_path: Path,
    mode: ScrubMode,
    session_id: Optional[str],
) -> None:
    console.print()
    if not entity_counts:
        console.print("[green]✅ No PII detected — document passed through unchanged.[/green]")
    else:
        table = Table(title="PII Scrub Summary", show_header=True, header_style="bold")
        table.add_column("Entity Type", style="cyan")
        table.add_column("Count", justify="right")
        table.add_column("Action", style="green")

        action = "Redacted" if mode == ScrubMode.REDACT else "Pseudonymised"
        for entity_type, count in sorted(entity_counts.items()):
            table.add_row(entity_type, str(count), action)

        console.print(table)

    console.print(f"\n[bold green]✅ Saved to:[/bold green] {output_path}")

    if mode == ScrubMode.PSEUDONYMISE and session_id:
        console.print(f"[yellow]🔑 Session ID:[/yellow] {session_id}")
        console.print("[dim]Keep this ID to restore original values after AI processing.[/dim]")

    console.print("[dim]Audit log updated: ~/.piiscrub/audit.db[/dim]")
    console.print("[yellow]⚠[/yellow]  [dim]Automated detection — review the output before sharing sensitive documents.[/dim]")


# ---------------------------------------------------------------------------
# batch command
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("folder", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--mode", type=click.Choice(["redact", "pseudonymise"]), default="redact",
              show_default=True)
@click.option("--output-dir", "-o", type=click.Path(path_type=Path), required=False,
              default=None, help="Output directory (default: same as input)")
@click.option("--threshold", type=float, default=0.6, show_default=True)
@click.option("--high-accuracy", is_flag=True, default=False)
@click.option("--passphrase", envvar="PIISCRUB_PASSPHRASE", default=None)
@click.option("--session", default=None, help="Shared session ID for cross-document consistency")
def batch(
    folder: Path,
    mode: str,
    output_dir: Optional[Path],
    threshold: float,
    high_accuracy: bool,
    passphrase: Optional[str],
    session: Optional[str],
) -> None:
    """Scrub all supported documents in a folder."""
    from piiscrub.output import get_output_extension
    scrub_mode = ScrubMode(mode)

    if scrub_mode == ScrubMode.PSEUDONYMISE and not passphrase:
        passphrase = click.prompt("Passphrase for pseudonymisation mapping", hide_input=True)

    files = [
        f for f in folder.rglob("*")
        if f.is_file() and f.suffix.lower() in _SUPPORTED_EXTENSIONS
    ]

    if not files:
        console.print(f"[yellow]No supported files found in {folder}[/yellow]")
        return

    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

    analyzer, spacy_model = _build_analyzer(high_accuracy)

    mapping_db = None
    session_id = session or str(uuid.uuid4())
    if scrub_mode == ScrubMode.PSEUDONYMISE:
        from piiscrub.mapping import MappingDB
        mapping_db = MappingDB(passphrase=passphrase)

    audit_log = AuditLog()
    total_counts: dict[str, int] = {}
    success, failed = 0, 0

    with Progress(console=console) as progress:
        task = progress.add_task("Processing files…", total=len(files))

        for file in files:
            out_ext = get_output_extension(file.suffix)
            if output_dir:
                out = output_dir / f"{file.stem}_piiscrub{out_ext}"
            else:
                out = file.parent / f"{file.stem}_piiscrub{out_ext}"

            progress.update(task, description=f"Scrubbing {file.name}…")
            try:
                counts = _run_scrub(
                    input_path=file,
                    output_path=out,
                    mode=scrub_mode,
                    analyzer=analyzer,
                    audit_log=audit_log,
                    threshold=threshold,
                    entities=DEFAULT_ENTITIES,
                    spacy_model=spacy_model,
                    session_id=session_id,
                    mapping_db=mapping_db,
                )
                for k, v in counts.items():
                    total_counts[k] = total_counts.get(k, 0) + v
                success += 1
            except Exception as exc:
                console.print(f"[red]✗ {file.name}: {exc}[/red]")
                failed += 1
            finally:
                progress.advance(task)

    if mapping_db:
        mapping_db.close()
    audit_log.close()

    console.print(f"\n[bold green]✅ Batch complete:[/bold green] {success} scrubbed, {failed} failed")
    if total_counts:
        _print_summary(total_counts, output_dir or folder, scrub_mode, None)


# ---------------------------------------------------------------------------
# restore command
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.argument("session_id")
@click.option("--passphrase", envvar="PIISCRUB_PASSPHRASE", required=False, default=None)
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
def restore(
    file: Path,
    session_id: str,
    passphrase: Optional[str],
    output: Optional[Path],
) -> None:
    """Restore pseudonymised values in AI output using mapping table.

    FILE: the AI's output file containing fake values (from pseudonymise mode)
    SESSION_ID: the session ID printed when the document was originally scrubbed
    """
    if not passphrase:
        passphrase = click.prompt("Passphrase used during pseudonymisation", hide_input=True)

    from piiscrub.mapping import MappingDB

    db = MappingDB(passphrase=passphrase)
    replacements = db.get_session_replacements(session_id, passphrase)
    db.close()

    if not replacements:
        console.print(f"[yellow]No mappings found for session {session_id}[/yellow]")
        raise SystemExit(1)

    text = file.read_text(encoding="utf-8", errors="replace")
    for fake, real in replacements.items():
        text = text.replace(fake, real)

    if output is None:
        output = file.parent / f"{file.stem}_restored{file.suffix}"

    output.write_text(text, encoding="utf-8")
    console.print(f"\n[bold green]✅ Restored {len(replacements)} values → {output}[/bold green]")


# ---------------------------------------------------------------------------
# audit command
# ---------------------------------------------------------------------------

@cli.group()
def audit() -> None:
    """GDPR audit log commands."""


@audit.command("export")
@click.option("--output", "-o", type=click.Path(path_type=Path),
              default=Path("audit_export.csv"), show_default=True)
@click.option("--since", type=click.DateTime(), default=None)
@click.option("--until", type=click.DateTime(), default=None)
def audit_export(output: Path, since, until) -> None:
    """Export audit log to CSV for DPIA/ICO accountability evidence."""
    log = AuditLog()
    count = log.export_csv(output)
    log.close()
    if count == 0:
        console.print("[yellow]Audit log is empty.[/yellow]")
    else:
        console.print(f"[bold green]✅ Exported {count} entries → {output}[/bold green]")


# ---------------------------------------------------------------------------
# serve command (web UI)
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--port", default=_DEFAULT_PORT, show_default=True,
              help="Port to listen on")
@click.option("--no-browser", is_flag=True, default=False,
              help="Don't open browser automatically")
@click.option("--high-accuracy", is_flag=True, default=False)
def serve(port: int, no_browser: bool, high_accuracy: bool) -> None:
    """Start local web UI at http://localhost:{port}.

    Data never leaves your machine.
    """
    _check_spacy_model("en_core_web_trf" if high_accuracy else _DEFAULT_SPACY_MODEL)

    console.print(f"\n[bold]PIIScrub Web UI[/bold]")
    console.print(f"Starting at [cyan]http://localhost:{port}[/cyan]")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    if not no_browser:
        import threading
        import webbrowser
        def _open():
            import time
            time.sleep(1.2)
            webbrowser.open(f"http://localhost:{port}")
        threading.Thread(target=_open, daemon=True).start()

    try:
        import uvicorn
        from piiscrub.web import create_app
        app = create_app(high_accuracy=high_accuracy)
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    except ImportError:
        console.print("[red]✗ Web UI requires uvicorn and fastapi.[/red]")
        console.print("  Run: [cyan]pip install piiscrub[web][/cyan]")
        raise SystemExit(1)


if __name__ == "__main__":
    cli()
