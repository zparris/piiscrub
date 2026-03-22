# -*- mode: python ; coding: utf-8 -*-
#
# PIIScrub — PyInstaller build spec
#
# Build with:
#   uv run pyinstaller piiscrub.spec --clean
#
# Output: dist/PIIScrub/  (one-dir bundle, ~700 MB)
#
# NOTE: run this on each target platform (macOS / Windows / Linux) separately.
# GitHub Actions handles the matrix — see .github/workflows/release.yml.

import subprocess
import sys
from PyInstaller.utils.hooks import collect_all, collect_data_files

# ---------------------------------------------------------------------------
# Locate the spaCy en_core_web_lg model directory at build time
# ---------------------------------------------------------------------------
_model_result = subprocess.run(
    [
        sys.executable, "-c",
        "import en_core_web_lg, pathlib; "
        "print(pathlib.Path(en_core_web_lg.__file__).parent)",
    ],
    capture_output=True,
    text=True,
    check=True,
)
_spacy_model_dir = _model_result.stdout.strip()
print(f"[piiscrub.spec] spaCy model dir: {_spacy_model_dir}")

# ---------------------------------------------------------------------------
# Collect packages that use dynamic imports / native extensions
# ---------------------------------------------------------------------------
datas: list = []
binaries: list = []
hiddenimports: list = []

_collect_pkgs = [
    "fitz",               # PyMuPDF — native .so/.dll
    "uvicorn",            # ASGI server — dynamic protocol/loop loading
    "fastapi",            # web framework — dynamic middleware
    "starlette",          # fastapi dependency — dynamic routing
    "anyio",              # async backend — dynamic driver selection
    "pydantic",           # data validation — dynamic validators
    "spacy",              # NLP — Cython extensions, language registry
    "thinc",              # spaCy dependency — GPU backends, registry
    "presidio_analyzer",  # PII detection — recognizer registry
    "presidio_anonymizer",# PII anonymization — operator registry
    "structlog",          # logging — dynamic processors
    "faker",              # fake data generation — locale plugins
    "cryptography",       # encryption — native backends
    "sqlalchemy",         # ORM — dialect plugins
    "click",              # CLI — dynamic command loading
    "rich",               # terminal — renderable registry
]

for _pkg in _collect_pkgs:
    try:
        _d, _b, _h = collect_all(_pkg)
        datas += _d
        binaries += _b
        hiddenimports += _h
    except Exception as _exc:
        print(f"[piiscrub.spec] WARNING: collect_all({_pkg!r}) failed: {_exc}")

# spaCy model — bundle the entire package directory
datas += [(_spacy_model_dir, "en_core_web_lg")]

# presidio YAML pattern files (phone, email, etc.)
datas += collect_data_files("presidio_analyzer")

# python-docx template directory
datas += collect_data_files("docx")

# ---------------------------------------------------------------------------
# Explicit hidden imports PyInstaller's static analysis misses
# ---------------------------------------------------------------------------
hiddenimports += [
    # spaCy
    "spacy.lang.en",
    "spacy.lang.en.stop_words",
    "spacy.lang.en.punctuation",
    "spacy.lang.en.lex_attrs",
    "spacy.lexeme",
    "spacy.tokens",
    "spacy.vocab",
    "en_core_web_lg",
    # SQLAlchemy
    "sqlalchemy.dialects.sqlite",
    "sqlalchemy.dialects.sqlite.pysqlite",
    "sqlalchemy.ext.declarative",
    # uvicorn dynamic loaders
    "uvicorn.loops.auto",
    "uvicorn.loops.asyncio",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan.on",
    # presidio recognizers (loaded via registry, not static imports)
    "presidio_analyzer.predefined_recognizers",
    "presidio_analyzer.predefined_recognizers.en",
    # python-multipart (fastapi file uploads)
    "multipart",
    # anyio backends
    "anyio._backends._asyncio",
    # email extraction (eml support)
    "email",
    "email.mime",
    "email.mime.text",
    "email.mime.multipart",
]

# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
a = Analysis(
    ["src/piiscrub/__main__.py"],
    pathex=["src"],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "matplotlib",
        "notebook",
        "jupyter",
        "IPython",
        "PIL",       # Pillow — not used by piiscrub
        "PyQt5",
        "wx",
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="PIIScrub",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,      # UPX compression is known to break some .so files
    console=True,   # keep terminal open — shows startup URL and Ctrl+C hint
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="PIIScrub",
)
