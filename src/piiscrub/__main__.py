"""Entry point for PIIScrub desktop binary (PyInstaller).

When the user double-clicks PIIScrub.app or runs the binary directly,
this module starts the local web server and opens the browser automatically.

Port selection: tries 7890 first, then 7891–7899 if already in use.
"""
from __future__ import annotations

import socket
import threading
import time
import webbrowser


def _find_free_port(start: int = 7890, attempts: int = 10) -> int:
    """Return the first free TCP port starting from *start*."""
    for port in range(start, start + attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return start  # fallback — uvicorn will surface the bind error clearly


def main() -> None:
    port = _find_free_port()
    url = f"http://localhost:{port}"

    print()
    print("  PIIScrub — local PII scrubber")
    print(f"  Starting at {url}")
    print("  Press Ctrl+C to stop")
    print()

    def _open_browser() -> None:
        time.sleep(1.5)
        webbrowser.open(url)

    threading.Thread(target=_open_browser, daemon=True).start()

    try:
        import uvicorn
        from piiscrub.web import create_app

        app = create_app(high_accuracy=False)
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    except ImportError as exc:
        print(f"\n  Error: missing dependency — {exc}")
        print("  This binary may be incomplete. Please re-download from GitHub.")
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("\n  PIIScrub stopped.")


if __name__ == "__main__":
    main()
