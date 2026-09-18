"""atpt desktop — run the web console as a native desktop app.

Starts the existing web server (atpt/web.py) on a private localhost port in a
background thread, then opens it in a native OS window (pywebview: WKWebView on
macOS, WebKitGTK on Linux). If pywebview is unavailable, it falls back to a
chromeless browser app-window, so `atpt desktop` still works from a plain source
checkout. The core stays dependency-free — pywebview is imported lazily.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "ATPTmaster"


def data_home(env=None, platform=None) -> Path:
    """Per-user writable directory for engagement state, uploads and reports.

    A double-clicked bundle runs from a read-only location, so state must live
    elsewhere. An explicit ATPT_HOME always wins (used by the source-checkout
    launcher). Otherwise: ~/Library/Application Support/ATPTmaster on macOS,
    $XDG_DATA_HOME/ATPTmaster (default ~/.local/share/ATPTmaster) on Linux.
    """
    env = os.environ if env is None else env
    if env.get("ATPT_HOME"):
        return Path(env["ATPT_HOME"])
    platform = sys.platform if platform is None else platform
    home = Path(env.get("HOME", str(Path.home())))
    if platform == "darwin":
        return home / "Library" / "Application Support" / APP_NAME
    xdg = env.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else home / ".local" / "share"
    return base / APP_NAME


def pick_free_port(host: str) -> int:
    """Ask the OS for an unused TCP port on `host` and return it."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, 0))
        return s.getsockname()[1]


class _Server:
    """A running console server plus the thread it runs in."""

    def __init__(self, httpd, thread, host, port):
        self._httpd = httpd
        self._thread = thread
        self.host = host
        self.port = port

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


def start_server(project_dir, host="127.0.0.1", port=None) -> _Server:
    """Start the web console on a background daemon thread and return a handle."""
    import threading

    from .web import make_server

    port = pick_free_port(host) if port is None else port
    httpd = make_server(project_dir, port=port, host=host)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return _Server(httpd, thread, host, port)


def wait_until_ready(host: str, port: int, timeout: float = 10.0) -> bool:
    """Poll the port until it accepts a connection, or the timeout elapses."""
    import socket
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def bundle_root() -> Path:
    """Directory holding the shipped code + resources (modules/, atpt/assets/).

    In a PyInstaller bundle that is the extracted _MEIPASS dir; from a source
    checkout it is the repo root (the parent of the atpt package).
    """
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return Path(meipass)
    return Path(__file__).resolve().parent.parent


def prepare_home(code_root: Path, home: Path) -> Path:
    """Seed a writable data home from the bundled resources and return it.

    Copies `modules/` and `atpt/assets/` into `home` if they are not already
    there (first run of a packaged app), never overwriting a user's copy, and
    ensures `home/var/` exists. When `home` is the code root itself (a source
    checkout), nothing is copied. Returns the directory to serve from.
    """
    import shutil

    code_root, home = Path(code_root), Path(home)
    home.mkdir(parents=True, exist_ok=True)
    if code_root.resolve() != home.resolve():
        for rel in ("modules", "atpt/assets"):
            src, dst = code_root / rel, home / rel
            if src.is_dir() and not dst.exists():
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(src, dst)
    (home / "var").mkdir(parents=True, exist_ok=True)
    return home


def _open_native(url: str, title: str = APP_NAME) -> None:
    """Open a native OS window (pywebview). Raises ImportError if unavailable.

    Blocks until the user closes the window.
    """
    import webview  # optional dependency; installed only for the desktop path

    webview.create_window(title, url, width=1200, height=820, min_size=(900, 600))
    webview.start()


def _open_browser(url: str) -> None:
    """Fallback: open the console in a chromeless browser app-window and block.

    Prefers a Chromium-family browser with --app= (no tabs/address bar). If none
    is found, opens the default browser and blocks so the daemon server stays up.
    """
    import shutil
    import subprocess
    import webbrowser

    for exe in ("google-chrome", "chromium", "chromium-browser", "brave-browser",
                "microsoft-edge"):
        path = shutil.which(exe)
        if path:
            proc = subprocess.Popen([path, f"--app={url}"])
            proc.wait()
            return
    # macOS: Google Chrome installed as an app bundle rather than on PATH.
    if sys.platform == "darwin" and Path(
        "/Applications/Google Chrome.app"
    ).exists():
        proc = subprocess.Popen(
            ["open", "-n", "-W", "-a", "Google Chrome", "--args", f"--app={url}"]
        )
        proc.wait()
        return
    webbrowser.open(url)
    print(f"ATPTmaster desktop: console at {url}  (Ctrl-C to quit)")
    try:
        import time

        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


def open_window(url: str, title: str = APP_NAME, native=None, browser=None) -> str:
    """Open the console window, preferring native and falling back to browser.

    Returns "native" or "browser" to say which path was taken. Blocks until the
    window (or fallback browser) is closed.
    """
    native = _open_native if native is None else native
    browser = _open_browser if browser is None else browser
    try:
        native(url, title)
        return "native"
    except ImportError:
        browser(url)
        return "browser"


def launch(host: str = "127.0.0.1") -> int:
    """Start the console and open it as a desktop app. Blocks until closed."""
    project_dir = prepare_home(bundle_root(), data_home())
    os.environ["ATPT_HOME"] = str(project_dir)
    srv = start_server(project_dir, host=host)
    try:
        if not wait_until_ready(srv.host, srv.port, timeout=15):
            print("error: console server did not start", file=sys.stderr)
            return 1
        open_window(f"http://{srv.host}:{srv.port}/")
    finally:
        from . import vpn
        vpn.disconnect()          # never leave a THM/lab tunnel up after the app closes
        srv.stop()
    return 0
