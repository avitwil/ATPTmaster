"""Background OpenVPN manager — bring up a CTF/lab tunnel from a stored .ovpn.

Runs `openvpn` under `sudo` as a long-lived background process, streams its log
in a reader thread, and reports status (connecting → connected → down). The sudo
password is fed once on stdin (from privilege, memory only) and never stored.
Single active tunnel at a time. Stdlib-only; never raises.
"""
from __future__ import annotations
import atexit
import shutil
import subprocess
import threading
from pathlib import Path

_LOCK = threading.Lock()
_STATE: dict = {"proc": None, "status": "down", "config": None, "log": [],
                "error": None, "sudo_pw": None}
_ATEXIT_REGISTERED = False


def _have(binary: str) -> bool:
    return shutil.which(binary) is not None


def _reader(proc):
    for line in iter(proc.stdout.readline, ""):
        line = line.rstrip("\n")
        low = line.lower()
        with _LOCK:
            _STATE["log"].append(line)
            _STATE["log"] = _STATE["log"][-200:]
            if "initialization sequence completed" in low:
                _STATE["status"] = "connected"
            elif "auth_failed" in low or "auth-failure" in low:
                _STATE["status"] = "error"
                _STATE["error"] = "authentication failed"
            elif "incorrect password" in low or "sorry, try again" in low:
                _STATE["status"] = "error"
                _STATE["error"] = "sudo password rejected"
    with _LOCK:                                   # process ended
        if _STATE["status"] not in ("error",):
            _STATE["status"] = "down"
        _STATE["proc"] = None


def status() -> dict:
    with _LOCK:
        return {"status": _STATE["status"], "config": _STATE["config"],
                "error": _STATE["error"], "log_tail": "\n".join(_STATE["log"][-15:])}


def is_up() -> bool:
    with _LOCK:
        p = _STATE["proc"]
    return p is not None and p.poll() is None


def wait_connected(timeout: float = 30.0) -> bool:
    """Block until the tunnel reports 'connected', or give up. Used before a run
    so recon doesn't scan a route that isn't up yet. Returns True iff connected."""
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        s = status()["status"]
        if s == "connected":
            return True
        if s in ("error", "down"):
            return False
        time.sleep(0.2)
    return False


def connect(config_path: str, sudo_password: str | None = None) -> dict:
    p = Path(config_path or "")
    if not config_path or not p.is_file():
        return {"ok": False, "error": f"VPN config not found: {config_path}"}
    if not _have("openvpn"):
        return {"ok": False, "error": "openvpn not installed (sudo apt install -y openvpn)"}
    if is_up():
        return {"ok": True, "already": True, "status": status()["status"]}
    argv = ["sudo", "-S", "-p", "", "openvpn", "--config", str(p)]
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    if sudo_password is not None:
        try:
            proc.stdin.write(sudo_password + "\n")
            proc.stdin.flush()
        except Exception:
            pass
    with _LOCK:
        # sudo_pw kept in memory only (never on disk/log) so disconnect() can
        # elevate to kill the root-owned openvpn — same posture as privilege.py.
        _STATE.update(proc=proc, status="connecting", config=str(p), log=[],
                      error=None, sudo_pw=sudo_password)
    threading.Thread(target=_reader, args=(proc,), daemon=True).start()
    _ensure_atexit_teardown()
    return {"ok": True, "status": "connecting"}


def _ensure_atexit_teardown() -> None:
    """Register disconnect() to run when the process exits, so closing the app
    (desktop window close, or Ctrl-C on `atpt serve`) always tears the tunnel
    down instead of orphaning a root openvpn. Registered once per process."""
    global _ATEXIT_REGISTERED
    if not _ATEXIT_REGISTERED:
        atexit.register(disconnect)
        _ATEXIT_REGISTERED = True


def _elevated_kill(config: str) -> None:
    """Terminate the running openvpn. It runs as root under sudo, so a plain
    signal from this (unprivileged) process fails with EPERM — we must re-elevate.
    Targets exactly our tunnel by its --config path. Uses the in-memory sudo
    password captured at connect (falls back to `sudo -n` for NOPASSWD sudoers).
    Never raises."""
    with _LOCK:
        pw = _STATE.get("sudo_pw")
    pat = f"openvpn --config {config}"
    if pw is not None:
        argv, stdin = ["sudo", "-S", "-p", "", "pkill", "-TERM", "-f", pat], pw + "\n"
    else:
        argv, stdin = ["sudo", "-n", "pkill", "-TERM", "-f", pat], None
    try:
        subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=10)
    except Exception:
        pass


def disconnect() -> dict:
    with _LOCK:
        proc = _STATE["proc"]
        config = _STATE["config"]
    # Best-effort direct terminate first (harmless; works only if we happen to
    # own the process). openvpn runs as root under sudo, so this usually can't
    # signal it and we fall through to the elevated kill below.
    if proc and proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            pass
    # The real teardown: re-elevate to kill the root-owned openvpn by config path.
    if config:
        _elevated_kill(config)
    with _LOCK:
        _STATE.update(status="down", proc=None, config=None, sudo_pw=None)
    return {"ok": True, "status": "down"}
