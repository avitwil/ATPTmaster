"""Background OpenVPN manager — bring up a CTF/lab tunnel from a stored .ovpn.

Runs `openvpn` under `sudo` as a long-lived background process, streams its log
in a reader thread, and reports status (connecting → connected → down). The sudo
password is fed once on stdin (from privilege, memory only) and never stored.
Single active tunnel at a time. Stdlib-only; never raises.
"""
from __future__ import annotations
import shutil
import subprocess
import threading
from pathlib import Path

_LOCK = threading.Lock()
_STATE: dict = {"proc": None, "status": "down", "config": None, "log": [], "error": None}


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
        _STATE.update(proc=proc, status="connecting", config=str(p), log=[], error=None)
    threading.Thread(target=_reader, args=(proc,), daemon=True).start()
    return {"ok": True, "status": "connecting"}


def disconnect() -> dict:
    with _LOCK:
        proc = _STATE["proc"]
    if not proc or proc.poll() is not None:
        with _LOCK:
            _STATE["status"] = "down"
            _STATE["proc"] = None
        return {"ok": True, "status": "down"}
    try:
        proc.terminate()
        try:
            proc.wait(timeout=6)
        except Exception:
            proc.kill()
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    with _LOCK:
        _STATE["status"] = "down"
        _STATE["proc"] = None
    return {"ok": True, "status": "down"}
