"""Sending payloads to GoldHEN's BinLoader (TCP 9090) and getting ps4debug.bin.

The BinLoader takes whatever arrives on one connection as a payload: an empty connection (a port
probe) makes it stop listening until it is re-enabled in the GoldHEN menu. So this module never
probes 9090; it only connects to send real data.
"""

from __future__ import annotations

import hashlib
import socket
import time
import urllib.request
from pathlib import Path
from typing import Callable

from .config import Config, cache_dir
from .lock import _os_lock
from .ps4debug import Ps4DebugUnavailable

PS4DEBUG_VERSION = "v1.1.19"
PS4DEBUG_URL = f"https://github.com/GoldHEN/ps4debug/releases/download/{PS4DEBUG_VERSION}/ps4debug_{PS4DEBUG_VERSION}.bin"
PS4DEBUG_SHA256 = "8af40c2412768bb2cd64c46b9913ee2f7ff2f076c98f6a2f5c7c0534aee15b2e"


class PayloadError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ps4debug_bin(configured: str | None = None, download: bool = True) -> Path:
    """Local ps4debug.bin: PS4_PS4DEBUG_BIN, else the cached official release (downloaded once from
    GoldHEN's GitHub and checked against its known SHA-256)."""
    if configured:
        p = Path(configured).expanduser()
        if not p.is_file():
            raise PayloadError(f"PS4_PS4DEBUG_BIN={p} not found")
        return p
    p = cache_dir() / f"ps4debug_{PS4DEBUG_VERSION}.bin"
    if p.is_file() and sha256(p.read_bytes()) == PS4DEBUG_SHA256:
        return p
    if not download:
        raise PayloadError("ps4debug.bin not cached; set PS4_PS4DEBUG_BIN")
    with urllib.request.urlopen(PS4DEBUG_URL, timeout=30) as r:
        data = r.read()
    if sha256(data) != PS4DEBUG_SHA256:
        raise PayloadError(f"downloaded ps4debug has an unexpected SHA-256 ({sha256(data)}); not using it")
    p.write_bytes(data)
    return p


def send(host: str, port: int, data: bytes, timeout: float = 10.0) -> int:
    if not data:
        raise PayloadError("empty payload (it would disarm the BinLoader)")
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        raise PayloadError(
            f"BinLoader {host}:{port} not listening ({e}). Enable it in GoldHEN (Settings > BinLoader Server); "
            "after a payload or an empty connection it may need re-enabling."
        ) from e
    with s:
        s.sendall(data)
        s.shutdown(socket.SHUT_WR)
    return len(data)


def port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Not for the BinLoader port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class Ps4DebugLoader:
    """Loads ps4debug when a tool needs it and it is not running (after every console boot).

    Given to Ps4Debug(loader=...). Several processes share the console, so the load happens under
    a machine-wide lock and only if the port is still closed once the lock is held. Nothing is sent
    in read-only mode, while another session holds the console reservation, or when GoldHEN's FTP
    does not answer (console off or in rest mode). After a failure the same error is returned for a
    while instead of sending the payload again on every call."""

    def __init__(self, cfg: Config, busy: Callable[[], str | None] | None = None):
        self.cfg, self.busy = cfg, busy
        self.loads = 0
        self.last_load: dict | None = None
        self._retry_at = 0.0
        self._error = ""

    def _fail(self, message: str, retry_after: float) -> None:
        self._error = message
        self._retry_at = time.monotonic() + retry_after
        raise Ps4DebugUnavailable(message)

    def __call__(self) -> bool:
        c = self.cfg
        if c.read_only:
            raise Ps4DebugUnavailable("ps4debug is not loaded and the server is read-only (PS4_READ_ONLY=1)")
        if not c.auto_load_ps4debug:
            raise Ps4DebugUnavailable("ps4debug is not loaded: ps4_load_ps4debug (auto-loading is off, "
                                      "PS4_AUTO_LOAD_PS4DEBUG=0)")
        if time.monotonic() < self._retry_at:
            raise Ps4DebugUnavailable(self._error)
        if self.busy and (holder := self.busy()):
            raise Ps4DebugUnavailable(f"ps4debug is not loaded and the console is reserved by {holder}; "
                                      "it is loaded on first use once the console is free")
        with _os_lock(cache_dir() / f"ps4debug-load-{c.host}.lock", timeout=45):
            if port_open(c.host, c.debug_port):
                return True  # another process loaded it while we waited
            if not port_open(c.host, c.ftp_port, timeout=3):
                self._fail(f"the console does not answer on GoldHEN's FTP ({c.host}:{c.ftp_port}): it is off, in "
                           "rest mode, or GoldHEN is not running (after a reboot the user has to enable it "
                           "again)", 10)
            try:
                path = ps4debug_bin(c.ps4debug_bin)
                n = send(c.host, c.binloader_port, path.read_bytes())
            except (PayloadError, OSError) as e:
                self._fail(f"could not load ps4debug: {e}", 10)
            up = wait_port(c.host, c.debug_port, 15)
            if up is None:
                self._fail(f"ps4debug was sent to the BinLoader ({n} bytes) but port {c.debug_port} did not open "
                           "within 15 s: check that the BinLoader is enabled in GoldHEN (it can need re-enabling "
                           "after a payload), then retry", 60)
            self.loads += 1
            self.last_load = {"at": time.strftime("%H:%M:%S"), "up_after_s": up}
            return True


def wait_port(host: str, port: int, timeout: float) -> float | None:
    """Seconds until host:port accepts a connection (None on timeout). Not for the BinLoader port."""
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                return round(time.monotonic() - t0, 2)
        except OSError:
            time.sleep(0.5)
    return None
