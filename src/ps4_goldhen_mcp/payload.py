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

from .config import cache_dir

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
