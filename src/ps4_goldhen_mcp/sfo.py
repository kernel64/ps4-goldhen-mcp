"""param.sfo reader (PS4 app metadata: TITLE, TITLE_ID, CONTENT_ID, APP_VER, CATEGORY...)."""

from __future__ import annotations

import struct


def parse_sfo(data: bytes) -> dict:
    if len(data) < 20 or data[:4] != b"\0PSF":
        raise ValueError("not a param.sfo")
    _ver, key_off, data_off, count = struct.unpack_from("<IIII", data, 4)
    out: dict = {}
    for i in range(count):
        k_off, fmt, length, _max, d_off = struct.unpack_from("<HHIII", data, 20 + 16 * i)
        end = data.index(b"\0", key_off + k_off)
        key = data[key_off + k_off:end].decode("ascii", "replace")
        raw = data[data_off + d_off:data_off + d_off + length]
        if fmt == 0x0404:
            out[key] = struct.unpack("<I", raw[:4])[0]
        else:
            out[key] = raw.split(b"\0", 1)[0].decode("utf-8", "replace")
    return out


def pkg_content_id(path: str) -> str:
    """Content ID stored in a .pkg header (offset 0x40, 36 bytes)."""
    with open(path, "rb") as f:
        head = f.read(0x80)
    if head[:4] != b"\x7fCNT":
        raise ValueError(f"{path} is not a PS4 package")
    return head[0x40:0x40 + 36].decode("ascii", "replace")
