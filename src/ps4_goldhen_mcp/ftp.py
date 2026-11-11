"""File access through GoldHEN's FTP server (port 2121, anonymous).

GoldHEN's server is small: it prefers a single client, lists with Unix-style LIST lines and has no
MLSD. Each operation opens a session (or reuses the one already open) under a lock, and retries
once on a dropped connection.
"""

from __future__ import annotations

import contextlib
import ftplib
import hashlib
import io
import posixpath
import re
import socket
import threading
import time
from pathlib import Path

_LIST_RE = re.compile(
    r"^(?P<mode>[\-dlcbps][rwxsStT\-]{9})\s+\d+\s+\S+\s+\S+\s+(?P<size>\d+)\s+"
    r"(?P<date>\w{3}\s+\d{1,2}\s+(?:\d{4}|\d{1,2}:\d{2}))\s+(?P<name>.+)$"
)

# Paths an agent should never delete or rename by accident (system, user data, GoldHEN's own files).
PROTECTED = re.compile(
    r"^/(?:$|system|system_ex|system_data|preinst|preinst2|update|dev|mnt|user(?:/(?:home|app|patch|appmeta|license|savedata|system|trophy|settings|av_contents)?)?/?$"
    r"|data/?$|data/GoldHEN/?$|data/GoldHEN/(?:config\.ini|plugins\.ini|plugins/?)$)"
)


class FtpError(RuntimeError):
    pass


def norm(path: str) -> str:
    p = (path or "/").replace("\\", "/")
    if not p.startswith("/"):
        p = "/" + p
    p = posixpath.normpath(p)
    return "/" if p in (".", "//") else p


def parse_list_line(line: str) -> dict | None:
    m = _LIST_RE.match(line.strip())
    if not m:
        return None
    name = m["name"]
    if m["mode"][0] == "l" and " -> " in name:
        name = name.split(" -> ", 1)[0]
    if name in (".", ".."):
        return None
    return {"name": name, "is_dir": m["mode"][0] == "d", "size": int(m["size"]), "mode": m["mode"], "date": m["date"]}


class Ps4Ftp:
    def __init__(self, host: str, port: int = 2121, timeout: float = 10.0):
        self.host, self.port, self.timeout = host, port, timeout
        self._ftp: ftplib.FTP | None = None
        self._lock = threading.RLock()

    def _connect(self) -> ftplib.FTP:
        f = ftplib.FTP()
        try:
            f.connect(self.host, self.port, timeout=self.timeout)
            f.login()
            f.voidcmd("TYPE I")
        except (OSError, ftplib.Error) as e:
            with contextlib.suppress(Exception):
                f.close()
            raise FtpError(f"FTP {self.host}:{self.port} unreachable ({e}). Is GoldHEN's FTP server enabled?") from e
        return f

    def close(self) -> None:
        with self._lock:
            if self._ftp:
                with contextlib.suppress(Exception):
                    self._ftp.quit()
                with contextlib.suppress(Exception):
                    self._ftp.close()
            self._ftp = None

    def _run(self, fn):
        """Run fn(ftp) on the shared session, reconnecting once if the server dropped it."""
        with self._lock:
            for attempt in (0, 1):
                if self._ftp is None:
                    self._ftp = self._connect()
                try:
                    return fn(self._ftp)
                except ftplib.error_perm:
                    raise
                except (OSError, EOFError, ftplib.Error) as e:
                    self.close()
                    if attempt:
                        raise FtpError(f"FTP error: {e}") from e
                    time.sleep(0.3)

    def idle_close(self) -> None:
        """GoldHEN's server serves one client well: drop the session between tool calls."""
        self.close()

    def list_dir(self, path: str) -> list[dict]:
        p = norm(path)

        def go(f: ftplib.FTP):
            lines: list[str] = []
            f.retrlines(f"LIST {p}", lines.append)
            return lines

        try:
            lines = self._run(go)
        except ftplib.error_perm as e:
            raise FileNotFoundError(f"{p}: {e}") from None
        out = [e for e in (parse_list_line(l) for l in lines) if e]
        out.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
        return out

    def stat(self, path: str) -> dict | None:
        p = norm(path)
        if p == "/":
            return {"name": "/", "is_dir": True, "size": 0}
        parent, name = posixpath.split(p)
        try:
            for e in self.list_dir(parent):
                if e["name"] == name:
                    return e
        except FileNotFoundError:
            return None
        return None

    def exists(self, path: str) -> bool:
        return self.stat(path) is not None

    def walk(self, root: str, max_entries: int = 100000):
        """Yield (full_path, entry) for every file and folder under root."""
        stack, count = [norm(root)], 0
        while stack:
            d = stack.pop()
            for e in self.list_dir(d):
                full = posixpath.join(d, e["name"])
                yield full, e
                count += 1
                if count >= max_entries:
                    return
                if e["is_dir"]:
                    stack.append(full)

    def download(self, remote: str, local: str | Path | None = None, max_bytes: int | None = None, tail: bool = False) -> bytes | int:
        """Download to `local` (returns the size) or to memory (returns the bytes, optionally only
        the first or last max_bytes)."""
        p = norm(remote)
        if local is not None:
            dest = Path(local)
            dest.parent.mkdir(parents=True, exist_ok=True)

            def go_file(f: ftplib.FTP):
                with open(dest, "wb") as out:
                    f.retrbinary(f"RETR {p}", out.write, blocksize=1 << 16)
                return dest.stat().st_size

            return self._wrap_missing(p, go_file)

        if max_bytes and tail:
            st = self.stat(p)
            if st and st["size"] > max_bytes:
                rest = st["size"] - max_bytes
                return self._wrap_missing(p, lambda f: self._retr_mem(f, p, None, rest))
        return self._wrap_missing(p, lambda f: self._retr_mem(f, p, max_bytes, None))

    @staticmethod
    def _retr_mem(f: ftplib.FTP, p: str, limit: int | None, rest: int | None) -> bytes:
        buf = io.BytesIO()

        class _Enough(Exception):
            pass

        def cb(chunk: bytes):
            buf.write(chunk)
            if limit and buf.tell() >= limit:
                raise _Enough

        try:
            f.retrbinary(f"RETR {p}", cb, blocksize=1 << 16, rest=rest)
        except _Enough:
            with contextlib.suppress(Exception):
                f.abort()
            # the data connection was cut early: the control channel is in an unknown state
            raise _Reset(buf.getvalue()[:limit]) from None
        return buf.getvalue()

    def _wrap_missing(self, p: str, fn):
        try:
            return self._run(fn)
        except _Reset as r:
            self.close()
            return r.data
        except ftplib.error_perm as e:
            raise FileNotFoundError(f"{p}: {e}") from None

    def upload(self, local: str | Path, remote: str, verify: bool = True) -> dict:
        src = Path(local)
        p = norm(remote)
        size = src.stat().st_size
        t0 = time.time()

        def go(f: ftplib.FTP):
            with open(src, "rb") as fh:
                f.storbinary(f"STOR {p}", fh, blocksize=1 << 16)

        try:
            self._run(go)
        except ftplib.error_perm as e:
            raise FtpError(f"upload to {p} refused: {e} (does the folder exist? read-only partition?)") from None
        out = {"remote": p, "bytes": size, "seconds": round(time.time() - t0, 2)}
        if verify:
            st = self.stat(p)
            if not st or st["size"] != size:
                raise FtpError(f"upload of {p} incomplete: console has {st and st['size']} bytes, expected {size}")
            out["verified_size"] = True
        return out

    def upload_bytes(self, data: bytes, remote: str) -> None:
        p = norm(remote)
        self._run(lambda f: f.storbinary(f"STOR {p}", io.BytesIO(data)))

    def md5(self, remote: str) -> str:
        """md5 of a console file, by reading it back (GoldHEN's FTP has no checksum command)."""
        h = hashlib.md5()
        p = norm(remote)
        self._wrap_missing(p, lambda f: f.retrbinary(f"RETR {p}", h.update, blocksize=1 << 16))
        return h.hexdigest()

    def mkdir(self, path: str) -> None:
        p = norm(path)
        with contextlib.suppress(ftplib.error_perm):
            self._run(lambda f: f.mkd(p))
        if not (self.stat(p) or {}).get("is_dir"):
            raise FtpError(f"could not create {p}")

    def makedirs(self, path: str) -> None:
        p = norm(path)
        parts = [x for x in p.split("/") if x]
        cur = ""
        for i, part in enumerate(parts):
            cur += "/" + part
            st = self.stat(cur)
            if st is None:
                with contextlib.suppress(ftplib.error_perm):
                    self._run(lambda f, c=cur: f.mkd(c))
            elif not st["is_dir"]:
                raise FtpError(f"{cur} exists and is a file")
        if not (self.stat(p) or {}).get("is_dir"):
            raise FtpError(f"could not create {p}")

    def check_mutable(self, path: str) -> str:
        p = norm(path)
        if PROTECTED.match(p):
            raise PermissionError(f"refusing to change protected path {p}")
        return p

    def delete(self, path: str, recursive: bool = False, *, force: bool = False) -> int:
        p = norm(path) if force else self.check_mutable(path)
        st = self.stat(p)
        if st is None:
            raise FileNotFoundError(p)
        if not st["is_dir"]:
            self._run(lambda f: f.delete(p))
            return 1
        entries = self.list_dir(p)
        if entries and not recursive:
            raise FtpError(f"{p} is not empty (pass recursive=true)")
        n = 0
        for e in entries:
            n += self.delete(posixpath.join(p, e["name"]), recursive=True, force=True)
        self._run(lambda f: f.rmd(p))
        return n + 1

    def rename(self, src: str, dst: str) -> None:
        a, b = self.check_mutable(src), self.check_mutable(dst)
        try:
            self._run(lambda f: f.rename(a, b))
        except ftplib.error_perm as e:
            raise FtpError(f"rename {a} -> {b} refused: {e}") from None


class _Reset(Exception):
    def __init__(self, data: bytes):
        self.data = data


def port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
