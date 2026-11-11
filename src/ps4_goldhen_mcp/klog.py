"""Background reader of GoldHEN's klog server (TCP 3232): the system log, apps' stdout/printf and
sceKernelDebugOutText included, plus the kernel's crash reports.

On connect the server first replays its history buffer: lines received before the first quiet gap
are flagged `backlog` and ignored by wait_for(). Fatal-signal reports are grouped into crash records
(see crash.py) as they stream by.

GoldHEN's klog serves one client at a time (the next gets "failed to open klog [error: -16]"), so
the listener holding the console connection relays the lines on a loopback port, announced in
~/.ps4-goldhen-mcp/klog-<host>-<port>.json, and other sessions read from it. When it goes away the
next one takes the console over.
"""

from __future__ import annotations

import collections
import contextlib
import json
import os
import re
import socket
import threading
import time

from . import crash as crash_mod
from .config import cache_dir

_PRIO = re.compile(r"^<\d{1,3}>")
_BUSY = re.compile(r"failed to open klog")
BACKLOG_GAP = 0.6  # seconds of silence that end the history replay
RELAY_HISTORY = 3000  # lines a listener joining the relay gets as its backlog


class _Busy(Exception):
    """The console's klog is held by a client that does not relay it."""


class KlogListener:
    def __init__(self, host: str, port: int = 3232, *, max_lines: int = 20000, log_file: str | None = None):
        self.host, self.port = host, port
        self.lines: collections.deque[dict] = collections.deque(maxlen=max_lines)
        self.crashes: collections.deque[dict] = collections.deque(maxlen=20)
        self.next_id = 1
        self.log_file = log_file
        self._cv = threading.Condition()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self.connected = False
        self.last_error: str | None = None
        self.connects = 0
        self._crash_buf: list[str] | None = None
        self._crash_tail = 0
        self.source: str | None = None  # "console" or "shared by pid N" while connected
        self._relay: socket.socket | None = None
        self._token = os.urandom(8).hex()  # tells our own relay file from another listener's
        self._relay_clients: list[socket.socket] = []

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="klog", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        s = self._sock
        if s:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=3)
        self._thread = None

    def wait_connected(self, timeout: float = 5.0) -> bool:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.connected and not self._in_backlog:
                return True
            time.sleep(0.05)
        return self.connected

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                s, direct, source = self._open()
            except OSError as e:
                self.connected = False
                self.last_error = f"connect: {e}"
                self._stop.wait(2.0)
                continue
            self._sock = s
            self.connected = True
            self.source = source
            self.connects += 1
            self.last_error = None
            self._in_backlog = True
            last_rx = time.monotonic()
            s.settimeout(0.2)
            pending = b""
            got_lines = False
            busy = False
            try:
                while not self._stop.is_set():
                    try:
                        chunk = s.recv(65536)
                    except socket.timeout:
                        if self._in_backlog and time.monotonic() - last_rx > BACKLOG_GAP:
                            self._in_backlog = False
                        self._flush_crash_if_stale()
                        if direct:
                            self._start_relay()
                        continue
                    if not chunk:
                        raise ConnectionError("closed by console" if direct else "the sharing listener went away")
                    last_rx = time.monotonic()
                    pending += chunk
                    *full, pending = pending.split(b"\n")
                    for raw in full:
                        text = raw.decode("utf-8", "replace").rstrip("\r")
                        if direct and not got_lines and _BUSY.search(text):
                            raise _Busy
                        got_lines = True
                        if direct:
                            self._start_relay()
                        self._add(text)
            except _Busy:
                busy = True
                self.last_error = ("the console's klog is held by another client that does not share it (an older "
                                   "ps4-goldhen-mcp server, curl, telnet...): close it or restart that MCP server")
            except OSError as e:
                self.last_error = str(e)
            finally:
                self.connected = False
                self.source = None
                self._sock = None
                self._stop_relay()
                try:
                    s.close()
                except OSError:
                    pass
            if self._stop.is_set():
                break
            if busy:
                self._stop.wait(3.0)
            else:
                self._add("[klog] connection lost, reconnecting", kind="info")
                self._stop.wait(1.0)

    _in_backlog = False

    def _relay_file(self):
        return cache_dir() / f"klog-{self.host}-{self.port}.json"

    def _open(self) -> tuple[socket.socket, bool, str]:
        """A listener that already owns the console connection, else the console itself."""
        try:
            info = json.loads(self._relay_file().read_text())
            if info.get("token") != self._token:
                s = socket.create_connection(("127.0.0.1", int(info["port"])), timeout=1)
                return s, False, f"shared by pid {info.get('pid')}"
        except (OSError, ValueError, KeyError, TypeError):
            pass
        return socket.create_connection((self.host, self.port), timeout=5), True, "console"

    def _start_relay(self) -> None:
        if self._relay is not None:
            return
        try:
            srv = socket.socket()
            srv.bind(("127.0.0.1", 0))
            srv.listen(8)
            self._relay_file().write_text(json.dumps({"pid": os.getpid(), "port": srv.getsockname()[1], "token": self._token}))
        except OSError:
            return
        self._relay = srv
        threading.Thread(target=self._relay_accept, args=(srv,), name="klog-relay", daemon=True).start()

    def _relay_accept(self, srv: socket.socket) -> None:
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            c.settimeout(2.0)
            with self._cv:  # no line can slip between the history and the live feed
                history = [l["text"] for l in self.lines if l["kind"] != "info"][-RELAY_HISTORY:]
                try:
                    if history:
                        c.sendall(("\n".join(history) + "\n").encode("utf-8", "replace"))
                    self._relay_clients.append(c)
                except OSError:
                    c.close()

    def _stop_relay(self) -> None:
        srv, self._relay = self._relay, None
        if srv is None:
            return
        with contextlib.suppress(OSError, ValueError):
            f = self._relay_file()
            if json.loads(f.read_text()).get("token") == self._token:
                f.unlink()
        with contextlib.suppress(OSError):
            srv.close()
        with self._cv:
            clients, self._relay_clients = self._relay_clients, []
        for c in clients:
            with contextlib.suppress(OSError):
                c.close()

    def _add(self, text: str, kind: str | None = None) -> None:
        text = _PRIO.sub("", text)
        if not text and kind is None:
            return
        backlog = self._in_backlog
        k = kind or ("crash" if self._crash_buf is not None or crash_mod.is_start(text) else "log")
        with self._cv:
            rec = {"id": self.next_id, "t": time.time(), "text": text, "kind": k}
            if backlog:
                rec["backlog"] = True
            self.lines.append(rec)
            self.next_id += 1
            self._cv.notify_all()
            if self._relay_clients and kind is None:
                data = (text + "\n").encode("utf-8", "replace")
                for c in list(self._relay_clients):
                    try:
                        c.sendall(data)
                    except OSError:
                        self._relay_clients.remove(c)
                        with contextlib.suppress(OSError):
                            c.close()
        if self.log_file:
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(text + "\n")
            except OSError:
                pass
        self._feed_crash(text, rec["id"], backlog)

    def _feed_crash(self, text: str, line_id: int, backlog: bool) -> None:
        if crash_mod.is_start(text):
            self._finish_crash()
            self._crash_buf = [text]
            self._crash_meta = {"first_line_id": line_id, "backlog": backlog, "t": time.time()}
            self._crash_tail = 0
            return
        if self._crash_buf is None:
            return
        self._crash_buf.append(text)
        self._crash_meta["t"] = time.time()
        if text.startswith("#"):
            self._crash_tail = 0
        else:
            self._crash_tail += 1
            # the report is all '#' lines, with a few unrelated lines interleaved
            if self._crash_tail > 12:
                self._finish_crash()

    def _flush_crash_if_stale(self) -> None:
        if self._crash_buf is not None and time.time() - self._crash_meta["t"] > 1.5:
            self._finish_crash()

    def _finish_crash(self) -> None:
        if self._crash_buf is None:
            return
        report = crash_mod.parse_report(self._crash_buf)
        report.update(self._crash_meta)
        report.pop("t", None)
        with self._cv:
            self.crashes.append(report)
            self._cv.notify_all()
        self._crash_buf = None

    def get(self, since_id: int | None = None, pattern: str | None = None, limit: int = 200,
            include_backlog: bool = False, include_system: bool = True) -> dict:
        rx = re.compile(pattern, re.I) if pattern else None
        with self._cv:
            items = [l for l in self.lines if (since_id is None or l["id"] >= since_id)
                     and (include_backlog or not l.get("backlog"))
                     and (include_system or not _is_system(l["text"]))
                     and (rx is None or rx.search(l["text"]))]
            nxt = self.next_id
        truncated = len(items) > limit
        items = items[-limit:]
        out = {"lines": [f"{l['id']}: {l['text']}" for l in items], "next_since_id": nxt,
               "truncated_older": truncated, "connected": self.connected}
        if not self.connected and self.last_error:
            out["not_connected"] = self.last_error
        return out

    def wait_for(self, pattern: str, timeout: float, since_id: int | None = None, crash_aborts: bool = True) -> dict:
        """Block until a line matching pattern (regex, case-insensitive) arrives after since_id
        (default: now), or a crash report, or timeout."""
        rx = re.compile(pattern, re.I)
        with self._cv:
            start = self.next_id if since_id is None else since_id
            crashes_before = len(self.crashes)
        deadline = time.monotonic() + timeout
        checked = start
        with self._cv:
            while True:
                for l in list(self.lines):
                    if l["id"] < checked or l.get("backlog"):
                        continue
                    if rx.search(l["text"]):
                        return {"matched": True, "line": f"{l['id']}: {l['text']}", "next_since_id": l["id"] + 1}
                checked = self.next_id
                if crash_aborts and len(self.crashes) > crashes_before:
                    c = self.crashes[-1]
                    if not c.get("backlog"):
                        return {"matched": False, "crashed": True, "crash": crash_mod.summary(c), "next_since_id": self.next_id}
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return {"matched": False, "timed_out": True, "next_since_id": self.next_id, "connected": self.connected}
                self._cv.wait(min(remaining, 0.5))

    def clear(self) -> None:
        with self._cv:
            self.lines.clear()
            self.crashes.clear()


_SYSTEM = re.compile(r"^\[(?:Sce\w+|mbus|Performance Warning)\]|^#LOGIN MGR#|^PRINT_TIME_TICK|^LoginJob|^ScePsP|^@ ")


def _is_system(text: str) -> bool:
    return bool(_SYSTEM.search(text))
