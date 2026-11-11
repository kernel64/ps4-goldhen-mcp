"""Client for ps4debug (golden's PS4 debugger payload, GoldHEN fork v1.1.19 by Ctn & SiSTRo).

Written from the protocol description (packet layouts in jogolden/ps4debug's libdebug and the
0BSD-licensed PyPS4debug by Jay184), not copied from either.

Wire format: little-endian. Every command starts with a 12-byte header
    u32 magic 0xFFAABBCC, u32 command, u32 length of the command's fixed fields
followed by those fields; the console answers with a u32 status (0x80000000 = success), then data.
Debugger events arrive on a TCP connection the CONSOLE opens back to the PC on port 755.
"""

from __future__ import annotations

import contextlib
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Callable

MAGIC = 0xFFAABBCC
CHUNK = 8192

CMD_VERSION = 0xBD000001
CMD_EXT_FW_VERSION = 0xBD000500
CMD_EXT_DBG_VERSION = 0xBD000501
CMD_PROC_LIST = 0xBDAA0001
CMD_PROC_READ = 0xBDAA0002
CMD_PROC_WRITE = 0xBDAA0003
CMD_PROC_MAPS = 0xBDAA0004
CMD_PROC_INSTALL = 0xBDAA0005
CMD_PROC_CALL = 0xBDAA0006
CMD_PROC_ELF = 0xBDAA0007
CMD_PROC_PROTECT = 0xBDAA0008
CMD_PROC_INFO = 0xBDAA000A
CMD_PROC_ALLOC = 0xBDAA000B
CMD_PROC_FREE = 0xBDAA000C
CMD_DEBUG_ATTACH = 0xBDBB0001
CMD_DEBUG_DETACH = 0xBDBB0002
CMD_DEBUG_BREAKPT = 0xBDBB0003
CMD_DEBUG_WATCHPT = 0xBDBB0004
CMD_DEBUG_THREADS = 0xBDBB0005
CMD_DEBUG_STOPTHR = 0xBDBB0006
CMD_DEBUG_RESUMETHR = 0xBDBB0007
CMD_DEBUG_GETREGS = 0xBDBB0008
CMD_DEBUG_SETREGS = 0xBDBB0009
CMD_DEBUG_GETFPREGS = 0xBDBB000A
CMD_DEBUG_GETDBGREGS = 0xBDBB000C
CMD_DEBUG_STOPGO = 0xBDBB0010
CMD_DEBUG_THRINFO = 0xBDBB0011
CMD_DEBUG_SINGLESTEP = 0xBDBB0012
CMD_KERN_BASE = 0xBDCC0001
CMD_KERN_READ = 0xBDCC0002
CMD_KERN_WRITE = 0xBDCC0003
CMD_CONSOLE_REBOOT = 0xBDDD0001
CMD_CONSOLE_END = 0xBDDD0002
CMD_CONSOLE_PRINT = 0xBDDD0003
CMD_CONSOLE_NOTIFY = 0xBDDD0004

STATUS = {
    0x80000000: "success",
    0xF0000001: "error",
    0xF0000002: "too much data",
    0xF0000003: "data null",
    0xF0000004: "already debugging",
    0xF0000005: "invalid index",
}
SUCCESS = 0x80000000

DEBUG_EVENT_PORT = 755
DEBUG_EVENT_SIZE = 0x4A0
MAX_BREAKPOINTS = 30
MAX_WATCHPOINTS = 4

# FreeBSD amd64 struct reg (0xB0 bytes)
REG_NAMES = ["r15", "r14", "r13", "r12", "r11", "r10", "r9", "r8", "rdi", "rsi", "rbp", "rbx", "rdx", "rcx", "rax"]
PROT = {1: "r", 2: "w", 4: "x"}


class Ps4DebugError(RuntimeError):
    pass


class Ps4DebugUnavailable(Ps4DebugError):
    pass


def parse_regs(b: bytes) -> dict:
    vals = struct.unpack_from("<15Q", b, 0)
    out = {n: v for n, v in zip(REG_NAMES, vals)}
    trapno, fs, gs, err, es, ds = struct.unpack_from("<IHHIHH", b, 0x78)
    rip, cs, rflags, rsp, ss = struct.unpack_from("<5Q", b, 0x88)
    out.update(rip=rip, rsp=rsp, rflags=rflags, cs=cs, ss=ss, trapno=trapno, err=err, fs=fs, gs=gs)
    return out


def pack_regs(r: dict) -> bytes:
    b = bytearray(0xB0)
    struct.pack_into("<15Q", b, 0, *[r.get(n, 0) & 0xFFFFFFFFFFFFFFFF for n in REG_NAMES])
    struct.pack_into("<IHHIHH", b, 0x78, r.get("trapno", 0), r.get("fs", 0), r.get("gs", 0), r.get("err", 0), 0, 0)
    struct.pack_into("<5Q", b, 0x88, r.get("rip", 0), r.get("cs", 0), r.get("rflags", 0), r.get("rsp", 0), r.get("ss", 0))
    return bytes(b)


def _cstr(b: bytes) -> str:
    return b.split(b"\0", 1)[0].decode("utf-8", "replace")


def prot_str(p: int) -> str:
    return "".join(PROT[k] if p & k else "-" for k in (1, 2, 4))


@dataclass
class DebugEvent:
    t: float
    lwpid: int
    status: int
    thread_name: str
    regs: dict

    @property
    def signal(self) -> int:
        # wait(2) status of a stopped thread: (sig << 8) | 0x7f
        return (self.status >> 8) & 0xFF if (self.status & 0xFF) == 0x7F else self.status

    def to_dict(self) -> dict:
        return {"t": round(self.t, 3), "lwpid": self.lwpid, "status": hex(self.status), "signal": self.signal,
                "thread": self.thread_name, "rip": hex(self.regs.get("rip", 0)), "rsp": hex(self.regs.get("rsp", 0))}


class Ps4Debug:
    """One persistent command connection (port 744), reconnected on demand. Thread-safe."""

    def __init__(self, host: str, port: int = 744, timeout: float = 10.0, event_port: int = DEBUG_EVENT_PORT,
                 loader: Callable[[], bool] | None = None):
        self.host, self.port, self.timeout = host, port, timeout
        # called when the port refuses connections (console up, ps4debug not loaded); True = loaded
        self.loader = loader
        # bumped on every new connection: what was learnt about the console before may be stale
        self.epoch = 0
        self.event_port = event_port
        self._sock: socket.socket | None = None
        self._lock = threading.RLock()
        self.attached_pid: int | None = None
        self.events: list[DebugEvent] = []
        self._ev_cv = threading.Condition()
        self._ev_server: socket.socket | None = None
        self._ev_thread: threading.Thread | None = None
        self._ev_stop = threading.Event()
        self._rpc_stubs: dict[int, int] = {}
        self._stubs_checked = True

    def available(self, timeout: float = 1.0) -> bool:
        try:
            with socket.create_connection((self.host, self.port), timeout=timeout):
                return True
        except OSError:
            return False

    def _conn(self) -> socket.socket:
        if self._sock is None:
            try:
                s = socket.create_connection((self.host, self.port), timeout=self.timeout)
            except ConnectionRefusedError as e:
                if not (self.loader and self.loader()):
                    raise self._unavailable(e) from e
                self._new_instance()
                try:
                    s = socket.create_connection((self.host, self.port), timeout=self.timeout)
                except OSError as e2:
                    raise self._unavailable(e2) from e2
            except OSError as e:
                raise self._unavailable(e) from e
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._sock = s
            self.epoch += 1
        return self._sock

    def _unavailable(self, e: Exception) -> Ps4DebugUnavailable:
        return Ps4DebugUnavailable(
            f"ps4debug not reachable on {self.host}:{self.port} ({e}). Load it with ps4_load_ps4debug "
            "(GoldHEN BinLoader on port 9090); it must be reloaded after every console reboot.")

    def _new_instance(self) -> None:
        """A freshly loaded ps4debug knows nothing of the previous one's stubs and debug session."""
        self._rpc_stubs.clear()
        self._stubs_checked = True
        self.attached_pid = None

    def close(self) -> None:
        with self._lock:
            if self._sock:
                with contextlib.suppress(OSError):
                    self._sock.close()
                # the console may have rebooted in between: check the stubs before using them again
                self._stubs_checked = False
            self._sock = None

    def _recv(self, n: int) -> bytes:
        s = self._conn()
        buf = bytearray()
        while len(buf) < n:
            chunk = s.recv(min(n - len(buf), 1 << 16))
            if not chunk:
                raise ConnectionError("ps4debug closed the connection")
            buf += chunk
        return bytes(buf)

    def _send(self, data: bytes) -> None:
        s = self._conn()
        for i in range(0, len(data), CHUNK):
            s.sendall(data[i:i + CHUNK])

    def _cmd(self, cmd: int, fields: bytes = b"") -> None:
        self._send(struct.pack("<III", MAGIC, cmd, len(fields)) + fields)

    def _status(self, what: str) -> None:
        st = struct.unpack("<I", self._recv(4))[0]
        if st != SUCCESS:
            raise Ps4DebugError(f"ps4debug {what}: {STATUS.get(st, hex(st))}")

    def _u32(self) -> int:
        return struct.unpack("<I", self._recv(4))[0]

    def _u64(self) -> int:
        return struct.unpack("<Q", self._recv(8))[0]

    def _txn(self, fn, what: str):
        """Run one request/response exchange; on a broken connection reconnect and retry once
        (only for exchanges that are safe to repeat)."""
        with self._lock:
            for attempt in (0, 1):
                try:
                    return fn()
                except (OSError, ConnectionError) as e:
                    self.close()
                    if attempt or isinstance(e, Ps4DebugUnavailable):
                        if isinstance(e, Ps4DebugUnavailable):
                            raise
                        raise Ps4DebugUnavailable(f"ps4debug {what}: connection lost ({e})") from e
                    time.sleep(0.2)

    def version(self) -> str:
        def go():
            self._cmd(CMD_VERSION)
            return self._recv(self._u32()).decode("ascii", "replace")
        return self._txn(go, "version")

    def firmware(self) -> int | None:
        def go():
            self._cmd(CMD_EXT_FW_VERSION)
            return struct.unpack("<H", self._recv(2))[0]
        try:
            return self._txn(go, "fw version")
        except Ps4DebugError:
            return None

    def debugger_version(self) -> str | None:
        def go():
            self._cmd(CMD_EXT_DBG_VERSION)
            return self._recv(self._u32()).decode("ascii", "replace")
        try:
            return self._txn(go, "debugger version")
        except Ps4DebugError:
            return None

    def processes(self) -> list[dict]:
        def go():
            self._cmd(CMD_PROC_LIST)
            self._status("proc list")
            n = self._u32()
            data = self._recv(36 * n)
            return [{"pid": struct.unpack_from("<I", data, 36 * i + 32)[0], "name": _cstr(data[36 * i:36 * i + 32])} for i in range(n)]
        return self._txn(go, "proc list")

    def process_info(self, pid: int) -> dict:
        def go():
            self._cmd(CMD_PROC_INFO, struct.pack("<I", pid))
            self._status("proc info")
            b = self._recv(188)
            return {"pid": struct.unpack_from("<I", b, 0)[0], "name": _cstr(b[4:44]), "path": _cstr(b[44:108]),
                    "title_id": _cstr(b[108:124]), "content_id": _cstr(b[124:188])}
        return self._txn(go, "proc info")

    def find_pid(self, name: str) -> int | None:
        for p in self.processes():
            if p["name"] == name:
                return p["pid"]
        low = name.lower()
        for p in self.processes():
            if low in p["name"].lower():
                return p["pid"]
        return None

    def maps(self, pid: int) -> list[dict]:
        def go():
            self._cmd(CMD_PROC_MAPS, struct.pack("<I", pid))
            self._status("proc maps")
            n = self._u32()
            data = self._recv(58 * n)
            out = []
            for i in range(n):
                o = 58 * i
                start, end, off = struct.unpack_from("<QQQ", data, o + 32)
                prot = struct.unpack_from("<H", data, o + 56)[0]
                out.append({"name": _cstr(data[o:o + 32]), "start": start, "end": end, "offset": off, "prot": prot})
            return out
        return self._txn(go, "proc maps")

    def read(self, pid: int, addr: int, length: int) -> bytes:
        out = bytearray()
        # big reads are split so one bad page doesn't fail everything and the socket stays responsive
        step = 0x10000
        for off in range(0, length, step):
            n = min(step, length - off)

            def go(a=addr + off, n=n):
                self._cmd(CMD_PROC_READ, struct.pack("<IQI", pid, a, n))
                self._status(f"read {a:#x}")
                return self._recv(n)
            out += self._txn(go, "read")
        return bytes(out)

    def write(self, pid: int, addr: int, data: bytes) -> None:
        with self._lock:
            try:
                self._cmd(CMD_PROC_WRITE, struct.pack("<IQI", pid, addr, len(data)))
                self._status(f"write {addr:#x}")
                self._send(data)
                self._status(f"write {addr:#x}")
            except (OSError, ConnectionError) as e:
                self.close()
                raise Ps4DebugUnavailable(f"ps4debug write: connection lost ({e})") from e

    def protect(self, pid: int, addr: int, length: int, prot: int) -> None:
        def go():
            self._cmd(CMD_PROC_PROTECT, struct.pack("<IQII", pid, addr, length, prot))
            self._status("protect")
        self._txn(go, "protect")

    def alloc(self, pid: int, length: int) -> int:
        def go():
            self._cmd(CMD_PROC_ALLOC, struct.pack("<II", pid, length))
            self._status("alloc")
            return self._u64()
        return self._txn(go, "alloc")

    def free(self, pid: int, addr: int, length: int) -> None:
        def go():
            self._cmd(CMD_PROC_FREE, struct.pack("<IQI", pid, addr, length))
            self._status("free")
        self._txn(go, "free")

    def install_rpc(self, pid: int) -> int:
        if pid in self._rpc_stubs and not self._stubs_checked:
            # a stub that is no longer mapped (console rebooted, same pid) would be jumped into blindly
            self._rpc_stubs = {p: a for p, a in self._rpc_stubs.items()
                               if any(m["start"] <= a < m["end"] for m in self.maps(p))}
            self._stubs_checked = True
        if pid in self._rpc_stubs:
            return self._rpc_stubs[pid]

        def go():
            self._cmd(CMD_PROC_INSTALL, struct.pack("<I", pid))
            self._status("install rpc")
            return self._u64()
        stub = self._txn(go, "install rpc")
        self._rpc_stubs[pid] = stub
        return stub

    def call(self, pid: int, address: int, *args: int) -> int:
        """Call address(args...) in process pid (up to 6 integer/pointer args). Returns rax.
        Not retried: a call may have side effects."""
        if len(args) > 6:
            raise ValueError("at most 6 arguments")
        stub = self.install_rpc(pid)
        regs = [a & 0xFFFFFFFFFFFFFFFF for a in args] + [0] * (6 - len(args))
        with self._lock:
            try:
                self._cmd(CMD_PROC_CALL, struct.pack("<IQQ6Q", pid, stub, address, *regs))
                self._status(f"call {address:#x}")
                _pid, rax = struct.unpack("<IQ", self._recv(12))
                return rax
            except (OSError, ConnectionError) as e:
                self.close()
                raise Ps4DebugUnavailable(f"ps4debug call: connection lost ({e})") from e

    def load_elf(self, pid: int, elf: bytes) -> None:
        with self._lock:
            self._cmd(CMD_PROC_ELF, struct.pack("<II", pid, len(elf)))
            self._status("elf")
            self._send(elf)
            self._status("elf")

    def kernel_base(self) -> int:
        def go():
            self._cmd(CMD_KERN_BASE)
            self._status("kernel base")
            return self._u64()
        return self._txn(go, "kernel base")

    def kernel_read(self, addr: int, length: int) -> bytes:
        def go():
            self._cmd(CMD_KERN_READ, struct.pack("<QI", addr, length))
            self._status("kernel read")
            return self._recv(length)
        return self._txn(go, "kernel read")

    def notify(self, message: str, kind: int = 222) -> None:
        raw = message.encode("utf-8")[:500] + b"\0"

        def go():
            self._cmd(CMD_CONSOLE_NOTIFY, struct.pack("<II", kind, len(raw)))
            self._send(raw)
            self._status("notify")
        self._txn(go, "notify")

    def print(self, message: str) -> None:
        raw = message.encode("utf-8") + b"\0"

        def go():
            self._cmd(CMD_CONSOLE_PRINT, struct.pack("<I", len(raw)))
            self._send(raw)
            self._status("print")
        self._txn(go, "print")

    def reboot(self) -> None:
        with self._lock:
            with contextlib.suppress(OSError, ConnectionError):
                self._cmd(CMD_CONSOLE_REBOOT)
            self.close()
            self._new_instance()

    def _event_loop(self, server: socket.socket) -> None:
        server.settimeout(0.5)
        conn = None
        while not self._ev_stop.is_set():
            if conn is None:
                try:
                    conn, _ = server.accept()
                    conn.settimeout(0.5)
                except socket.timeout:
                    continue
                except OSError:
                    break
            buf = b""
            try:
                while not self._ev_stop.is_set():
                    try:
                        chunk = conn.recv(DEBUG_EVENT_SIZE - len(buf))
                    except socket.timeout:
                        continue
                    if not chunk:
                        raise ConnectionError
                    buf += chunk
                    if len(buf) == DEBUG_EVENT_SIZE:
                        lwpid, status = struct.unpack_from("<II", buf, 0)
                        ev = DebugEvent(time.time(), lwpid, status, _cstr(buf[8:48]), parse_regs(buf[48:48 + 0xB0]))
                        with self._ev_cv:
                            self.events.append(ev)
                            del self.events[:-200]
                            self._ev_cv.notify_all()
                        buf = b""
            except (OSError, ConnectionError):
                with contextlib.suppress(OSError):
                    conn.close()
                conn = None
        if conn:
            with contextlib.suppress(OSError):
                conn.close()

    def attach(self, pid: int) -> None:
        with self._lock:
            if self.attached_pid is not None:
                raise Ps4DebugError(f"already attached to pid {self.attached_pid}; detach first")
            if self._ev_server is None:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    srv.bind(("0.0.0.0", self.event_port))
                except OSError as e:
                    srv.close()
                    raise Ps4DebugError(f"cannot listen on TCP {self.event_port} for debugger events ({e}); another debugger open?") from e
                srv.listen(1)
                self._ev_server = srv
                self._ev_stop.clear()
                self._ev_thread = threading.Thread(target=self._event_loop, args=(srv,), name="ps4dbg-events", daemon=True)
                self._ev_thread.start()

            def go():
                self._cmd(CMD_DEBUG_ATTACH, struct.pack("<I", pid))
                self._status("attach")
            self._txn(go, "attach")
            self.attached_pid = pid
            with self._ev_cv:
                self.events.clear()

    def detach(self) -> None:
        with self._lock:
            try:
                def go():
                    self._cmd(CMD_DEBUG_DETACH)
                    self._status("detach")
                self._txn(go, "detach")
            finally:
                self.attached_pid = None
                self._stop_events()

    def _stop_events(self) -> None:
        self._ev_stop.set()
        if self._ev_server:
            with contextlib.suppress(OSError):
                self._ev_server.close()
        if self._ev_thread:
            self._ev_thread.join(timeout=2)
        self._ev_server = None
        self._ev_thread = None

    def event_link_up(self) -> bool:
        return self._ev_thread is not None and self._ev_thread.is_alive()

    def _need_attach(self) -> None:
        if self.attached_pid is None:
            raise Ps4DebugError("not attached: call attach first")

    def stopgo(self, action: int) -> None:
        """0 = resume, 1 = stop, 2 = kill the attached process."""
        self._need_attach()

        def go():
            self._cmd(CMD_DEBUG_STOPGO, struct.pack("<I", action))
            self._status("stopgo")
        self._txn(go, "stopgo")
        if action == 2:
            self.attached_pid = None
            self._stop_events()

    def breakpoint(self, index: int, enabled: bool, address: int) -> None:
        self._need_attach()
        if not 0 <= index < MAX_BREAKPOINTS:
            raise ValueError(f"breakpoint index 0..{MAX_BREAKPOINTS - 1}")

        def go():
            self._cmd(CMD_DEBUG_BREAKPT, struct.pack("<IIQ", index, int(enabled), address))
            self._status("breakpoint")
        self._txn(go, "breakpoint")

    def watchpoint(self, index: int, enabled: bool, length: int, kind: int, address: int) -> None:
        """length code: 0=1 byte, 1=2, 3=4, 2=8. kind: 0=exec, 1=write, 3=read/write."""
        self._need_attach()

        def go():
            self._cmd(CMD_DEBUG_WATCHPT, struct.pack("<IIIIQ", index, int(enabled), length, kind, address))
            self._status("watchpoint")
        self._txn(go, "watchpoint")

    def threads(self) -> list[int]:
        self._need_attach()

        def go():
            self._cmd(CMD_DEBUG_THREADS)
            self._status("threads")
            n = self._u32()
            return list(struct.unpack(f"<{n}I", self._recv(4 * n)))
        return self._txn(go, "threads")

    def thread_info(self, lwpid: int) -> dict:
        self._need_attach()

        def go():
            self._cmd(CMD_DEBUG_THRINFO, struct.pack("<I", lwpid))
            self._status("thread info")
            b = self._recv(40)
            return {"lwpid": lwpid, "pid": struct.unpack_from("<I", b, 0)[0], "priority": struct.unpack_from("<i", b, 4)[0], "name": _cstr(b[8:40])}
        return self._txn(go, "thread info")

    def stop_thread(self, lwpid: int) -> None:
        self._need_attach()

        def go():
            self._cmd(CMD_DEBUG_STOPTHR, struct.pack("<I", lwpid))
            self._status("stop thread")
        self._txn(go, "stop thread")

    def resume_thread(self, lwpid: int) -> None:
        self._need_attach()

        def go():
            self._cmd(CMD_DEBUG_RESUMETHR, struct.pack("<I", lwpid))
            self._status("resume thread")
        self._txn(go, "resume thread")

    def get_regs(self, lwpid: int) -> dict:
        self._need_attach()

        def go():
            self._cmd(CMD_DEBUG_GETREGS, struct.pack("<I", lwpid))
            self._status("get regs")
            return parse_regs(self._recv(0xB0))
        return self._txn(go, "get regs")

    def set_regs(self, lwpid: int, regs: dict) -> None:
        self._need_attach()
        with self._lock:
            self._cmd(CMD_DEBUG_SETREGS, struct.pack("<II", lwpid, 0xB0))
            self._status("set regs")
            self._send(pack_regs(regs))
            self._status("set regs")

    def single_step(self) -> None:
        self._need_attach()

        def go():
            self._cmd(CMD_DEBUG_SINGLESTEP)
            self._status("single step")
        self._txn(go, "single step")

    def wait_event(self, timeout: float, since: int = 0) -> tuple[list[DebugEvent], int]:
        deadline = time.monotonic() + timeout
        with self._ev_cv:
            while len(self.events) <= since:
                rem = deadline - time.monotonic()
                if rem <= 0:
                    break
                self._ev_cv.wait(rem)
            return list(self.events[since:]), len(self.events)
