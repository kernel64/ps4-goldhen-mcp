"""Fake PS4 for the tests: GoldHEN-like FTP (pyftpdlib on a temp folder), a klog server and a
ps4debug server with a small fake process. Starting the agent's thread starts FakeAgent, which speaks
the agent's protocol in Python (the real blob is tested by tests/test_agent_blob.py).

Run on its own:  python tests/mock_ps4.py  (FTP 2121->21210, klog 32320, ps4debug 7440)
"""

from __future__ import annotations

import contextlib
import select
import shutil
import socket
import socketserver
import struct
import tempfile
import threading
import time
from pathlib import Path

MAGIC = 0xFFAABBCC
OK = 0x80000000
ERR = 0xF0000001

CRASH_SAMPLE = """#
# A user thread receives a fatal signal
#
# signal: 11 (SIGSEGV)
# thread ID: 100598
# thread name: eboot.bin
# proc ID: 109
# proc name: eboot.bin
# reason: page fault (user write data, page not present)
# fault address: 0000000000000000
#
# registers:
# rax: 0000000000000000  rbx: 00000010000048d0
# rip: 0000000000483288  eflags: 00010202
#
# backtrace:
copyin: eboot.bin has nonsleeping lock
# 00000000004007d3
# 0000000000bd0965
#
# dynamic libraries:
# /app0/eboot.bin
#  text: 0000000000400000:0000000001bb8000 r-x
#  data: 0000000001c3c000:0000000001e54000 rw-
# /X0GEVgvRuq/common/lib/libkernel_sys.sprx
#  text: 0000000800000000:0000000800050000 r-x
#
next line after the report""".splitlines()

KERNEL_TEXT = 0x800000000
SYSCALL_591 = KERNEL_TEXT + 0x100
SYSCALL_592 = KERNEL_TEXT + 0x120
PTHREAD_CREATE = 0x800002F00
AGENT_FUNCTIONS = ["sceNetSocket", "sceNetBind", "sceNetListen", "sceNetAccept", "sceNetRecv", "sceNetSend",
                   "sceNetSocketClose", "sceNetSetsockopt", "sceUserServiceGetForegroundUser",
                   "sceLncUtilLaunchApp", "sceSystemServiceKillApp", "sceSystemServiceGetAppIdOfBigApp",
                   "sceAppInstUtilInitialize", "sceAppInstUtilAppInstallPkg", "sceAppInstUtilGetTitleIdFromPkg",
                   "sceAppInstUtilAppUnInstall", "sceAppInstUtilAppExists"]
# like the console: sceLncUtilLaunchApp has no name, only sceSystemServiceLaunchApp (which calls it) does
LNC_LAUNCH = 0x800004C10
LAUNCH_WRAPPER = 0x800004AE0
FAKE_SYMBOLS = {"sceKernelGetCpuFrequency": (8193, 0x800001000), "scePthreadCreate": (8193, PTHREAD_CREATE),
                "sceSystemServiceLaunchApp": (113, LAUNCH_WRAPPER),
                **{n: (113, 0x800003000 + 0x10 * i) for i, n in enumerate(AGENT_FUNCTIONS) if n != "sceLncUtilLaunchApp"}}
AGENT_MAGIC = 0x50533441474E5431
AGENT_VERSION = 4  # what FakeAgent answers to PING
NO_BIG_APP = 0x80AA000A


def _wrapper(n: int) -> bytes:
    return b"\x48\xC7\xC0" + struct.pack("<I", n) + b"\x49\x89\xCA\x0F\x05\x72\x01\xC3"


class FakeProcessState:
    def __init__(self):
        self.mem: dict[int, int] = {}
        code = bytearray(0x1000)
        code[0x100:0x100 + 13] = _wrapper(591)
        code[0x120:0x120 + 13] = _wrapper(592)
        self.write(KERNEL_TEXT, bytes(code))
        self.write(0x400000, bytes(range(256)) * 16)
        # push rbp; mov rbp, rsp; sub rsp, 0x20; test rdx, rdx; call LNC_LAUNCH; leave; ret
        head = bytes.fromhex("554889e54883ec204885d2")
        rel = LNC_LAUNCH - (LAUNCH_WRAPPER + len(head) + 5)
        self.write(LAUNCH_WRAPPER, head + b"\xe8" + struct.pack("<i", rel) + bytes.fromhex("c9c3"))
        self.next_alloc = 0x10000
        self.procs = [(0, "kernel"), (41, "SceShellCore"), (42, "SceShellUI"), (45, "ScePartyDaemon"), (64, "eboot.bin")]
        self.info = {42: ("SceShellUI", "/app0/eboot.bin", "NPXS20001", ""),
                     45: ("ScePartyDaemon", "/app0/eboot.bin", "NPXS21002", ""),
                     64: ("eboot.bin", "/app0/eboot.bin", "HRSA00002", "IV0000-HRSA00002_00-H64PRDPPROBE0000")}
        self.maps = [("libkernel_sys.sprx", KERNEL_TEXT, KERNEL_TEXT + 0x1000, 5), ("eboot.bin", 0x400000, 0x401000, 5),
                     ("libSceSystemService.sprx", 0x800003000, 0x800006000, 5)]
        self.notifications: list[str] = []
        self.calls: list[tuple] = []
        self.attached: int | None = None
        self.breakpoints: dict[int, int] = {}
        # what the agent sees: one big app at a time, installed titles, packages on the console
        self.big_app: tuple[int, int] | None = (0x60000001, 64)  # (app id, pid)
        self.next_app = 0x60000002
        self.installed = {"HRSA00002": "IV0000-HRSA00002_00-H64PRDPPROBE0000"}
        self.pkgs = {"/data/pkg/new.pkg": "HRSA00099"}
        self.launches: list[tuple[str, list[str]]] = []
        self.agent: FakeAgent | None = None
        self.agent_starts = 0
        self.freed: list[tuple[int, int]] = []
        self.launch_delay = 0.0
        # ps4debug's own state: payloads the BinLoader got, RPC stubs, a counter bumped by reboot()
        self.payloads: list[bytes] = []
        self.rpc_installs = 0
        self.stub_mapped = False
        self.generation = 0
        self.install_paths: list[str] = []

    def write(self, addr: int, data: bytes) -> None:
        for i, b in enumerate(data):
            self.mem[addr + i] = b

    def read(self, addr: int, n: int) -> bytes:
        return bytes(self.mem.get(addr + i, 0) for i in range(n))

    def cstr(self, addr: int) -> str:
        out = bytearray()
        while (b := self.mem.get(addr + len(out), 0)) and len(out) < 256:
            out.append(b)
        return out.decode()

    def call(self, rip: int, args: list[int]) -> int:
        self.calls.append((rip, args))
        if rip == SYSCALL_592:
            handles = [0, 113, 8193]
            self.write(args[0], struct.pack(f"<{len(handles)}i", *handles))
            self.write(args[2], struct.pack("<Q", len(handles)))
            return 0
        if rip == SYSCALL_591:
            name = self.cstr(args[1])
            h, addr = FAKE_SYMBOLS.get(name, (None, 0))
            if h == (args[0] & 0xFFFFFFFF):
                self.write(args[2], struct.pack("<Q", addr))
                return 0
            return 0xFFFFFFFFFFFFFFFF
        if rip == 0x800001000:
            return 1600000000
        if rip == PTHREAD_CREATE:
            entry, table = args[2], args[3]
            magic, _ver, port, base, size, pid = struct.unpack("<QIIQQI", self.read(table, 36))
            if magic != AGENT_MAGIC or entry != base:
                return 0x80020016
            self.write(table + 8, struct.pack("<I", AGENT_VERSION))
            self.agent = FakeAgent(self, table, port, base, size, pid)
            self.agent_starts += 1
            return 0
        return 0

    def app_launch(self, title: str, args: list[str]) -> int:
        self.launches.append((title, args))
        if self.big_app:
            return 0x8094000C
        if title not in self.installed:
            return 0x80940031
        app_id, self.next_app = self.next_app, self.next_app + 1
        pid = max(p for p, _ in self.procs) + 1
        self.big_app = (app_id, pid)

        def appear():
            time.sleep(self.launch_delay)
            self.info[pid] = ("eboot.bin", "/app0/eboot.bin", title, self.installed[title])
            self.procs.append((pid, "eboot.bin"))
        threading.Thread(target=appear, daemon=True).start()
        return app_id

    def app_kill(self, app_id: int) -> int:
        if not self.big_app or self.big_app[0] != app_id:
            return 0x80940010
        pid = self.big_app[1]
        self.procs = [p for p in self.procs if p[0] != pid]
        self.big_app = None
        return 0


class FakeAgent:
    """The agent's protocol (companion/agent.c) on top of FakeProcessState."""

    def __init__(self, st: FakeProcessState, table: int, port: int, base: int, size: int, pid: int):
        self.st, self.table, self.base, self.size, self.pid = st, table, base, size, pid
        self.srv = socket.socket()
        try:
            self.srv.bind(("127.0.0.1", port))
        except OSError:
            st.write(table + 0x24, struct.pack("<Ii", 0x80000002, -0x7FBEFFD0))
            self.srv.close()
            return
        self.srv.listen(2)
        st.write(table + 0x24, struct.pack("<I", 1))
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        quit_ = False
        while not quit_:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            with c, c.makefile("rwb") as f:
                for raw in f:
                    reply, quit_ = self._handle(raw.decode().strip())
                    f.write(reply.encode() + b"\n")
                    f.flush()
                    if quit_:
                        break
        self.srv.close()
        self.st.write(self.table + 0x24, struct.pack("<I", 2))

    def _pkg_title(self, path: str) -> str | None:
        """Known test paths, or a fake package file whose content starts with "FAKEPKG <TITLE_ID>"."""
        p = path.removeprefix("/user")
        if p in self.st.pkgs:
            return self.st.pkgs[p]
        f = self.st.root / p.lstrip("/")
        if f.is_file() and (head := f.read_bytes()[:18]).startswith(b"FAKEPKG "):
            return head[8:17].decode()
        return None

    def _handle(self, line: str) -> tuple[str, bool]:
        st = self.st
        cmd, *a = line.split()

        def err(code: int, text: str) -> tuple[str, bool]:
            return f"ERR {code:x} {text}", False

        def is_title(t: str) -> bool:
            return len(t) == 9 and t[:4].isalpha() and t[:4].isupper() and t[4:].isdigit()

        if cmd == "PING":
            return f"OK ps4-dev-agent {AGENT_VERSION} {self.base:x} {self.size:x} {self.pid}", False
        if cmd == "QUIT":
            return "OK bye", True
        if cmd == "FGUSER":
            return "OK 10000000", False
        if cmd == "BIGAPP":
            return f"OK {st.big_app[0] if st.big_app else NO_BIG_APP:x}", False
        if cmd == "LAUNCH":
            if not a or not is_title(a[0]):
                return err(0, "bad title id")
            rc = st.app_launch(a[0], a[1:])
            return err(rc, "sceLncUtilLaunchApp") if rc & 0x80000000 else (f"OK {rc:x}", False)
        if cmd == "KILL":
            rc = st.app_kill(int(a[0], 16))
            return err(rc, "sceSystemServiceKillApp") if rc else ("OK", False)
        if cmd == "KILLBIG":
            if not st.big_app:
                return err(NO_BIG_APP, "no big app")
            app_id = st.big_app[0]
            st.app_kill(app_id)
            return f"OK {app_id:x}", False
        if cmd == "PKGINFO":
            t = self._pkg_title(a[0])
            return (f"OK {t} 1", False) if t else err(0x80990015, "sceAppInstUtilGetTitleIdFromPkg")
        if cmd == "INSTALL":
            t = self._pkg_title(a[0])
            if not t:
                return err(0x80990015, "sceAppInstUtilAppInstallPkg")
            if t in st.installed:
                return err(0x80990002, "sceAppInstUtilAppInstallPkg")
            f = st.root / a[0].removeprefix("/user").lstrip("/")
            if f.is_file():  # like the console: the package is moved into the app folder
                (st.root / "user/app" / t).mkdir(parents=True, exist_ok=True)
                f.replace(st.root / "user/app" / t / "app.pkg")
            st.installed[t] = f"IV0000-{t}_00-MOCKPKG000000000"
            st.install_paths.append(a[0])
            return f"OK {st.installed[t]}", False
        if cmd == "EXISTS":
            return f"OK {int(a[0] in st.installed)}", False
        if cmd == "UNINSTALL":
            if a[0] not in st.installed:
                return err(0x80990088, "sceAppInstUtilAppUnInstall")
            del st.installed[a[0]]
            shutil.rmtree(st.root / "user/app" / a[0], ignore_errors=True)
            return "OK", False
        return err(0, "unknown command")


class _DbgHandler(socketserver.BaseRequestHandler):
    def _rx(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            c = self.request.recv(n - len(buf))
            if not c:
                raise ConnectionError
            buf += c
        return buf

    def _tx(self, *parts: bytes) -> None:
        self.request.sendall(b"".join(parts))

    def _st(self, code: int = OK) -> bytes:
        return struct.pack("<I", code)

    def handle(self):
        st: FakeProcessState = self.server.state
        generation = st.generation
        try:
            while True:
                magic, cmd, ln = struct.unpack("<III", self._rx(12))
                assert magic == MAGIC
                f = self._rx(ln) if ln else b""
                if st.generation != generation:  # the console rebooted under this connection
                    return
                if cmd == 0xBD000001:
                    self._tx(struct.pack("<I", 3), b"1.3")
                elif cmd == 0xBD000500:
                    self._tx(struct.pack("<H", 505))
                elif cmd == 0xBD000501:
                    s = b"Ctn & SiSTRo v1.1.19"
                    self._tx(struct.pack("<I", len(s)), s)
                elif cmd == 0xBDAA0001:
                    body = b"".join(n.encode().ljust(32, b"\0") + struct.pack("<I", p) for p, n in st.procs)
                    self._tx(self._st(), struct.pack("<I", len(st.procs)), body)
                elif cmd == 0xBDAA000A:
                    pid = struct.unpack("<I", f)[0]
                    name, path, tid, cid = st.info.get(pid, ("?", "", "", ""))
                    self._tx(self._st(), struct.pack("<I", pid) + name.encode().ljust(40, b"\0") + path.encode().ljust(64, b"\0")
                             + tid.encode().ljust(16, b"\0") + cid.encode().ljust(64, b"\0"))
                elif cmd == 0xBDAA0004:
                    maps = st.maps + ([("(NoName)rpcstub", 0x7000000, 0x7004000, 7)] if st.stub_mapped else [])
                    body = b"".join(n.encode().ljust(32, b"\0") + struct.pack("<QQQH", s, e, 0, p) for n, s, e, p in maps)
                    self._tx(self._st(), struct.pack("<I", len(maps)), body)
                elif cmd == 0xBDAA0002:
                    pid, addr, n = struct.unpack("<IQI", f)
                    self._tx(self._st(), st.read(addr, n))
                elif cmd == 0xBDAA0003:
                    pid, addr, n = struct.unpack("<IQI", f)
                    self._tx(self._st())
                    st.write(addr, self._rx(n))
                    self._tx(self._st())
                elif cmd == 0xBDAA000B:
                    pid, n = struct.unpack("<II", f)
                    a = st.next_alloc
                    st.next_alloc += (n + 0xFFF) & ~0xFFF
                    self._tx(self._st(), struct.pack("<Q", a))
                elif cmd == 0xBDAA000C:
                    pid, addr, n = struct.unpack("<IQI", f)
                    st.freed.append((addr, n))
                    self._tx(self._st())
                elif cmd == 0xBDAA0008:
                    self._tx(self._st())
                elif cmd == 0xBDAA0005:
                    st.rpc_installs += 1
                    st.stub_mapped = True
                    self._tx(self._st(), struct.pack("<Q", 0x7000000))
                elif cmd == 0xBDAA0006:
                    pid, stub, rip, *regs = struct.unpack("<IQQ6Q", f)
                    rax = st.call(rip, regs)
                    self._tx(self._st(), struct.pack("<IQ", pid, rax & 0xFFFFFFFFFFFFFFFF))
                elif cmd == 0xBDDD0004:
                    kind, n = struct.unpack("<II", f)
                    st.notifications.append(self._rx(n).rstrip(b"\0").decode())
                    self._tx(self._st())
                elif cmd == 0xBDBB0001:
                    st.attached = struct.unpack("<I", f)[0]
                    self._tx(self._st())
                    threading.Thread(target=self._send_event, args=(self.client_address[0],), daemon=True).start()
                elif cmd == 0xBDBB0002:
                    st.attached = None
                    self._tx(self._st())
                elif cmd == 0xBDBB0005:
                    self._tx(self._st(), struct.pack("<I", 2), struct.pack("<II", 100001, 100002))
                elif cmd == 0xBDBB0011:
                    lw = struct.unpack("<I", f)[0]
                    self._tx(self._st(), struct.pack("<Ii", st.attached or 0, 700) + f"thread{lw}".encode().ljust(32, b"\0"))
                elif cmd == 0xBDBB0008:
                    regs = bytearray(0xB0)
                    struct.pack_into("<Q", regs, 0x88, 0x401234)
                    self._tx(self._st(), bytes(regs))
                elif cmd == 0xBDBB0003:
                    idx, en, addr = struct.unpack("<IIQ", f)
                    st.breakpoints[idx] = addr if en else 0
                    self._tx(self._st())
                elif cmd == 0xBDBB0010:
                    self._tx(self._st())
                else:
                    self._tx(self._st(ERR))
        except (ConnectionError, OSError):
            pass

    def _send_event(self, host: str) -> None:
        port = self.server.event_port
        for _ in range(20):
            try:
                with socket.create_connection((host, port), timeout=1) as s:
                    ev = bytearray(0x4A0)
                    struct.pack_into("<II", ev, 0, 100001, (5 << 8) | 0x7F)
                    ev[8:8 + 7] = b"main_th"
                    struct.pack_into("<Q", ev, 48 + 0x88, 0x401000)
                    s.sendall(bytes(ev))
                    time.sleep(0.5)
                    return
            except OSError:
                time.sleep(0.1)


class _Threaded(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _BinLoaderHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = b""
        while chunk := self.request.recv(65536):
            data += chunk
        self.server.on_payload(data)


class _KlogHandler(socketserver.BaseRequestHandler):
    def handle(self):
        srv = self.server
        with srv.cv:  # like GoldHEN: one client at a time
            if srv.clients:
                with contextlib.suppress(OSError):
                    self.request.sendall(b"[GoldHEN] <klog> failed to open klog [error: -16]\n")
                return
            srv.clients += 1
        try:
            self._serve(srv)
        finally:
            with srv.cv:
                srv.clients -= 1

    def _serve(self, srv):
        try:
            for line in srv.backlog:
                self.request.sendall(f"<118>{line}\n".encode())
            sent = 0
            while not srv.stopping:
                with srv.cv:
                    srv.cv.wait(0.2)
                    new = srv.live[sent:]
                for line in new:
                    self.request.sendall(f"{line}\n".encode())
                sent += len(new)
                # a client that left frees the klog for the next one
                if select.select([self.request], [], [], 0)[0] and not self.request.recv(64):
                    return
        except OSError:
            pass


class MockPs4:
    def __init__(self, ftp_port: int = 0, klog_port: int = 0, dbg_port: int = 0, event_port: int = 7550,
                 ps4debug_loaded: bool = True, binloader: bool = True):
        from pyftpdlib.authorizers import DummyAuthorizer
        from pyftpdlib.handlers import FTPHandler
        from pyftpdlib.servers import ThreadedFTPServer

        self.root = Path(tempfile.mkdtemp(prefix="mockps4_"))
        for d in ("data/GoldHEN", "data/pkg", "user/app/HRSA00002", "system_data/priv/appmeta/HRSA00002", "data/sce_coredumps"):
            (self.root / d).mkdir(parents=True, exist_ok=True)
        (self.root / "data/GoldHEN/config.ini").write_text("[BinLoader]\nEnabled = 1\n")
        auth = DummyAuthorizer()
        auth.add_anonymous(str(self.root), perm="elradfmwMT")
        handler = type("H", (FTPHandler,), {"authorizer": auth, "banner": "mock goldhen"})
        self.ftp = ThreadedFTPServer(("127.0.0.1", ftp_port), handler)
        self.ftp_port = self.ftp.address[1]
        threading.Thread(target=self.ftp.serve_forever, kwargs={"timeout": 0.2}, daemon=True).start()

        self.klog = _Threaded(("127.0.0.1", klog_port), _KlogHandler)
        self.klog.backlog = ["old line 1", "old line 2 init ok"]
        self.klog.live = []
        self.klog.cv = threading.Condition()
        self.klog.stopping = False
        self.klog.clients = 0
        self.klog_port = self.klog.server_address[1]
        threading.Thread(target=self.klog.serve_forever, daemon=True).start()

        self.state = FakeProcessState()
        self.state.root = self.root
        self.event_port = event_port
        self.dbg_port = dbg_port
        self._bind_ps4debug()
        if ps4debug_loaded:
            self._start_ps4debug()

        # GoldHEN's BinLoader: any payload "is" ps4debug here; it starts listening a moment later
        self.binloader = _Threaded(("127.0.0.1", 0), _BinLoaderHandler)
        self.binloader.on_payload = self._payload
        self.binloader_port = self.binloader.server_address[1]
        self.binloader_running = binloader
        if binloader:
            threading.Thread(target=self.binloader.serve_forever, daemon=True).start()
        else:
            self.binloader.server_close()

    def _bind_ps4debug(self) -> None:
        # nothing listens on the port: connections are refused, as on a console without ps4debug
        if not self.dbg_port:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                self.dbg_port = probe.getsockname()[1]
        self.dbg = None
        self.dbg_running = False

    def _start_ps4debug(self) -> None:
        self.dbg = _Threaded(("127.0.0.1", self.dbg_port), _DbgHandler)
        self.dbg.state = self.state
        self.dbg.event_port = self.event_port
        self.dbg_running = True
        threading.Thread(target=self.dbg.serve_forever, daemon=True).start()

    def _payload(self, data: bytes) -> None:
        self.state.payloads.append(data)
        if data and not self.dbg_running:
            threading.Timer(0.3, self._start_ps4debug).start()

    def reboot(self) -> None:
        """The console reboots: open connections die, ps4debug and its stubs are gone."""
        self.state.generation += 1
        self.state.stub_mapped = False
        if self.dbg_running:
            self.dbg.shutdown()
            self.dbg.server_close()
        self._bind_ps4debug()

    def say(self, *lines: str) -> None:
        with self.klog.cv:
            self.klog.live.extend(lines)
            self.klog.cv.notify_all()

    def close(self) -> None:
        self.klog.stopping = True
        self.ftp.close_all()
        for s in (self.klog,) + ((self.binloader,) if self.binloader_running else ()) + ((self.dbg,) if self.dbg_running else ()):
            s.shutdown()
            s.server_close()


if __name__ == "__main__":
    m = MockPs4(21210, 32320, 7440)
    print(f"mock PS4: ftp {m.ftp_port}, klog {m.klog_port}, ps4debug {m.dbg_port}, root {m.root}")
    while True:
        time.sleep(5)
        m.say(f"[mock] tick {time.time():.0f}")
