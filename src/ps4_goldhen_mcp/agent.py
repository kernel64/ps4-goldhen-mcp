"""Launching and closing apps through a small agent running on the console.

companion/agent.c is built into a position-independent blob (_agent_blob.py, see companion/build.py).
`Agent.inject` copies it into ScePartyDaemon with ps4debug, fills its table of system functions and
starts it with scePthreadCreate; it then answers one text command per line on TCP 9226. It stays
loaded until the console reboots, and a later session finds it again with PING.
"""

from __future__ import annotations

import base64
import hashlib
import socket
import struct
import time

from .ps4debug import Ps4Debug, Ps4DebugError
from .rpc import RemoteProcess

DEFAULT_PORT = 9226
DEFAULT_HOST_PROCESS = "ScePartyDaemon"

MAGIC = 0x50533441474E5431  # "PS4AGNT1"
TABLE_HEADER = 0x30
TABLE_STATE = 0x24
ST_LISTENING, ST_STOPPED, ST_FAILED = 1, 2, 0x80000000
PAGE = 0x4000

# Same order as the function pointers of struct agent_table. Optional ones may be missing in the host.
FUNCTIONS: list[tuple[str, bool]] = [
    ("sceNetSocket", True), ("sceNetBind", True), ("sceNetListen", True), ("sceNetAccept", True),
    ("sceNetRecv", True), ("sceNetSend", True), ("sceNetSocketClose", True), ("sceNetSetsockopt", True),
    ("sceUserServiceGetForegroundUser", True), ("sceLncUtilLaunchApp", True),
    ("sceSystemServiceKillApp", True), ("sceSystemServiceGetAppIdOfBigApp", True),
    ("sceAppInstUtilInitialize", False), ("sceAppInstUtilAppInstallPkg", False),
    ("sceAppInstUtilGetTitleIdFromPkg", False), ("sceAppInstUtilAppUnInstall", False),
    ("sceAppInstUtilAppExists", False),
]
FAIL_STAGE = {1: "sceNetSocket", 2: "sceNetBind/sceNetListen (is the port already taken?)"}


def lnc_launch_from_wrapper(dbg: Ps4Debug, pid: int, wrapper: int) -> int:
    """sceLncUtilLaunchApp has no name on 5.05, but it is the first call made by
    sceSystemServiceLaunchApp. The wrapper itself must not be used: it drops the caller's user."""
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs

    maps = [m for m in dbg.maps(pid) if m["start"] <= wrapper < m["end"]]
    module = maps[0]["name"] if maps else None
    for insn in Cs(CS_ARCH_X86, CS_MODE_64).disasm(dbg.read(pid, wrapper, 0x90), wrapper):
        if insn.mnemonic == "ret":
            break
        if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
            target = int(insn.op_str, 16)
            if module is None or any(m["name"] == module and m["start"] <= target < m["end"] for m in dbg.maps(pid)):
                return target
            break
    return 0


class AgentError(RuntimeError):
    """The agent answered ERR, or it could not be started."""

    def __init__(self, message: str, code: int = 0):
        super().__init__(message)
        self.code = code


class AgentUnreachable(AgentError):
    pass


def blob() -> tuple[bytes, int]:
    try:
        from . import _agent_blob as b
    except ImportError:
        raise AgentError("the agent is not built: run `uv run python companion/build.py` "
                         "(needs clang and ld.lld from LLVM 18)") from None
    data = base64.b64decode("".join(b.BLOB_B64) if not isinstance(b.BLOB_B64, str) else b.BLOB_B64)
    if hashlib.sha256(data).hexdigest() != b.SHA256:
        raise AgentError("_agent_blob.py is corrupted: rebuild it with companion/build.py")
    return data, b.VERSION


class Agent:
    def __init__(self, dbg: Ps4Debug, host: str, port: int = DEFAULT_PORT, timeout: float = 10.0,
                 host_process: str = DEFAULT_HOST_PROCESS):
        self.dbg, self.host, self.port, self.timeout, self.host_process = dbg, host, port, timeout, host_process

    def request(self, line: str, timeout: float | None = None) -> str:
        """Send one command; returns what follows "OK" in the reply."""
        if "\n" in line or "\r" in line:
            raise ValueError("one command per request")
        try:
            with socket.create_connection((self.host, self.port), timeout=timeout or self.timeout) as s:
                s.sendall(line.encode() + b"\n")
                buf = b""
                while not buf.endswith(b"\n"):
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
        except OSError as e:
            raise AgentUnreachable(f"agent not reachable on {self.host}:{self.port} ({e})") from e
        reply = buf.decode(errors="replace").strip()
        if reply == "OK" or reply.startswith("OK "):
            return reply[3:]
        if reply.startswith("ERR "):
            code_s, _, text = reply[4:].partition(" ")
            code = int(code_s, 16)
            raise AgentError(f"{text}: 0x{code:08x}" if code else text, code)
        raise AgentUnreachable(f"unexpected reply from port {self.port}: {reply[:80]!r} (is it our agent?)")

    def ping(self, timeout: float = 1.5) -> dict | None:
        """Where the agent is loaded, or None when nothing answers."""
        try:
            name, version, base, size, pid = self.request("PING", timeout).split()
        except (AgentUnreachable, ValueError):
            return None
        if name != "ps4-dev-agent":
            return None
        return {"version": int(version), "base": int(base, 16), "size": int(size, 16), "host_pid": int(pid)}

    def ensure(self) -> dict:
        """Make sure the current version of the agent runs; inject it if needed."""
        _, version = blob()
        info = self.ping()
        if info and info["version"] == version:
            return {**info, "injected": False}
        if info:
            self.unload()
        return self.inject()

    def inject(self) -> dict:
        code, version = blob()
        pid = self.dbg.find_pid(self.host_process)
        if pid is None:
            raise AgentError(f"host process {self.host_process} is not running on the console")
        rp = RemoteProcess(self.dbg, pid, self.host_process)
        try:
            addrs = {name: rp.dlsym(name) or 0 for name, _ in FUNCTIONS}
            create = rp.dlsym("scePthreadCreate")
            if not addrs["sceLncUtilLaunchApp"] and (wrapper := rp.dlsym("sceSystemServiceLaunchApp")):
                addrs["sceLncUtilLaunchApp"] = lnc_launch_from_wrapper(self.dbg, pid, wrapper)
        finally:
            rp.close()
        missing = [n for n, required in FUNCTIONS if required and not addrs[n]]
        if not create:
            missing.append("scePthreadCreate")
        if missing:
            raise AgentError(f"{self.host_process} lacks {', '.join(missing)}: pick another host process")

        table_off = (len(code) + 15) & ~15
        table_len = TABLE_HEADER + 8 * len(FUNCTIONS)
        thread_off = table_off + table_len
        name_off = thread_off + 8
        size = (name_off + 32 + PAGE - 1) & ~(PAGE - 1)
        base = self.dbg.alloc(pid, size)
        try:
            if not any(m["start"] <= base < m["end"] and m["prot"] & 4 for m in self.dbg.maps(pid)):
                self.dbg.protect(pid, base, size, 7)
            table = struct.pack("<QIIQQIIiI", MAGIC, 0, self.port, base, size, pid, 0, 0, 0)
            table += struct.pack(f"<{len(FUNCTIONS)}Q", *(addrs[n] for n, _ in FUNCTIONS))
            image = code.ljust(table_off, b"\0") + table + b"\0" * 8 + b"ps4-dev-agent\0"
            self.dbg.write(pid, base, image)
            if self.dbg.read(pid, base, len(image)) != image:
                raise AgentError("the agent image read back from the console differs from what was written")
            rc = self.dbg.call(pid, create, base + thread_off, 0, base, base + table_off, base + name_off) & 0xFFFFFFFF
            if rc:
                raise AgentError(f"scePthreadCreate failed in {self.host_process}: 0x{rc:08x}", rc)
        except Exception:
            self._free(pid, base, size)
            raise

        deadline = time.monotonic() + 5
        state = err = 0
        while time.monotonic() < deadline:
            state, err = struct.unpack("<Ii", self.dbg.read(pid, base + table_off + TABLE_STATE, 8))
            if state:
                break
            time.sleep(0.1)
        if state != ST_LISTENING:
            if state & ST_FAILED:  # the thread has returned: its memory can go
                time.sleep(0.3)
                self._free(pid, base, size)
                raise AgentError(f"the agent could not listen on port {self.port}: "
                                 f"{FAIL_STAGE.get(state & 0xFF, 'unknown step')} returned 0x{err & 0xFFFFFFFF:08x}", err)
            # still 0: the thread may be running, so its memory is left in place
            raise AgentError(f"the agent thread did not start in {self.host_process} (image left at {base:#x})")
        info = self.ping(self.timeout)
        if not info:
            raise AgentUnreachable(f"the agent listens in {self.host_process} but port {self.port} does not answer "
                                   "from the PC (firewall?)")
        return {**info, "injected": True, "host_process": self.host_process, "port": self.port, "version": version}

    def unload(self) -> dict:
        """Stop the agent thread and free its memory in the host process."""
        info = self.ping()
        if not info:
            return {"unloaded": False, "note": "no agent running"}
        self.request("QUIT")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and self.ping(0.5):
            time.sleep(0.1)
        time.sleep(0.5)  # QUIT is answered a few instructions before the thread returns
        self._free(info["host_pid"], info["base"], info["size"])
        return {"unloaded": True, **info}

    def _free(self, pid: int, base: int, size: int) -> None:
        try:
            self.dbg.free(pid, base, size)
        except Ps4DebugError:
            pass

    def foreground_user(self) -> int:
        return int(self.request("FGUSER"), 16)

    def big_app(self) -> int | None:
        """App ID of the running game / app, None when only the system UI runs."""
        v = int(self.request("BIGAPP"), 16)
        return None if v & 0x80000000 else v

    def launch(self, title_id: str, args: tuple[str, ...] | list[str] = ()) -> int:
        for a in args:
            if not a or any(c.isspace() for c in a) or not a.isprintable():
                raise ValueError(f"launch argument {a!r}: no spaces or control characters")
        return int(self.request(" ".join(["LAUNCH", title_id, *args])), 16)

    def kill(self, app_id: int) -> None:
        self.request(f"KILL {app_id:x}")

    def kill_big(self) -> int:
        return int(self.request("KILLBIG"), 16)

    def pkg_info(self, console_path: str) -> dict:
        title, is_app = self.request(f"PKGINFO {_path(console_path)}").split()
        return {"title_id": title, "is_app": is_app == "1"}

    def install_pkg(self, console_path: str) -> str | None:
        """Starts the install (it goes on in the background); returns the content ID when the
        system gives it."""
        return self.request(f"INSTALL {_path(console_path)}", max(self.timeout, 60)) or None

    def exists(self, title_id: str) -> bool:
        return self.request(f"EXISTS {title_id}") == "1"

    def uninstall(self, title_id: str) -> None:
        self.request(f"UNINSTALL {title_id}", max(self.timeout, 60))


def _path(p: str) -> str:
    if not p.startswith("/") or any(c.isspace() for c in p) or not p.isprintable():
        raise ValueError(f"console path {p!r}: absolute, without spaces")
    # /data is how FTP and apps see it; the install service needs the real path
    return "/user" + p if p.startswith("/data/") else p
