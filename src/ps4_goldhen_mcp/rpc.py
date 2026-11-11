"""Calling system functions inside a console process through ps4debug (PROC_INSTALL + PROC_CALL).

Symbols are resolved with the kernel's own dynamic linker: the syscall wrappers of libkernel
(`mov rax, N; mov r10, rcx; syscall`) are found by scanning its code in the target, then
sys_dynlib_get_list (592) gives the loaded module handles and sys_dynlib_dlsym (591) resolves a
name in each. Every call runs on ps4debug's RPC thread inside the target process.

A function that misbehaves can bring the target down, so SceShellCore, the kernel and the other
core daemons are refused unless allow_system=True.
"""

from __future__ import annotations

import re
import struct
import threading

from .ps4debug import Ps4Debug, Ps4DebugError

SYS_DYNLIB_DLSYM = 591
SYS_DYNLIB_GET_LIST = 592

_WRAPPER = re.compile(rb"(?:\x48\xC7\xC0|\xB8)(....)\x49\x89\xCA\x0F\x05", re.S)

# processes whose death freezes or reboots the console
CRITICAL = {"kernel", "mini-syscore.elf", "SceShellCore", "SceSysCore.elf", "GnmCompositor.elf", "orbis_audiod.elf",
            "SceSysAvControl.elf", "SceVdecProxy.elf", "SceVencProxy.elf"}

SCRATCH = 0x4000


class RemoteProcess:
    def __init__(self, dbg: Ps4Debug, pid: int, name: str = "", *, allow_system: bool = False):
        if name in CRITICAL and not allow_system:
            raise PermissionError(f"refusing remote calls into {name}: a crash there freezes or reboots the console")
        self.dbg, self.pid, self.name = dbg, pid, name
        self._syscalls: dict[int, int] | None = None
        self._handles: list[int] | None = None
        self._symbols: dict[str, int] = {}
        self._scratch: int | None = None
        self._lock = threading.RLock()

    def alive(self) -> bool:
        return any(p["pid"] == self.pid for p in self.dbg.processes())

    def scratch(self) -> int:
        if self._scratch is None:
            self._scratch = self.dbg.alloc(self.pid, SCRATCH)
        return self._scratch

    def close(self) -> None:
        if self._scratch is not None:
            try:
                self.dbg.free(self.pid, self._scratch, SCRATCH)
            except Ps4DebugError:
                pass
            self._scratch = None

    def syscall_wrappers(self) -> dict[int, int]:
        if self._syscalls is None:
            found: dict[int, int] = {}
            segs = [m for m in self.dbg.maps(self.pid) if m["name"].startswith("libkernel") and m["prot"] & 4]
            if not segs:
                raise Ps4DebugError(f"libkernel code not found in pid {self.pid}")
            for s in segs:
                data = self.dbg.read(self.pid, s["start"], s["end"] - s["start"])
                for m in _WRAPPER.finditer(data):
                    found.setdefault(struct.unpack("<I", m.group(1))[0], s["start"] + m.start())
            self._syscalls = found
        return self._syscalls

    def syscall(self, number: int, *args: int) -> int:
        addr = self.syscall_wrappers().get(number)
        if addr is None:
            raise Ps4DebugError(f"no libkernel wrapper for syscall {number}")
        return self.dbg.call(self.pid, addr, *args)

    def write(self, offset: int, data: bytes) -> int:
        """Write into the scratch page; returns the remote address."""
        if offset + len(data) > SCRATCH:
            raise ValueError("scratch overflow")
        addr = self.scratch() + offset
        self.dbg.write(self.pid, addr, data)
        return addr

    def read(self, offset: int, n: int) -> bytes:
        return self.dbg.read(self.pid, self.scratch() + offset, n)

    def handles(self) -> list[int]:
        if self._handles is None:
            buf = self.scratch()
            self.syscall(SYS_DYNLIB_GET_LIST, buf, 512, buf + 0x800)
            n = min(struct.unpack("<Q", self.read(0x800, 8))[0], 512)
            self._handles = list(struct.unpack(f"<{n}i", self.read(0, 4 * n)))
        return self._handles

    def dlsym(self, name: str) -> int | None:
        with self._lock:
            if name in self._symbols:
                return self._symbols[name]
            name_addr = self.write(0xC00, name.encode() + b"\0")
            out = self.scratch() + 0xBF0
            for h in self.handles():
                self.dbg.write(self.pid, out, b"\0" * 8)
                if self.syscall(SYS_DYNLIB_DLSYM, h, name_addr, out) & 0xFFFFFFFF == 0:
                    addr = struct.unpack("<Q", self.dbg.read(self.pid, out, 8))[0]
                    if addr:
                        self._symbols[name] = addr
                        return addr
            return None

    def call(self, name_or_addr: str | int, *args: int) -> int:
        addr = name_or_addr if isinstance(name_or_addr, int) else self.dlsym(name_or_addr)
        if not addr:
            raise Ps4DebugError(f"symbol {name_or_addr} not found in {self.name or self.pid}")
        return self.dbg.call(self.pid, addr, *args)

    def call32(self, name: str, *args: int) -> int:
        """Call and return rax as a signed 32-bit int (SCE error codes are negative)."""
        v = self.call(name, *args) & 0xFFFFFFFF
        return v - (1 << 32) if v & 0x80000000 else v


def sce_err(v: int) -> str:
    return f"0x{v & 0xFFFFFFFF:08x}"
