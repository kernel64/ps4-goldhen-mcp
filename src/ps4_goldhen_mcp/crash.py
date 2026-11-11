"""Parsing and symbolising the kernel's fatal-signal reports printed in the klog.

A report looks like:
    # A user thread receives a fatal signal
    # signal: 11 (SIGSEGV)
    # thread ID: 100598 / thread name / proc ID / proc name / reason / fault address
    # registers:  "# rax: 0000...  rbx: 0000..." pairs
    # backtrace:  "# 00000000004007d3" lines
    # dynamic libraries:  "# /app0/eboot.bin" then " text: start:end r-x" / " data: ..."
Addresses are resolved as module+offset, and against a local unstripped ELF (symbols, DWARF lines)
when the caller gives one.
"""

from __future__ import annotations

import bisect
import re
from pathlib import Path

_START = re.compile(r"A user thread receives a fatal signal", re.I)
_KV = re.compile(r"^#\s*(signal|thread ID|thread name|proc ID|proc name|reason|fault address)\s*:\s*(.*)$", re.I)
_REG = re.compile(r"\b(r[a-z0-9]{1,2}|eflags|BrF|BrT)\s*:\s*([0-9a-fA-F]{8,16})")
_ADDR_LINE = re.compile(r"^#\s+([0-9a-fA-F]{8,16})\s*$")
_LIB = re.compile(r"^#\s+(/\S+)\s*$")
_SEG = re.compile(r"^#\s+(text|data)\s*:\s*([0-9a-fA-F]+):([0-9a-fA-F]+)\s+(\S+)")


def is_start(text: str) -> bool:
    return bool(_START.search(text))


def parse_report(lines: list[str]) -> dict:
    out: dict = {"registers": {}, "backtrace": [], "modules": []}
    section = None
    lib: dict | None = None
    for text in lines:
        t = text.rstrip()
        low = t.lower()
        if low.startswith("# registers"):
            section = "regs"
            continue
        if low.startswith("# backtrace"):
            section = "bt"
            continue
        if low.startswith("# dynamic libraries"):
            section = "libs"
            continue
        m = _KV.match(t)
        if m:
            out[m.group(1).lower().replace(" ", "_")] = m.group(2).strip()
            continue
        if section == "regs":
            for name, val in _REG.findall(t):
                out["registers"][name.lower() if name not in ("BrF", "BrT") else name] = "0x" + val.lower()
        elif section == "bt":
            m = _ADDR_LINE.match(t)
            if m:
                out["backtrace"].append(int(m.group(1), 16))
        elif section == "libs":
            m = _LIB.match(t)
            if m:
                lib = {"path": m.group(1)}
                out["modules"].append(lib)
                continue
            m = _SEG.match(t)
            if m and lib is not None:
                lib[m.group(1)] = (int(m.group(2), 16), int(m.group(3), 16))
    out["raw"] = lines
    return out


def locate(addr: int, modules: list[dict]) -> dict | None:
    for m in modules:
        for seg in ("text", "data"):
            r = m.get(seg)
            if r and r[0] <= addr < r[1]:
                return {"module": m["path"].rsplit("/", 1)[-1], "path": m["path"], "segment": seg,
                        "offset": addr - m["text"][0] if "text" in m else addr - r[0]}
    return None


def where(addr: int, modules: list[dict], symbols: "ElfSymbols | None" = None) -> str:
    loc = locate(addr, modules)
    s = f"0x{addr:x}"
    if not loc:
        return s
    s += f" {loc['module']}+0x{loc['offset']:x}"
    if symbols and loc["module"] == symbols.module_name:
        sym = symbols.lookup(loc["offset"])
        if sym:
            s += f" ({sym})"
    return s


def summary(report: dict, symbols: "ElfSymbols | None" = None, raw: bool = False) -> dict:
    mods = report.get("modules", [])
    regs = report.get("registers", {})
    out = {k: report[k] for k in ("signal", "reason", "fault_address", "proc_name", "proc_id", "thread_name", "thread_id") if k in report}
    if "rip" in regs:
        out["rip"] = where(int(regs["rip"], 16), mods, symbols)
    out["backtrace"] = [where(a, mods, symbols) for a in report.get("backtrace", [])[:32]]
    out["registers"] = regs
    out["modules"] = [f"{m['path']} text {m['text'][0]:#x}-{m['text'][1]:#x}" for m in mods if "text" in m][:40]
    if "first_line_id" in report:
        out["klog_line"] = report["first_line_id"]
    if raw:
        out["raw"] = report.get("raw", [])
    return out


class ElfSymbols:
    """Function symbols and DWARF line table of a local, unstripped ELF (the eboot before
    create-fself), addressed by offset from the start of its first executable segment, which is
    what `module+offset` in a crash report means."""

    def __init__(self, path: str | Path, module_name: str = "eboot.bin"):
        from elftools.elf.elffile import ELFFile

        self.path = str(path)
        self.module_name = module_name
        self.funcs: list[tuple[int, int, str]] = []
        self.lines: list[tuple[int, str, int]] = []
        with open(path, "rb") as f:
            elf = ELFFile(f)
            loads = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
            text = [s for s in loads if s["p_flags"] & 1] or loads
            self.base = min(s["p_vaddr"] for s in text) if text else 0
            for sec in elf.iter_sections():
                if sec.header["sh_type"] in ("SHT_SYMTAB", "SHT_DYNSYM"):
                    for sym in sec.iter_symbols():
                        if sym["st_info"]["type"] == "STT_FUNC" and sym["st_value"]:
                            self.funcs.append((sym["st_value"], sym["st_size"], sym.name))
            if elf.has_dwarf_info():
                try:
                    dwarf = elf.get_dwarf_info()
                    for cu in dwarf.iter_CUs():
                        lp = dwarf.line_program_for_CU(cu)
                        if not lp:
                            continue
                        files = lp["file_entry"]
                        ver = lp.header["version"]
                        for e in lp.get_entries():
                            st = e.state
                            if st and not st.end_sequence:
                                idx = st.file if ver >= 5 else st.file - 1
                                name = files[idx].name.decode("utf-8", "replace") if 0 <= idx < len(files) else "?"
                                self.lines.append((st.address, name, st.line))
                except Exception:  # pragma: no cover - odd DWARF
                    self.lines = []
        self.funcs.sort()
        self.lines.sort()
        self._fstarts = [f[0] for f in self.funcs]
        self._lstarts = [l[0] for l in self.lines]

    def lookup(self, offset: int) -> str | None:
        addr = self.base + offset
        out = None
        i = bisect.bisect_right(self._fstarts, addr) - 1
        if i >= 0:
            start, size, name = self.funcs[i]
            if not size or addr < start + size + 16:
                out = f"{_demangle(name)}+0x{addr - start:x}"
        j = bisect.bisect_right(self._lstarts, addr) - 1
        if j >= 0 and addr - self.lines[j][0] < 0x1000:
            _, fname, line = self.lines[j]
            out = (out + " " if out else "") + f"{Path(fname).name}:{line}"
        return out


def _demangle(name: str) -> str:
    return name  # mangled C++ names stay readable enough; no demangler dependency
