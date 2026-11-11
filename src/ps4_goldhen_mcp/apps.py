"""Installed and running apps.

- installed: /user/app/<TITLE_ID> folders (FTP) + /system_data/priv/appmeta/<TITLE_ID>/param.sfo
  for the name and version.
- running: ps4debug process list, each process' title ID from PROC_INFO.
- launch / close: the console-side agent (agent.py); one game or app runs at a time.
- install / uninstall: the agent too, for homebrew packages only (retail title IDs are refused).
"""

from __future__ import annotations

import os
import posixpath
import re
import tempfile
import time
from pathlib import Path

from .agent import Agent
from .config import cache_dir
from .ftp import Ps4Ftp, norm
from .ps4debug import Ps4Debug
from .sfo import parse_sfo

TITLE_ID = re.compile(r"^[A-Z]{4}\d{5}$")
SYSTEM_TITLE = re.compile(r"^NPXS\d{5}$")
# Sony-assigned prefixes of retail games and apps (disc and digital, every region)
RETAIL_TITLE = re.compile(r"^(?:CUS[A-E]|PCAS|PCJS|PCKS|PCCS|PLAS|PLJS|PLJM|PLKS|PLCS)\d{5}$")


def check_title_id(title_id: str) -> str:
    t = title_id.strip().upper()
    if not TITLE_ID.match(t):
        raise ValueError(f"bad title ID {title_id!r} (expected 4 letters + 5 digits, e.g. HRSA00002)")
    return t


def app_meta(ftp: Ps4Ftp, title_id: str) -> dict:
    for path in (f"/system_data/priv/appmeta/{title_id}/param.sfo", f"/user/appmeta/{title_id}/param.sfo"):
        try:
            data = ftp.download(path)
        except (FileNotFoundError, OSError):
            continue
        try:
            sfo = parse_sfo(data)
        except ValueError:
            continue
        return {k: sfo[k] for k in ("TITLE", "APP_VER", "VERSION", "CATEGORY", "CONTENT_ID") if k in sfo}
    return {}


def installed(ftp: Ps4Ftp, with_names: bool = True, limit: int = 200) -> list[dict]:
    out = []
    for e in ftp.list_dir("/user/app"):
        if e["is_dir"] and TITLE_ID.match(e["name"]):
            item = {"title_id": e["name"], "installed": e["date"]}
            if with_names and len(out) < limit:
                item.update(app_meta(ftp, e["name"]))
            out.append(item)
    return out


def running(dbg: Ps4Debug) -> list[dict]:
    """User apps currently running (games and homebrew, plus system apps with a title ID other
    than the shell)."""
    out = []
    for p in dbg.processes():
        if p["name"] == "eboot.bin":
            info = dbg.process_info(p["pid"])
            if info.get("title_id") and not SYSTEM_TITLE.match(info["title_id"]):
                out.append(info)
    return out


def find_running(dbg: Ps4Debug, title_id: str) -> dict | None:
    for info in running(dbg):
        if info["title_id"] == title_id:
            return info
    return None


def _wait(cond, timeout: float, step: float = 0.25):
    deadline = time.monotonic() + timeout
    while True:
        v = cond()
        if v or time.monotonic() >= deadline:
            return v
        time.sleep(step)


def _titles(dbg: Ps4Debug) -> list[str]:
    return [a["title_id"] for a in running(dbg)]


def close(agent: Agent, dbg: Ps4Debug, title_id: str | None = None, timeout: float = 15.0) -> dict:
    """Close the running game / app (the "big app"). With title_id, only if that is the one running."""
    agent.ensure()
    before = _titles(dbg)
    if title_id:
        title_id = check_title_id(title_id)
        if title_id not in before:
            raise LookupError(f"{title_id} is not running" + (f" (running: {', '.join(before)})" if before else ""))
    if agent.big_app() is None:
        return {"closed": [], "note": "no app is running"}
    app_id = agent.kill_big()
    if _wait(lambda: agent.big_app() is None and not (set(before) & set(_titles(dbg))), timeout) is False:
        raise TimeoutError(f"app 0x{app_id:x} ({', '.join(before)}) was asked to close but still runs after {timeout:g} s")
    return {"closed": before, "app_id": f"0x{app_id:x}"}


def launch(agent: Agent, dbg: Ps4Debug, title_id: str, args: tuple[str, ...] | list[str] = (), *,
           replace: bool = True, timeout: float = 20.0) -> dict:
    """Start an installed app by title ID. The console runs one game / app at a time: the running
    one is closed first (replace=True) or the launch is refused."""
    title_id = check_title_id(title_id)
    if SYSTEM_TITLE.match(title_id):
        raise PermissionError(f"{title_id} is a system title: only games and homebrew are launched")
    agent.ensure()
    out: dict = {"title_id": title_id}
    if agent.big_app() is not None:
        current = _titles(dbg)
        if not replace:
            raise RuntimeError(f"{', '.join(current) or 'an app'} is running: close it first or pass replace=true")
        out["closed"] = close(agent, dbg, timeout=timeout)["closed"]
    app_id = agent.launch(title_id, args)
    out["app_id"] = f"0x{app_id:x}"
    info = _wait(lambda: find_running(dbg, title_id), timeout)
    if not info:
        raise TimeoutError(f"{title_id} was launched (app 0x{app_id:x}) but its process did not appear in {timeout:g} s: "
                           "check ps4_log / ps4_crash_report")
    out["pid"] = info["pid"]
    return out


def _installed(agent: Agent, ftp: Ps4Ftp, title_id: str) -> bool:
    return agent.exists(title_id) and ftp.exists(f"/user/app/{title_id}")


def _copy_on_console(ftp: Ps4Ftp, src: str, dst: str) -> None:
    """GoldHEN's FTP cannot copy on the console: through a temporary file on the PC."""
    with tempfile.TemporaryDirectory(dir=cache_dir()) as tmp:
        local = Path(tmp) / posixpath.basename(src)
        ftp.download(src, local)
        ftp.upload(local, dst)


def install(agent: Agent, ftp: Ps4Ftp, dbg: Ps4Debug, console_path: str, *, replace: bool = False,
            keep_pkg: bool = True, timeout: float = 300.0) -> dict:
    """Install a homebrew package that is on the console.

    The system moves the package into /user/app/<TITLE_ID>/app.pkg, so with keep_pkg a copy is
    installed and the file stays where it was. An installed title of the same ID is refused, or
    with replace closed if running and uninstalled first (its save data is kept by the system)."""
    if os.environ.get("PS4_EXPERIMENTAL_INSTALL") != "1":
        raise RuntimeError(
            "ps4_install is disabled: apps installed this way may not launch (0x8002000c, the kernel cannot "
            "map the moved app.pkg). Install the package with GoldHEN's Package Installer on the console. "
            "PS4_EXPERIMENTAL_INSTALL=1 enables it for tests.")
    pkg = norm(console_path)
    if not pkg.lower().endswith(".pkg"):
        raise ValueError(f"{pkg} is not a .pkg file")
    st = ftp.stat(pkg)
    if st is None or st["is_dir"]:
        raise FileNotFoundError(f"no package at {pkg} on the console")
    agent.ensure()
    info = agent.pkg_info(pkg)
    title_id = check_title_id(info["title_id"])
    if SYSTEM_TITLE.match(title_id) or RETAIL_TITLE.match(title_id):
        raise PermissionError(f"{pkg} is {title_id}, a retail or system title: only homebrew packages are installed")
    out: dict = {"title_id": title_id, "pkg": pkg, "bytes": st["size"]}
    if _installed(agent, ftp, title_id):
        if not replace:
            meta = app_meta(ftp, title_id)
            what = " ".join(v for v in (meta.get("TITLE"), meta.get("APP_VER")) if v)
            raise FileExistsError(f"{title_id}{f' ({what})' if what else ''} is already installed: "
                                  "pass replace=true to uninstall it first")
        out["replaced"] = uninstall(agent, ftp, dbg, title_id)
    source = pkg
    if keep_pkg:
        folder, name = posixpath.split(pkg)
        source = posixpath.join(folder, f".install-{name}")
        t0 = time.monotonic()
        _copy_on_console(ftp, pkg, source)
        out["copied_in_s"] = round(time.monotonic() - t0, 1)
    t0 = time.monotonic()
    try:
        content_id = agent.install_pkg(source)
    except Exception:
        if keep_pkg and ftp.exists(source):
            ftp.delete(source)
        raise
    if not _wait(lambda: _installed(agent, ftp, title_id), timeout, 1.0):
        raise TimeoutError(f"{title_id} was handed to the installer but is not installed after {timeout:g} s "
                           "(see ps4_log)")
    out["installed_in_s"] = round(time.monotonic() - t0, 1)
    meta = app_meta(ftp, title_id)
    out.update({k.lower(): v for k, v in meta.items() if k in ("TITLE", "APP_VER", "CONTENT_ID")})
    if content_id and "content_id" not in out:
        out["content_id"] = content_id
    out["pkg_kept"] = ftp.exists(pkg)
    return out


def uninstall(agent: Agent, ftp: Ps4Ftp, dbg: Ps4Debug, title_id: str, *, allow_retail: bool = False,
              timeout: float = 60.0) -> dict:
    """Remove an installed homebrew (closed first if it runs). Retail titles only with allow_retail."""
    title_id = check_title_id(title_id)
    if SYSTEM_TITLE.match(title_id):
        raise PermissionError(f"{title_id} is a system title")
    if RETAIL_TITLE.match(title_id) and not allow_retail:
        raise PermissionError(f"{title_id} is a retail title: ask the user, then pass allow_retail=true")
    agent.ensure()
    if not agent.exists(title_id):
        raise LookupError(f"{title_id} is not installed")
    meta = app_meta(ftp, title_id)
    out: dict = {"title_id": title_id, **{k.lower(): meta[k] for k in ("TITLE", "APP_VER") if k in meta}}
    if find_running(dbg, title_id):
        out["closed"] = close(agent, dbg, title_id)["closed"]
    agent.uninstall(title_id)
    if not _wait(lambda: not agent.exists(title_id) and not ftp.exists(f"/user/app/{title_id}"), timeout, 1.0):
        raise TimeoutError(f"{title_id} is still installed {timeout:g} s after the uninstall request")
    out["uninstalled"] = True
    return out
