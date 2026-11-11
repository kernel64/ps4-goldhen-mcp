"""Installed and running apps.

- installed: /user/app/<TITLE_ID> folders (FTP) + /system_data/priv/appmeta/<TITLE_ID>/param.sfo
  for the name and version.
- running: ps4debug process list, each process' title ID from PROC_INFO.
- launch / close: the console-side agent (agent.py); one game or app runs at a time.
"""

from __future__ import annotations

import re
import time

from .agent import Agent
from .ftp import Ps4Ftp
from .ps4debug import Ps4Debug
from .sfo import parse_sfo

TITLE_ID = re.compile(r"^[A-Z]{4}\d{5}$")
SYSTEM_TITLE = re.compile(r"^NPXS\d{5}$")


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
