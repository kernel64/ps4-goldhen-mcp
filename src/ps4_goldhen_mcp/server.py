"""MCP server exposing a jailbroken PS4 (GoldHEN + ps4debug) to Claude Code.

Run:  PS4_HOST=192.168.1.40 ps4-goldhen-mcp
"""

from __future__ import annotations

import atexit
import functools
import os
import re
import sys
import time
from pathlib import Path
from typing import Literal

from mcp.server.mcpserver import Image, MCPServer as _Server
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from . import apps as apps_mod, capture as capture_mod, crash as crash_mod, deploy as deploy_mod, payload as payload_mod
from .agent import Agent
from .config import Config
from .ftp import FtpError, Ps4Ftp, norm, port_open
from .klog import KlogListener
from .lock import ConsoleBusy, ConsoleLock, describe as describe_lock
from .ps4debug import Ps4Debug, Ps4DebugError, Ps4DebugUnavailable, prot_str
from .rpc import RemoteProcess, sce_err

INSTRUCTIONS = """\
Tools to drive a jailbroken PS4 (GoldHEN) over the LAN: GoldHEN's FTP (files), its klog server
(system log + apps' printf + kernel crash reports), ps4debug (processes, memory, debugger) and an
HDMI capture card on the PC (what the TV shows).

Typical homebrew loop:
1. Build the .pkg / files on the PC. A new pkg goes to /data/pkg/ (`ps4_upload`) and the user
   installs it with GoldHEN's Package Installer (`ps4_install` is disabled for now: apps it installs
   may not launch). `ps4_deploy` syncs a folder of data files (only changed files), no reinstall.
2. `ps4_launch(title_id, wait_for="<line your app prints at init>")` starts an installed app without
   the pad and blocks until that klog line (or a crash). The console runs one game / app at a time:
   the running one is closed first. `ps4_deploy(..., launch=title_id, wait_for=...)` does both.
   `ps4_close` closes the running app. Only installed titles can be started; nothing is installed,
   patched or unlocked by these tools.
3. On a crash, `ps4_crash_report` gives signal, registers and backtrace resolved as module+offset,
   and function/file:line when you pass the unstripped ELF of your eboot (before create-fself).
4. `ps4_capture_photo` / `_burst` / `_video` / `_record` show the real HDMI output.

The console prepares itself: after a boot, the first tool that needs ps4debug sends it to GoldHEN's
BinLoader, and launching or closing an app loads the small agent thread that does it (`ps4_agent`
shows it). `ps4_status` reports both. `ps4_load_ps4debug(force=true)` only forces a reload. Never
probe port 9090 yourself: an empty connection disarms the BinLoader. Do not launch apps with `ps4_call` and sceSystemServiceLaunchApp: that
function drops the user and crashes the console UI. `ps4_call` refuses core daemons; ask the user
before experimenting with it.

Console paths are POSIX (`/data/homebrew/MyApp/x.bin`). Local paths are on the PC (absolute).
Addresses are hex strings (`0x400000`) or ints. Processes are given by pid or name (`eboot.bin`).

The console may be shared with other Claude Code sessions. Tools that change it reserve it
automatically when it is free. Before a multi-step test, call `ps4_lock(reason=...)`, and
`ps4_unlock` when done. If another session holds it you get a "Console reserved by" error: wait with
`ps4_lock(wait_seconds=...)` or do other work. Never work around a reservation.
"""

cfg = Config.from_env()
ftp = Ps4Ftp(cfg.host, cfg.ftp_port, cfg.timeout)
dbg = Ps4Debug(cfg.host, cfg.debug_port, cfg.timeout)
klog = KlogListener(cfg.host, cfg.klog_port, log_file=cfg.log_file)
agent = Agent(dbg, cfg.host, cfg.agent_port, cfg.timeout, cfg.agent_host_process)
console_lock = ConsoleLock(cfg.host, lease_seconds=cfg.lock_lease)


def _reserved_by_other() -> str | None:
    st = console_lock.status()
    return describe_lock(st) if st and not st.get("held_by_me") else None


ps4debug_loader = payload_mod.Ps4DebugLoader(cfg, _reserved_by_other)
dbg.loader = ps4debug_loader
atexit.register(lambda: console_lock.release())
card = capture_mod.CaptureCard.from_env()
_remote: dict[int, tuple[int, RemoteProcess]] = {}  # pid -> (connection epoch, symbols and scratch)


def _stop_recording_at_exit() -> None:
    if card.recording and card.recording.running:
        card.stop_recording()


atexit.register(_stop_recording_at_exit)

LOCK_HINT = "Wait for it with ps4_lock(wait_seconds=...) or do something else and retry later."

mcp = _Server("ps4", instructions=INSTRUCTIONS)

RO = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False)
DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False)


def _addr(v: str | int) -> int:
    if isinstance(v, int):
        return v
    s = v.strip().lower().replace("_", "").replace("`", "")
    return int(s[2:] if s.startswith("0x") else s, 16)


def _guard_write() -> None:
    if cfg.read_only:
        raise PermissionError("Server is in read-only mode (PS4_READ_ONLY=1).")
    tool = sys._getframe(1).f_code.co_name
    try:
        console_lock.claim(f"auto: {tool}")
    except ConsoleBusy as e:
        raise ConsoleBusy(e.info, LOCK_HINT) from None


def _local(path: str) -> Path:
    return Path(os.path.expandvars(path)).expanduser().resolve()


def friendly(fn):
    """Renew our reservation, turn transport errors into actionable messages, and drop the FTP
    session after each call (GoldHEN's FTP server serves one client well)."""

    @functools.wraps(fn)
    def wrapper(*a, **kw):
        console_lock.renew()
        try:
            return fn(*a, **kw)
        except ToolError:
            raise
        except Ps4DebugUnavailable as e:
            _remote.clear()
            raise ToolError(str(e)) from e
        except FtpError as e:
            raise ToolError(f"{e}\nCheck: console on, GoldHEN running with its FTP server, IP {cfg.host}.") from e
        except Exception as e:  # the SDK hides the text of any other exception from the client
            raise ToolError(f"{type(e).__name__}: {e}") from e
        finally:
            ftp.idle_close()

    return wrapper


def _ensure_klog() -> None:
    if not klog.running:
        klog.start()
        klog.wait_connected(3.0)


def _pid(process: str | int) -> tuple[int, str]:
    if isinstance(process, int) or str(process).isdigit():
        pid = int(process)
        for p in dbg.processes():
            if p["pid"] == pid:
                return pid, p["name"]
        raise ValueError(f"no process with pid {pid}")
    pid = dbg.find_pid(str(process))
    if pid is None:
        raise ValueError(f"no process named {process!r} (see ps4_processes)")
    return pid, str(process)


# Console status / payloads
@mcp.tool(annotations=RO)
@friendly
def ps4_status() -> dict:
    """What answers on the console (FTP, klog, ps4debug), ps4debug and firmware version, running
    apps, klog channel state and who holds the console reservation. Never touches the BinLoader port."""
    out: dict = {"host": cfg.host, "ftp": port_open(cfg.host, cfg.ftp_port), "klog_port": port_open(cfg.host, cfg.klog_port)}
    loads = ps4debug_loader.loads
    try:
        out["ps4debug"] = dbg.version()
    except Ps4DebugUnavailable as e:
        out["ps4debug"] = f"not available: {e}"
    else:
        if ps4debug_loader.loads > loads:
            out["ps4debug_loaded_now"] = ps4debug_loader.last_load
        fw = dbg.firmware()
        out["firmware"] = f"{fw // 100}.{fw % 100:02d}" if fw else None
        out["ps4debug_build"] = dbg.debugger_version()
        try:
            out["running_apps"] = apps_mod.running(dbg)
        except Ps4DebugError as e:
            out["running_apps"] = f"error: {e}"
        info = agent.ping()
        out["launch_agent"] = f"v{info['version']} in {agent.host_process}" if info else "loaded on first launch / close"
    out["klog_listener"] = {"running": klog.running, "connected": klog.connected, "source": klog.source,
                            "lines": len(klog.lines), "crashes": len(klog.crashes)}
    if klog.running and not klog.connected and klog.last_error:
        out["klog_listener"]["error"] = klog.last_error
    out["reservation"] = console_lock.status() or "free"
    out["read_only"] = cfg.read_only
    return out


def _launch(title_id: str, args: list[str] | None, replace: bool, wait_for: str | None, wait_timeout: float) -> dict:
    since = None
    if wait_for:
        re.compile(wait_for)  # a bad pattern fails before anything is closed or started
        _ensure_klog()
        since = klog.next_id
    out = apps_mod.launch(agent, dbg, title_id, args or (), replace=replace)
    if wait_for:
        out["log"] = klog.wait_for(wait_for, max(1.0, min(wait_timeout, 600.0)), since)
    return out


@mcp.tool(annotations=WRITE)
@friendly
def ps4_load_ps4debug(force: bool = False) -> dict:
    """Load ps4debug (GoldHEN fork v1.1.19, checked SHA-256) through GoldHEN's BinLoader (port 9090)
    and wait for its port 744. Not needed in normal use: the server loads it by itself when a tool
    needs it. force=true sends it again even if it answers."""
    _guard_write()
    if dbg.available() and not force:
        return {"already_loaded": dbg.version()}
    path = payload_mod.ps4debug_bin(cfg.ps4debug_bin)
    n = payload_mod.send(cfg.host, cfg.binloader_port, path.read_bytes())
    up = payload_mod.wait_port(cfg.host, cfg.debug_port, 15)
    if up is None:
        raise RuntimeError(f"sent {n} bytes but ps4debug did not open port {cfg.debug_port} within 15 s")
    dbg.close()
    dbg._new_instance()
    return {"sent_bytes": n, "file": str(path), "up_after_s": up, "version": dbg.version(), "build": dbg.debugger_version()}


@mcp.tool(annotations=DESTRUCTIVE)
@friendly
def ps4_send_payload(local_path: str) -> dict:
    """Send any .bin payload to GoldHEN's BinLoader (port 9090). It runs with kernel rights: only send
    payloads you trust. The BinLoader may need re-enabling in GoldHEN after each payload."""
    _guard_write()
    data = _local(local_path).read_bytes()
    return {"sent_bytes": payload_mod.send(cfg.host, cfg.binloader_port, data), "sha256": payload_mod.sha256(data)}


@mcp.tool(annotations=WRITE)
@friendly
def ps4_notify(message: str) -> str:
    """Show a notification pop-up on the TV (ps4debug)."""
    _guard_write()
    dbg.notify(message)
    return "shown"


@mcp.tool(annotations=DESTRUCTIVE)
@friendly
def ps4_reboot(wait_until_back: bool = True, timeout_seconds: float = 180) -> dict:
    """Reboot the console (ps4debug). Everything running is lost, and GoldHEN does not survive it:
    the user has to run the GoldHEN exploit again on the console before any tool works. Ask the
    user first. With wait_until_back, waits for the console to go down, then for GoldHEN's FTP to
    answer again (timeout_seconds, max 900). ps4debug and the launch agent are then loaded again by
    the next tool that needs them."""
    _guard_write()
    dbg.reboot()
    _remote.clear()
    out: dict = {"reboot": "sent", "note": "GoldHEN must be enabled again on the console by the user"}
    if wait_until_back:
        t0 = time.monotonic()
        deadline = t0 + max(60.0, min(timeout_seconds, 900.0))
        while payload_mod.port_open(cfg.host, cfg.ftp_port, 2) and time.monotonic() < deadline:
            time.sleep(3)
        out["down_after_s"] = round(time.monotonic() - t0)
        back = payload_mod.wait_port(cfg.host, cfg.ftp_port, max(0.0, deadline - time.monotonic()))
        out["goldhen_back_after_s"] = None if back is None else round(time.monotonic() - t0)
        if back is None:
            out["note"] = "the console has not come back with GoldHEN yet: the user has to enable GoldHEN again"
    return out


# Files (GoldHEN FTP)
@mcp.tool(annotations=RO)
@friendly
def ps4_list_dir(path: str = "/data", recursive: bool = False, max_entries: int = 300) -> dict:
    """List a console folder (name, size, is_dir, date). recursive walks sub-folders."""
    p = norm(path)
    if recursive:
        items = [{"path": full, "size": e["size"], "is_dir": e["is_dir"]} for full, e in ftp.walk(p, max_entries + 1)]
    else:
        items = [{k: e[k] for k in ("name", "size", "is_dir", "date")} for e in ftp.list_dir(p)]
    return {"path": p, "entries": items[:max_entries], "truncated": len(items) > max_entries}


@mcp.tool(annotations=RO)
@friendly
def ps4_download(remote_path: str, local_path: str) -> dict:
    """Copy a console file to the PC."""
    dest = _local(local_path)
    if dest.is_dir():
        dest = dest / Path(remote_path).name
    size = ftp.download(remote_path, dest)
    return {"local": str(dest), "bytes": size}


@mcp.tool(annotations=RO)
@friendly
def ps4_read_text_file(remote_path: str, max_bytes: int = 65536, tail: bool = False) -> str:
    """Read a text file on the console (app logs in /data/..., GoldHEN config...). tail=True reads
    the end of a big file."""
    data = ftp.download(remote_path, max_bytes=max(1, min(max_bytes, 1 << 20)), tail=tail)
    return data.decode("utf-8", "replace")


@mcp.tool(annotations=WRITE)
@friendly
def ps4_upload(local_path: str, remote_path: str) -> dict:
    """Send a PC file to the console (size checked after upload). remote_path may be a folder
    (ending with /). Packages usually go to /data/pkg/ for GoldHEN's Package Installer."""
    _guard_write()
    src = _local(local_path)
    dst = remote_path.rstrip("/") + "/" + src.name if remote_path.endswith("/") else remote_path
    parent = norm(dst).rsplit("/", 1)[0] or "/"
    if not ftp.exists(parent):
        ftp.makedirs(parent)
    return ftp.upload(src, dst)


@mcp.tool(annotations=WRITE)
@friendly
def ps4_mkdir(path: str) -> str:
    """Create a console folder (and its parents)."""
    _guard_write()
    ftp.makedirs(path)
    return f"created {norm(path)}"


@mcp.tool(annotations=DESTRUCTIVE)
@friendly
def ps4_rename(src: str, dst: str) -> str:
    """Rename / move a console file or folder (system and GoldHEN paths are refused)."""
    _guard_write()
    ftp.rename(src, dst)
    return f"{norm(src)} -> {norm(dst)}"


@mcp.tool(annotations=DESTRUCTIVE)
@friendly
def ps4_delete(path: str, recursive: bool = False) -> str:
    """Delete a console file, or a folder (recursive=true if not empty). System partitions, /user
    roots, /data itself and GoldHEN's config are refused."""
    _guard_write()
    n = ftp.delete(path, recursive)
    return f"deleted {norm(path)} ({n} entries)"


@mcp.tool(annotations=WRITE)
@friendly
def ps4_deploy(local_path: str, remote_dir: str | None = None, force: bool = False, prune: bool = False,
               excludes: list[str] | None = None, launch: str | None = None, wait_for: str | None = None,
               wait_timeout: float = 30) -> dict:
    """Sync a local build folder (or file) to a console folder: only files that changed since the
    last deploy are sent. remote_dir defaults to PS4_DEPLOY_ROOT/<local folder name>. prune also
    deletes console files missing locally (careful: includes files the app wrote there).
    launch=<title ID> then starts that installed app as ps4_launch does (the running app is closed
    first), wait_for blocks until its klog line."""
    _guard_write()
    local = _local(local_path)
    target = remote_dir or f"{cfg.deploy_root.rstrip('/')}/{local.name if local.is_dir() else local.stem}"
    if launch:
        apps_mod.check_title_id(launch)
    out = deploy_mod.deploy(ftp, str(local), target, excludes=excludes, force=force, prune=prune)
    if launch:
        out["launch"] = _launch(launch, None, True, wait_for, wait_timeout)
    return out


# Apps
@mcp.tool(annotations=RO)
@friendly
def ps4_apps(which: Literal["running", "installed", "both"] = "both", names: bool = True) -> dict:
    """Installed apps (/user/app, with TITLE / APP_VER from param.sfo when names=true) and running
    ones (title ID, content ID, pid; needs ps4debug)."""
    out: dict = {}
    if which in ("installed", "both"):
        out["installed"] = apps_mod.installed(ftp, with_names=names)
    if which in ("running", "both"):
        try:
            out["running"] = apps_mod.running(dbg)
        except Ps4DebugUnavailable as e:
            out["running"] = f"unknown: {e}"
    return out


@mcp.tool(annotations=WRITE)
@friendly
def ps4_launch(title_id: str, args: list[str] | None = None, replace: bool = True, wait_for: str | None = None,
               wait_timeout: float = 30) -> dict:
    """Start an installed game / app by title ID (see ps4_apps), without the pad. The console runs
    one at a time: the running one is closed first (its unsaved progress is lost), or the launch is
    refused with replace=false. args are passed to the app's main() (no spaces in an argument).
    wait_for = regex of a klog line the app prints (e.g. its "init ok"): the call then blocks until
    that line, a crash report or wait_timeout seconds, and returns it under "log".
    Returns the app ID and the pid of the new process."""
    _guard_write()
    return _launch(title_id, args, replace, wait_for, wait_timeout)


@mcp.tool(annotations=WRITE)
@friendly
def ps4_close(title_id: str | None = None) -> dict:
    """Close the running game / app (unsaved progress is lost). With title_id, only if that title
    is the one running. Returns what was closed; nothing to close is not an error."""
    _guard_write()
    return apps_mod.close(agent, dbg, title_id)


@mcp.tool(annotations=WRITE)
@friendly
def ps4_install(local_path: str | None = None, console_path: str | None = None, replace: bool = False,
                keep_pkg: bool = True, wait_seconds: float = 300) -> dict:
    """DISABLED for now (apps installed this way may not launch): install with GoldHEN's Package
    Installer instead and tell the user. Install a homebrew .pkg without the pad. local_path = a package on the PC (sent to /data/pkg/
    first), or console_path = one already on the console. The system moves the package it installs,
    so keep_pkg (default) installs a copy and the console file stays. If the title is already
    installed it is refused, or with replace=true closed if running and uninstalled first (the
    system keeps its save data). Retail and system title IDs are refused: this is for your own
    homebrew. Returns the title ID, name and version once the system lists it."""
    _guard_write()
    if os.environ.get("PS4_EXPERIMENTAL_INSTALL") != "1":
        apps_mod.install(agent, ftp, dbg, "/disabled.pkg")  # raises the explanation
    if bool(local_path) == bool(console_path):
        raise ValueError("give either local_path (a pkg on the PC) or console_path (a pkg on the console)")
    keep = keep_pkg
    if local_path:
        src = _local(local_path)
        if src.suffix.lower() != ".pkg" or not src.is_file():
            raise FileNotFoundError(f"{src} is not a .pkg file")
        if not ftp.exists("/data/pkg"):
            ftp.makedirs("/data/pkg")
        console_path = f"/data/pkg/{src.name}"
        ftp.upload(src, console_path)
        keep = False  # the original is on the PC
    out = apps_mod.install(agent, ftp, dbg, console_path, replace=replace, keep_pkg=keep,
                           timeout=max(30.0, min(wait_seconds, 1800.0)))
    if local_path:
        out["sent_from"] = str(_local(local_path))
    return out


@mcp.tool(annotations=DESTRUCTIVE)
@friendly
def ps4_uninstall(title_id: str, allow_retail: bool = False) -> dict:
    """Uninstall an installed homebrew by title ID (closed first if it runs). Its save data stays
    on the console. Retail games are refused unless allow_retail=true, which needs the user's
    explicit agreement for that title; system titles are always refused."""
    _guard_write()
    return apps_mod.uninstall(agent, ftp, dbg, title_id, allow_retail=allow_retail)


@mcp.tool(annotations=WRITE)
@friendly
def ps4_agent(action: Literal["status", "load", "unload"] = "status") -> dict:
    """The console-side agent that launches and closes apps: a small thread the server injects into
    a system daemon (ScePartyDaemon) through ps4debug, listening on TCP PS4_AGENT_PORT (9226).
    ps4_launch / ps4_close load it on demand; it is gone after a console reboot. status = where it
    runs; load = inject it now; unload = stop it and free its memory."""
    if action == "status":
        info = agent.ping()
        return {"running": bool(info), **(info or {}), "port": agent.port, "host_process": agent.host_process}
    _guard_write()
    return agent.ensure() if action == "load" else agent.unload()


# Logs (klog)
@mcp.tool(annotations=RO)
@friendly
def ps4_log(since_id: int | None = None, pattern: str | None = None, limit: int = 200,
            hide_system: bool = False, include_backlog: bool = False) -> dict:
    """Console log lines collected in the background from GoldHEN's klog server: apps' printf /
    stdout / sceKernelDebugOutText, system services, kernel crash reports. Starts the listener on
    first use. Pass since_id=<next_since_id of the previous call> to get only new lines; pattern is a
    case-insensitive regex; hide_system drops the chatty Sce* service lines. Lines replayed from the
    console's history at connect time are hidden unless include_backlog."""
    _ensure_klog()
    return klog.get(since_id, pattern, max(1, min(limit, 2000)), include_backlog, not hide_system)


@mcp.tool(annotations=RO)
@friendly
def ps4_wait_for_log(pattern: str, timeout_seconds: float = 30, since_id: int | None = None) -> dict:
    """Block until a klog line matches pattern (regex, case-insensitive), a crash report arrives,
    or timeout (max 600 s). since_id defaults to "from now": take next_since_id from ps4_log BEFORE
    launching the app so its first lines aren't missed."""
    _ensure_klog()
    return klog.wait_for(pattern, max(1.0, min(timeout_seconds, 600.0)), since_id)


@mcp.tool(annotations=WRITE)
@friendly
def ps4_clear_log() -> str:
    """Forget the klog lines and crash reports collected so far (on the PC only)."""
    klog.clear()
    return "cleared"


@mcp.tool(annotations=RO)
@friendly
def ps4_crash_report(index: int = -1, elf_path: str | None = None, raw: bool = False) -> dict:
    """Last (or index-th) kernel crash report seen in the klog: signal, reason, fault address,
    thread/process, registers, backtrace as module+offset. With elf_path (your unstripped eboot ELF,
    before create-fself), eboot.bin addresses also get function+offset and file:line. raw=true adds
    the report text. Also lists core dumps in /data/sce_coredumps."""
    _ensure_klog()
    if not klog.crashes:
        out: dict = {"crash": None, "note": "no crash report seen since the klog listener started"}
    else:
        rep = list(klog.crashes)[index]
        syms = crash_mod.ElfSymbols(_local(elf_path)) if elf_path else None
        out = {"crash": crash_mod.summary(rep, syms, raw), "reports_seen": len(klog.crashes)}
    try:
        out["coredumps"] = [e["name"] for e in ftp.list_dir("/data/sce_coredumps")][-10:]
    except (FileNotFoundError, FtpError):
        pass
    return out


@mcp.tool(annotations=RO)
@friendly
def ps4_symbolize(elf_path: str, offsets: list[str], module: str = "eboot.bin") -> list[str]:
    """Resolve module offsets (hex, as in `eboot.bin+0x83288`) to function+offset and file:line
    with a local unstripped ELF."""
    syms = crash_mod.ElfSymbols(_local(elf_path), module)
    return [f"{o}: {syms.lookup(_addr(o)) or '?'}" for o in offsets[:200]]


# HDMI capture card
def _capture_meta(meta: dict) -> str:
    st = console_lock.status()
    if st and not st["held_by_me"]:
        meta["note"] = describe_lock(st)
    return str(meta)


def _sheet(frames: list, labels: list[str], thumb_width: int) -> Image:
    return Image(data=capture_mod.contact_sheet(frames, labels, thumb_width=thumb_width), format="jpeg")


@mcp.tool(annotations=RO)
@friendly
def ps4_capture_photo(save_path: str | None = None, max_width: int = 1280):
    """Photo of the console's HDMI output through the USB capture card: exactly what the TV shows.
    Saves a full-size PNG (save_path, or PS4_CAPTURE_DIR) and returns it scaled to max_width.
    The card is exclusive: it fails if OBS or another session (Xbox server included) has it open."""
    shot = card.photo(_local(save_path) if save_path else None)
    jpg, size = capture_mod.preview_jpeg(shot["path"], max_width)
    return [Image(data=jpg, format="jpeg"), _capture_meta({**shot, "size": f"{size[0]}x{size[1]}"})]


@mcp.tool(annotations=RO)
@friendly
def ps4_capture_burst(count: int = 8, interval_ms: int = 250, save_dir: str | None = None, thumb_width: int = 480):
    """Burst of `count` HDMI photos (max 120) taken `interval_ms` apart (0 = every frame, ~30/s), for
    flicker, animations or short glitches. Returns one contact sheet; full-size JPEGs are saved."""
    b = card.burst(count, max(0, interval_ms) / 1000, _local(save_dir) if save_dir else None)
    labels = [f"#{i} +{t:.2f}s" for i, t in enumerate(b["times"])]
    frames = b["frames"]
    meta = {"dir": b["dir"], "count": len(frames)}
    return [_sheet(frames[:24], labels, thumb_width), _capture_meta(meta)]


def _video_result(r: dict, preview_frames: int) -> list:
    out: list = []
    if preview_frames > 0:
        frames, times = capture_mod.sample_video(r["path"], max(1, min(preview_frames, 24)))
        out.append(_sheet(frames, [f"{t:.1f}s" for t in times], 320))
    out.append(_capture_meta(r))
    return out


@mcp.tool(annotations=RO)
@friendly
def ps4_capture_video(seconds: float = 10, save_path: str | None = None, audio: bool = True, preview_frames: int = 6):
    """Record an HDMI clip (MP4 with sound) and wait for it, max 300 s. Returns a contact sheet and
    the file path. For a recording spanning other actions, use ps4_capture_record."""
    r = card.record(max(1.0, min(seconds, 300.0)), _local(save_path) if save_path else None, audio=audio)
    return _video_result(r, preview_frames)


@mcp.tool(annotations=RO)
@friendly
def ps4_capture_record(action: Literal["start", "stop", "status"], save_path: str | None = None, audio: bool = True,
                       max_seconds: float = 600, preview_frames: int = 6):
    """Background HDMI recording: start, do anything (launch, logs...), then stop, which returns the
    MP4 path and a contact sheet. Ends by itself after max_seconds (max 3600). While it runs,
    ps4_capture_photo returns its latest frame. status also lists the capture devices."""
    if action == "start":
        return card.start_recording(_local(save_path) if save_path else None, audio=audio, max_seconds=max(5.0, min(max_seconds, 3600.0)))
    if action == "stop":
        return _video_result(card.stop_recording(), preview_frames)
    return {**card.status(), "devices": card.devices(), "output_dir": str(card.out_dir)}


# Processes / memory (ps4debug)
@mcp.tool(annotations=RO)
@friendly
def ps4_processes(details: bool = False, filter: str | None = None) -> list:
    """Console processes (pid, name). details=true adds path, title ID and content ID (one extra
    request per process: use filter to limit, a case-insensitive substring of the name)."""
    procs = dbg.processes()
    if filter:
        procs = [p for p in procs if filter.lower() in p["name"].lower()]
    if details:
        return [dbg.process_info(p["pid"]) for p in procs[:80]]
    return [f"{p['pid']} {p['name']}" for p in procs]


@mcp.tool(annotations=RO)
@friendly
def ps4_memory_map(process: str | int, filter: str | None = None, max_entries: int = 200) -> dict:
    """Memory map of a process (pid or name): start-end, protection, name. filter = substring of
    the mapping name (e.g. 'eboot', 'libkernel')."""
    pid, name = _pid(process)
    maps = dbg.maps(pid)
    if filter:
        maps = [m for m in maps if filter.lower() in m["name"].lower()]
    lines = [f"{m['start']:#014x}-{m['end']:#014x} {prot_str(m['prot'])} {m['name']}" for m in maps]
    return {"pid": pid, "process": name, "count": len(lines), "maps": lines[:max_entries], "truncated": len(lines) > max_entries}


@mcp.tool(annotations=RO)
@friendly
def ps4_read_memory(process: str | int, address: str, length: int = 256, format: Literal["hex", "u32", "u64", "ascii"] = "hex") -> str:
    """Read process memory (max 64 KiB) as a hex dump, u32/u64 words or ASCII."""
    pid, _ = _pid(process)
    a = _addr(address)
    data = dbg.read(pid, a, max(1, min(length, 0x10000)))
    if format == "ascii":
        return data.decode("latin-1").replace("\0", ".")
    if format in ("u32", "u64"):
        w = 4 if format == "u32" else 8
        rows = []
        for off in range(0, len(data) - len(data) % w, w * 4):
            words = [int.from_bytes(data[o:o + w], "little") for o in range(off, min(off + w * 4, len(data)), w)]
            rows.append(f"{a + off:#014x}: " + " ".join(f"{x:0{2 * w}x}" for x in words))
        return "\n".join(rows)
    rows = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        rows.append(f"{a + off:#014x}: {chunk.hex(' '):<47}  {asc}")
    return "\n".join(rows)


@mcp.tool(annotations=DESTRUCTIVE)
@friendly
def ps4_write_memory(process: str | int, address: str, hex_data: str) -> str:
    """Write bytes (hex string) into process memory."""
    _guard_write()
    pid, _ = _pid(process)
    data = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", hex_data))
    dbg.write(pid, _addr(address), data)
    return f"wrote {len(data)} bytes at {_addr(address):#x}"


@mcp.tool(annotations=RO)
@friendly
def ps4_find_bytes(process: str | int, start: str, length: int, pattern: str, max_hits: int = 32) -> list[str]:
    """Search process memory for a byte pattern ('48 8b ?? 05', ?? = any byte), max 16 MiB."""
    pid, _ = _pid(process)
    a = _addr(start)
    data = dbg.read(pid, a, max(1, min(length, 16 << 20)))
    toks = pattern.split()
    rx = re.compile(b"".join(b"." if t in ("??", "?") else re.escape(bytes.fromhex(t)) for t in toks), re.S)
    return [f"{a + m.start():#x}" for _, m in zip(range(max_hits), rx.finditer(data))]


@mcp.tool(annotations=RO)
@friendly
def ps4_disassemble(process: str | int, address: str, count: int = 32) -> str:
    """x86-64 disassembly (capstone) of process code."""
    import capstone

    pid, _ = _pid(process)
    a = _addr(address)
    data = dbg.read(pid, a, max(16, min(count, 400)) * 15)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    out = [f"{i.address:#014x}: {i.bytes.hex():<22} {i.mnemonic} {i.op_str}" for _, i in zip(range(count), md.disasm(data, a))]
    return "\n".join(out)


@mcp.tool(annotations=DESTRUCTIVE)
@friendly
def ps4_call(process: str | int, function: str, args: list[str] | None = None) -> dict:
    """Advanced: call a function inside a process through ps4debug RPC. function = exported name
    (resolved with the dynamic linker, e.g. 'sceKernelGetCpuFrequency') or an address starting with 0x; args =
    up to 6 integers (hex strings). Core daemons (SceShellCore...) are refused. A bad call can crash
    the target; in SceShellUI it can freeze the console UI: ask the user before experimenting."""
    _guard_write()
    pid, name = _pid(process)
    dbg.version()  # connects (and loads ps4debug if needed) so the epoch below is current
    cached = _remote.get(pid)
    rp = cached[1] if cached and cached[0] == dbg.epoch and cached[1].name == name else None
    if rp is None:
        rp = RemoteProcess(dbg, pid, name)
        _remote[pid] = (dbg.epoch, rp)
    target: str | int = _addr(function) if function.lower().startswith("0x") else function
    vals = [_addr(x) for x in (args or [])]
    rax = rp.call(target, *vals)
    return {"rax": hex(rax), "as_int32": rax & 0xFFFFFFFF if not rax & 0x80000000 else (rax & 0xFFFFFFFF) - (1 << 32), "sce": sce_err(rax)}


# Debugger (ps4debug)
@mcp.tool(annotations=DESTRUCTIVE)
@friendly
def ps4_debug_attach(process: str | int) -> dict:
    """Attach ps4debug's debugger to a process (pid or name, e.g. 'eboot.bin'). The console then
    connects back to this PC on TCP 755 to report breakpoints/signals (allow it in the Windows
    firewall). Detach with ps4_debug_detach."""
    _guard_write()
    pid, name = _pid(process)
    if name in ("SceShellUI", "SceShellCore"):
        raise PermissionError(f"refusing to attach to {name}: stopping it freezes the console UI")
    dbg.attach(pid)
    time.sleep(0.5)
    return {"attached": pid, "process": name, "event_link": dbg.event_link_up(), "threads": dbg.threads()[:64]}


@mcp.tool(annotations=WRITE)
@friendly
def ps4_debug_detach() -> str:
    """Detach the debugger (the process keeps running)."""
    dbg.detach()
    return "detached"


@mcp.tool(annotations=DESTRUCTIVE)
@friendly
def ps4_execution(action: Literal["stop", "go", "kill", "step"]) -> str:
    """Stop / resume / kill the attached process, or single-step the stopped thread."""
    _guard_write()
    if action == "step":
        dbg.single_step()
    else:
        dbg.stopgo({"go": 0, "stop": 1, "kill": 2}[action])
    return action


@mcp.tool(annotations=DESTRUCTIVE)
@friendly
def ps4_breakpoint(action: Literal["set", "clear"], index: int = 0, address: str | None = None) -> str:
    """Software breakpoint slot `index` (0-29) at address in the attached process. Hits show up in
    ps4_debug_events."""
    _guard_write()
    if action == "set" and not address:
        raise ValueError("address required")
    dbg.breakpoint(index, action == "set", _addr(address) if address else 0)
    return f"breakpoint {index} {'set at ' + address if action == 'set' else 'cleared'}"


@mcp.tool(annotations=DESTRUCTIVE)
@friendly
def ps4_watchpoint(index: int, enabled: bool, address: str, size: Literal[1, 2, 4, 8] = 4,
                   kind: Literal["exec", "write", "readwrite"] = "write") -> str:
    """Hardware watchpoint slot `index` (0-3) in the attached process."""
    _guard_write()
    dbg.watchpoint(index, enabled, {1: 0, 2: 1, 4: 3, 8: 2}[size], {"exec": 0, "write": 1, "readwrite": 3}[kind], _addr(address))
    return f"watchpoint {index} {'on' if enabled else 'off'}"


@mcp.tool(annotations=RO)
@friendly
def ps4_threads() -> list[dict]:
    """Threads of the attached process (lwpid, name, priority)."""
    return [dbg.thread_info(t) for t in dbg.threads()[:128]]


@mcp.tool(annotations=RO)
@friendly
def ps4_registers(lwpid: int) -> dict:
    """General registers of a thread of the attached process (stop it first for stable values)."""
    return {k: hex(v) for k, v in dbg.get_regs(lwpid).items()}


@mcp.tool(annotations=RO)
@friendly
def ps4_debug_events(timeout_seconds: float = 0, since: int = 0) -> dict:
    """Debugger events (breakpoint hits, signals) reported by the console since attach. With
    timeout_seconds > 0, waits for a new one. Pass since=<next> from the previous call."""
    evs, nxt = dbg.wait_event(max(0.0, min(timeout_seconds, 600.0)), since)
    return {"events": [e.to_dict() for e in evs[-50:]], "next": nxt, "event_link": dbg.event_link_up()}


# Sharing the console between sessions
@mcp.tool(annotations=WRITE)
@friendly
def ps4_lock(reason: str, wait_seconds: float = 0, owner: str | None = None) -> dict:
    """Reserve the console for a test so other Claude Code sessions (and scripts using the CLI) can't
    upload / launch / reboot in the middle of it. Waits up to wait_seconds (max 1800) if someone else
    holds it. Renewed by each of your tool calls; expires after PS4_LOCK_LEASE s (default 600)
    without any. Also starts the klog listener. Release with ps4_unlock."""
    if owner:
        console_lock.owner = owner
    try:
        info = console_lock.acquire(reason, wait_seconds=max(0.0, min(wait_seconds, 1800.0)))
    except ConsoleBusy as e:
        raise ConsoleBusy(e.info, LOCK_HINT) from None
    _ensure_klog()
    return info


@mcp.tool(annotations=WRITE)
@friendly
def ps4_unlock() -> str:
    """Release your reservation of the console."""
    if not console_lock.release():
        st = console_lock.status()
        return "you did not hold the console" + (f"; {describe_lock(st)}" if st else " (it is free)")
    return "console released"


@mcp.tool(annotations=RO)
@friendly
def ps4_lock_status() -> dict | str:
    """Who has the console reserved, or "free"."""
    return console_lock.status() or "free"


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
