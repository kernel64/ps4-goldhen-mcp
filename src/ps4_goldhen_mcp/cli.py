"""Command line: `ps4 <command>` (PS4_HOST must be set), for build scripts and quick checks."""

from __future__ import annotations

import argparse
import json
import sys
import time

from . import apps as apps_mod, capture as capture_mod, crash as crash_mod, deploy as deploy_mod, payload as payload_mod
from .agent import Agent
from .config import Config
from .ftp import Ps4Ftp, port_open
from .klog import KlogListener
from .lock import ConsoleBusy, ConsoleLock
from .ps4debug import Ps4Debug

WRITE_COMMANDS = {"put", "mkdir", "rm", "mv", "deploy", "load-ps4debug", "notify", "reboot", "launch", "close", "agent"}


def _print(obj) -> None:
    print(obj if isinstance(obj, str) else json.dumps(obj, indent=2, default=str))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ps4", description="Drive a GoldHEN PS4 (FTP, klog, ps4debug, HDMI capture)")
    ap.add_argument("--host")
    ap.add_argument("--wait-lock", type=float, default=0, help="seconds to wait if another session holds the console")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("info")
    p = sub.add_parser("ls"); p.add_argument("path", nargs="?", default="/data")
    p = sub.add_parser("get"); p.add_argument("remote"); p.add_argument("local")
    p = sub.add_parser("cat"); p.add_argument("remote"); p.add_argument("--tail", action="store_true")
    p = sub.add_parser("put"); p.add_argument("local"); p.add_argument("remote")
    p = sub.add_parser("mkdir"); p.add_argument("path")
    p = sub.add_parser("rm"); p.add_argument("path"); p.add_argument("-r", action="store_true"); p.add_argument("--force", action="store_true")
    p = sub.add_parser("mv"); p.add_argument("src"); p.add_argument("dst")
    p = sub.add_parser("deploy"); p.add_argument("local"); p.add_argument("remote"); p.add_argument("--force", action="store_true"); p.add_argument("--prune", action="store_true")
    p = sub.add_parser("apps"); p.add_argument("--no-names", action="store_true")
    p = sub.add_parser("ps")
    p = sub.add_parser("launch", help="start an installed app (the running one is closed first)")
    p.add_argument("title_id"); p.add_argument("args", nargs="*"); p.add_argument("--no-replace", action="store_true")
    p.add_argument("--wait", metavar="REGEX", help="block until this klog line"); p.add_argument("--timeout", type=float, default=30)
    p = sub.add_parser("close", help="close the running app"); p.add_argument("title_id", nargs="?")
    p = sub.add_parser("agent"); p.add_argument("action", choices=["status", "load", "unload"], nargs="?", default="status")
    p = sub.add_parser("log"); p.add_argument("-f", action="store_true", help="follow"); p.add_argument("--grep"); p.add_argument("--seconds", type=float, default=3)
    p = sub.add_parser("wait"); p.add_argument("pattern"); p.add_argument("--timeout", type=float, default=30)
    p = sub.add_parser("symbolize"); p.add_argument("elf"); p.add_argument("offsets", nargs="+")
    sub.add_parser("load-ps4debug")
    p = sub.add_parser("notify"); p.add_argument("message")
    sub.add_parser("reboot")
    sub.add_parser("lock-status")
    p = sub.add_parser("unlock"); p.add_argument("--force", action="store_true")
    p = sub.add_parser("capture"); p.add_argument("what", choices=["devices", "photo", "burst", "video"]); p.add_argument("arg", nargs="?"); p.add_argument("--interval-ms", type=int, default=250)
    a = ap.parse_args(argv)

    if a.cmd == "symbolize":
        syms = crash_mod.ElfSymbols(a.elf)
        for o in a.offsets:
            print(o, syms.lookup(int(o, 16)) or "?")
        return 0
    if a.cmd == "capture":
        card = capture_mod.CaptureCard.from_env()
        if a.what == "devices":
            _print(card.devices())
        elif a.what == "photo":
            _print(card.photo(a.arg))
        elif a.what == "burst":
            _print(card.burst(int(a.arg or 8), a.interval_ms / 1000))
        else:
            _print(card.record(float(a.arg or 10)))
        return 0

    cfg = Config.from_env(a.host)
    lock = ConsoleLock(cfg.host, lease_seconds=cfg.lock_lease)
    if a.cmd == "lock-status":
        _print(lock.status() or "free")
        return 0
    if a.cmd == "unlock":
        _print("released" if lock.release(force=a.force) else "not held (use --force to clear someone else's)")
        return 0
    if a.cmd in WRITE_COMMANDS:
        if cfg.read_only:
            print("read-only mode (PS4_READ_ONLY=1)", file=sys.stderr)
            return 2
        try:
            lock.acquire(f"cli: {a.cmd}", wait_seconds=a.wait_lock)
        except ConsoleBusy as e:
            print(e, file=sys.stderr)
            return 3
    ftp = Ps4Ftp(cfg.host, cfg.ftp_port, cfg.timeout)
    dbg = Ps4Debug(cfg.host, cfg.debug_port, cfg.timeout)
    if a.cmd != "load-ps4debug":
        dbg.loader = payload_mod.Ps4DebugLoader(
            cfg, lambda: None if not (st := lock.status()) or st.get("held_by_me") else st.get("owner", "someone"))
    try:
        if a.cmd == "info":
            out = {"ftp": port_open(cfg.host, cfg.ftp_port), "klog": port_open(cfg.host, cfg.klog_port)}
            if dbg.available():
                out.update(ps4debug=dbg.version(), firmware=dbg.firmware(), running=apps_mod.running(dbg))
            else:
                out["ps4debug"] = "not loaded"
            _print(out)
        elif a.cmd == "ls":
            for e in ftp.list_dir(a.path):
                print(f"{'d' if e['is_dir'] else '-'} {e['size']:>12} {e['date']:>12} {e['name']}")
        elif a.cmd == "get":
            _print({"bytes": ftp.download(a.remote, a.local)})
        elif a.cmd == "cat":
            sys.stdout.write(ftp.download(a.remote, max_bytes=1 << 20, tail=a.tail).decode("utf-8", "replace"))
        elif a.cmd == "put":
            _print(ftp.upload(a.local, a.remote))
        elif a.cmd == "mkdir":
            ftp.makedirs(a.path)
        elif a.cmd == "rm":
            _print({"deleted": ftp.delete(a.path, a.r, force=a.force)})
        elif a.cmd == "mv":
            ftp.rename(a.src, a.dst)
        elif a.cmd == "deploy":
            _print(deploy_mod.deploy(ftp, a.local, a.remote, force=a.force, prune=a.prune))
        elif a.cmd == "apps":
            _print(apps_mod.installed(ftp, with_names=not a.no_names))
        elif a.cmd == "ps":
            for p in dbg.processes():
                print(p["pid"], p["name"])
        elif a.cmd in ("launch", "close", "agent"):
            agent = Agent(dbg, cfg.host, cfg.agent_port, cfg.timeout, cfg.agent_host_process)
            if a.cmd == "close":
                _print(apps_mod.close(agent, dbg, a.title_id))
            elif a.cmd == "agent":
                if a.action == "status":
                    info = agent.ping()
                    _print({"running": bool(info), **(info or {}), "port": agent.port, "host_process": agent.host_process})
                else:
                    _print(agent.ensure() if a.action == "load" else agent.unload())
            else:
                k = since = None
                if a.wait:
                    k = KlogListener(cfg.host, cfg.klog_port)
                    k.start()
                    k.wait_connected(3)
                    since = k.next_id
                out = apps_mod.launch(agent, dbg, a.title_id, a.args, replace=not a.no_replace)
                if k:
                    out["log"] = k.wait_for(a.wait, a.timeout, since)
                    k.stop()
                _print(out)
                if k and not out["log"].get("matched"):
                    return 1
        elif a.cmd in ("log", "wait"):
            k = KlogListener(cfg.host, cfg.klog_port)
            k.start()
            k.wait_connected(3)
            if a.cmd == "wait":
                r = k.wait_for(a.pattern, a.timeout)
                _print(r)
                return 0 if r.get("matched") else 1
            since = None
            end = time.time() + a.seconds
            while a.f or time.time() < end:
                r = k.get(since, a.grep, 1000)
                for line in r["lines"]:
                    print(line, flush=True)
                since = r["next_since_id"]
                time.sleep(0.3)
        elif a.cmd == "load-ps4debug":
            if dbg.available():
                _print({"already_loaded": dbg.version()})
            else:
                path = payload_mod.ps4debug_bin(cfg.ps4debug_bin)
                n = payload_mod.send(cfg.host, cfg.binloader_port, path.read_bytes())
                _print({"sent": n, "up_after_s": payload_mod.wait_port(cfg.host, cfg.debug_port, 15)})
        elif a.cmd == "notify":
            dbg.notify(a.message)
        elif a.cmd == "reboot":
            dbg.reboot()
    finally:
        ftp.close()
        dbg.close()
        if a.cmd in WRITE_COMMANDS:
            lock.release()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
