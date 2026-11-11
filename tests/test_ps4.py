import struct
import time

import pytest

from mock_ps4 import CRASH_SAMPLE, MockPs4
from ps4_goldhen_mcp import crash as crash_mod
from ps4_goldhen_mcp.deploy import deploy
from ps4_goldhen_mcp.ftp import Ps4Ftp, parse_list_line
from ps4_goldhen_mcp.klog import KlogListener
from ps4_goldhen_mcp.lock import ConsoleBusy, ConsoleLock
from ps4_goldhen_mcp.payload import PayloadError, send
from ps4_goldhen_mcp.ps4debug import Ps4Debug, Ps4DebugError, pack_regs, parse_regs
from ps4_goldhen_mcp.rpc import RemoteProcess
from ps4_goldhen_mcp.sfo import parse_sfo
from ps4_goldhen_mcp import apps as apps_mod


@pytest.fixture(scope="module")
def mock():
    m = MockPs4(event_port=7551)
    yield m
    m.close()


@pytest.fixture()
def ftp(mock):
    f = Ps4Ftp("127.0.0.1", mock.ftp_port, 5)
    yield f
    f.close()


@pytest.fixture()
def dbg(mock):
    d = Ps4Debug("127.0.0.1", mock.dbg_port, 5, event_port=7551)
    yield d
    d.close()


def test_parse_goldhen_list_line():
    e = parse_list_line("-rw-rw-rw- 1 0 0 452 Nov 10 06:21 config.ini")
    assert e == {"name": "config.ini", "is_dir": False, "size": 452, "mode": "-rw-rw-rw-", "date": "Nov 10 06:21"}
    assert parse_list_line("drwxr-xr-x 5 0 0 512 Dec  8 2026 cheats")["is_dir"]
    assert parse_list_line("drwxrwxrwx 6 0 0 512 Jan 14 2026 .") is None


def test_ftp_roundtrip(ftp, tmp_path):
    src = tmp_path / "a.bin"
    src.write_bytes(b"x" * 100000)
    ftp.makedirs("/data/test/sub")
    r = ftp.upload(src, "/data/test/sub/a.bin")
    assert r["verified_size"] and r["bytes"] == 100000
    assert ftp.stat("/data/test/sub/a.bin")["size"] == 100000
    assert ftp.download("/data/test/sub/a.bin", max_bytes=10) == b"x" * 10
    assert len(ftp.download("/data/test/sub/a.bin", max_bytes=50, tail=True)) == 50
    assert ftp.download("/data/GoldHEN/config.ini").startswith(b"[BinLoader]")
    ftp.rename("/data/test/sub/a.bin", "/data/test/sub/b.bin")
    assert ftp.delete("/data/test", recursive=True) == 3
    assert not ftp.exists("/data/test")


def test_ftp_protected(ftp):
    for p in ("/", "/data", "/system/common", "/data/GoldHEN/config.ini", "/user/app"):
        with pytest.raises(PermissionError):
            ftp.delete(p, recursive=True)


def test_deploy_incremental(ftp, tmp_path, monkeypatch):
    monkeypatch.setenv("PS4_CACHE_DIR", str(tmp_path / "cache"))
    d = tmp_path / "build"
    (d / "assets").mkdir(parents=True)
    (d / "eboot.bin").write_bytes(b"E" * 1000)
    (d / "assets" / "x.png").write_bytes(b"P" * 10)
    (d / "skip.o").write_bytes(b"o")
    r1 = deploy(ftp, str(d), "/data/homebrew/app")
    assert r1["uploaded_count"] == 2
    r2 = deploy(ftp, str(d), "/data/homebrew/app")
    assert r2["uploaded_count"] == 0 and r2["skipped_unchanged"] == 2
    (d / "eboot.bin").write_bytes(b"F" * 1001)
    (d / "assets" / "x.png").unlink()
    r3 = deploy(ftp, str(d), "/data/homebrew/app", prune=True)
    assert r3["uploaded"] == ["eboot.bin"] and r3["deleted"] == ["assets/x.png"]


def test_klog_backlog_wait_and_crash(mock):
    k = KlogListener("127.0.0.1", mock.klog_port)
    k.start()
    assert k.wait_connected(5)
    # the history replayed at connect is flagged and does not satisfy wait_for
    assert k.get(include_backlog=True)["lines"]
    assert k.get()["lines"] == []
    r = k.wait_for("init ok", 0.5)
    assert r.get("timed_out")
    since = k.next_id
    mock.say("[app] hello", "[app] init ok")
    r = k.wait_for("init ok", 5, since_id=since)
    assert r["matched"] and "init ok" in r["line"]
    mock.say(*CRASH_SAMPLE)
    r = k.wait_for("never", 5)
    assert r.get("crashed")
    c = r["crash"]
    assert c["signal"].startswith("11") and c["proc_name"] == "eboot.bin"
    assert c["rip"] == "0x483288 eboot.bin+0x83288"
    assert c["backtrace"][0] == "0x4007d3 eboot.bin+0x7d3"
    k.stop()


def test_klog_is_shared_between_listeners(mock, tmp_path, monkeypatch, request):
    """The console serves one klog client; the second listener reads through the first, and takes
    the console over when the first stops."""
    monkeypatch.setenv("PS4_CACHE_DIR", str(tmp_path))
    a = KlogListener("127.0.0.1", mock.klog_port)
    b = KlogListener("127.0.0.1", mock.klog_port)
    a.start()
    request.addfinalizer(a.stop)
    request.addfinalizer(b.stop)
    assert a.wait_connected(5) and a.source == "console"
    mock.say("[app] before b")
    assert a.wait_for("before b", 5, since_id=1)["matched"]
    b.start()
    assert b.wait_connected(5) and b.source.startswith("shared by pid")
    # b's backlog is what a had collected, and it does not satisfy wait_for
    assert any("before b" in l for l in b.get(include_backlog=True)["lines"])
    assert b.get()["lines"] == []
    since = b.next_id
    mock.say("[app] seen by both")
    assert b.wait_for("seen by both", 5, since_id=since)["matched"]
    assert a.wait_for("seen by both", 5, since_id=1)["matched"]
    assert not any("failed to open klog" in l["text"] for l in list(a.lines) + list(b.lines))
    a.stop()
    deadline = time.time() + 10
    while time.time() < deadline and b.source != "console":
        time.sleep(0.1)
    assert b.source == "console" and b.wait_connected(5)  # the console's history replay is over
    since = b.next_id
    mock.say("[app] after takeover")
    assert b.wait_for("after takeover", 5, since_id=since)["matched"]
    b.stop()
    assert not list(tmp_path.glob("klog-*.json"))


def test_klog_held_by_a_foreign_client(mock, tmp_path, monkeypatch, request):
    monkeypatch.setenv("PS4_CACHE_DIR", str(tmp_path))
    import socket as socket_mod
    foreign = socket_mod.create_connection(("127.0.0.1", mock.klog_port))  # e.g. curl: no relay
    time.sleep(0.3)
    k = KlogListener("127.0.0.1", mock.klog_port)
    k.start()
    request.addfinalizer(k.stop)
    request.addfinalizer(foreign.close)
    time.sleep(1.0)
    r = k.get(include_backlog=True)
    assert not r["connected"] and "held by another client" in r["not_connected"] and r["lines"] == []
    foreign.close()
    assert k.wait_connected(8) and k.source == "console"
    k.stop()


def test_crash_parse_modules():
    rep = crash_mod.parse_report(CRASH_SAMPLE)
    assert rep["registers"]["rbx"] == "0x00000010000048d0"
    assert [m["path"] for m in rep["modules"]] == ["/app0/eboot.bin", "/X0GEVgvRuq/common/lib/libkernel_sys.sprx"]
    assert crash_mod.where(0x800000010, rep["modules"]) == "0x800000010 libkernel_sys.sprx+0x10"


def test_ps4debug_basics(dbg, mock):
    assert dbg.version() == "1.3"
    assert dbg.firmware() == 505
    assert "v1.1.19" in dbg.debugger_version()
    assert {"pid": 42, "name": "SceShellUI"} in dbg.processes()
    assert dbg.process_info(64)["title_id"] == "HRSA00002"
    assert dbg.maps(42)[0]["name"] == "libkernel_sys.sprx"
    assert dbg.read(42, 0x400010, 4) == bytes([16, 17, 18, 19])
    dbg.write(42, 0x500000, b"hello")
    assert dbg.read(42, 0x500000, 5) == b"hello"
    dbg.notify("hi there")
    assert mock.state.notifications[-1] == "hi there"
    assert apps_mod.running(dbg) == [dbg.process_info(64)]


def test_regs_roundtrip():
    r = {"rax": 1, "rip": 0x401000, "rsp": 0x7ff0, "r15": 15}
    back = parse_regs(pack_regs(r))
    assert back["rax"] == 1 and back["rip"] == 0x401000 and back["rsp"] == 0x7ff0 and back["r15"] == 15


def test_rpc_dlsym_and_call(dbg):
    rp = RemoteProcess(dbg, 42, "SceShellUI")
    assert rp.syscall_wrappers()[591] == 0x800000100
    assert rp.handles() == [0, 113, 8193]
    assert rp.dlsym("sceKernelGetCpuFrequency") == 0x800001000
    assert rp.dlsym("nope") is None
    assert rp.call("sceKernelGetCpuFrequency") == 1600000000


def test_rpc_refuses_core_daemons(dbg):
    with pytest.raises(PermissionError):
        RemoteProcess(dbg, 41, "SceShellCore")


def test_debugger_attach_events(dbg):
    dbg.attach(64)
    assert dbg.threads() == [100001, 100002]
    assert dbg.thread_info(100001)["name"] == "thread100001"
    assert dbg.get_regs(100001)["rip"] == 0x401234
    dbg.breakpoint(0, True, 0x401000)
    evs, nxt = dbg.wait_event(5)
    assert evs and evs[0].signal == 5 and evs[0].regs["rip"] == 0x401000 and evs[0].thread_name == "main_th"
    with pytest.raises(Ps4DebugError):
        dbg.attach(64)
    dbg.detach()
    with pytest.raises(Ps4DebugError):
        dbg.threads()


def test_payload_refuses_empty():
    with pytest.raises(PayloadError):
        send("127.0.0.1", 9, b"")


def test_sfo():
    keys = [(b"TITLE", "Harissa64"), (b"TITLE_ID", "HRSA00002")]
    key_tbl = b"".join(k + b"\0" for k, _ in keys)
    while len(key_tbl) % 4:
        key_tbl += b"\0"
    entries, data, koff = b"", b"", 0
    for k, v in keys:
        raw = v.encode() + b"\0"
        entries += struct.pack("<HHIII", koff, 0x0204, len(raw), 16, len(data))
        data += raw.ljust(16, b"\0")
        koff += len(k) + 1
    key_off = 20 + len(entries)
    blob = b"\0PSF" + struct.pack("<IIII", 0x101, key_off, key_off + len(key_tbl), len(keys)) + entries + key_tbl + data
    assert parse_sfo(blob) == {"TITLE": "Harissa64", "TITLE_ID": "HRSA00002"}


def test_lock_between_sessions(tmp_path, monkeypatch):
    monkeypatch.setenv("PS4_CACHE_DIR", str(tmp_path))
    a = ConsoleLock("1.2.3.4", owner="A")
    b = ConsoleLock("1.2.3.4", owner="B")
    a.acquire("test")
    with pytest.raises(ConsoleBusy):
        b.claim("x")
    assert a.release()
    assert b.claim("x")["owner"] == "B"
