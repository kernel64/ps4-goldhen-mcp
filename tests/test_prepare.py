"""The console prepares itself: ps4debug is loaded on first use, once, and nothing stale survives a reboot."""

import threading

import pytest

from mock_ps4 import MockPs4
from ps4_goldhen_mcp.config import Config
from ps4_goldhen_mcp.payload import Ps4DebugLoader
from ps4_goldhen_mcp.ps4debug import Ps4Debug, Ps4DebugUnavailable


@pytest.fixture()
def fresh(tmp_path, monkeypatch):
    """A console just booted: GoldHEN runs, ps4debug is not loaded."""
    monkeypatch.setenv("PS4_CACHE_DIR", str(tmp_path))
    m = MockPs4(event_port=7561, ps4debug_loaded=False)
    yield m
    m.close()


def cfg_for(m: MockPs4, tmp_path, **kw) -> Config:
    payload = tmp_path / "ps4debug.bin"
    payload.write_bytes(b"\x90" * 64)
    return Config(host="127.0.0.1", ftp_port=m.ftp_port, debug_port=m.dbg_port, binloader_port=m.binloader_port,
                  ps4debug_bin=str(payload), **kw)


def client(m: MockPs4, loader) -> Ps4Debug:
    return Ps4Debug("127.0.0.1", m.dbg_port, 10, event_port=7561, loader=loader)


def test_loaded_on_first_use_then_reused(fresh, tmp_path):
    loader = Ps4DebugLoader(cfg_for(fresh, tmp_path))
    d = client(fresh, loader)
    assert {"pid": 45, "name": "ScePartyDaemon"} in d.processes()
    assert fresh.state.payloads == [b"\x90" * 64] and loader.loads == 1
    d.close()
    other = client(fresh, Ps4DebugLoader(cfg_for(fresh, tmp_path)))  # another session
    assert other.version() == "1.3"
    assert len(fresh.state.payloads) == 1
    d.close(), other.close()


def test_two_sessions_at_once_send_it_once(fresh, tmp_path):
    clients = [client(fresh, Ps4DebugLoader(cfg_for(fresh, tmp_path))) for _ in range(3)]
    results = []
    threads = [threading.Thread(target=lambda c=c: results.append(c.version())) for c in clients]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert results == ["1.3"] * 3
    assert len(fresh.state.payloads) == 1
    for c in clients:
        c.close()


@pytest.mark.parametrize("kw, busy, message", [
    ({"read_only": True}, None, "read-only"),
    ({"auto_load_ps4debug": False}, None, "auto-loading is off"),
    ({}, lambda: "harissa64 (test)", "reserved by harissa64"),
])
def test_never_sent_when_not_allowed(fresh, tmp_path, kw, busy, message):
    d = client(fresh, Ps4DebugLoader(cfg_for(fresh, tmp_path, **kw), busy))
    with pytest.raises(Ps4DebugUnavailable, match=message):
        d.processes()
    assert fresh.state.payloads == []


def test_binloader_off_gives_a_clear_error_and_backs_off(tmp_path, monkeypatch):
    monkeypatch.setenv("PS4_CACHE_DIR", str(tmp_path))
    m = MockPs4(event_port=7562, ps4debug_loaded=False, binloader=False)
    try:
        loader = Ps4DebugLoader(cfg_for(m, tmp_path))
        d = client(m, loader)
        with pytest.raises(Ps4DebugUnavailable, match="Enable it in GoldHEN"):
            d.processes()
        # the next call answers from the back-off instead of trying again
        with pytest.raises(Ps4DebugUnavailable, match="Enable it in GoldHEN"):
            d.processes()
        assert m.state.payloads == []
    finally:
        m.close()


def test_reboot_reloads_and_drops_stale_rpc_stubs(fresh, tmp_path):
    loader = Ps4DebugLoader(cfg_for(fresh, tmp_path))
    d = client(fresh, loader)
    assert d.call(45, 0x800001000) == 1600000000
    assert fresh.state.rpc_installs == 1
    epoch = d.epoch

    # a dropped connection alone: the stub is still mapped, so it is reused
    d.close()
    assert d.call(45, 0x800001000) == 1600000000
    assert fresh.state.rpc_installs == 1

    # the console reboots (same pid for the daemon): ps4debug is loaded again, the stub re-installed
    fresh.reboot()
    with pytest.raises(Ps4DebugUnavailable):  # the call that hits the dead connection is not retried
        d.call(45, 0x800001000)
    assert {"pid": 45, "name": "ScePartyDaemon"} in d.processes()
    assert len(fresh.state.payloads) == 2 and d.epoch > epoch
    assert d.call(45, 0x800001000) == 1600000000
    assert fresh.state.rpc_installs == 2
    d.close()
