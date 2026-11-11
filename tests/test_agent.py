"""The console-side agent against the mock: injection through ps4debug, launch / close, packages."""

import socket
import struct

import pytest

from mock_ps4 import AGENT_FUNCTIONS, LNC_LAUNCH, MockPs4
from ps4_goldhen_mcp import apps as apps_mod
from ps4_goldhen_mcp.agent import FUNCTIONS, TABLE_HEADER, Agent, AgentError, blob
from ps4_goldhen_mcp.ps4debug import Ps4Debug


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def mock():
    m = MockPs4(event_port=7553)
    yield m
    if m.state.agent:
        m.state.agent.srv.close()
    m.close()


@pytest.fixture()
def dbg(mock):
    d = Ps4Debug("127.0.0.1", mock.dbg_port, 5, event_port=7553)
    yield d
    d.close()


@pytest.fixture()
def agent(dbg):
    return Agent(dbg, "127.0.0.1", port=free_port(), timeout=5)


def test_blob_and_table_layout():
    code, version = blob()
    assert version == 3 and 1000 < len(code) < 0x3000
    assert [n for n, _ in FUNCTIONS] == AGENT_FUNCTIONS
    assert TABLE_HEADER + 8 * len(FUNCTIONS) == 184  # sizeof(struct agent_table), printed by tests/agent_host.c


def test_inject_once_then_reuse(agent, mock):
    assert agent.ping() is None
    info = agent.ensure()
    assert info["injected"] and info["host_pid"] == 45 and info["version"] == 3
    code, _ = blob()
    assert mock.state.read(info["base"], len(code)) == code
    # the launch entry of the table is sceLncUtilLaunchApp, found through the wrapper's call instruction
    table = info["base"] + ((len(code) + 15) & ~15)
    slot = [n for n, _ in FUNCTIONS].index("sceLncUtilLaunchApp")
    assert struct.unpack("<Q", mock.state.read(table + TABLE_HEADER + 8 * slot, 8))[0] == LNC_LAUNCH
    assert agent.ensure()["injected"] is False
    assert mock.state.agent_starts == 1
    assert agent.foreground_user() == 0x10000000
    # a new PC session (another Agent object) finds the running agent
    assert Agent(agent.dbg, "127.0.0.1", port=agent.port).ensure()["injected"] is False


def test_launch_replaces_the_running_app(agent, dbg, mock):
    assert [a["title_id"] for a in apps_mod.running(dbg)] == ["HRSA00002"]
    with pytest.raises(RuntimeError, match="HRSA00002 is running"):
        apps_mod.launch(agent, dbg, "HRSA00002", replace=False)
    mock.state.launch_delay = 0.4
    r = apps_mod.launch(agent, dbg, "hrsa00002", ["--rom", "/data/roms/x.z64"])
    assert r["closed"] == ["HRSA00002"] and r["pid"] != 64 and r["app_id"] == "0x60000002"
    assert mock.state.launches == [("HRSA00002", ["--rom", "/data/roms/x.z64"])]
    assert dbg.process_info(r["pid"])["title_id"] == "HRSA00002"


def test_close(agent, dbg):
    with pytest.raises(LookupError, match="CUSA00001 is not running .running: HRSA00002"):
        apps_mod.close(agent, dbg, "CUSA00001")
    r = apps_mod.close(agent, dbg, "HRSA00002")
    assert r == {"closed": ["HRSA00002"], "app_id": "0x60000001"}
    assert apps_mod.running(dbg) == [] and agent.big_app() is None
    assert apps_mod.close(agent, dbg)["closed"] == []


def test_launch_errors(agent, dbg):
    with pytest.raises(ValueError):
        apps_mod.launch(agent, dbg, "nope")
    with pytest.raises(PermissionError):
        apps_mod.launch(agent, dbg, "NPXS20001")
    with pytest.raises(ValueError):
        agent.launch("HRSA00002", ["two words"])
    with pytest.raises(AgentError, match="sceLncUtilLaunchApp: 0x80940031") as e:
        apps_mod.launch(agent, dbg, "CUSA00001")
    assert e.value.code == 0x80940031


def test_packages(agent):
    agent.ensure()
    assert agent.pkg_info("/data/pkg/new.pkg") == {"title_id": "HRSA00099", "is_app": True}
    assert not agent.exists("HRSA00099")
    agent.install_pkg("/data/pkg/new.pkg")
    assert agent.exists("HRSA00099")
    agent.uninstall("HRSA00099")
    assert not agent.exists("HRSA00099")
    with pytest.raises(AgentError):
        agent.install_pkg("/data/pkg/missing.pkg")
    with pytest.raises(ValueError):
        agent.install_pkg("data/pkg/relative.pkg")


def test_unload_frees_the_host_memory(agent, mock):
    info = agent.ensure()
    assert agent.unload()["unloaded"]
    assert (info["base"], info["size"]) in mock.state.freed
    assert agent.ping() is None
    assert agent.unload() == {"unloaded": False, "note": "no agent running"}
    assert agent.ensure()["injected"] and mock.state.agent_starts == 2


def test_port_taken(agent, mock):
    with socket.socket() as s:
        s.bind(("127.0.0.1", agent.port))
        s.listen(1)
        with pytest.raises(AgentError, match="could not listen"):
            agent.inject()
    # nothing stays in the host: the symbol lookup scratch page and the agent image are both freed
    assert len(mock.state.freed) == 2 and mock.state.next_alloc == 0x10000 + 2 * 0x4000


def test_core_daemons_are_not_hosts(dbg):
    with pytest.raises(PermissionError):
        Agent(dbg, "127.0.0.1", port=free_port(), host_process="SceShellCore").inject()


def test_cli_launch_close(mock, monkeypatch, tmp_path, capsys):
    import json

    from ps4_goldhen_mcp.cli import main

    for k, v in {"PS4_HOST": "127.0.0.1", "PS4_DEBUG_PORT": mock.dbg_port, "PS4_FTP_PORT": mock.ftp_port,
                 "PS4_KLOG_PORT": mock.klog_port, "PS4_AGENT_PORT": free_port(), "PS4_CACHE_DIR": tmp_path}.items():
        monkeypatch.setenv(k, str(v))
    assert main(["agent"]) == 0
    assert json.loads(capsys.readouterr().out)["running"] is False
    assert main(["launch", "HRSA00002", "--", "--save", "/data/s.st"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["closed"] == ["HRSA00002"] and mock.state.launches == [("HRSA00002", ["--save", "/data/s.st"])]
    assert main(["close", "HRSA00002"]) == 0
    assert json.loads(capsys.readouterr().out)["closed"] == ["HRSA00002"]
    assert main(["agent", "unload"]) == 0
    assert json.loads(capsys.readouterr().out)["unloaded"] is True
    assert not list(tmp_path.glob("locks/*")) or main(["lock-status"]) == 0
