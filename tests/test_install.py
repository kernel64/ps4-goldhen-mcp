"""Installing and uninstalling homebrew packages through the agent, against the mock."""

import json
import socket

import pytest

from mock_ps4 import MockPs4
from ps4_goldhen_mcp import apps as apps_mod
from ps4_goldhen_mcp.agent import Agent
from ps4_goldhen_mcp.ftp import Ps4Ftp
from ps4_goldhen_mcp.ps4debug import Ps4Debug


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PS4_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("PS4_EXPERIMENTAL_INSTALL", "1")
    m = MockPs4(event_port=7563)
    d = Ps4Debug("127.0.0.1", m.dbg_port, 5, event_port=7563)
    f = Ps4Ftp("127.0.0.1", m.ftp_port, 5)
    a = Agent(d, "127.0.0.1", port=free_port(), timeout=5)
    yield m, d, f, a
    f.close()
    d.close()
    if m.state.agent:
        m.state.agent.srv.close()
    m.close()


def put_pkg(m: MockPs4, name: str, title_id: str) -> str:
    (m.root / "data/pkg" / name).write_bytes(b"FAKEPKG " + title_id.encode() + b"\n" + b"\0" * 4000)
    return f"/data/pkg/{name}"


def test_install_keeps_the_package(env):
    m, d, f, a = env
    pkg = put_pkg(m, "IV0000-HRSA00099_00-TEST.pkg", "HRSA00099")
    r = apps_mod.install(a, f, d, pkg, timeout=10)
    assert r["title_id"] == "HRSA00099" and r["pkg_kept"] is True
    assert (m.root / "data/pkg/IV0000-HRSA00099_00-TEST.pkg").is_file()
    assert not (m.root / "data/pkg/.install-IV0000-HRSA00099_00-TEST.pkg").exists()  # the copy was consumed
    assert (m.root / "user/app/HRSA00099/app.pkg").is_file()
    assert m.state.install_paths == ["/user/data/pkg/.install-IV0000-HRSA00099_00-TEST.pkg"]


def test_install_can_consume_the_package(env):
    m, d, f, a = env
    pkg = put_pkg(m, "x.pkg", "HRSA00098")
    r = apps_mod.install(a, f, d, pkg, keep_pkg=False, timeout=10)
    assert r["pkg_kept"] is False and not (m.root / "data/pkg/x.pkg").exists()


def test_installed_title_needs_replace(env):
    m, d, f, a = env
    pkg = put_pkg(m, "probe.pkg", "HRSA00002")  # installed and running in the mock
    with pytest.raises(FileExistsError, match="replace=true"):
        apps_mod.install(a, f, d, pkg, timeout=10)
    r = apps_mod.install(a, f, d, pkg, replace=True, timeout=10)
    assert r["replaced"]["closed"] == ["HRSA00002"] and r["replaced"]["uninstalled"]
    assert a.exists("HRSA00002") and (m.root / "user/app/HRSA00002/app.pkg").is_file()


@pytest.mark.parametrize("title_id", ["CUSA01042", "PLAS00001", "NPXS20001"])
def test_retail_and_system_packages_are_refused(env, title_id):
    m, d, f, a = env
    pkg = put_pkg(m, "game.pkg", title_id)
    with pytest.raises(PermissionError, match="only homebrew"):
        apps_mod.install(a, f, d, pkg, timeout=10)
    assert m.state.install_paths == []


def test_disabled_by_default(env, monkeypatch):
    m, d, f, a = env
    monkeypatch.delenv("PS4_EXPERIMENTAL_INSTALL")
    pkg = put_pkg(m, "x.pkg", "HRSA00098")
    with pytest.raises(RuntimeError, match="disabled"):
        apps_mod.install(a, f, d, pkg)
    assert m.state.install_paths == []


def test_bad_paths(env):
    m, d, f, a = env
    with pytest.raises(FileNotFoundError):
        apps_mod.install(a, f, d, "/data/pkg/missing.pkg")
    with pytest.raises(ValueError, match="not a .pkg"):
        apps_mod.install(a, f, d, "/data/GoldHEN/config.ini")


def test_uninstall(env):
    m, d, f, a = env
    r = apps_mod.uninstall(a, f, d, "HRSA00002")  # running: closed first
    assert r["closed"] == ["HRSA00002"] and r["uninstalled"]
    assert not a.exists("HRSA00002") and not (m.root / "user/app/HRSA00002").exists()
    with pytest.raises(LookupError, match="not installed"):
        apps_mod.uninstall(a, f, d, "HRSA00002")
    with pytest.raises(PermissionError, match="system"):
        apps_mod.uninstall(a, f, d, "NPXS20001")
    m.state.installed["CUSA01042"] = "EP0101-CUSA01042_00-PES2015HG0000000"
    with pytest.raises(PermissionError, match="ask the user"):
        apps_mod.uninstall(a, f, d, "CUSA01042")
    assert apps_mod.uninstall(a, f, d, "CUSA01042", allow_retail=True)["uninstalled"]


def test_cli_install_from_the_pc(env, tmp_path, monkeypatch, capsys):
    from ps4_goldhen_mcp.cli import main

    m, d, f, a = env
    for k, v in {"PS4_HOST": "127.0.0.1", "PS4_DEBUG_PORT": m.dbg_port, "PS4_FTP_PORT": m.ftp_port,
                 "PS4_KLOG_PORT": m.klog_port, "PS4_AGENT_PORT": a.port}.items():
        monkeypatch.setenv(k, str(v))
    local = tmp_path / "IV0000-HRSA00097_00-CLI.pkg"
    local.write_bytes(b"FAKEPKG HRSA00097\n" + b"\0" * 100)
    assert main(["install", str(local)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["title_id"] == "HRSA00097" and local.is_file()
    assert main(["uninstall", "HRSA00097"]) == 0
    assert json.loads(capsys.readouterr().out)["uninstalled"] is True
