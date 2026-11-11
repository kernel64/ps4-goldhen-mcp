"""The real agent blob (companion/build/agent.bin), run on Linux x86-64 with fake system functions
(tests/agent_host.c). On Windows this goes through WSL; skipped when there is no WSL / gcc or when
the blob has not been built (uv run python companion/build.py)."""

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from ps4_goldhen_mcp import _agent_blob

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "companion" / "build" / "agent.bin"


def _run_host() -> dict:
    if not BIN.exists():
        pytest.skip("companion/build/agent.bin not built")
    if sys.platform == "win32":
        if not shutil.which("wsl"):
            pytest.skip("no WSL")
        cmd = ["wsl", "--cd", str(ROOT), "-e", "python3", "tests/agent_host_client.py", "9227"]
    else:
        cmd = [sys.executable, "tests/agent_host_client.py", "9227"]
    try:
        r = subprocess.run(cmd, cwd=ROOT, capture_output=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        pytest.skip(f"host test could not run: {e}")
    out = r.stdout.decode(errors="replace").strip()
    if r.returncode or not out.startswith("{"):
        if b"gcc" in r.stderr and b"not found" in r.stderr:
            pytest.skip("no gcc in WSL")
        pytest.fail(f"agent_host failed ({r.returncode}): {out[-500:]} {r.stderr.decode(errors='replace')[-800:]}")
    return json.loads(out)


@pytest.fixture(scope="module")
def host():
    return _run_host()


def test_embedded_blob_is_the_built_one():
    if not BIN.exists():
        pytest.skip("companion/build/agent.bin not built")
    assert hashlib.sha256(BIN.read_bytes()).hexdigest() == _agent_blob.SHA256, "run companion/build.py again"


def test_launch_and_kill(host):
    s1, s2 = host["sessions"][0], host["sessions"][1]
    assert s1 == ["OK ps4-dev-agent 3 7a1234000 8000 45", "OK 10000000", "OK 80aa000a", "ERR 0 bad title id",
                  "ERR 0 bad title id", "ERR 80940031 sceLncUtilLaunchApp", "OK 60000f0b", "OK 60000f0b",
                  "ERR 8094000c sceLncUtilLaunchApp"]
    assert s2 == ["ERR 80940010 sceSystemServiceKillApp", "ERR 0 bad app id", "ERR 0 bad app id", "ERR 0 bad app id",
                  "OK 60000f0b", "ERR 80aa000a no big app", "OK 80aa000a", "ERR 0 empty command",
                  "ERR 0 unknown command", "OK ps4-dev-agent 3 7a1234000 8000 45"]
    log = host["log"]
    # the launch parameter the system gets: 0x18 bytes (firmware 5.05), the foreground user, argv as given
    assert "launch HRSA00064 size=0x18 user=0x10000000 attr=0 crash=0 check=0 args=[--rom][/data/x.z64] argc=2" in log
    assert "launch NOPE00001 size=0x18 user=0x10000000 attr=0 crash=0 check=0 args= argc=0" in log
    assert "kill 0x60000f0b -1 0 0" in log
    assert not any(line.startswith("launch hrsa") or "HRSA000645" in line for line in log)


def test_packages(host):
    assert host["sessions"][2] == ["OK HRSA00099 1", "ERR 0 expected an absolute path", "OK 0", "OK", "OK 1", "OK",
                                   "ERR 80990088 sceAppInstUtilAppUnInstall", "OK 1", "ERR 0 bad title id"]
    assert host["noinst"] == ["ERR 0 libSceAppInstUtil is not available in the host process", "OK bye"]


def test_robustness(host):
    assert host["sessions"][3] == ["ERR 0 line too long", "OK ps4-dev-agent 3 7a1234000 8000 45"]
    assert host["after_silent"][0].startswith("OK ps4-dev-agent") and host["silent_wait"] < 3
    assert host["quit"] == ["OK bye"]
    log = host["log"]
    assert log[0] == "start size=%d table=184" % len(BIN.read_bytes())
    assert "bind len=16 sa_len=16 family=2 port=9227" in log
    assert log[-1] == "stopped state=0x2 version=3 last_error=0"
    # wrong table: nothing is called, no state is written
    assert host["badmagic"] == [host["badmagic"][0], "stopped state=0 version=0 last_error=0"]
