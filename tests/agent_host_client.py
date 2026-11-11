"""Runs inside Linux (WSL): builds tests/agent_host.c, starts it on the real agent blob and plays
command lines against it. Prints one JSON object: the replies and what the fake system saw.

    python3 tests/agent_host_client.py [port]
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9226

SESSIONS = [
    ["PING", "FGUSER", "BIGAPP", "LAUNCH hrsa00064", "LAUNCH HRSA000645", "LAUNCH NOPE00001",
     "LAUNCH HRSA00064 --rom /data/x.z64", "BIGAPP", "LAUNCH CUSA00001"],
    ["KILL 1234", "KILL zz", "KILL", "KILL 80000001", "KILLBIG", "KILLBIG", "BIGAPP", "", "FOO bar", "  PING  \r"],
    ["PKGINFO /data/pkg/new.pkg", "PKGINFO data/x", "EXISTS HRSA00099", "INSTALL /data/pkg/new.pkg",
     "EXISTS HRSA00099", "UNINSTALL HRSA00099", "UNINSTALL HRSA00099", "EXISTS HRSA00064", "EXISTS bad"],
    ["X" * 3000, "PING"],
]


def play(lines):
    out = []
    with socket.create_connection(("127.0.0.1", PORT), timeout=5) as s, s.makefile("rwb") as f:
        for line in lines:
            f.write(line.encode() + b"\n")
            f.flush()
            out.append(f.readline().decode().rstrip())
    return out


def run(mode=None):
    exe = os.path.join(tempfile.gettempdir(), "agent_host")
    subprocess.run(["gcc", "-O1", "-Wall", "-o", exe, os.path.join(ROOT, "tests", "agent_host.c")], check=True)
    args = [exe, os.path.join(ROOT, "companion", "build", "agent.bin"), str(PORT)] + ([mode] if mode else [])
    return subprocess.Popen(args, stdout=subprocess.PIPE, text=True, env=dict(os.environ, AGENT_HOST_TIMEOUT_MS="600"))


def wait_port():
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", PORT), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.1)
    raise SystemExit("agent_host did not listen")


result = {}
p = run()
wait_port()
result["sessions"] = [play(s) for s in SESSIONS]
silent = socket.create_connection(("127.0.0.1", PORT))  # says nothing: must not block the next client
t0 = time.time()
result["after_silent"] = play(["PING"])
result["silent_wait"] = round(time.time() - t0, 2)
silent.close()
result["quit"] = play(["QUIT"])
result["log"] = p.communicate(timeout=10)[0].splitlines()

p = run("noinst")
wait_port()
result["noinst"] = play(["EXISTS HRSA00064", "QUIT"])
p.communicate(timeout=10)

p = run("badmagic")  # a table that is not ours: the agent returns without touching anything
result["badmagic"] = p.communicate(timeout=10)[0].splitlines()
print(json.dumps(result))
