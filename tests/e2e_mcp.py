"""Manual end-to-end check: starts the MCP server over stdio against a mock console that has just
booted (no ps4debug yet: the first tool loads it).
   uv run --extra dev python tests/e2e_mcp.py"""
import asyncio, os, socket, sys, tempfile, threading
sys.path.insert(0, os.path.dirname(__file__))
from mock_ps4 import MockPs4, CRASH_SAMPLE
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

m = MockPs4(event_port=7552, ps4debug_loaded=False)
PAYLOAD = os.path.join(tempfile.mkdtemp(), "ps4debug.bin")
with open(PAYLOAD, "wb") as f:
    f.write(bytes(64))
LOCAL_PKG = os.path.join(tempfile.mkdtemp(), "IV0000-HRSA00096_00-E2E.pkg")
with open(LOCAL_PKG, "wb") as f:
    f.write(b"FAKEPKG HRSA00096" + bytes(100))
with socket.socket() as _s:
    _s.bind(("127.0.0.1", 0))
    AGENT_PORT = _s.getsockname()[1]


def say_later(*lines, delay=1.5):
    threading.Timer(delay, lambda: m.say(*lines)).start()


async def main():
    env = dict(os.environ, PS4_HOST="127.0.0.1", PS4_FTP_PORT=str(m.ftp_port), PS4_KLOG_PORT=str(m.klog_port),
               PS4_DEBUG_PORT=str(m.dbg_port), PS4_CACHE_DIR=tempfile.mkdtemp(), PYTHONPATH="src",
               PS4_AGENT_PORT=str(AGENT_PORT), PS4_BINLOADER_PORT=str(m.binloader_port), PS4_PS4DEBUG_BIN=PAYLOAD,
               PS4_EXPERIMENTAL_INSTALL="1")
    params = StdioServerParameters(command=sys.executable, args=["-m", "ps4_goldhen_mcp"], env=env)
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = (await s.list_tools()).tools
            print(len(tools), [t.name for t in tools])
            calls = [("ps4_status", {}), ("ps4_lock", {"reason": "e2e"}), ("ps4_list_dir", {"path": "/data"}),
                     ("ps4_mkdir", {"path": "/data/e2e"}), ("ps4_apps", {}),
                     ("ps4_processes", {"details": True}), ("ps4_memory_map", {"process": "SceShellUI"}),
                     ("ps4_read_memory", {"process": "eboot.bin", "address": "0x400000", "length": 32}),
                     ("ps4_disassemble", {"process": 64, "address": "0x800000100", "count": 3}),
                     ("ps4_call", {"process": "SceShellUI", "function": "sceKernelGetCpuFrequency"}),
                     ("ps4_log", {}), ("ps4_notify", {"message": "hello"}),
                     ("ps4_agent", {}), ("ps4_launch", {"title_id": "HRSA00002", "wait_for": "h64: init ok"}),
                     ("ps4_agent", {}), ("ps4_launch", {"title_id": "HRSA00002", "replace": False}),
                     ("ps4_close", {"title_id": "CUSA00001"}), ("ps4_close", {}), ("ps4_close", {}),
                     ("ps4_launch", {"title_id": "NPXS20001"}),
                     ("ps4_install", {"local_path": LOCAL_PKG}), ("ps4_install", {"local_path": LOCAL_PKG}),
                     ("ps4_uninstall", {"title_id": "HRSA00096"}), ("ps4_uninstall", {"title_id": "CUSA00031"}),
                     ("ps4_crash_report", {}), ("ps4_delete", {"path": "/data"}), ("ps4_unlock", {})]
            for name, args in calls:
                if args.get("wait_for"):
                    say_later("[h64] boot", "h64: init ok")
                if name == "ps4_crash_report":
                    m.say(*CRASH_SAMPLE)
                    await asyncio.sleep(2)
                res = await s.call_tool(name, args)
                for c in res.content:
                    if c.type == "text":
                        print(f"--- {name} (err={res.is_error}):", c.text[:400])
asyncio.run(main())
print("payloads sent to the BinLoader:", len(m.state.payloads))
m.close()
