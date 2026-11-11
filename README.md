# ps4-goldhen-mcp

The PS4 sibling of my [xbox360-mcp](https://github.com/kernel64/xbox360-mcp): a small tool that lets
Claude Code (or a build script) work on a jailbroken PS4 by itself while I develop homebrew.
It talks to what GoldHEN and ps4debug already offer on the console, plus a USB HDMI capture card on
the PC. Three ways to use it:

- as an MCP server, so Claude Code can deploy, launch and close apps, read logs, dig into crashes,
  poke memory and look at the TV on its own;
- from the command line (`ps4 ...`), for build scripts;
- as a Python library.

I use it on a base PS4 on firmware 5.05 with GoldHEN and ps4debug v1.1.19.

## Console side

- **GoldHEN** with its FTP server (port 2121) and klog server (port 3232) enabled.
- **BinLoader** enabled in GoldHEN (port 9090): the tool sends ps4debug through it.
- **ps4debug** (GoldHEN's fork, [v1.1.19](https://github.com/GoldHEN/ps4debug/releases)): it isn't
  resident, it has to be sent again after every boot. `ps4_load_ps4debug` (or `ps4 load-ps4debug`)
  does it, downloading the official release once and checking its SHA-256.

Don't "test" port 9090 with a bare connection (telnet, port scanner...): the BinLoader takes the
empty connection as a payload and stops listening until you toggle it again in the GoldHEN menu.

## Install

```powershell
git clone https://github.com/kernel64/ps4-goldhen-mcp
cd ps4-goldhen-mcp
uv sync
$env:PS4_HOST = "192.168.1.40"
uv run ps4 info
```

## With Claude Code

```powershell
claude mcp add ps4 --scope user -e PS4_HOST=192.168.1.40 -- uv --directory C:\path\to\ps4-goldhen-mcp run ps4-goldhen-mcp
```

`examples/CLAUDE-snippet.md` is the text I paste into a homebrew project's `CLAUDE.md`.

What Claude gets (44 tools, all prefixed `ps4_`):

- **console**: status (what answers, firmware, ps4debug version, running apps), load ps4debug, send a
  payload, notification on the TV, reboot;
- **files** (GoldHEN FTP): list, download, read a text file, upload (size checked), mkdir, rename,
  delete (system paths and GoldHEN's config are refused), incremental `ps4_deploy`;
- **apps**: installed apps with their names (param.sfo) and the running ones (title ID, pid);
  `ps4_launch` starts an installed app by title ID and can wait for a log line, `ps4_close` closes the
  running one, `ps4_deploy` can launch after syncing;
- **logs**: everything the klog server streams (your `printf`, system services, kernel messages),
  collected in the background; `ps4_wait_for_log` blocks on a regex and stops early on a crash;
- **crashes**: the kernel's fatal-signal reports are parsed (signal, reason, registers, backtrace,
  modules) and every address is shown as `module+offset`; with your unstripped ELF (before
  `create-fself`) eboot addresses also get `function+offset file:line`;
- **screen**: HDMI photo, burst, clip with sound, background recording (contact sheets);
- **ps4debug**: processes, memory map, read/write/search memory, x86-64 disassembly, remote function
  calls, debugger (attach, breakpoints, watchpoints, threads, registers, events).

### Launching and closing apps

`ps4_launch("ABCD00001", wait_for="myapp: init ok")` starts an installed app with no one at the pad and
returns when the app prints that line (or crashes). The PS4 runs one game or app at a time, so the
running one is closed first (`replace=false` refuses instead). `ps4_close` closes it.

How it works: the server injects a 4.5 KB agent (`companion/agent.c`, freestanding, no imports) into
`ScePartyDaemon` through ps4debug, starts it as a thread and talks to it over TCP (port 9226, one text
command per line). The daemon already has the libraries needed, and the console keeps running if it
dies. The agent is loaded on demand and is gone after a reboot, like ps4debug; `ps4_agent` shows or
unloads it. Like GoldHEN's FTP and ps4debug, its port is open to the whole LAN: keep the console on a
network you trust.

Two things I learned the hard way on 5.05:

- `sceSystemServiceLaunchApp` must not be used. It replaces the user you give with -1; the app starts,
  then SceShellUI crashes a few seconds later ("Invalid User Id" in its app database code, error
  CE-36329-3 on the TV), whatever process calls it. The function to call is `sceLncUtilLaunchApp`,
  which the dynamic linker does not give by name: the server reads its address from the first `call`
  of the wrapper.
- its parameter is 0x18 bytes there (`{u32 size; s32 user; s32 attr; s32 crash_report; u64 flags}`),
  not the 0x20 bytes of OpenOrbis' header.

Only installed titles are started, and system titles (`NPXS...`) are refused. Nothing is installed,
patched, decrypted or unlocked by these tools: installing a pkg is still done from GoldHEN's Package
Installer.

The built agent is committed as text (`src/ps4_goldhen_mcp/_agent_blob.py`, base64 with its SHA-256,
checked at load time), so a clone works without a PS4 toolchain. After a change to `companion/agent.c`,
rebuild it with `uv run python companion/build.py` (clang and ld.lld from LLVM 18, or set
`PS4_LLVM_BIN`); the script also checks the blob is position independent. `tests/test_agent_blob.py`
then runs the real blob on Linux (WSL on Windows) against fake system functions.

## Configuration

| Variable | Default | |
|---|---|---|
| `PS4_HOST` | | console IP (required) |
| `PS4_FTP_PORT` / `PS4_KLOG_PORT` / `PS4_DEBUG_PORT` / `PS4_BINLOADER_PORT` | 2121 / 3232 / 744 / 9090 | |
| `PS4_TIMEOUT` | `10` | seconds |
| `PS4_DEPLOY_ROOT` | `/data/homebrew` | default target of `ps4_deploy` |
| `PS4_LOG_FILE` | | also append every klog line to this file |
| `PS4_READ_ONLY` | `0` | refuse anything that changes the console |
| `PS4_PS4DEBUG_BIN` | | use this ps4debug.bin instead of the cached official one |
| `PS4_AUTO_LOAD_PS4DEBUG` | `1` | `ps4_launch` / `ps4_close` load ps4debug themselves after a reboot |
| `PS4_AGENT_PORT` / `PS4_AGENT_HOST_PROCESS` | 9226 / `ScePartyDaemon` | the launch agent's port and the daemon it lives in |
| `PS4_LOCK_LEASE` | `600` | reservation lease, seconds |
| `PS4_OWNER` | project folder | name other sessions see when you hold the console |
| `PS4_CAPTURE_VIDEO` / `PS4_CAPTURE_AUDIO` | auto | capture device names (DirectShow) |
| `PS4_CAPTURE_SIZE` / `PS4_CAPTURE_FPS` / `PS4_CAPTURE_DIR` | 1920x1080 / 30 / `~/ps4-captures` | |

## Several sessions, one console

Same as the Xbox tool: anything that changes the console reserves it if it's free, `ps4_lock` reserves
it for a multi-step test and `ps4_unlock` frees it. The reservation is a file under
`~/.ps4-goldhen-mcp/locks/`, renewed by each call and dropped when the holder's process is gone or
after `PS4_LOCK_LEASE` seconds. `ps4 unlock --force` clears a stuck one.

GoldHEN's klog server only serves one client (the next one gets `failed to open klog [error: -16]`),
so the server holding it relays the lines to the other sessions and to `ps4 log` on a loopback port;
when it stops, the next one takes the console over. A plain `curl` or telnet on port 3232 still blocks
everyone.

The capture card is exclusive too: if OBS or the Xbox server has it open, captures fail with "in use".

## Debugger events

After `ps4_debug_attach`, ps4debug connects back to the PC on TCP 755 to report breakpoints and
signals: allow Python on that port in the Windows firewall (private network).

## Command line

```powershell
uv run ps4 info
uv run ps4 ls /data
uv run ps4 put build\app.pkg /data/pkg/app.pkg
uv run ps4 deploy build\data /data/homebrew/myapp
uv run ps4 log -f --grep myapp
uv run ps4 wait "init ok" --timeout 60
uv run ps4 launch ABCD00001 --wait "init ok"      # arguments for the app go after --
uv run ps4 close
uv run ps4 symbolize build\eboot.elf 83288 7d3
uv run ps4 load-ps4debug
uv run ps4 capture photo
```

## Tests

`tests/mock_ps4.py` is a fake console (FTP, klog with history replay and a crash report, ps4debug with
a fake process, syscall wrappers, dlsym, debugger events and the launch agent):

```powershell
uv run --extra dev pytest
uv run --extra dev python tests/e2e_mcp.py   # the MCP server over stdio against the mock
```

## Credits

- ps4debug by [golden](https://github.com/jogolden/ps4debug), GoldHEN fork by ctn123 and SiSTRo. The
  client here is written from the protocol, helped by
  [PyPS4debug](https://github.com/Jay184/PyPS4debug) (0BSD) for the packet layouts.
- [GoldHEN](https://github.com/GoldHEN/GoldHEN) for the FTP, klog and BinLoader servers.
- [Orbis-Suite](https://github.com/OSM-Made/Orbis-Suite) and
  [ItemzFlow](https://github.com/LightningMods/Itemzflow) (GPL-3) were read to understand how apps are
  launched and killed (`sceLncUtilLaunchApp` with the foreground user, `sceSystemServiceKillApp`); no code
  was copied. The 0x18-byte launch parameter layout matches OSM-Made's
  [StubMaker](https://github.com/OSM-Made/StubMaker) headers and was checked against the console's own
  library.
