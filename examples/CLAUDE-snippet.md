## PS4 (`ps4` MCP server)

The jailbroken PS4 (GoldHEN) is reachable through the `ps4_*` tools.

- Build output: `build-ps4\myapp\` (pkg + unstripped ELF `eboot.elf`)   <!-- adjust -->
- Title ID: `ABCD00001`                                                <!-- adjust -->
- Log line printed when init is OK: `myapp: init ok`                    <!-- adjust: regex -->
- App log files on the console: `/data/myapp/`                         <!-- adjust -->

The console is shared with other Claude Code sessions.

Test loop after each change:
1. Build.
2. `ps4_lock(reason=<what you are testing>)`. If another session has it, wait or retry later.
3. `ps4_status`: checks the console and prepares it (ps4debug is loaded by itself after a boot).
4. Send the files: `ps4_deploy` (data files) or `ps4_upload` (pkg to `/data/pkg/`; a new pkg is
   installed by the user from GoldHEN's Package Installer: ask them).
5. `ps4_launch(title_id=<Title ID>, wait_for=<init log>)`: closes the running app, starts ours and
   returns its init line (or the crash). `ps4_close` when the test is over.
6. On a crash: `ps4_crash_report(elf_path=<unstripped eboot ELF>)` and match function/file:line.
7. `ps4_capture_photo` / `ps4_capture_video` to check the picture.
8. `ps4_unlock` when done.

Print with `printf` / `sceKernelDebugOutText`: that's what the klog shows.
