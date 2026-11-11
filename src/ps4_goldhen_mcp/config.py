"""Configuration via environment variables (set them in .mcp.json / `claude mcp add -e`)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def cache_dir() -> Path:
    base = Path(os.environ.get("PS4_CACHE_DIR") or Path.home() / ".ps4-goldhen-mcp")
    base.mkdir(parents=True, exist_ok=True)
    return base


@dataclass
class Config:
    host: str
    ftp_port: int = 2121
    klog_port: int = 3232
    debug_port: int = 744
    binloader_port: int = 9090
    rpi_port: int = 12800
    timeout: float = 10.0
    read_only: bool = False
    log_file: str | None = None
    deploy_root: str = "/data/homebrew"
    lock_lease: float = 600.0
    ps4debug_bin: str | None = None
    auto_load_ps4debug: bool = True
    http_host: str | None = None  # PC address the console uses to download packages
    agent_port: int = 9226
    agent_host_process: str = "ScePartyDaemon"

    @classmethod
    def from_env(cls, host: str | None = None) -> "Config":
        h = host or os.environ.get("PS4_HOST") or os.environ.get("PS4_IP")
        if not h:
            raise SystemExit("PS4_HOST is not set. Example: PS4_HOST=192.168.1.40 (IP of the PS4 running GoldHEN).")
        env = os.environ.get
        return cls(
            host=h,
            ftp_port=int(env("PS4_FTP_PORT", "2121")),
            klog_port=int(env("PS4_KLOG_PORT", "3232")),
            debug_port=int(env("PS4_DEBUG_PORT", "744")),
            binloader_port=int(env("PS4_BINLOADER_PORT", "9090")),
            rpi_port=int(env("PS4_RPI_PORT", "12800")),
            timeout=float(env("PS4_TIMEOUT", "10")),
            read_only=_bool("PS4_READ_ONLY", False),
            log_file=env("PS4_LOG_FILE") or None,
            deploy_root=env("PS4_DEPLOY_ROOT", "/data/homebrew"),
            lock_lease=float(env("PS4_LOCK_LEASE", "600")),
            ps4debug_bin=env("PS4_PS4DEBUG_BIN") or None,
            auto_load_ps4debug=_bool("PS4_AUTO_LOAD_PS4DEBUG", True),
            http_host=env("PS4_HTTP_HOST") or None,
            agent_port=int(env("PS4_AGENT_PORT", "9226")),
            agent_host_process=env("PS4_AGENT_HOST_PROCESS", "ScePartyDaemon"),
        )
