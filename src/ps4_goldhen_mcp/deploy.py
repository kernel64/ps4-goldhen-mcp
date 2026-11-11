"""Incremental deployment of a local build folder to the console over FTP.

Only files whose content changed since the last deploy (sha1 cache) or whose size differs on the
console are uploaded, so the edit -> build -> run loop stays fast.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import posixpath
import time
from pathlib import Path

from .config import cache_dir
from .ftp import Ps4Ftp, norm

DEFAULT_EXCLUDES = [".git", ".vs", "*.o", "*.obj", "*.d", "*.map", "*.pdb", "*.tlog", "*.log", "*.gp4", "CMakeFiles"]


def _cache_path() -> Path:
    return cache_dir() / "deploy_cache.json"


def _load_cache() -> dict:
    try:
        return json.loads(_cache_path().read_text("utf-8"))
    except (OSError, ValueError):
        return {}


def _save_cache(cache: dict) -> None:
    try:
        _cache_path().write_text(json.dumps(cache, indent=0), "utf-8")
    except OSError:
        pass


def _sha1(path: Path) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _local_digest(path: Path, cached: object) -> tuple[str, dict]:
    st = path.stat()
    if isinstance(cached, dict) and cached.get("size") == st.st_size and cached.get("mtime_ns") == st.st_mtime_ns:
        digest = str(cached["sha1"])
    else:
        digest = _sha1(path)
    return digest, {"sha1": digest, "size": st.st_size, "mtime_ns": st.st_mtime_ns}


def _excluded(rel: str, patterns: list[str]) -> bool:
    parts = rel.replace("\\", "/").split("/")
    return any(fnmatch.fnmatch(p, pat) for pat in patterns for p in parts)


def iter_local(local: Path, excludes: list[str]):
    if local.is_file():
        yield local, local.name
        return
    for root, dirs, files in os.walk(local):
        rel_root = os.path.relpath(root, local)
        dirs[:] = [d for d in dirs if not _excluded(os.path.join(rel_root, d), excludes)]
        for name in files:
            rel = os.path.normpath(os.path.join(rel_root, name)).replace("\\", "/")
            if not _excluded(rel, excludes):
                yield Path(root) / name, rel


def deploy(ftp: Ps4Ftp, local_path: str, remote_dir: str, *, excludes: list[str] | None = None,
           force: bool = False, prune: bool = False) -> dict:
    """Sync local_path (folder or single file) into remote_dir. prune=True also deletes console files
    that no longer exist locally (careful: that includes files the app wrote there itself)."""
    local = Path(local_path).expanduser().resolve()
    if not local.exists():
        raise FileNotFoundError(f"Local path not found: {local}")
    if prune and not local.is_dir():
        raise ValueError("prune needs a local folder, not a single file")
    root = norm(remote_dir)
    if prune:
        ftp.check_mutable(root)
    patterns = DEFAULT_EXCLUDES if excludes is None else excludes
    cache = _load_cache()
    started = time.time()

    remote_sizes: dict[str, int] = {}
    if ftp.exists(root):
        for full, e in ftp.walk(root):
            if not e["is_dir"]:
                remote_sizes[full] = e["size"]
    else:
        ftp.makedirs(root)

    uploaded, skipped, total = [], 0, 0
    made: set[str] = {root}
    seen: set[str] = set()
    try:
        for path, rel in iter_local(local, patterns):
            remote = posixpath.join(root, rel)
            seen.add(remote)
            key = f"{ftp.host}|{remote}"
            entry = cache.get(key)
            digest, new_entry = _local_digest(path, entry)
            if not force and remote_sizes.get(remote) == new_entry["size"] and isinstance(entry, dict) and entry.get("sha1") == digest:
                cache[key] = new_entry
                skipped += 1
                continue
            parent = posixpath.dirname(remote)
            if parent not in made:
                ftp.makedirs(parent)
                made.add(parent)
            ftp.upload(path, remote)
            cache[key] = new_entry
            uploaded.append(rel)
            total += new_entry["size"]
        deleted: list[str] = []
        if prune:
            for full in sorted(remote_sizes):
                if full not in seen:
                    ftp.delete(full, force=True)
                    cache.pop(f"{ftp.host}|{full}", None)
                    deleted.append(full[len(root):].lstrip("/"))
    finally:
        _save_cache(cache)
    out = {
        "remote_dir": root,
        "uploaded": uploaded[:50] + (["..."] if len(uploaded) > 50 else []),
        "uploaded_count": len(uploaded),
        "skipped_unchanged": skipped,
        "bytes_sent": total,
        "seconds": round(time.time() - started, 2),
    }
    if prune:
        out["deleted"] = deleted
    return out
