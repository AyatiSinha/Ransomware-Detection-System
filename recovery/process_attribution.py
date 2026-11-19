"""Heuristic suspect process attribution using two-snapshot I/O write-byte deltas."""

import os
import time
from pathlib import Path
from typing import Dict, Optional, Set

try:
    import psutil  # type: ignore
except ImportError:
    psutil = None  # type: ignore

SYSTEM_PROCESS_NAMES: Set[str] = {
    "systemd",
    "init",
    "kthreadd",
    "journald",
    "systemd-journald",
    "dbus-daemon",
    "sshd",
    "svchost.exe",
    "System",
    "Registry",
    "csrss.exe",
    "smss.exe",
    "services.exe",
    "lsass.exe",
}


def _snapshot_write_bytes_proc() -> Dict[int, tuple[str, int]]:
    """Fallback Linux /proc/<pid>/io reader when psutil is not installed."""
    snap: Dict[int, tuple[str, int]] = {}
    proc_root = Path("/proc")
    if not proc_root.exists():
        return snap
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            comm = (entry / "comm").read_text(encoding="utf-8", errors="ignore").strip()
            io_text = (entry / "io").read_text(encoding="utf-8", errors="ignore")
            write_bytes = 0
            for line in io_text.splitlines():
                if line.startswith("write_bytes:"):
                    write_bytes = int(line.split(":", 1)[1].strip())
                    break
            snap[pid] = (comm, write_bytes)
        except (OSError, ValueError):
            continue
    return snap


def _snapshot_write_bytes() -> Dict[int, tuple[str, int]]:
    if psutil is None:
        return _snapshot_write_bytes_proc()
    snap: Dict[int, tuple[str, int]] = {}
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            pid = proc.info["pid"]
            name = proc.info.get("name") or ""
            io = proc.io_counters()
            if io is not None:
                snap[pid] = (name, int(io.write_bytes))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, AttributeError):
            continue
    return snap


def find_suspect_pid(
    protected_folder: Optional[Path] = None,
    interval_seconds: float = 0.5,
    exclude_pids: Optional[Set[int]] = None,
) -> Optional[dict]:
    """Identify the process with the highest write_bytes delta across a 0.5s window.

    Note: This is a user-space heuristic rather than kernel-level ETW/eBPF tracing,
    so it can occasionally attribute the wrong process when multiple writers are active.
    """
    excluded = set(exclude_pids or set())
    excluded.add(os.getpid())

    snap1 = _snapshot_write_bytes()
    time.sleep(max(0.05, interval_seconds))
    snap2 = _snapshot_write_bytes()

    best_pid: Optional[int] = None
    best_name: str = ""
    best_delta: int = 0

    for pid, (name, bytes2) in snap2.items():
        if pid in excluded or name in SYSTEM_PROCESS_NAMES:
            continue
        if pid not in snap1:
            continue
        delta = bytes2 - snap1[pid][1]
        if delta > best_delta:
            best_delta = delta
            best_pid = pid
            best_name = name

    if best_pid is None:
        return None

    open_in_protected = False
    if protected_folder is not None and psutil is not None:
        try:
            proc = psutil.Process(best_pid)
            prot_str = str(Path(protected_folder).resolve())
            for f in proc.open_files():
                if f.path.startswith(prot_str):
                    open_in_protected = True
                    break
        except Exception:
            pass

    return {
        "pid": best_pid,
        "name": best_name,
        "write_bytes_delta": best_delta,
        "open_in_protected": open_in_protected,
    }
