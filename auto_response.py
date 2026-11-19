"""Automated containment engine (dry_run=True by default).

Adapted from Mangesh-Bhattacharya/Ransomware-Detection-System.
"""

import os
import shutil
import signal
import time
from pathlib import Path
from typing import Optional

try:
    import psutil  # type: ignore
except ImportError:
    psutil = None  # type: ignore


class AutoResponse:
    """Dry-run-by-default containment actions: terminate process, quarantine file, isolate network."""

    def __init__(
        self,
        quarantine_dir: Path | str = "logs/quarantine",
        dry_run: bool = True,
    ) -> None:
        self.quarantine_dir = Path(quarantine_dir).resolve()
        self.dry_run = dry_run
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

    def terminate_process(self, pid: int, force_live: Optional[bool] = None) -> dict:
        """Terminate a suspect process by PID. Respects dry_run=True unless overridden."""
        is_dry = self.dry_run if force_live is None else (not force_live)
        if pid == os.getpid():
            return {"action": "terminate_process", "pid": pid, "dry_run": True, "status": "skipped_self"}

        if is_dry:
            return {
                "action": "terminate_process",
                "pid": pid,
                "dry_run": True,
                "status": "simulated_terminate",
            }

        try:
            if psutil is not None:
                proc = psutil.Process(pid)
                proc.terminate()
                proc.wait(timeout=3)
            else:
                os.kill(pid, signal.SIGTERM)
            return {
                "action": "terminate_process",
                "pid": pid,
                "dry_run": False,
                "status": "terminated",
            }
        except Exception as exc:
            return {
                "action": "terminate_process",
                "pid": pid,
                "dry_run": False,
                "status": f"error: {exc}",
            }

    def quarantine_file(self, file_path: Path | str, force_live: Optional[bool] = None) -> dict:
        """Move a suspect/encrypted file to logs/quarantine (never deletes files)."""
        src = Path(file_path).resolve()
        is_dry = self.dry_run if force_live is None else (not force_live)

        if not src.exists():
            return {"action": "quarantine_file", "path": str(src), "status": "missing"}

        dest = self.quarantine_dir / f"{int(time.time() * 1000)}_{src.name}"
        if is_dry:
            return {
                "action": "quarantine_file",
                "source": str(src),
                "destination": str(dest),
                "dry_run": True,
                "status": "simulated_quarantine",
            }

        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dest))
        return {
            "action": "quarantine_file",
            "source": str(src),
            "destination": str(dest),
            "dry_run": False,
            "status": "quarantined",
        }

    def isolate_network(self) -> dict:
        """Placeholder for host network isolation (dry_run=True by default)."""
        return {
            "action": "isolate_network",
            "dry_run": self.dry_run,
            "status": "simulated_isolation" if self.dry_run else "not_implemented_in_sandbox",
        }
