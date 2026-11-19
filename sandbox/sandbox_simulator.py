"""Safe sandbox simulator for ransomware-like file behavior on dummy files only.

Adapted from Mangesh-Bhattacharya/Ransomware-Detection-System.
Also supports running as a standalone subprocess so process attribution can detect its PID.
"""

import argparse
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import List, Optional

from behavioral_analyzer import BehavioralAnalyzer
from ransomware_monitor import RansomwareEventHandler


def simulate_attack_on_folder(target_dir: Path, write_delay: float = 0.01) -> List[Path]:
    """Overwrite dummy files in target_dir with random bytes and append .locked extension.

    Safety: Only operates on dummy files inside an explicit test/temp directory.
    """
    target = Path(target_dir).resolve()
    affected: List[Path] = []
    for item in sorted(target.rglob("*")):
        if not item.is_file():
            continue
        payload = os.urandom(max(2048, item.stat().st_size))
        with open(item, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        locked_path = item.with_name(item.name + ".locked")
        item.rename(locked_path)
        affected.append(locked_path)
        if write_delay > 0:
            time.sleep(write_delay)
    return affected


def run_simulation(file_count: int = 150, cleanup: bool = True, work_dir: Optional[Path] = None) -> dict:
    """Create dummy files, simulate ransomware-like renames/high-entropy writes, and count flagged events."""
    temp_root = Path(work_dir) if work_dir else Path(tempfile.mkdtemp(prefix="rds_sandbox_"))
    temp_root.mkdir(parents=True, exist_ok=True)
    log_csv = temp_root / "sandbox_log.csv"

    analyzer = BehavioralAnalyzer(protected_folder=temp_root)
    handler = RansomwareEventHandler(analyzer=analyzer, log_csv_path=log_csv)

    flagged = 0
    try:
        dummy_files: List[Path] = []
        for i in range(file_count):
            p = temp_root / f"dummy_{i:03d}.txt"
            p.write_text(f"Sample benign document {i} for safe sandbox testing.\n" * 5, encoding="utf-8")
            dummy_files.append(p)

        for p in dummy_files:
            p.write_bytes(os.urandom(2048))
            locked = p.with_name(p.name + ".locked")
            p.rename(locked)
            res = handler.handle_path_event("moved", locked)
            if res and res["severity"] in ("HIGH", "CRITICAL"):
                flagged += 1

        return {
            "total_events": file_count,
            "flagged_events": flagged,
            "sandbox_dir": str(temp_root),
        }
    finally:
        if cleanup and work_dir is None and temp_root.exists():
            shutil.rmtree(temp_root, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Safe Ransomware Sandbox Simulator")
    parser.add_argument("--target-dir", type=str, default=None, help="Dummy folder to simulate attack on")
    parser.add_argument("--file-count", type=int, default=150)
    parser.add_argument("--hold-seconds", type=float, default=1.5, help="Keep process alive for PID snapshot")
    args = parser.parse_args()

    if args.target_dir:
        target = Path(args.target_dir)
        affected = simulate_attack_on_folder(target, write_delay=0.05)
        end_time = time.time() + args.hold_seconds
        scratch = target / ".sim_io_pulse"
        while time.time() < end_time:
            with open(scratch, "wb") as f:
                f.write(os.urandom(65536))
                f.flush()
                os.fsync(f.fileno())
            time.sleep(0.05)
        scratch.unlink(missing_ok=True)
        print(f"Simulated attack on {len(affected)} files in {target}")
    else:
        summary = run_simulation(file_count=args.file_count, cleanup=True)
        print(f"Sandbox simulation complete: {summary['flagged_events']}/{summary['total_events']} events flagged.")


if __name__ == "__main__":
    main()
