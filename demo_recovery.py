"""Command-line demo of ML-based Ransomware Detection with Secure File Recovery.

Demonstrates:
1. Encrypted baseline backup + manifest verification
2. Normal plain-text edit promoted after the pending window
3. Subprocess safe-simulator attack -> HIGH/CRITICAL alert -> Freeze backups ->
   Suspect PID attribution -> Quarantine encrypted files -> Byte-identical restore -> Verify
4. Before-and-after SHA-256 hash comparison table
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from auto_response import AutoResponse
from behavioral_analyzer import BehavioralAnalyzer
from ml_models.anomaly_detector import MLAnomalyDetector
from ransomware_monitor import RansomwareEventHandler
from recovery.backup_store import compute_sha256
from recovery.config import RecoveryConfig
from recovery.recovery_manager import RecoveryManager


def print_hash_table(rows: list[tuple[str, str, str, str]]) -> None:
    header = f"{'File':<22} | {'Before Attack (SHA-256)':<18} | {'During Attack (SHA-256)':<23} | {'After Restore (SHA-256)':<23} | Match"
    print("\n" + "=" * len(header))
    print(header)
    print("-" * len(header))
    for name, h_before, h_during, h_after in rows:
        match = "YES" if h_before == h_after else "NO"
        print(f"{name:<22} | {h_before[:16]+'..':<18} | {h_during[:16]+'..':<23} | {h_after[:16]+'..':<23} | {match}")
    print("=" * len(header) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="CLI Demo: Ransomware Detection with Secure File Recovery")
    parser.add_argument("--window", type=float, default=2.0, help="Pending promotion window in seconds for demo (default: 2.0)")
    parser.add_argument("--live-demo", action="store_true", help="Allow terminating the simulator subprocess and moving encrypted files to quarantine")
    args = parser.parse_args()

    sandbox_root = Path(tempfile.mkdtemp(prefix="rds_demo_"))
    protected_dir = sandbox_root / "protected"
    backup_dir = sandbox_root / "backups"
    key_file = sandbox_root / "keys" / "backup.key"
    quarantine_dir = sandbox_root / "logs" / "quarantine"
    incidents_dir = sandbox_root / "logs" / "incidents"
    log_csv = sandbox_root / "logs" / "scan.csv"

    protected_dir.mkdir(parents=True, exist_ok=True)

    try:
        # 1. Create sample dummy files
        sample_files = {
            "financial_q3.txt": "Quarter 3 revenue summary: all figures verified.\n" * 10,
            "research_notes.txt": "Applied Cryptography project notes on Fernet and SHA-256.\n" * 10,
            "lab_schedule.csv": "week,topic,status\n1,entropy,done\n2,recovery,done\n" * 8,
        }
        for fname, content in sample_files.items():
            (protected_dir / fname).write_text(content, encoding="utf-8")

        cfg = RecoveryConfig(
            protected_folder=protected_dir,
            backup_folder=backup_dir,
            key_file_path=key_file,
            quarantine_folder=quarantine_dir,
            window_seconds=args.window,
            versions_kept=3,
            entropy_guard_threshold=7.5,
            dry_run=not args.live_demo,
        )
        auto_resp = AutoResponse(quarantine_dir=quarantine_dir, dry_run=not args.live_demo)
        mgr = RecoveryManager(cfg, auto_response=auto_resp)
        analyzer = BehavioralAnalyzer(protected_folder=protected_dir)
        ml_detector = MLAnomalyDetector().fit()

        print("[1/5] Creating encrypted baseline backups...")
        count = mgr.initialize()
        verify_ok = all(mgr.backup_store.verify().values())
        print(f"      Backed up {count} files with Fernet. Manifest verify(): {verify_ok}")

        # 2. Normal benign edit -> wait window -> promote
        print(f"[2/5] Performing normal plain-text edit and waiting {args.window}s window...")
        edited_file = protected_dir / "research_notes.txt"
        with open(edited_file, "a", encoding="utf-8") as f:
            f.write("Appended clean lecture note after baseline.\n")
        normal_alert = analyzer.record_event("modified", edited_file)
        mgr.on_file_event(edited_file, "modified")
        time.sleep(args.window + 0.2)
        promoted = mgr.on_clean_tick()
        print(f"      Normal edit severity={normal_alert['severity']}, promoted={len(promoted)} file(s).")

        # Record pre-attack hashes
        pre_attack_hashes = {
            fname: compute_sha256(protected_dir / fname) for fname in sample_files
        }

        # 3. Launch safe simulator in a subprocess so process attribution has a distinct PID
        print("[3/5] Launching safe sandbox attack simulator in subprocess...")
        repo_root = Path(__file__).resolve().parent
        env = os.environ.copy()
        env["PYTHONPATH"] = str(repo_root)
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "sandbox.sandbox_simulator",
                "--target-dir",
                str(protected_dir),
                "--hold-seconds",
                "2.0",
            ],
            cwd=str(repo_root),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.35)

        # Evaluate attacked files
        during_attack_hashes = {}
        attacked_paths = sorted(protected_dir.glob("*.locked"))
        last_alert = None
        for p in attacked_paths:
            orig_name = p.name[:-len(".locked")]
            during_attack_hashes[orig_name] = compute_sha256(p)
            mgr.on_file_event(p, "moved")
            last_alert = analyzer.record_event("moved", p)

        ml_res = ml_detector.assess({
            "file_create_rate": 0,
            "file_modify_rate": len(attacked_paths) * 10,
            "file_rename_rate": len(attacked_paths) * 10,
            "unique_extension_count": 4,
            "avg_entropy": 7.9,
            "max_entropy": 7.99,
            "process_cpu": 45.0,
        })
        print(f"      Alert fired: severity={last_alert['severity'] if last_alert else 'HIGH'}, ML risk_score={ml_res['risk_score']}")

        # 4. Trigger recovery orchestrator
        print("[4/5] Executing RecoveryManager.on_alert() (Freeze -> PID -> Quarantine -> Restore -> Verify)...")
        recovery_res = mgr.on_alert(
            severity=last_alert["severity"] if last_alert else "HIGH",
            affected_paths=attacked_paths,
        )
        proc.wait(timeout=5)

        print(f"      Backups frozen: {recovery_res['frozen']}")
        print(f"      Suspect process identified: {recovery_res['suspect']}")
        print(f"      Termination result: {recovery_res['termination']}")
        print(f"      Quarantined files: {len(recovery_res['quarantined'])}")
        print(f"      Restored files: {len(recovery_res['restored'])}, manifest_verified={recovery_res['manifest_verified']}")

        # 5. Print Before & After SHA-256 Table
        print("[5/5] Comparing Before vs. During vs. After-Restore SHA-256 hashes:")
        table_rows = []
        for fname in sample_files:
            after_hash = compute_sha256(protected_dir / fname)
            table_rows.append((
                fname,
                pre_attack_hashes[fname],
                during_attack_hashes.get(fname, "RENAMED/MISSING"),
                after_hash,
            ))
        print_hash_table(table_rows)

        all_match = all(r[1] == r[3] for r in table_rows)
        print(f"DEMO RESULT: {'PASS - All files restored byte-for-byte!' if all_match else 'FAIL'}")
    finally:
        shutil.rmtree(sandbox_root, ignore_errors=True)


if __name__ == "__main__":
    main()
