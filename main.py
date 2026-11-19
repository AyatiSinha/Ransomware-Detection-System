"""Entry point for the ML-based Ransomware Detection with Secure File Recovery system.

--industry and --ioc flags removed per project specification.
"""

import argparse
from pathlib import Path

from behavioral_analyzer import BehavioralAnalyzer
from ransomware_monitor import RansomwareEventHandler, start_monitoring
from recovery.config import RecoveryConfig
from recovery.recovery_manager import RecoveryManager


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ML-based Ransomware Detection with Secure File Recovery"
    )
    parser.add_argument("--watch", type=str, required=True, help="Protected folder to monitor")
    parser.add_argument("--backup", type=str, required=True, help="Encrypted backup folder (outside --watch)")
    parser.add_argument("--key-file", type=str, required=True, help="Fernet key file path (outside --backup)")
    parser.add_argument("--window", type=float, default=60.0, help="Pending promotion window in seconds")
    parser.add_argument("--live", action="store_true", help="Enable live process termination/quarantine (default: dry-run)")
    args = parser.parse_args()

    cfg = RecoveryConfig(
        protected_folder=Path(args.watch),
        backup_folder=Path(args.backup),
        key_file_path=Path(args.key_file),
        window_seconds=args.window,
        dry_run=not args.live,
    )
    recovery_mgr = RecoveryManager(cfg)
    count = recovery_mgr.initialize()
    print(f"Initialized encrypted baseline for {count} protected files.")

    analyzer = BehavioralAnalyzer(protected_folder=cfg.protected_folder)
    handler = RansomwareEventHandler(
        analyzer=analyzer,
        recovery_manager=recovery_mgr,
        backup_folder=cfg.backup_folder,
    )
    print(f"Monitoring {cfg.protected_folder} (dry_run={cfg.dry_run})...")
    start_monitoring([cfg.protected_folder], handler)


if __name__ == "__main__":
    main()
