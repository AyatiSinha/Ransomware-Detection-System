"""Orchestrator tying file events, freeze-on-alert, process attribution, quarantine, and restore."""

from pathlib import Path
from typing import List, Optional, Set

from auto_response import AutoResponse
from recovery.backup_store import BackupStore
from recovery.config import RecoveryConfig
from recovery.pending_tracker import PendingTracker
from recovery.process_attribution import find_suspect_pid


class RecoveryManager:
    """Coordinates baseline backups, pending promotions, and post-attack recovery."""

    def __init__(self, config: RecoveryConfig, auto_response: Optional[AutoResponse] = None) -> None:
        self.config = config
        self.backup_store = BackupStore(config)
        self.pending_tracker = PendingTracker(config, self.backup_store)
        self.auto_response = auto_response or AutoResponse(
            quarantine_dir=config.quarantine_folder,
            dry_run=config.dry_run,
        )

    def initialize(self) -> int:
        """Create encrypted baseline backups for all files in the protected folder."""
        return self.backup_store.init_baseline()

    def on_file_event(self, file_path: Path, event_type: str = "modified") -> None:
        """Record modified/created protected files as pending without altering backups."""
        path = Path(file_path).resolve()
        if self.config.backup_folder in path.parents or path == self.config.backup_folder:
            return
        if event_type in ("created", "modified", "moved") and path.is_file():
            self.pending_tracker.mark_pending(path)

    def on_clean_tick(self) -> List[dict]:
        """Promote pending files whose clean window has elapsed."""
        return self.pending_tracker.tick()

    def on_alert(
        self,
        severity: str,
        affected_paths: Optional[List[Path]] = None,
        suspect_pid_override: Optional[int] = None,
        exclude_pids: Optional[Set[int]] = None,
    ) -> dict:
        """Respond to HIGH/CRITICAL alert: freeze, attribute, terminate, quarantine, restore, verify."""
        if severity.upper() not in ("HIGH", "CRITICAL"):
            return {"triggered": False, "reason": f"Severity {severity} below recovery threshold"}

        # 1. Freeze backups immediately so no encrypted file can ever be promoted
        self.pending_tracker.freeze()
        freeze_ts = self.pending_tracker.freeze_timestamp

        # 2. Identify suspect process
        if suspect_pid_override is not None:
            suspect = {"pid": suspect_pid_override, "name": "override", "write_bytes_delta": 0}
        else:
            suspect = find_suspect_pid(
                protected_folder=self.config.protected_folder,
                exclude_pids=exclude_pids,
            )

        # 3. Terminate suspect process (respects dry_run unless explicitly disabled)
        termination_result = None
        if suspect and suspect.get("pid"):
            termination_result = self.auto_response.terminate_process(suspect["pid"])

        # 4. Quarantine encrypted/damaged files (move, never delete)
        quarantined: List[dict] = []
        candidate_paths: Set[Path] = set()
        if affected_paths:
            for p in affected_paths:
                candidate_paths.add(Path(p).resolve())
        for p_str in self.pending_tracker.list_pending():
            candidate_paths.add(Path(p_str).resolve())

        # Also catch any files in protected_folder that no longer match manifest hashes
        manifest_hashes = {
            rel: versions[-1]["sha256"]
            for rel, versions in self.backup_store.manifest.items()
            if versions
        }
        for item in self.config.protected_folder.rglob("*"):
            if item.is_file():
                candidate_paths.add(item.resolve())

        for path in sorted(candidate_paths):
            if not path.is_file():
                continue
            try:
                rel = str(path.relative_to(self.config.protected_folder))
            except ValueError:
                rel = str(path)
            # Quarantine if it was modified/renamed or differs from last known-good hash
            from recovery.backup_store import compute_sha256
            expected_sha = manifest_hashes.get(rel)
            if expected_sha is None or compute_sha256(path) != expected_sha:
                q_res = self.auto_response.quarantine_file(path)
                quarantined.append(q_res)

        # 5. Restore all protected files from newest pre-attack backup and verify hashes
        restored = self.backup_store.restore_all(before_timestamp=freeze_ts)
        self.pending_tracker.clear_pending()
        manifest_verification = self.backup_store.verify()

        return {
            "triggered": True,
            "severity": severity.upper(),
            "frozen": self.pending_tracker.is_frozen(),
            "suspect": suspect,
            "termination": termination_result,
            "quarantined": quarantined,
            "restored": restored,
            "manifest_verified": all(manifest_verification.values()),
        }
