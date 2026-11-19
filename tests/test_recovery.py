"""Automated acceptance test suite covering Section 9 criteria of the Project Brief."""

import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from auto_response import AutoResponse
from behavioral_analyzer import BehavioralAnalyzer
from ml_models.anomaly_detector import MLAnomalyDetector
from ransomware_monitor import RansomwareEventHandler
from recovery.backup_store import BackupStore, compute_sha256
from recovery.config import RecoveryConfig
from recovery.recovery_manager import RecoveryManager
from sandbox.sandbox_simulator import run_simulation, simulate_attack_on_folder


class TestSecureFileRecovery(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="rds_test_"))
        self.protected = self.root / "protected"
        self.backup = self.root / "backups"
        self.key_file = self.root / "keys" / "backup.key"
        self.quarantine = self.root / "logs" / "quarantine"
        self.protected.mkdir(parents=True, exist_ok=True)

        self.f1 = self.protected / "doc1.txt"
        self.f2 = self.protected / "doc2.txt"
        self.f3 = self.protected / "archive.zip"
        self.f1.write_text("Important university document 1.\n" * 10, encoding="utf-8")
        self.f2.write_text("Important university document 2.\n" * 10, encoding="utf-8")
        self.f3.write_bytes(os.urandom(1024))  # High-entropy compressed format

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_01_baseline_and_verify(self) -> None:
        cfg = RecoveryConfig(self.protected, self.backup, self.key_file, self.quarantine, window_seconds=1.0)
        store = BackupStore(cfg)
        count = store.init_baseline()
        self.assertEqual(count, 3)
        report = store.verify()
        self.assertTrue(all(report.values()))
        # Key must be outside backup folder
        self.assertNotEqual(self.key_file.parent.resolve(), self.backup.resolve())

    def test_02_normal_edit_promoted_after_window(self) -> None:
        cfg = RecoveryConfig(self.protected, self.backup, self.key_file, self.quarantine, window_seconds=0.8)
        mgr = RecoveryManager(cfg)
        mgr.initialize()

        with open(self.f1, "a", encoding="utf-8") as f:
            f.write("Clean normal edit.\n")
        new_sha = compute_sha256(self.f1)
        mgr.on_file_event(self.f1, "modified")

        # Before window elapses, should not promote
        self.assertEqual(len(mgr.on_clean_tick()), 0)
        time.sleep(0.9)
        promoted = mgr.on_clean_tick()
        self.assertEqual(len(promoted), 1)
        self.assertEqual(mgr.backup_store.list_versions(self.f1)[-1]["sha256"], new_sha)

    def test_03_entropy_guard_blocks_silent_high_entropy_plaintext_and_allows_zip(self) -> None:
        cfg = RecoveryConfig(self.protected, self.backup, self.key_file, self.quarantine, window_seconds=0.3)
        mgr = RecoveryManager(cfg)
        mgr.initialize()

        # High-entropy write to .txt should be blocked by entropy guard
        self.f2.write_bytes(os.urandom(4096))
        mgr.on_file_event(self.f2, "modified")
        # High-entropy write to .zip should be skipped by entropy guard and promoted
        self.f3.write_bytes(os.urandom(1024))
        mgr.on_file_event(self.f3, "modified")

        time.sleep(0.4)
        promoted = mgr.on_clean_tick()
        promoted_names = {Path(p["file"]).name for p in promoted}
        self.assertIn("archive.zip", promoted_names)
        self.assertNotIn("doc2.txt", promoted_names)

    def test_04_attack_freeze_quarantine_and_byte_identical_restore(self) -> None:
        cfg = RecoveryConfig(
            self.protected, self.backup, self.key_file, self.quarantine,
            window_seconds=2.0, dry_run=False
        )
        auto_resp = AutoResponse(quarantine_dir=self.quarantine, dry_run=False)
        mgr = RecoveryManager(cfg, auto_response=auto_resp)
        mgr.initialize()

        pre_hashes = {p.name: compute_sha256(p) for p in [self.f1, self.f2, self.f3]}
        manifest_before = {k: [v["sha256"] for v in vs] for k, vs in mgr.backup_store.manifest.items()}

        # Simulate a pending edit before attack begins
        with open(self.f1, "a", encoding="utf-8") as f:
            f.write("Unconfirmed pending edit.\n")
        mgr.on_file_event(self.f1, "modified")

        # Simulate attack
        attacked = simulate_attack_on_folder(self.protected, write_delay=0.0)
        analyzer = BehavioralAnalyzer(protected_folder=self.protected)
        alert = analyzer.record_event("moved", attacked[0])
        self.assertIn(alert["severity"], ("HIGH", "CRITICAL"))

        res = mgr.on_alert(alert["severity"], affected_paths=attacked)
        self.assertTrue(res["frozen"])
        self.assertTrue(res["manifest_verified"])

        # Encrypted files moved to quarantine (not deleted)
        quarantined_files = list(self.quarantine.iterdir())
        self.assertGreaterEqual(len(quarantined_files), 3)

        # Backup manifest hashes unchanged by attack
        manifest_after = {k: [v["sha256"] for v in vs] for k, vs in mgr.backup_store.manifest.items()}
        self.assertEqual(manifest_before, manifest_after)

        # Byte-identical restore for all protected files (including pending f1)
        for name, old_sha in pre_hashes.items():
            self.assertEqual(compute_sha256(self.protected / name), old_sha)

    def test_05_sandbox_simulation_150_events_and_ml_detector(self) -> None:
        sim = run_simulation(file_count=150, cleanup=True)
        self.assertEqual(sim["total_events"], 150)
        self.assertEqual(sim["flagged_events"], 150)

        ml = MLAnomalyDetector().fit()
        risk = ml.assess({
            "file_create_rate": 25,
            "file_modify_rate": 40,
            "file_rename_rate": 35,
            "unique_extension_count": 6,
            "avg_entropy": 7.85,
            "max_entropy": 7.99,
            "process_cpu": 60.0,
        })
        self.assertTrue(risk["is_anomalous"])

    def test_06_dry_run_default_preserved(self) -> None:
        resp = AutoResponse(quarantine_dir=self.quarantine)
        self.assertTrue(resp.dry_run)
        term = resp.terminate_process(999999)
        self.assertTrue(term["dry_run"])


if __name__ == "__main__":
    unittest.main()
