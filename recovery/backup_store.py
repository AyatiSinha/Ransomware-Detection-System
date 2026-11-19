"""Encrypted versioned backup store with Fernet, manifest tracking, and atomic writes."""

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional

from cryptography.fernet import Fernet

from recovery.config import RecoveryConfig


def compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


class BackupStore:
    """Manages Fernet-encrypted file backups, version retention, and manifest verification."""

    def __init__(self, config: RecoveryConfig) -> None:
        self.config = config
        self.backup_dir = self.config.backup_folder
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.backup_dir / "manifest.json"
        self._fernet = Fernet(self._load_or_create_key())
        self.manifest: Dict[str, List[dict]] = self._load_manifest()

    def _load_or_create_key(self) -> bytes:
        key_path = self.config.key_file_path
        key_path.parent.mkdir(parents=True, exist_ok=True)
        if key_path.exists():
            return key_path.read_bytes().strip()
        key = Fernet.generate_key()
        self._atomic_write_bytes(key_path, key)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        return key

    @staticmethod
    def _atomic_write_bytes(target_path: Path, data: bytes) -> None:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=str(target_path.parent), prefix=".tmp_")
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, target_path)
        except Exception:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            raise

    def _load_manifest(self) -> Dict[str, List[dict]]:
        if self.manifest_path.exists():
            return json.loads(self.manifest_path.read_text(encoding="utf-8"))
        return {}

    def _save_manifest(self) -> None:
        payload = json.dumps(self.manifest, indent=2, sort_keys=True).encode("utf-8")
        self._atomic_write_bytes(self.manifest_path, payload)

    def _rel_key(self, file_path: Path) -> str:
        resolved = Path(file_path).resolve()
        try:
            return str(resolved.relative_to(self.config.protected_folder))
        except ValueError:
            return str(resolved)

    def init_baseline(self) -> int:
        """Back up every file currently inside the protected folder."""
        count = 0
        for item in sorted(self.config.protected_folder.rglob("*")):
            if item.is_file():
                self.add_version(item)
                count += 1
        return count

    def add_version(self, file_path: Path) -> dict:
        """Encrypt and store a new known-good version of file_path, keeping at most N versions."""
        src = Path(file_path).resolve()
        if not src.is_file():
            raise FileNotFoundError(f"Cannot back up missing file: {src}")

        rel_key = self._rel_key(src)
        plaintext = src.read_bytes()
        sha256_plain = hashlib.sha256(plaintext).hexdigest()
        size_bytes = len(plaintext)
        timestamp = time.time()

        encrypted = self._fernet.encrypt(plaintext)
        safe_id = hashlib.sha256(rel_key.encode("utf-8")).hexdigest()[:16]
        version_num = len(self.manifest.get(rel_key, [])) + 1
        blob_name = f"{safe_id}_v{int(timestamp * 1000)}_{version_num}.enc"
        blob_path = self.backup_dir / blob_name

        self._atomic_write_bytes(blob_path, encrypted)
        blob_sha256 = compute_sha256(blob_path)
        if self._fernet.decrypt(blob_path.read_bytes()) != plaintext:
            blob_path.unlink(missing_ok=True)
            raise IOError(f"Post-write verification failed for {blob_path}")

        entry = {
            "version": version_num,
            "blob": blob_name,
            "sha256": sha256_plain,
            "blob_sha256": blob_sha256,
            "size": size_bytes,
            "timestamp": timestamp,
        }

        versions = self.manifest.setdefault(rel_key, [])
        versions.append(entry)

        while len(versions) > self.config.versions_kept:
            oldest = versions.pop(0)
            old_blob = self.backup_dir / oldest["blob"]
            if old_blob.exists():
                old_blob.unlink()

        self._save_manifest()
        return entry

    def list_versions(self, file_path: Path) -> List[dict]:
        """Return stored version metadata for a protected file."""
        rel_key = self._rel_key(Path(file_path))
        return list(self.manifest.get(rel_key, []))

    def restore_file(self, file_path: Path, before_timestamp: Optional[float] = None) -> dict:
        """Restore a protected file from its newest valid backup version."""
        target = Path(file_path).resolve()
        rel_key = self._rel_key(target)
        versions = self.manifest.get(rel_key, [])
        if not versions:
            raise KeyError(f"No backup versions found for {rel_key}")

        candidates = versions
        if before_timestamp is not None:
            filtered = [v for v in versions if v["timestamp"] <= before_timestamp]
            if filtered:
                candidates = filtered

        chosen = candidates[-1]
        blob_path = self.backup_dir / chosen["blob"]
        if not blob_path.exists():
            raise FileNotFoundError(f"Backup blob missing: {blob_path}")

        plaintext = self._fernet.decrypt(blob_path.read_bytes())
        actual_sha = hashlib.sha256(plaintext).hexdigest()
        if actual_sha != chosen["sha256"]:
            raise ValueError(
                f"Manifest hash mismatch for {rel_key}: expected {chosen['sha256']}, got {actual_sha}"
            )

        self._atomic_write_bytes(target, plaintext)
        restored_sha = compute_sha256(target)
        if restored_sha != chosen["sha256"]:
            raise ValueError(f"Post-restore SHA-256 verification failed for {target}")

        return {
            "file": str(target),
            "rel_key": rel_key,
            "restored_version": chosen["version"],
            "sha256": restored_sha,
            "verified": True,
        }

    def restore_all(self, before_timestamp: Optional[float] = None) -> List[dict]:
        """Restore every file recorded in the manifest."""
        results = []
        for rel_key in list(self.manifest.keys()):
            target = self.config.protected_folder / rel_key
            results.append(self.restore_file(target, before_timestamp=before_timestamp))
        return results

    def verify(self) -> Dict[str, bool]:
        """Verify every encrypted backup blob and manifest entry."""
        report: Dict[str, bool] = {}
        for rel_key, versions in self.manifest.items():
            if not versions:
                report[rel_key] = False
                continue
            all_ok = True
            for v in versions:
                blob_path = self.backup_dir / v["blob"]
                if not blob_path.exists():
                    all_ok = False
                    break
                if compute_sha256(blob_path) != v["blob_sha256"]:
                    all_ok = False
                    break
                try:
                    plaintext = self._fernet.decrypt(blob_path.read_bytes())
                    if hashlib.sha256(plaintext).hexdigest() != v["sha256"]:
                        all_ok = False
                        break
                except Exception:
                    all_ok = False
                    break
            report[rel_key] = all_ok
        return report
