"""Pending change tracker with promotion window, freeze-on-alert, and entropy guard."""

import math
import time
from collections import Counter
from pathlib import Path
from typing import Dict, List

from recovery.backup_store import BackupStore
from recovery.config import RecoveryConfig


def calculate_shannon_entropy(file_path: Path, sample_bytes: int = 1024 * 1024) -> float:
    """Compute Shannon entropy (0.0 - 8.0 bits/byte) of a file."""
    path = Path(file_path)
    if not path.is_file():
        return 0.0
    data = path.read_bytes()[:sample_bytes]
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


class PendingTracker:
    """Tracks unconfirmed file changes and promotes them only after a clean window."""

    def __init__(self, config: RecoveryConfig, backup_store: BackupStore) -> None:
        self.config = config
        self.backup_store = backup_store
        self._pending: Dict[str, float] = {}
        self._frozen: bool = False
        self._freeze_timestamp: float | None = None

    def is_frozen(self) -> bool:
        return self._frozen

    @property
    def freeze_timestamp(self) -> float | None:
        return self._freeze_timestamp

    def freeze(self) -> None:
        """Immediately halt all backup promotions on HIGH/CRITICAL alert."""
        if not self._frozen:
            self._frozen = True
            self._freeze_timestamp = time.time()

    def unfreeze(self) -> None:
        """Resume promotions after an incident has been resolved."""
        self._frozen = False
        self._freeze_timestamp = None

    def mark_pending(self, file_path: Path) -> None:
        """Record a modified file as pending without touching its existing backup."""
        resolved = str(Path(file_path).resolve())
        self._pending[resolved] = time.time()

    def list_pending(self) -> List[str]:
        return list(self._pending.keys())

    def clear_pending(self) -> None:
        self._pending.clear()

    def promote_clean(self, now: float | None = None) -> List[dict]:
        """Promote pending files whose window elapsed without an alert and below entropy guard."""
        if self._frozen:
            return []

        current_time = now if now is not None else time.time()
        promoted: List[dict] = []

        for path_str, marked_at in list(self._pending.items()):
            if current_time - marked_at < self.config.window_seconds:
                continue

            path = Path(path_str)
            if not path.is_file():
                self._pending.pop(path_str, None)
                continue

            ext = path.suffix.lower()
            if ext not in self.config.skip_entropy_extensions:
                entropy = calculate_shannon_entropy(path)
                if entropy >= self.config.entropy_guard_threshold:
                    # Entropy guard blocks silent promotion of suspiciously high-entropy writes
                    continue

            entry = self.backup_store.add_version(path)
            self._pending.pop(path_str, None)
            promoted.append({"file": path_str, "version": entry["version"], "sha256": entry["sha256"]})

        return promoted

    def tick(self) -> List[dict]:
        """Convenience wrapper for periodic promotion checks."""
        return self.promote_clean()
