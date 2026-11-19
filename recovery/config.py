"""Configuration settings for the Secure File Recovery system."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import FrozenSet


COMPRESSED_EXTENSIONS: FrozenSet[str] = frozenset(
    {".zip", ".jpg", ".jpeg", ".png", ".mp4", ".pdf", ".docx", ".xlsx", ".pptx", ".gz", ".7z"}
)


@dataclass
class RecoveryConfig:
    """Central configuration for encrypted backup, pending window, and entropy guard."""

    protected_folder: Path
    backup_folder: Path
    key_file_path: Path
    quarantine_folder: Path = Path("logs/quarantine")
    window_seconds: float = 60.0
    versions_kept: int = 3
    entropy_guard_threshold: float = 7.5
    skip_entropy_extensions: FrozenSet[str] = field(default_factory=lambda: COMPRESSED_EXTENSIONS)
    dry_run: bool = True

    def __post_init__(self) -> None:
        self.protected_folder = Path(self.protected_folder).resolve()
        self.backup_folder = Path(self.backup_folder).resolve()
        self.key_file_path = Path(self.key_file_path).resolve()
        self.quarantine_folder = Path(self.quarantine_folder).resolve()

        if self.backup_folder == self.protected_folder or self.protected_folder in self.backup_folder.parents:
            raise ValueError(
                "backup_folder must be outside protected_folder to prevent watcher event loops."
            )
        if self.key_file_path.parent == self.backup_folder or self.backup_folder in self.key_file_path.parents:
            raise ValueError(
                "key_file_path must be stored outside backup_folder."
            )
