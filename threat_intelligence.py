"""Threat intelligence module: Layer 1 suspicious extensions + SHA-256 helper.

Layers 4 (known-hash matching) and 6 (industry profiles / compliance / severity_boost)
have been removed per project specification. Any alert inside the protected folder is HIGH.
"""

import hashlib
from pathlib import Path
from typing import FrozenSet

SUSPICIOUS_EXTENSIONS: FrozenSet[str] = frozenset(
    {
        ".locked", ".locky", ".cerber", ".wannacry", ".wncry", ".wcry", ".crypt",
        ".crypted", ".crypto", ".enc", ".encrypted", ".ryk", ".ryuk", ".conti",
        ".revil", ".sodinokibi", ".lockbit", ".blackcat", ".alphv", ".maze",
        ".egregor", ".dharma", ".phobos", ".makop", ".stop", ".djvu", ".vu",
        ".zepto", ".odin", ".thor", ".aesir", ".zzzzz", ".micro", ".mp3",
        ".ecc", ".ezz", ".exx", ".xyz", ".zzz", ".aaa", ".abc", ".vvv",
        ".xxx", ".ttt", ".xtbl", ".crinf", ".r5a", ".xrtn", ".nx", ".pay",
        ".ransom", ".creeper", ".hydra", ".petya", ".notpetya",
    }
)


def compute_file_sha256(file_path: Path | str) -> str:
    """Compute SHA-256 digest of a file (reused by the backup manifest)."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


class ThreatIntelligence:
    """Layer 1 suspicious extension detector and protected-folder alert rule."""

    def __init__(self, protected_folder: Path | str | None = None) -> None:
        self.protected_folder = Path(protected_folder).resolve() if protected_folder else None

    def is_suspicious_extension(self, file_path: Path | str) -> bool:
        ext = Path(file_path).suffix.lower()
        return ext in SUSPICIOUS_EXTENSIONS

    def is_in_protected_folder(self, file_path: Path | str) -> bool:
        if self.protected_folder is None:
            return True
        resolved = Path(file_path).resolve()
        return resolved == self.protected_folder or self.protected_folder in resolved.parents

    def evaluate_path(self, file_path: Path | str) -> dict:
        ext_hit = self.is_suspicious_extension(file_path)
        in_protected = self.is_in_protected_folder(file_path)
        return {
            "extension_hit": ext_hit,
            "extension": Path(file_path).suffix.lower(),
            "in_protected_folder": in_protected,
        }
