"""Behavioral analyzer: Layer 2 sliding-window rates + Layer 3 Shannon entropy.

Layer 4 (hash_hit) and Layer 6 (industry profiles / severity_boost) removed.
"""

import math
import time
from collections import Counter, deque
from pathlib import Path
from typing import Deque, Dict, Set

from threat_intelligence import ThreatIntelligence


def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def file_entropy(file_path: Path | str, max_bytes: int = 1024 * 1024) -> float:
    """Read up to max_bytes from a file and return its Shannon entropy."""
    path = Path(file_path)
    if not path.is_file():
        return 0.0
    try:
        return shannon_entropy(path.read_bytes()[:max_bytes])
    except OSError:
        return 0.0


class BehavioralAnalyzer:
    """Sliding-window behavioral detector combining extension, rate, and entropy signals."""

    def __init__(
        self,
        window_seconds: float = 60.0,
        protected_folder: Path | str | None = None,
    ) -> None:
        self.window_seconds = window_seconds
        self.ti = ThreatIntelligence(protected_folder=protected_folder)
        self.events: Deque[tuple[float, str, str]] = deque()
        self.recent_extensions: Deque[tuple[float, str]] = deque()
        self.alert_history: list[dict] = []

    def reset_engine(self, protected_folder: Path | str | None = None) -> None:
        """Reset sliding-window counters (industry argument removed)."""
        self.events.clear()
        self.recent_extensions.clear()
        self.alert_history.clear()
        if protected_folder is not None:
            self.ti = ThreatIntelligence(protected_folder=protected_folder)

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()
        while self.recent_extensions and self.recent_extensions[0][0] < cutoff:
            self.recent_extensions.popleft()

    def record_event(self, event_type: str, file_path: Path | str, process_hit: bool = False) -> dict:
        now = time.time()
        self._prune(now)

        path = Path(file_path)
        ext = path.suffix.lower()
        self.events.append((now, event_type, str(path)))
        if ext:
            self.recent_extensions.append((now, ext))

        counts = self.get_rates(now)
        entropy = file_entropy(path) if event_type in ("created", "modified", "moved") else 0.0
        ti_eval = self.ti.evaluate_path(path)

        score = 0
        reasons = []
        if ti_eval["extension_hit"]:
            score += 4
            reasons.append(f"suspicious_extension:{ext}")
        if entropy >= 7.2:
            score += 3
            reasons.append(f"high_entropy:{entropy:.2f}")
        if counts["total_events"] >= 15:
            score += 3
            reasons.append(f"high_rate:{counts['total_events']}/min")
        if counts["unique_extensions"] >= 4:
            score += 2
            reasons.append(f"extension_diversity:{counts['unique_extensions']}")
        if process_hit:
            score += 4
            reasons.append("suspicious_process_name")

        # Single protected-folder rule replacing Layer 6 industry severity boosts:
        # any alert triggered inside the protected folder is at least HIGH.
        if score >= 6:
            severity = "CRITICAL"
        elif score >= 3:
            severity = "HIGH"
        elif score >= 1:
            severity = "LOW"
        else:
            severity = "INFO"

        if severity in ("LOW",) and ti_eval["in_protected_folder"] and (ti_eval["extension_hit"] or entropy >= 7.2):
            severity = "HIGH"

        result = {
            "timestamp": now,
            "event_type": event_type,
            "path": str(path),
            "extension": ext,
            "entropy": round(entropy, 4),
            "score": score,
            "severity": severity,
            "reasons": reasons,
            "rates": counts,
        }
        if severity in ("HIGH", "CRITICAL"):
            self.alert_history.append(result)
        return result

    def get_rates(self, now: float | None = None) -> Dict[str, int]:
        current = now if now is not None else time.time()
        self._prune(current)
        modifies = sum(1 for _, t, _ in self.events if t == "modified")
        renames = sum(1 for _, t, _ in self.events if t == "moved")
        deletes = sum(1 for _, t, _ in self.events if t == "deleted")
        creates = sum(1 for _, t, _ in self.events if t == "created")
        unique_exts: Set[str] = {ext for _, ext in self.recent_extensions}
        return {
            "created": creates,
            "modified": modifies,
            "renamed": renames,
            "deleted": deletes,
            "total_events": len(self.events),
            "unique_extensions": len(unique_exts),
        }

    def build_llm_context_packet(self) -> dict:
        return {
            "window_seconds": self.window_seconds,
            "rates": self.get_rates(),
            "recent_alerts": self.alert_history[-10:],
        }
