"""Ransomware monitor: Layer 5 process heuristics + Watchdog handler + Recovery hooks."""

import csv
import time
from pathlib import Path
from typing import Iterable, Optional, Set

try:
    import psutil  # type: ignore
except ImportError:
    psutil = None  # type: ignore

try:
    from watchdog.events import FileSystemEventHandler  # type: ignore
    from watchdog.observers import Observer  # type: ignore
except ImportError:
    FileSystemEventHandler = object  # type: ignore
    Observer = None  # type: ignore

from behavioral_analyzer import BehavioralAnalyzer
from incident_reporter import IncidentReporter
from recovery.recovery_manager import RecoveryManager

SUSPICIOUS_PROCESS_KEYWORDS: Set[str] = {
    "wannacry", "locky", "cerber", "cryptolocker", "ryuk", "conti",
    "lockbit", "revil", "sodinokibi", "maze", "petya", "notpetya",
    "ransom", "encryptor",
}


def check_suspicious_processes() -> list[dict]:
    """Layer 5: Scan running processes for known ransomware-like names."""
    hits = []
    if psutil is None:
        return hits
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = (proc.info.get("name") or "").lower()
            if any(kw in name for kw in SUSPICIOUS_PROCESS_KEYWORDS):
                hits.append({"pid": proc.info["pid"], "name": proc.info.get("name")})
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return hits


class RansomwareEventHandler(FileSystemEventHandler):  # type: ignore
    """Watchdog event handler integrated with BehavioralAnalyzer and RecoveryManager."""

    def __init__(
        self,
        analyzer: BehavioralAnalyzer,
        recovery_manager: Optional[RecoveryManager] = None,
        backup_folder: Optional[Path] = None,
        log_csv_path: Path | str = "logs/ransomware_scan_log.csv",
        reporter: Optional[IncidentReporter] = None,
    ) -> None:
        self.analyzer = analyzer
        self.recovery_manager = recovery_manager
        self.backup_folder = Path(backup_folder).resolve() if backup_folder else None
        self.log_csv_path = Path(log_csv_path).resolve()
        self.log_csv_path.parent.mkdir(parents=True, exist_ok=True)
        self.reporter = reporter or IncidentReporter()
        self._init_csv()

    def _init_csv(self) -> None:
        if not self.log_csv_path.exists():
            with open(self.log_csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                # SHA-256 and industry columns removed per specification
                writer.writerow(["timestamp", "event_type", "path", "extension", "entropy", "severity"])

    def _is_excluded(self, path: Path) -> bool:
        resolved = path.resolve()
        if self.backup_folder is not None:
            if resolved == self.backup_folder or self.backup_folder in resolved.parents:
                return True
        if "logs" in resolved.parts and ("quarantine" in resolved.parts or "incidents" in resolved.parts):
            return True
        return False

    def handle_path_event(self, event_type: str, file_path: Path | str) -> Optional[dict]:
        path = Path(file_path)
        if self._is_excluded(path):
            return None

        # Hook 1: Notify recovery manager of file event (marks pending, never touches backup)
        if self.recovery_manager is not None:
            self.recovery_manager.on_file_event(path, event_type=event_type)

        proc_hits = check_suspicious_processes()
        alert = self.analyzer.record_event(event_type, path, process_hit=bool(proc_hits))

        with open(self.log_csv_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                alert["timestamp"],
                alert["event_type"],
                alert["path"],
                alert["extension"],
                alert["entropy"],
                alert["severity"],
            ])

        # Hook 2: Trigger recovery on HIGH or CRITICAL alerts
        if alert["severity"] in ("HIGH", "CRITICAL"):
            recovery_summary = None
            if self.recovery_manager is not None:
                recovery_summary = self.recovery_manager.on_alert(
                    severity=alert["severity"],
                    affected_paths=[path],
                )
            self.reporter.create_report(alert, recovery_summary=recovery_summary)
            alert["recovery"] = recovery_summary

        return alert

    def on_created(self, event) -> None:
        if not event.is_directory:
            self.handle_path_event("created", event.src_path)

    def on_modified(self, event) -> None:
        if not event.is_directory:
            self.handle_path_event("modified", event.src_path)

    def on_moved(self, event) -> None:
        if not event.is_directory:
            self.handle_path_event("moved", event.dest_path)

    def on_deleted(self, event) -> None:
        if not event.is_directory:
            self.handle_path_event("deleted", event.src_path)


def start_monitoring(
    watch_paths: Iterable[Path | str],
    handler: RansomwareEventHandler,
    duration_seconds: Optional[float] = None,
) -> None:
    """Start Watchdog observer on protected directories (excluding backup folder)."""
    if Observer is None:
        raise ImportError("watchdog is required for live filesystem monitoring. Install requirements.txt.")
    observer = Observer()
    for p in watch_paths:
        observer.schedule(handler, str(Path(p).resolve()), recursive=True)
    observer.start()
    try:
        start = time.time()
        while True:
            time.sleep(0.5)
            if handler.recovery_manager is not None:
                handler.recovery_manager.on_clean_tick()
            if duration_seconds is not None and (time.time() - start) >= duration_seconds:
                break
    finally:
        observer.stop()
        observer.join()
