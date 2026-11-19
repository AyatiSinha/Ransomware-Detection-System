"""Incident reporter generating JSON incident reports (compliance fields removed)."""

import json
import time
import uuid
from pathlib import Path
from typing import Optional


class IncidentReporter:
    """Writes structured JSON incident reports to logs/incidents/."""

    def __init__(self, incidents_dir: Path | str = "logs/incidents") -> None:
        self.incidents_dir = Path(incidents_dir).resolve()
        self.incidents_dir.mkdir(parents=True, exist_ok=True)

    def create_report(self, alert: dict, recovery_summary: Optional[dict] = None) -> Path:
        incident_id = str(uuid.uuid4())
        payload = {
            "incident_id": incident_id,
            "timestamp": time.time(),
            "severity": alert.get("severity", "HIGH"),
            "event_type": alert.get("event_type"),
            "path": alert.get("path"),
            "entropy": alert.get("entropy"),
            "reasons": alert.get("reasons", []),
            "rates": alert.get("rates", {}),
            "recovery": recovery_summary or {},
        }
        out_path = self.incidents_dir / f"incident_{incident_id[:8]}.json"
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return out_path
