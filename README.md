# ML-based Ransomware Detection with Secure File Recovery

> **Attribution:** This project is a student extension of [Mangesh-Bhattacharya/Ransomware-Detection-System](https://github.com/Mangesh-Bhattacharya/Ransomware-Detection-System) (MIT License). All original detection, automated response, and sandbox simulation components are credited to **Mangesh Bhattacharya**.

## What Was Reused vs. What Was Built

- **Reused from Base Repository:**
  - Detection Layers 1, 2, 3, and 5 (`threat_intelligence.py`, `behavioral_analyzer.py`, `ransomware_monitor.py`)
  - ML Anomaly Detection (`ml_models/anomaly_detector.py` — `IsolationForest` + `RandomForestClassifier`)
  - Dry-run-by-default containment (`auto_response.py`) and safe dummy-file simulator (`sandbox/sandbox_simulator.py`)
- **New Work Built:**
  - Removed Layer 4 (known-hash matching) and Layer 6 (industry profiles, compliance tagging, severity boosts), replacing them with a single rule: any alert inside the protected folder is `HIGH`.
  - Added the `recovery/` package (`config.py`, `backup_store.py`, `pending_tracker.py`, `process_attribution.py`, `recovery_manager.py`) providing Fernet-encrypted, versioned backups, a 60-second pending promotion window with an entropy guard, freeze-on-alert, two-snapshot `write_bytes` suspect PID attribution, quarantine-before-restore, and byte-identical SHA-256 verification.
  - Added `demo_recovery.py` for an end-to-end CLI demonstration.

## Remaining Detection Layers

| Layer | Method | Module |
| :--- | :--- | :--- |
| 1 | Suspicious file extension matching (50+ ransomware extensions) | `threat_intelligence.py` |
| 2 | Behavioral rate analysis (renames, modifications, deletions, extension diversity) | `behavioral_analyzer.py` |
| 3 | Shannon entropy screening of modified files | `behavioral_analyzer.py` |
| 5 | Process name heuristics via `psutil` | `ransomware_monitor.py` |
| ML | Blended `IsolationForest` + `RandomForestClassifier` risk scoring | `ml_models/anomaly_detector.py` |

## Quick Start

```bash
pip install -r requirements.txt
python demo_recovery.py
```

Run the automated acceptance test suite:

```bash
python -m unittest discover -s tests -v
```
