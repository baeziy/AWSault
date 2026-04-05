"""
Handles saving and loading scan results to ~/.awsault/.

Results are stored as JSON so they can be inspected with --show
or exported with --output after a scan has completed.

Uses pathlib for cross-platform path handling (Linux, macOS, Windows).
"""

import json
import datetime
from pathlib import Path

_STORE_DIR = Path.home() / ".awsault"
_SCAN_FILE = _STORE_DIR / "last_scan.json"


def _serial(obj):
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return "<binary>"
    return str(obj)


def save_scan(quick, deep=None, findings=None, loot=None, meta=None):
    """
    Persist the scan results to disk. Called automatically after every scan
    so --show and standalone --output can access the data without rescanning.
    """
    _STORE_DIR.mkdir(parents=True, exist_ok=True)

    payload = {"meta": meta or {}}

    if quick:
        payload["services"] = {name: sr.to_dict() for name, sr in quick.items()}

    if deep:
        payload["deep"] = {k: v for k, v in deep.items() if v}

    if findings:
        payload["findings"] = [f.to_dict() for f in findings]

    if loot:
        payload["loot"] = loot

    _SCAN_FILE.write_text(json.dumps(payload, indent=2, default=_serial), encoding="utf-8")


def load_scan():
    """
    Load the last scan from disk.
    Returns the parsed dict, or None if no scan exists.
    """
    if not _SCAN_FILE.exists():
        return None
    try:
        return json.loads(_SCAN_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def scan_exists():
    """Check whether a saved scan file exists."""
    return _SCAN_FILE.exists()
