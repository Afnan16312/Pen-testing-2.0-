"""
Shared helpers for saving and loading JSON artefacts
produced by each stage of the penetration testing pipeline.
"""

import json
import os
import glob
from datetime import datetime


def save_json(data: object, path: str):
    """
    Serialise *data* to a pretty-printed JSON file at *path*.
    Creates parent directories as needed.
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def load_json(path: str) -> object:
    """Load and return parsed JSON from *path*."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_latest_json(directory: str, pattern: str) -> object | None:
    """
    Find the most recently modified file matching *pattern* inside *directory*
    and return its parsed JSON content.  Returns None if no match is found.

    Example:
        load_latest_json("results", "nmap_scan_*.json")
    """
    search = os.path.join(directory, pattern)
    matches = sorted(glob.glob(search), key=os.path.getmtime, reverse=True)
    if not matches:
        return None
    return load_json(matches[0])


def append_to_report(report_path: str, section: str, data: object):
    """
    Append a named section to an existing JSON report file,
    or create it if it does not yet exist.

    Args:
        report_path: Path to the cumulative report JSON
        section:     Key name for the new section
        data:        Data to store under that key
    """
    report = {}
    if os.path.exists(report_path):
        report = load_json(report_path)
    report[section] = data
    report["last_updated"] = datetime.now().isoformat()
    save_json(report, report_path)
