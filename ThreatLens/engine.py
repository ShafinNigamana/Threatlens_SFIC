"""
ThreatLens — Core Detection Engine
====================================
Parses ProcMon CSV logs and runs rule-based threat detection.
Works 100% offline with zero dependencies beyond Python stdlib + threat_db.
"""

import csv
import io
import re
from datetime import datetime
from collections import Counter
from threat_db import ALL_RULES, SEVERITY_ORDER, SEVERITY_EMOJI, match_rule, check_known_process


def parse_procmon_csv(file_content: str) -> list[dict]:
    """
    Parse ProcMon CSV export into a list of structured log entries.
    
    ProcMon CSV columns (standard export):
      "Time of Day","Process Name","PID","Operation","Path","Result","Detail"
    
    Some ProcMon versions also include:
      "Date & Time","Duration","Image Path","Command Line","User","Session","TID"
    
    We handle both formats gracefully.
    """
    entries = []
    
    # Try to detect and handle BOM (Byte Order Mark) that ProcMon sometimes adds
    if file_content.startswith('\ufeff'):
        file_content = file_content[1:]
    
    reader = csv.DictReader(io.StringIO(file_content))
    
    # Normalize column names (ProcMon has quotes and varies between versions)
    for row_num, row in enumerate(reader):
        # Build normalized entry
        entry = {
            "row_num": row_num + 1,
            "timestamp": _extract_field(row, ["Time of Day", "Date & Time", "time of day", "date & time"]),
            "process_name": _extract_field(row, ["Process Name", "process name"]),
            "pid": _extract_field(row, ["PID", "pid"]),
            "operation": _extract_field(row, ["Operation", "operation"]),
            "path": _extract_field(row, ["Path", "path"]),
            "result": _extract_field(row, ["Result", "result"]),
            "detail": _extract_field(row, ["Detail", "detail"]),
            "image_path": _extract_field(row, ["Image Path", "image path"]),
            "command_line": _extract_field(row, ["Command Line", "command line"]),
            "tid": _extract_field(row, ["TID", "tid"]),
            "duration": _extract_field(row, ["Duration", "duration"]),
            "user": _extract_field(row, ["User", "user"]),
        }
        
        # Skip entries where essential fields are missing
        if entry["operation"] and entry["process_name"]:
            entries.append(entry)
    
    return entries


def _extract_field(row: dict, possible_names: list[str]) -> str:
    """Extract a field from a CSV row trying multiple possible column names."""
    for name in possible_names:
        # Try exact match first
        if name in row:
            return (row[name] or "").strip()
        # Try case-insensitive
        for key in row:
            if key.strip().strip('"').lower() == name.lower():
                return (row[key] or "").strip()
    return ""


def analyze_logs(entries: list[dict]) -> dict:
    """
    Run the full detection pipeline on parsed log entries.
    
    Returns a result dict:
    {
        "total_entries": int,
        "scan_time": str,
        "threats": [
            {
                "row_num": int,
                "timestamp": str,
                "process_name": str,
                "pid": str,
                "operation": str,
                "path": str,
                "result": str,
                "detail": str,
                "severity": str,
                "threat_type": str,
                "category": str,
                "description": str,
                "mitre_id": str,
                "related_events": [...]
            },
            ...
        ],
        "summary": {
            "critical": int,
            "high": int,
            "medium": int,
            "low": int,
            "total_threats": int,
            "top_processes": [(name, count), ...],
            "top_threat_types": [(type, count), ...],
        },
        "timeline": [...],  # all threats sorted by timestamp
    }
    """
    threats = []
    scan_start = datetime.now()
    
    for entry in entries:
        # --- Check 1: Known malicious process name ---
        proc_match = check_known_process(entry["process_name"])
        if proc_match:
            severity, threat_type, description = proc_match
            threats.append({
                **entry,
                "severity": severity,
                "threat_type": f"Known Threat: {threat_type}",
                "category": "Known Malicious Process",
                "description": description,
                "mitre_id": "T1204",
            })
            continue  # Don't double-flag
        
        # --- Check 2: Rule-based detection ---
        for rule in ALL_RULES:
            if match_rule(
                rule,
                entry["operation"],
                entry["path"],
                entry["detail"],
                entry["process_name"],
            ):
                threats.append({
                    **entry,
                    "severity": rule["severity"],
                    "threat_type": rule["threat_type"],
                    "category": rule["category"],
                    "description": rule["description"],
                    "mitre_id": rule.get("mitre_id", "N/A"),
                })
                break  # First matching rule wins (rules ordered by specificity)
    
    # --- Deduplicate by (timestamp, operation, process_name, path) ---
    seen = set()
    unique_threats = []
    for t in threats:
        key = (t["timestamp"], t["operation"], t["process_name"], t["path"])
        if key not in seen:
            seen.add(key)
            unique_threats.append(t)
    threats = unique_threats
    
    # --- Find related events for each threat (±2 seconds window) ---
    for threat in threats:
        threat["related_events"] = _find_related_events(
            threat, entries, window_rows=20
        )
    
    # --- Sort threats by severity then timestamp ---
    threats.sort(key=lambda t: (SEVERITY_ORDER.get(t["severity"], 9), t["timestamp"]))
    
    # --- Build timeline (threats sorted by timestamp only) ---
    timeline = sorted(threats, key=lambda t: t["timestamp"])
    
    # --- Build summary ---
    severity_counts = Counter(t["severity"] for t in threats)
    process_counts = Counter(t["process_name"] for t in threats)
    type_counts = Counter(t["threat_type"] for t in threats)
    
    scan_duration = (datetime.now() - scan_start).total_seconds()
    
    result = {
        "total_entries": len(entries),
        "scan_time": f"{scan_duration:.2f}s",
        "threats": threats,
        "summary": {
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "total_threats": len(threats),
            "top_processes": process_counts.most_common(5),
            "top_threat_types": type_counts.most_common(5),
        },
        "timeline": timeline,
    }
    
    return result


def _find_related_events(threat: dict, all_entries: list[dict], window_rows: int = 20) -> list[dict]:
    """Find log entries near a threat event (by row proximity) from the same process or PID."""
    row = threat["row_num"]
    related = []
    
    for entry in all_entries:
        if abs(entry["row_num"] - row) <= window_rows and entry["row_num"] != row:
            # Same process or same target PID
            if (entry["process_name"] == threat["process_name"] or 
                entry["pid"] == threat["pid"]):
                related.append({
                    "timestamp": entry["timestamp"],
                    "operation": entry["operation"],
                    "path": entry["path"][:80] if entry["path"] else "",
                    "result": entry["result"],
                })
    
    return related[:10]  # Cap at 10 related events


def get_entries_for_ai(entries: list[dict], threats: list[dict], max_rows: int = 50) -> str:
    """
    Prepare a text summary of suspicious entries for the Gemini AI engine.
    Sends the threat entries + surrounding context for deeper analysis.
    """
    # Collect row numbers of threats and their neighbors
    threat_rows = set()
    for t in threats[:30]:  # Cap threats sent to AI
        row = t["row_num"]
        for r in range(max(0, row - 3), row + 4):
            threat_rows.add(r)
    
    lines = []
    for entry in entries:
        if entry["row_num"] in threat_rows:
            lines.append(
                f'{entry["timestamp"]} | {entry["process_name"]} (PID:{entry["pid"]}) | '
                f'{entry["operation"]} | {entry["path"][:100]} | {entry["result"]} | '
                f'{entry["detail"][:100]}'
            )
    
    return "\n".join(lines[:max_rows])
