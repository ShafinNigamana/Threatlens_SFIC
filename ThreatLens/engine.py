"""ProcMon CSV parser, offline rule-based detection engine, severity scorer, and timeline builder."""

import csv
import io
from datetime import datetime
from threat_db import THREAT_RULES

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _parse_timestamp_seconds(ts_str: str) -> float | None:
    """Convert ProcMon 'Time of Day' (e.g. 10:23:01.4450322) to seconds since midnight."""
    if not ts_str:
        return None
    clean = ts_str.strip().split()[0]
    # Trim fractional seconds to 6 digits for strptime
    if "." in clean:
        base, frac = clean.split(".", 1)
        clean = f"{base}.{frac[:6]}"
        fmt = "%H:%M:%S.%f"
    else:
        fmt = "%H:%M:%S"
    try:
        dt = datetime.strptime(clean, fmt)
        return dt.hour * 3600 + dt.minute * 60 + dt.second + dt.microsecond / 1_000_000
    except ValueError:
        return None


def _matches_rule(row: dict, rule: dict) -> bool:
    proc = row.get("process", "").lower()
    op = row.get("operation", "")
    op_lower = op.lower()
    path = row.get("path", "").lower()
    detail = row.get("detail", "").lower()

    if "process_in" in rule and proc not in rule["process_in"]:
        return False

    if "op_equals" in rule and op not in rule["op_equals"]:
        return False

    if "op_contains" in rule:
        if not any(tok.lower() in op_lower for tok in rule["op_contains"]):
            return False

    if "path_contains" in rule:
        tokens = [t.lower() for t in rule["path_contains"]]
        if rule.get("path_match_all"):
            if not all(t in path for t in tokens):
                return False
        else:
            if not any(t in path for t in tokens):
                return False

    if "detail_contains" in rule:
        if not any(tok.lower() in detail for tok in rule["detail_contains"]):
            return False

    return True


def parse_procmon_csv(file_bytes: bytes) -> list[dict]:
    """Parse ProcMon CSV bytes into normalized event dicts."""
    text = file_bytes.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    events = []
    for idx, raw in enumerate(reader):
        # Support standard ProcMon headers and common variations
        ts = (raw.get("Time of Day") or raw.get("Timestamp") or "").strip()
        proc = (raw.get("Process Name") or raw.get("Process") or "").strip()
        pid = (raw.get("PID") or "").strip()
        op = (raw.get("Operation") or "").strip()
        path = (raw.get("Path") or "").strip()
        result = (raw.get("Result") or "").strip()
        detail = (raw.get("Detail") or "").strip()

        if not op and not proc:
            continue

        events.append(
            {
                "row_index": idx + 1,
                "timestamp": ts,
                "ts_seconds": _parse_timestamp_seconds(ts),
                "process": proc,
                "pid": pid,
                "operation": op,
                "path": path,
                "result": result,
                "detail": detail,
            }
        )
    return events


def analyze_events(events: list[dict], max_threats: int = 250) -> dict:
    """Run offline rule engine across parsed events and build timeline + summary."""
    findings = []
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    seen_dedup = set()

    for i, ev in enumerate(events):
        for rule in THREAT_RULES:
            if not _matches_rule(ev, rule):
                continue

            # Deduplicate identical bursts (same rule + process + operation + path within same second)
            sec_bucket = int(ev["ts_seconds"]) if ev["ts_seconds"] is not None else ev["row_index"]
            dedup_key = (rule["id"], ev["process"].lower(), ev["operation"], ev["path"][:80], sec_bucket)
            if dedup_key in seen_dedup:
                continue
            seen_dedup.add(dedup_key)

            sev = rule["severity"]
            counts[sev] += 1

            # Collect +/- 2 seconds related events for context
            related = []
            ev_t = ev["ts_seconds"]
            if ev_t is not None:
                for j in range(max(0, i - 15), min(len(events), i + 16)):
                    cand = events[j]
                    if cand["ts_seconds"] is not None and abs(cand["ts_seconds"] - ev_t) <= 2.0:
                        related.append(
                            {
                                "timestamp": cand["timestamp"],
                                "process": cand["process"],
                                "operation": cand["operation"],
                                "path": cand["path"],
                                "result": cand["result"],
                                "is_current": j == i,
                            }
                        )
                        if len(related) >= 6:
                            break

            findings.append(
                {
                    "id": f"TH-{len(findings) + 1:03d}",
                    "rule_id": rule["id"],
                    "timestamp": ev["timestamp"] or f"Row {ev['row_index']}",
                    "ts_seconds": ev["ts_seconds"] or 0.0,
                    "process": ev["process"],
                    "pid": ev["pid"],
                    "operation": ev["operation"],
                    "path": ev["path"] or "(none)",
                    "result": ev["result"] or "N/A",
                    "detail": ev["detail"],
                    "severity": sev,
                    "ring": rule["ring"],
                    "threat_type": rule["threat_type"],
                    "title": rule["title"],
                    "why": rule["why"],
                    "action": rule["action"],
                    "related_events": related,
                }
            )
            break  # First matching rule wins per event

    # Sort chronologically by timestamp
    findings.sort(key=lambda x: (x["ts_seconds"], SEVERITY_ORDER.get(x["severity"], 9)))
    capped = findings[:max_threats]

    unique_procs = sorted({ev["process"] for ev in events if ev["process"]})
    return {
        "total_events": len(events),
        "total_threats": len(findings),
        "displayed_threats": len(capped),
        "processes": unique_procs,
        "summary": counts,
        "threats": capped,
    }
