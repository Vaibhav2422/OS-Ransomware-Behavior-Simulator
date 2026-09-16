"""
ml/export_features.py — Export labeled feature vectors from monitor logs.

Reads:
  logs/metrics_history.jsonl  — one WindowStats JSON object per line
  logs/alerts.csv             — alert events with timestamps

Joins them by nearest timestamp to assign labels:
  1 = alert window (within 2 s of an alert event)
  0 = normal

Writes:
  ml/features.csv — columns: file_events_per_sec, spawns_per_sec,
                              mem_delta_mb_per_sec, io_bytes_per_sec, label
"""

import csv
import json
import os
from datetime import datetime, timezone

METRICS_JSONL = os.path.join(os.path.dirname(__file__), "..", "logs", "metrics_history.jsonl")
ALERTS_CSV    = os.path.join(os.path.dirname(__file__), "..", "logs", "alerts.csv")
FEATURES_CSV  = os.path.join(os.path.dirname(__file__), "features.csv")

ALERT_WINDOW_SECONDS = 2


def parse_iso(ts: str) -> float:
    """Parse ISO-8601 UTC string to POSIX timestamp."""
    try:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return 0.0


def load_alert_timestamps() -> list:
    times = []
    try:
        with open(ALERTS_CSV, "r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                t = parse_iso(row.get("timestamp", ""))
                if t > 0:
                    times.append(t)
    except FileNotFoundError:
        pass
    return times


def is_alert_window(ts: float, alert_times: list) -> int:
    for at in alert_times:
        if abs(ts - at) <= ALERT_WINDOW_SECONDS:
            return 1
    return 0


def main():
    alert_times = load_alert_timestamps()
    print(f"[export] Loaded {len(alert_times)} alert timestamps")

    rows_written = 0
    with open(FEATURES_CSV, "w", encoding="utf-8", newline="") as out_fh:
        writer = csv.writer(out_fh)
        writer.writerow([
            "file_events_per_sec", "spawns_per_sec",
            "mem_delta_mb_per_sec", "io_bytes_per_sec", "label"
        ])

        try:
            with open(METRICS_JSONL, "r", encoding="utf-8") as jl:
                for line in jl:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    ts    = parse_iso(obj.get("timestamp", ""))
                    label = is_alert_window(ts, alert_times)
                    writer.writerow([
                        obj.get("file_events_per_sec",   0.0),
                        obj.get("spawns_per_sec",         0.0),
                        obj.get("mem_delta_mb_per_sec",   0.0),
                        obj.get("io_bytes_per_sec",       0.0),
                        label,
                    ])
                    rows_written += 1
        except FileNotFoundError:
            print("[export] logs/metrics_history.jsonl not found — run the monitor first")
            return

    print(f"[export] Wrote {rows_written} rows to {FEATURES_CSV}")
    alert_count = sum(1 for _ in open(FEATURES_CSV) if _[-2] == "1")
    print(f"[export] Label distribution — normal: {rows_written - alert_count}  alert: {alert_count}")


if __name__ == "__main__":
    main()
