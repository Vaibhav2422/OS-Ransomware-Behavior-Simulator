"""
dashboard/app.py — Flask web dashboard for the Ransomware Defense Monitor.

Routes:
  GET /              → renders index.html
  GET /api/metrics   → returns latest logs/metrics.json snapshot
  GET /api/alerts    → returns last 100 rows of logs/alerts.csv as JSON array

Run with:
  python dashboard/app.py
Then open http://localhost:5000 in a browser.
"""

import csv
import json
import os

from flask import Flask, jsonify, render_template

app = Flask(__name__)

METRICS_JSON  = os.path.join(os.path.dirname(__file__), "..", "logs", "metrics.json")
ALERTS_CSV    = os.path.join(os.path.dirname(__file__), "..", "logs", "alerts.csv")


def _read_metrics() -> dict:
    """Read logs/metrics.json; return empty defaults on any error."""
    try:
        with open(METRICS_JSON, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {
            "timestamp": "",
            "status": "normal",
            "alert_pid": None,
            "alert_reason": None,
            "metrics": {
                "file_events_per_sec": 0.0,
                "spawns_per_sec": 0.0,
                "mem_delta_mb_per_sec": 0.0,
                "io_bytes_per_sec": 0.0,
            },
            "processes": [],
        }


def _read_alerts(limit: int = 100) -> list:
    """Read last `limit` rows from logs/alerts.csv; return [] on any error."""
    rows = []
    try:
        with open(ALERTS_CSV, "r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                rows.append(row)
        return rows[-limit:]
    except (FileNotFoundError, csv.Error):
        return []


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/metrics")
def api_metrics():
    return jsonify(_read_metrics())


@app.route("/api/alerts")
def api_alerts():
    return jsonify(_read_alerts())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
