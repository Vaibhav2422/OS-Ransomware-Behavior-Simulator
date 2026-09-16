"""
ml/score.py — Score a single feature window with the trained Isolation Forest.

Usage:
  python ml/score.py --file-events=45.2 --spawns=7 --mem-delta=120 --io-bytes=15000000

Reads:  ml/model.pkl
Prints: anomaly score and classification (NORMAL / ANOMALY)
"""

import argparse
import os
import sys

try:
    import joblib
    import numpy as np
except ImportError as e:
    sys.exit(f"[score] Missing dependency: {e}\nInstall with: pip install scikit-learn joblib numpy")

MODEL_PKL = os.path.join(os.path.dirname(__file__), "model.pkl")


def main():
    parser = argparse.ArgumentParser(description="Score a feature window for anomaly detection")
    parser.add_argument("--file-events", type=float, default=0.0,
                        help="file_events_per_sec")
    parser.add_argument("--spawns",      type=float, default=0.0,
                        help="spawns_per_sec")
    parser.add_argument("--mem-delta",   type=float, default=0.0,
                        help="mem_delta_mb_per_sec")
    parser.add_argument("--io-bytes",    type=float, default=0.0,
                        help="io_bytes_per_sec")
    args = parser.parse_args()

    if not os.path.exists(MODEL_PKL):
        sys.exit("[score] model.pkl not found — run ml/train_model.py first")

    model = joblib.load(MODEL_PKL)
    features = np.array([[
        args.file_events,
        args.spawns,
        args.mem_delta,
        args.io_bytes,
    ]])

    prediction  = model.predict(features)[0]   # -1 = anomaly, 1 = normal
    score       = model.score_samples(features)[0]  # lower = more anomalous
    label       = "ANOMALY" if prediction == -1 else "NORMAL"

    print(f"Classification : {label}")
    print(f"Anomaly score  : {score:.6f}  (lower = more anomalous)")
    print(f"Input features :")
    print(f"  file_events_per_sec   = {args.file_events}")
    print(f"  spawns_per_sec        = {args.spawns}")
    print(f"  mem_delta_mb_per_sec  = {args.mem_delta}")
    print(f"  io_bytes_per_sec      = {args.io_bytes}")


if __name__ == "__main__":
    main()
