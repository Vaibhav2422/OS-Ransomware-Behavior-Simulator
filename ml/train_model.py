"""
ml/train_model.py — Train an Isolation Forest anomaly detector on feature data.

Usage:
  python ml/train_model.py

Reads:  ml/features.csv
Writes: ml/model.pkl  (joblib-serialized IsolationForest)

The model is trained on the full dataset (both normal and alert windows).
Isolation Forest is unsupervised — labels are only used for evaluation.
"""

import os
import sys

try:
    import joblib
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    from sklearn.metrics import classification_report, precision_score, recall_score
    from sklearn.model_selection import train_test_split
except ImportError as e:
    sys.exit(f"[train] Missing dependency: {e}\n"
             "Install with: pip install scikit-learn joblib pandas")

FEATURES_CSV = os.path.join(os.path.dirname(__file__), "features.csv")
MODEL_PKL    = os.path.join(os.path.dirname(__file__), "model.pkl")

FEATURE_COLS = [
    "file_events_per_sec",
    "spawns_per_sec",
    "mem_delta_mb_per_sec",
    "io_bytes_per_sec",
]


def main():
    if not os.path.exists(FEATURES_CSV):
        sys.exit("[train] features.csv not found — run ml/export_features.py first")

    df = pd.read_csv(FEATURES_CSV)
    if df.empty:
        sys.exit("[train] features.csv is empty")

    X = df[FEATURE_COLS].values
    y = df["label"].values  # 0 = normal, 1 = alert (for evaluation only)

    print(f"[train] Dataset: {len(df)} rows  "
          f"normal={int((y==0).sum())}  alert={int((y==1).sum())}")

    # Train / test split (80/20, stratified if possible)
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y)
    except ValueError:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42)

    # Isolation Forest — contamination = fraction of alert rows
    contamination = max(0.01, min(0.5, float((y_train == 1).mean())))
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train)
    print("[train] Model trained")

    # Evaluate: IF returns -1 for anomaly, 1 for normal
    # Map to 1 = alert, 0 = normal for comparison with our labels
    raw_pred  = model.predict(X_test)
    y_pred = (raw_pred == -1).astype(int)

    precision = precision_score(y_test, y_pred, zero_division=0)
    recall    = recall_score(y_test, y_pred, zero_division=0)
    print(f"[train] Test set — Precision: {precision:.3f}  Recall: {recall:.3f}")
    print(classification_report(y_test, y_pred,
                                 target_names=["normal", "alert"],
                                 zero_division=0))

    joblib.dump(model, MODEL_PKL)
    print(f"[train] Model saved to {MODEL_PKL}")


if __name__ == "__main__":
    main()
