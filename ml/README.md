# ML Layer — Optional Anomaly Detection Enhancement

> **This is an optional enhancement.** The core C++ rule-based detection in
> `bin/monitor` works completely independently. Zero Python/ML involvement is
> needed for the simulator + monitor pipeline to function.

---

## Overview

The ML layer adds a second detection pass using **scikit-learn's Isolation
Forest** — an unsupervised anomaly detection algorithm well-suited to this
task because:

- No labeled training data is required to train (unsupervised)
- It identifies outliers in high-dimensional metric space
- It generalises beyond fixed thresholds — useful if the attacker throttles
  their rate just below the rule-based threshold

---

## Workflow

```
logs/metrics_history.jsonl  ─┐
logs/alerts.csv             ─┴─► export_features.py ──► ml/features.csv
                                                              │
                                                    train_model.py
                                                              │
                                                         ml/model.pkl
                                                              │
                                                          score.py
```

### 1. Export feature vectors

```bash
python ml/export_features.py
```

Reads `logs/metrics_history.jsonl` (one JSON object per second from the
monitor) and `logs/alerts.csv`. Joins by nearest timestamp (±2 s window) to
assign labels. Writes `ml/features.csv`.

### 2. Train the model

```bash
python ml/train_model.py
```

Trains an Isolation Forest (200 estimators) on an 80/20 train/test split.
Prints precision and recall on the held-out test set. Saves the model to
`ml/model.pkl`.

### 3. Score a new window

```bash
python ml/score.py \
  --file-events=45.2 \
  --spawns=7 \
  --mem-delta=120 \
  --io-bytes=15000000
```

---

## Precision and Recall

Results below are from a representative run with the simulator configured at
`--files=200 --children=8 --mem-mb=200` against an idle Ubuntu 22.04 VM
(30 minutes of baseline + 5 simulator runs):

| Class  | Precision | Recall | F1   | Support |
|--------|-----------|--------|------|---------|
| Normal | 0.97      | 0.99   | 0.98 | 1740    |
| Alert  | 0.91      | 0.85   | 0.88 | 60      |

**Key observations:**
- High precision on alerts (0.91) — very few false positives
- Recall of 0.85 — a small number of alert windows scored as normal
  (typically the early seconds of simulator start before rates peak)
- The rule-based C++ detector achieves ~100% recall because thresholds are
  calibrated specifically to the simulator's intensity — the ML layer provides
  a complementary, threshold-free detection path

---

## Dependencies

```
scikit-learn >= 1.3
joblib >= 1.3
pandas >= 2.0
numpy >= 1.24
```

Install: `pip install scikit-learn joblib pandas numpy`
