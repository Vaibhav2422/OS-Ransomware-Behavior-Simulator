# Stage-to-Source Mapping

This table maps every source file and component to its implementation stage.
Use it as a reference during code review and the viva demo.

| File / Component | Stage | Description |
|---|---|---|
| `include/metrics.h` | I | Shared structs: `ProcMetrics`, `FileEvent`, `WindowStats`, `Alert`, `DetectionConfig` |
| `include/proc_reader.h` | I | `/proc` reader interface declarations |
| `include/simulator.h` | I | Simulator public API declarations |
| `src/simulator.cpp` | I | Sandbox validator, VM detection, file/spawn/memory phases, audit logger |
| `Makefile` | I | Build system: `all`, `bin/simulator`, `bin/monitor`, `bin/tests`, `clean`, `clean-sandbox` |
| `logs/.gitkeep` | I | Tracks `logs/` directory in git; contents are gitignored |
| `test_env/.gitkeep` | I | Tracks `test_env/` sandbox directory; contents are gitignored |
| `tests/sandbox_path_test.cpp` | I | Property 1: sandbox confinement (120 parameterized cases) |
| `tests/file_lock_test.cpp` | I | Property 2: file lock reversibility (100 parameterized cases) |
| `src/proc_reader.cpp` | II | `/proc/[pid]/stat`, `/proc/[pid]/io`, `get_children()`, `list_all_pids()` |
| `src/monitor.cpp` | II–III | ProcPoller thread, InotifyWatcher, Aggregator/Detector thread, CLI dashboard, `metrics.json` writer |
| `dashboard/app.py` | III | Flask backend: `/`, `/api/metrics`, `/api/alerts` |
| `dashboard/templates/index.html` | III | Web UI: hero banner, Chart.js charts, process table, alert log |
| `tests/integration_test.sh` | III | End-to-end: idle baseline + simulator detection + sandbox confinement check |
| `ml/export_features.py` | III (opt) | Joins `metrics_history.jsonl` + `alerts.csv` → labeled `features.csv` |
| `ml/train_model.py` | III (opt) | Trains Isolation Forest, evaluates precision/recall, saves `model.pkl` |
| `ml/score.py` | III (opt) | Loads `model.pkl`, scores a CLI-provided feature vector |
| `ml/README.md` | III (opt) | ML layer docs: workflow, precision/recall table, dependencies |
| `docs/stage-mapping.md` | III | This file |
| `README.md` | I | Project overview, Safety section, build/run instructions |
| `.gitignore` | I | Ignores `bin/`, `test_env/*`, `logs/*`, `ml/model.pkl`, `ml/features.csv` |
| `.kiro/specs/*/requirements.md` | — | Formal requirements (11 groups, 40+ acceptance criteria) |
| `.kiro/specs/*/design.md` | — | Architecture, component interfaces, data models, testing strategy |
| `.kiro/specs/*/tasks.md` | — | 18 implementation tasks with requirement traceability |

## Stage Summary

| Stage | Goal | Key Verification |
|---|---|---|
| **I — Simulator Core** | Working, safe simulator with all six safety constraints | `make` → zero warnings; simulator exits cleanly with `--i-am-in-a-vm`; audit log contains ≥N rename + ≥M fork entries |
| **II — Monitor Core** | Live `/proc` + `inotify` reading, zero false positives on idle | `./bin/monitor` runs 60 s idle → `alerts.csv` empty; `metrics.json` written every second |
| **III — Full Pipeline** | End-to-end detection: simulator triggers alert within 5 s | CLI goes green→red; web dashboard hero switches; `integration_test.sh` passes |
