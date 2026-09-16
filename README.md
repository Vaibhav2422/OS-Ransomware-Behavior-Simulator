# OS Ransomware Behavior Simulator

> **AI 3002 — Operating Systems Lab | Academic Project**
>
> A defensive, educational two-binary C++17 system that simulates ransomware behavioral signatures inside an isolated sandbox, then detects and responds to them using real-time OS-level signals.

---

## Table of Contents

- [Overview](#overview)
- [Safety](#safety)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Build Instructions](#build-instructions)
- [Run Instructions](#run-instructions)
- [Web Dashboard](#web-dashboard)
- [ML Layer (Optional)](#ml-layer-optional)
- [Testing](#testing)
- [Stage-wise Implementation](#stage-wise-implementation)

---

## Overview

This project consists of two binaries:

| Binary | Role |
|--------|------|
| `bin/simulator` | Mimics ransomware behavioral signatures (mass file renaming, memory bursts, rapid child spawning) inside `./test_env/` using **reversible, non-destructive operations only** |
| `bin/monitor` | Watches live OS signals via `/proc` and `inotify`, applies configurable threshold-based detection, responds with `SIGSTOP`/`SIGKILL`, and surfaces metrics on a CLI and web dashboard |

**Core language:** C++17 with POSIX APIs (`fork()`, `exec()`, `/proc` filesystem, `inotify`). No external C++ libraries required.  
**Platform:** Ubuntu Linux (tested on 22.04 LTS).  
**Optional components:** Python (Flask web dashboard, scikit-learn ML anomaly scoring).

---

## Safety

> **This is not functional malware.** All operations are strictly sandboxed, reversible, and audited. Six runtime safety constraints are enforced:

1. **Sandbox confinement** — The simulator resolves `./test_env/` to its absolute path at startup. Every file operation calls `validate_sandbox_path()` which uses `realpath()` to confirm the target path shares the sandbox prefix. Any path that escapes the sandbox causes an immediate `exit(1)`.

2. **No files written outside sandbox** — The simulator never reads or writes any path outside `./test_env/`. This is enforced at the code level (every `fopen`/`rename`/`ofstream` call is gated behind `validate_sandbox_path()`), not just by convention.

3. **Reversible-only file operations** — The file-lock phase renames files to `<filename>.simlocked`. This is a plain `rename()` — no bytes are modified or destroyed. The original content is fully recoverable by renaming back.

4. **VM/sandbox detection** — On startup, the simulator checks `/sys/class/dmi/id/product_name` and runs `systemd-detect-virt`. If neither confirms a VM environment, it prints a prominent warning and exits unless `--i-am-in-a-vm` is explicitly provided.

5. **Full audit log** — Every action (file create, file rename, fork, memory alloc/free) is written to `logs/simulator_actions.log` with an ISO-8601 timestamp. All actions are fully auditable after the run.

6. **Clean-slate reset** — `make clean-sandbox` deletes all files in `test_env/` and `logs/` and recreates the `.gitkeep` placeholders, restoring a known clean state.

---

## Architecture

```
bin/simulator                         bin/monitor
─────────────────────────────         ───────────────────────────────────────────
 Sandbox Validator                     ProcPoller thread  (every 500ms)
 VM Detection                          InotifyReader thread (blocking + poll)
 File Phase      ──file events──►      Aggregator/Detector thread (every 1s)
 Process-Spawn   ──child PIDs──►       Response Engine (SIGSTOP / SIGKILL)
 Memory Phase    ──VmSize spike──►     CLI Dashboard (ANSI in-place)
 Audit Logger                          logs/metrics.json + logs/alerts.csv
                                       │
                                       ▼ (optional Python)
                                   dashboard/app.py (Flask)
                                   ml/ (Isolation Forest)
```

---

## Project Structure

```
OS-Ransomware-Behavior-Simulator/
├── include/
│   ├── metrics.h          # Shared structs: ProcMetrics, FileEvent, WindowStats, Alert, DetectionConfig
│   ├── proc_reader.h      # /proc reader interface declarations
│   └── simulator.h        # Simulator function declarations
├── src/
│   ├── simulator.cpp      # Simulator: sandbox validator, VM detection, file/spawn/memory phases
│   ├── proc_reader.cpp    # /proc filesystem parser (Stage II)
│   └── monitor.cpp        # Monitor: ProcPoller, InotifyWatcher, Aggregator, CLI dashboard (Stage II/III)
├── tests/
│   ├── sandbox_path_test.cpp   # Property 1: sandbox confinement (100+ cases)
│   ├── file_lock_test.cpp      # Property 2: file lock reversibility (100+ cases)
│   └── integration_test.sh     # End-to-end integration test (Stage III)
├── dashboard/
│   ├── app.py             # Flask backend (Stage III)
│   └── templates/
│       └── index.html     # Web UI with Chart.js (Stage III)
├── ml/
│   ├── export_features.py # logs/ → features.csv (optional)
│   ├── train_model.py     # Isolation Forest trainer (optional)
│   ├── score.py           # Anomaly scorer (optional)
│   └── README.md          # ML precision/recall docs (optional)
├── docs/
│   └── stage-mapping.md   # Source file → Stage mapping
├── logs/
│   └── .gitkeep           # Directory tracked; contents ignored
├── test_env/
│   └── .gitkeep           # Sandbox directory; contents ignored
├── Makefile
└── README.md
```

---

## Build Instructions

### Prerequisites

- GCC ≥ 9 or Clang ≥ 10 with C++17 support
- `make`
- POSIX-compatible OS (Ubuntu 20.04+ recommended)
- For tests: `libgtest-dev` (`sudo apt install libgtest-dev`)
- For web dashboard: `pip install flask`
- For ML layer: `pip install scikit-learn joblib pandas hypothesis pytest`

### Build

```bash
# Build the simulator only (Stage I)
make

# Build both simulator and monitor (Stage II+)
make all

# Build and run tests
make bin/tests
./bin/tests

# Clean build artifacts
make clean

# Reset sandbox and logs to clean state
make clean-sandbox
```

---

## Run Instructions

### Simulator

```bash
# Run with default intensity inside a VM (required)
./bin/simulator --i-am-in-a-vm

# Custom intensity
./bin/simulator --files=200 --children=8 --mem-mb=200 --i-am-in-a-vm

# Options
#   --files=N        Number of dummy files to create and rename (default: 100)
#   --children=N     Number of child processes to spawn (default: 8)
#   --mem-mb=N       Memory to allocate and touch in MB (default: 128)
#   --i-am-in-a-vm   Bypass VM detection check (required on non-VM hosts)
```

After a run, check the audit log:

```bash
cat logs/simulator_actions.log
```

### Monitor

```bash
# Start the monitor (Stage II+)
./bin/monitor

# Monitor detects the simulator automatically once it starts.
# Alerts appear in logs/alerts.csv and on the CLI dashboard.
```

### Full Demo (both running)

```bash
# Terminal 1 — start monitor
./bin/monitor

# Terminal 2 — run simulator
./bin/simulator --files=200 --children=8 --mem-mb=200 --i-am-in-a-vm

# Monitor should detect and alert within ~5 seconds.
```

---

## Web Dashboard

```bash
# Start Flask backend (Stage III)
python dashboard/app.py

# Open http://localhost:5000 in a browser
```

Features:
- Full-width hero banner: pulsing green `● SYSTEM NORMAL` or flashing red `⚠ ALERT DETECTED`
- Four real-time Chart.js line charts (file-events/sec, spawns/sec, memory delta, I/O bytes/sec)
- Live process table with color-coded threat levels
- Auto-updating alert log with timestamp, PID, trigger reason, and metric values
- Updates every 1 second without page reload

---

## ML Layer (Optional)

The ML layer is an **optional enhancement** — the core C++ rule-based detection works without it.

```bash
# 1. Export feature vectors from logs
python ml/export_features.py

# 2. Train Isolation Forest on collected data
python ml/train_model.py

# 3. Score a new feature window
python ml/score.py --file-events=45 --spawns=6 --mem-delta=120 --io-bytes=15000000
```

See `ml/README.md` for precision/recall documentation on the held-out test split.

---

## Testing

### C++ Unit & Property Tests

```bash
make bin/tests
./bin/tests
```

Property tests use Google Test `INSTANTIATE_TEST_SUITE_P` with ≥100 cases each:

| Property | File | What it tests |
|----------|------|---------------|
| Property 1 | `tests/sandbox_path_test.cpp` | Sandbox path confinement — paths outside `test_env/` are always rejected |
| Property 2 | `tests/file_lock_test.cpp` | File lock reversibility — rename-to-`.simlocked` and back preserves all bytes |

### Integration Test

```bash
bash tests/integration_test.sh
```

Verifies:
1. Monitor produces zero alerts on idle (no false positives for 5 seconds)
2. Simulator run triggers ≥1 alert within 10 seconds
3. No simulator file exists outside `./test_env/`

### Python Property Tests

```bash
pytest tests/
```

Covers alert CSV round-trip (Property 7), metrics JSON round-trip (Property 8), and audit log completeness (Property 3) using the Hypothesis library.

---

## Stage-wise Implementation

| Stage | Components | Status |
|-------|-----------|--------|
| **I — Simulator Core** | `include/metrics.h`, `include/proc_reader.h`, `include/simulator.h`, `src/simulator.cpp`, `Makefile`, test scaffolding | ✅ Complete |
| **II — Monitor Core** | `src/proc_reader.cpp`, `src/monitor.cpp` (threads, aggregation, JSON/CSV writers) | 🔧 In Progress |
| **III — Detection & Dashboards** | Threshold engine, CLI dashboard, `dashboard/`, `ml/`, integration test | 🔧 In Progress |

See `docs/stage-mapping.md` for the full component-to-stage mapping table.

---

## License

Academic project — AI 3002 Operating Systems, Semester V.
