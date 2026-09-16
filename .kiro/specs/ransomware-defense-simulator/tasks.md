# Implementation Plan: Ransomware Defense Simulator

## Overview

Tasks follow the Stage I → II → III build order from the design. Each stage must pass its verification criteria before the next begins. Property-based and unit test sub-tasks are marked optional (`*`) so the core implementation can be verified first.

---

## Tasks

### Stage I — Simulator Core

- [x] 1. Create project scaffold and shared headers
  - Create `include/metrics.h` with `ProcMetrics`, `FileEvent`, `WindowStats`, `Alert`, `DetectionConfig` structs exactly as specified in the design Data Models section
  - Create `include/proc_reader.h` with function declarations: `read_proc_metrics`, `read_proc_io`, `get_children`, `list_all_pids`
  - Create `logs/.gitkeep` and `test_env/.gitkeep` so directories are tracked by git but contents are ignored
  - Create `.gitignore` entries for `logs/*`, `test_env/*`, `bin/*`, keeping `.gitkeep` files
  - _Requirements: 7.1, 7.2, 7.3, 7.4_

- [ ] 2. Implement build system
  - Create `Makefile` with targets: `all` (builds `bin/simulator` and `bin/monitor`), `bin/simulator`, `bin/monitor`, `bin/tests`, `clean`, `clean-sandbox`
  - `clean-sandbox` target must delete all files in `test_env/` and `logs/` and recreate `.gitkeep` files
  - Compile flags: `-std=c++17 -Wall -Wextra -Wpedantic -pthread`
  - _Requirements: 8.1, 8.2, 8.3, 1.6_

- [ ] 3. Implement simulator safety layer
  - In `src/simulator.cpp`, implement `validate_sandbox_path()`: use `realpath()` to resolve `./test_env/` and the target path; abort with error if they don't share the resolved prefix
  - Implement `detect_vm()`: read `/sys/class/dmi/id/product_name`, run `popen("systemd-detect-virt")`, return true if either confirms VM
  - Parse CLI flags: `--files=N`, `--children=N`, `--mem-mb=N`, `--i-am-in-a-vm`
  - On startup: call `validate_sandbox_path()` then `detect_vm()`; if VM not confirmed and `--i-am-in-a-vm` absent, print warning and `exit(1)`
  - _Requirements: 1.1, 1.2, 1.4, 2.5_

- [ ] 3.1 Write property test for sandbox path confinement
  - Use Google Test `INSTANTIATE_TEST_SUITE_P` with ≥100 path strings (relative, absolute, traversal attempts)
  - Verify `validate_sandbox_path()` returns true only for paths under resolved `./test_env/`
  - **Property 1: Sandbox path confinement**
  - **Validates: Requirements 1.2**

- [ ] 4. Implement simulator audit logger
  - Implement `AuditLogger` class in `src/simulator.cpp` (or a small helper): opens `logs/simulator_actions.log` on construction, writes ISO-8601 timestamp + message on each call, flushes after each write
  - _Requirements: 1.5, 2.6_

- [ ] 5. Implement simulator file phase
  - `populate_files(N)`: create `test_env/dummy_000.dat` … `test_env/dummy_NNN.dat`, each 4096 bytes of `0xAB` pattern; log each creation
  - `rename_files_locked()`: rename each `dummy_NNN.dat` → `dummy_NNN.dat.simlocked`; log each rename with source and destination paths
  - Every file operation must call `validate_sandbox_path()` on the target path before executing
  - _Requirements: 2.1, 2.2, 1.2, 1.3_

- [ ] 5.1 Write property test for file lock reversibility
  - Table of ≥100 random byte sequences (varying lengths 0–8192); write each as a temp file in `test_env/`; rename to `.simlocked` and back; verify file content is byte-for-byte identical
  - **Property 2: File lock reversibility**
  - **Validates: Requirements 1.3**

- [ ] 6. Implement simulator spawn and memory phases
  - `spawn_children(N)`: loop N times calling `fork()`; child calls `execl("/bin/sleep", "sleep", "1", nullptr)`; parent logs each fork with child PID; after loop, call `waitpid()` for all children
  - `allocate_and_touch(mb)`: `malloc(mb * 1024 * 1024)`; touch every 4096th byte to commit pages; `sleep(2)`; `free()`; log alloc start, alloc complete, and free events
  - _Requirements: 2.3, 2.4, 2.6_

- [ ] 7. Checkpoint — Stage I verification
  - Ensure `make` builds `bin/simulator` with zero warnings
  - Run `./bin/simulator --files=50 --children=4 --mem-mb=64 --i-am-in-a-vm` and verify clean exit
  - Check `logs/simulator_actions.log` contains ≥50 rename entries and ≥4 fork entries
  - Check all modified paths are under `./test_env/`
  - Run `make clean-sandbox` and verify `test_env/` and `logs/` are empty
  - Ensure all tests pass, ask the user if questions arise.

---

### Stage II — Monitor Core

- [ ] 8. Implement `proc_reader`
  - In `src/proc_reader.cpp`, implement `read_proc_metrics(pid)`: open and parse `/proc/[pid]/stat` (field 3=state, field 23=vsize); open and parse `/proc/[pid]/status` for `PPid:`; return populated `ProcMetrics`
  - Implement `read_proc_io(pid, m)`: open `/proc/[pid]/io`, parse `read_bytes:` and `write_bytes:` lines, store in `m`
  - Implement `get_children(parent_pid)`: scan all `/proc/[pid]/status` files for `PPid:` matching parent; return matching PIDs
  - Implement `list_all_pids()`: scan `/proc` for numeric directory entries; return as vector
  - All functions must handle missing/unreadable files gracefully (process may exit mid-read) — return empty/zero values, do not throw
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 5.1, 7.4_

- [ ] 8.1 Write unit tests for `proc_reader`
  - Parse a hard-coded valid `/proc/stat` fixture string; verify state, vsize fields
  - Parse a hard-coded `/proc/io` fixture; verify read_bytes, write_bytes
  - Test graceful handling of empty/malformed strings (no crash, returns zero-initialized struct)
  - _Requirements: 3.1, 5.1_

- [ ] 8.2 Write property test for ProcMetrics parse consistency
  - Google Test parameterized test with ≥100 synthetically-generated valid `/proc/[pid]/stat`-format strings
  - Verify: `state` is in `{R, S, D, Z, T, I}`, `vsize_bytes > 0` for all valid inputs
  - **Property 4: ProcMetrics parse consistency**
  - **Validates: Requirements 3.1**

- [ ] 9. Implement InotifyWatcher
  - In `src/monitor.cpp` (or a separate `src/inotify_watcher.cpp`), implement `InotifyWatcher` class as designed
  - Constructor: `inotify_init1(0)` (blocking fd — no `IN_NONBLOCK`), `inotify_add_watch()` on `./test_env/` with `IN_CREATE|IN_MODIFY|IN_MOVED_FROM|IN_MOVED_TO|IN_DELETE`; abort if either call fails
  - `poll_events(timeout_ms)`: call `poll()` with the given timeout (default 100ms) before reading; if `poll()` returns 0 (timeout), return empty vector; if `poll()` returns >0, `read()` the inotify fd and parse all available `inotify_event` structs; return `vector<FileEvent>` with path, mask, timestamp
  - Destructor: close fd
  - This approach avoids both spin-waiting (the `poll()` blocks up to 100ms) and infinite blocking (the timeout lets the thread check a shutdown flag)
  - _Requirements: 4.1, 4.2_

- [ ] 10. Implement monitor main loop and `WindowStats` aggregator
  - In `src/monitor.cpp`, implement three-thread design from the design document
  - ProcPoller thread: every 500ms, call `read_proc_metrics` + `read_proc_io` for all tracked PIDs; push to `metrics_queue`; discover new children via `get_children` and add to tracked set
  - InotifyReader thread: loop calling `inotify_watcher.poll_events(100)` (100ms timeout); push any returned `FileEvent` objects to `file_queue`; check a `std::atomic<bool> shutdown_flag` between calls to exit cleanly
  - Aggregator thread: wake every 1 second; drain both queues under mutex; compute per-second deltas for all four metrics; update `WindowStats` map
  - Protect shared state with a single `std::mutex`
  - Write `logs/metrics.json` atomically (write to `.metrics.json.tmp`, then `rename()`) every aggregator tick
  - _Requirements: 3.2, 3.3, 3.4, 4.2, 4.3, 5.2, 6.5_

- [ ] 10.1 Write property test for WindowStats monotonic I/O delta
  - Python/Hypothesis test: generate pairs `(before, after)` where `after >= before` (both uint64); verify computed delta `after - before >= 0` for all 100+ cases
  - **Property 5: WindowStats monotonic I/O delta**
  - **Validates: Requirements 5.2**

- [ ] 11. Checkpoint — Stage II verification
  - Ensure `make` builds both `bin/simulator` and `bin/monitor` with zero warnings
  - Run `./bin/monitor` for 60 seconds on idle system; verify `logs/alerts.csv` remains empty
  - Verify `logs/metrics.json` is written every second with valid JSON
  - Run `./bin/tests` — all unit tests pass
  - Ensure all tests pass, ask the user if questions arise.

---

### Stage III — Detection, Response, and Dashboards

- [ ] 12. Implement threshold detection and response engine
  - In `src/monitor.cpp` Aggregator thread, after updating `WindowStats`: compare each metric against `DetectionConfig` fields; if any exceeds threshold, call response engine
  - Response engine: send `SIGSTOP` or `SIGKILL` (per `DetectionConfig.use_sigkill`) to flagged PID; on `kill()` failure log errno and continue
  - Write structured `Alert` to `logs/alerts.csv` (append): columns `timestamp,pid,trigger_reason,file_events_per_sec,spawns_per_sec,mem_delta_mb_per_sec,io_bytes_per_sec`
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_

- [ ] 12.1 Write property test for threshold detection soundness
  - Google Test parameterized test with ≥100 `WindowStats` instances where all four metrics are strictly below their `DetectionConfig` defaults
  - Verify detector emits zero alerts for every sub-threshold input
  - **Property 6: Threshold detection soundness**
  - **Validates: Requirements 6.2**

- [ ] 12.2 Write property test for Alert CSV round-trip (Python/Hypothesis)
  - Generate random `Alert`-equivalent dicts (random timestamp strings, random PIDs, random metric floats); write to CSV row; parse back; verify all fields match
  - **Property 7: Alert CSV round-trip**
  - **Validates: Requirements 6.4**

- [ ] 13. Implement CLI dashboard
  - In `src/monitor.cpp`, implement `render_dashboard()` called once per aggregator tick
  - Use `\033[H\033[J` for in-place refresh (cursor home + clear screen)
  - STATUS line: `\033[92m[ NORMAL ]\033[0m` or `\033[91m\033[5m[ !! ALERT !! ]\033[0m`
  - Four metric bars: compute fill fraction = metric / threshold; render as 20-char `█`/`░` bar; color cyan normal, amber elevated (>50% threshold), red alert (>100%)
  - Alert log: last 5 entries from in-memory alert list; newest row `\033[97m` bright white
  - Zero external C++ dependencies — ANSI codes only
  - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6_

- [ ] 14. Implement web dashboard backend
  - In `dashboard/app.py`: Flask app with three routes: `GET /` (renders `index.html`), `GET /api/metrics` (reads and returns `logs/metrics.json`), `GET /api/alerts` (reads `logs/alerts.csv`, returns last 100 rows as JSON array)
  - Handle missing/empty files gracefully — return empty defaults, not 500 errors
  - _Requirements: 10.1, 10.8_

- [ ] 15. Implement web dashboard frontend
  - Create `dashboard/templates/index.html` with full UI as specified in design
  - CSS: define all color palette variables (`--bg`, `--normal`, `--warning`, `--alert`, `--cyan`, `--violet`, `--grid`) in `:root`; apply dark background, monospace fonts for data values
  - Hero banner: full-width div with pulsing green `● SYSTEM NORMAL` or flashing red `⚠ ALERT DETECTED`; include triggering PID and reason when alert is active
  - Four Chart.js line charts in a 2×2 grid; rolling 60-second window; neon-colored lines; labeled axes
  - Process table: columns PID, name, state, memory (MB), I/O (bytes/sec); amber row on elevated, red row on alert
  - Alert log table: columns timestamp, PID, process name, trigger reason, metrics; auto-prepend new rows; dim rows older than 30 seconds to 50% opacity
  - JS polling: `setInterval(() => fetchAndUpdate(), 1000)` — updates all elements without page reload
  - _Requirements: 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.8, 10.9_

- [ ] 15.1 Write property test for Metrics JSON round-trip (Python/Hypothesis)
  - Use Hypothesis to generate random dicts with float fields matching `WindowStats` structure; serialize to JSON string; deserialize; verify all float values equal within `1e-9` epsilon
  - **Property 8: Metrics JSON round-trip**
  - **Validates: Requirements 10.3, 10.8**

- [ ] 15.2 Implement append-only metrics history writer in monitor
  - In `src/monitor.cpp` Aggregator thread, after writing `logs/metrics.json`, also append the same `WindowStats` snapshot as a single newline-delimited JSON entry to `logs/metrics_history.jsonl`
  - Each line is a complete JSON object: `{"timestamp":"...","file_events_per_sec":...,"spawns_per_sec":...,"mem_delta_mb_per_sec":...,"io_bytes_per_sec":...}`
  - Open the file in append mode (`std::ofstream` with `std::ios::app`) and flush after each write
  - This file accumulates all history and is what `ml/export_features.py` reads — `metrics.json` is overwritten each second and has no history
  - _Requirements: 11.1_

- [ ] 16. Implement optional ML layer
  - `ml/export_features.py`: read `logs/metrics_history.jsonl` (one JSON object per line) and `logs/alerts.csv`; join by nearest timestamp to assign labels (1 = alert window, 0 = normal); output `ml/features.csv` with columns `file_events_per_sec, spawns_per_sec, mem_delta_mb_per_sec, io_bytes_per_sec, label`
  - `ml/train_model.py`: load `ml/features.csv`; train `sklearn.ensemble.IsolationForest`; save model to `ml/model.pkl` with `joblib`
  - `ml/score.py`: load `ml/model.pkl`; accept a feature vector via CLI args or stdin; print anomaly score and classification
  - `ml/README.md`: document precision and recall on a held-out test split; frame ML as optional enhancement — core C++ detection works without it
  - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5_

- [ ] 17. Write integration test and docs
  - Create `tests/integration_test.sh`: start `bin/monitor` in background; wait 5s; assert `logs/alerts.csv` empty; start simulator with `--i-am-in-a-vm`; wait 10s; assert `logs/alerts.csv` has ≥1 entry; assert no simulator-written file exists outside `test_env/`; kill monitor; exit 0 on pass
  - Create `docs/stage-mapping.md`: table mapping each source file/component to Stage I, II, or III
  - Update `README.md`: Overview, Safety section (all six safety constraints listed explicitly), Build instructions (`make`, `cmake --build .`), Run instructions for simulator and monitor, web dashboard launch command
  - _Requirements: 1.7, 8.1_

- [ ] 18. Final checkpoint — full end-to-end verification
  - `make` builds both binaries with zero warnings
  - `./bin/monitor` idle for 60 seconds → `logs/alerts.csv` empty (zero false positives)
  - `./bin/simulator --files=200 --children=8 --mem-mb=200 --i-am-in-a-vm` while monitor runs → alert in CSV within 5 seconds
  - `python dashboard/app.py` launches; hero banner switches green→red within 2 seconds of detection
  - `./bin/tests` — all C++ tests pass
  - `pytest tests/` — all Python property tests pass
  - `bash tests/integration_test.sh` — passes
  - Ensure all tests pass, ask the user if questions arise.

---

## Notes

- All tasks are required (comprehensive testing mode selected)
- Each task references specific requirements for traceability
- Stages must be completed in order — do not start Stage II until Stage I checkpoints pass
- All C++ must build with `-Wall -Wextra` and zero warnings — no suppressions
- All detection thresholds live in `DetectionConfig` in `include/metrics.h` — no magic numbers in `monitor.cpp`
- `logs/metrics.json` is overwritten each second (current snapshot only); `logs/metrics_history.jsonl` accumulates all history for the ML layer
