# Requirements Document

## Introduction

This project is a two-part academic systems-security application for an Operating Systems course (AI 3002) targeting Ubuntu Linux. It is a defensive, educational simulator — not functional malware. It consists of:

1. **Simulator** — reproduces ransomware behavioral signatures (rapid file renaming, mass memory allocation, rapid process spawning) inside an isolated sandbox directory using reversible, non-destructive operations only.
2. **Monitor / Defense Module** — watches real-time OS-level signals (process, memory, file-system, I/O) and detects the simulator's behavior using configurable threshold rules, with an optional ML anomaly-scoring layer, then responds by suspending/killing the flagged process and logging the event.

Core language: C++17 with POSIX APIs (`fork()`, `exec()`, `/proc` filesystem, `inotify`). No external C++ libraries. Optional bonus components (ML layer, web dashboard) may use Python.

## Glossary

- **Simulator**: The C++ binary (`bin/simulator`) that mimics ransomware behavioral signatures in a sandboxed directory.
- **Monitor**: The C++ binary (`bin/monitor`) that observes OS-level signals and detects/responds to suspicious behavior.
- **Sandbox**: The isolated directory `./test_env/` — the only location the Simulator may read or write.
- **ProcMetrics**: A struct holding per-process metrics (pid, name, state, vsize_bytes, read_bytes, write_bytes).
- **FileEvent**: A struct holding inotify file-system event data (path, inotify mask, timestamp).
- **WindowStats**: A struct holding rolling per-second counts used for threshold evaluation.
- **Alert**: A detection event written to `logs/alerts.csv` with timestamp, PID, trigger reason, and metric values.
- **Threshold**: A configurable limit defined in a single config struct; when exceeded, triggers an Alert.
- **CLI Dashboard**: The Monitor's in-place terminal output using ANSI escape codes.
- **Web Dashboard**: A Flask-based browser UI for live viva/demo display.
- **ML Layer**: An optional Python-based Isolation Forest anomaly scorer layered on top of rule-based detection.

---

## Requirements

### Requirement 1: Safety Constraints

**User Story:** As a course evaluator, I want strict safety guarantees enforced at runtime, so that the simulator cannot cause unintended damage to the host system.

#### Acceptance Criteria

1. WHEN the Simulator starts, THE Simulator SHALL resolve the sandbox path and refuse to run if the resolved absolute path does not match the expected `./test_env/` directory.
2. THE Simulator SHALL never read or write any file outside the `./test_env/` sandbox directory.
3. WHEN the Simulator performs a file-lock operation, THE Simulator SHALL use a reversible operation only (rename to `<filename>.simlocked` and/or a reversible XOR transform with a fixed, logged key) — never destroying original content irrecoverably.
4. WHEN the Simulator starts, THE Simulator SHALL detect whether it is running inside a VM by checking `/sys/class/dmi/id/product_name` or calling `systemd-detect-virt`, and SHALL print a prominent warning and exit if VM/sandbox execution cannot be confirmed, unless the `--i-am-in-a-vm` flag is provided.
5. THE Simulator SHALL write every action it takes to `logs/simulator_actions.log` with an ISO-8601 timestamp so all actions are fully auditable.
6. THE Build System SHALL provide a `clean-sandbox` target that resets `./test_env/` and `./logs/` to a known clean state.
7. THE README SHALL contain a section titled "Safety" explicitly describing all constraints above.

---

### Requirement 2: Simulator Core Behavior

**User Story:** As a student, I want the simulator to reproduce realistic ransomware behavioral signatures in a controlled way, so that the monitor has observable signals to detect.

#### Acceptance Criteria

1. WHEN the Simulator starts, THE Simulator SHALL populate `test_env/` with a configurable number of dummy files.
2. WHEN running the file-rename phase, THE Simulator SHALL rapidly rename each file to `<filename>.simlocked` to simulate mass file locking.
3. WHEN running the process-spawn phase, THE Simulator SHALL rapidly spawn a configurable number of child processes using `fork()`/`exec()`/`wait()`.
4. WHEN running the memory phase, THE Simulator SHALL allocate a configurable amount of memory (in MB), touch all pages to commit them, then free the memory.
5. THE Simulator SHALL accept CLI flags `--files=<N>`, `--children=<N>`, and `--mem-mb=<N>` to configure the intensity of each behavioral phase.
6. WHEN any simulated phase completes, THE Simulator SHALL log the phase name, duration, and intensity to `logs/simulator_actions.log`.

---

### Requirement 3: Monitor — Process Monitoring

**User Story:** As a student, I want the monitor to read live process data from the `/proc` filesystem, so that it can track process state and memory usage in real time.

#### Acceptance Criteria

1. WHEN the Monitor is running, THE Monitor SHALL parse `/proc/[pid]/stat` and `/proc/[pid]/status` for each tracked process to obtain process state, spawn lineage, and `VmSize`.
2. WHEN the Monitor reads process data, THE Monitor SHALL compute the `VmSize` delta between consecutive readings and store it in a `WindowStats` entry.
3. THE Monitor SHALL track all monitored processes concurrently, including child processes spawned by the Simulator.
4. WHEN a new child process is detected under a monitored parent PID, THE Monitor SHALL add the child to the monitored set automatically.

---

### Requirement 4: Monitor — File-System Monitoring

**User Story:** As a student, I want the monitor to observe file-system events on the sandbox directory in real time, so that it can count rename/create/modify/delete event rates.

#### Acceptance Criteria

1. WHEN the Monitor starts, THE Monitor SHALL call `inotify_init()` and `inotify_add_watch()` on the `./test_env/` directory to subscribe to create, modify, rename, and delete events.
2. WHEN an inotify event is received, THE Monitor SHALL record a `FileEvent` (path, inotify mask, timestamp) and increment the per-second file-event counter in `WindowStats`.
3. THE Monitor SHALL compute a rolling file-events-per-second rate over a configurable time window.

---

### Requirement 5: Monitor — I/O Monitoring

**User Story:** As a student, I want the monitor to track I/O throughput per process, so that abnormal read/write rates can be detected.

#### Acceptance Criteria

1. WHEN the Monitor reads process data, THE Monitor SHALL parse `/proc/[pid]/io` to obtain cumulative `read_bytes` and `write_bytes` for each tracked process.
2. THE Monitor SHALL compute per-second I/O throughput deltas between consecutive readings and store them in `WindowStats`.

---

### Requirement 6: Monitor — Detection Logic

**User Story:** As a student, I want configurable threshold-based detection, so that the monitor flags processes whose behavior matches ransomware signatures.

#### Acceptance Criteria

1. THE Monitor SHALL define all detection thresholds (file-events/sec, process-spawns/sec, memory-delta/sec, I/O bytes/sec) in a single configuration struct — not as scattered magic numbers in code.
2. WHEN any metric in `WindowStats` exceeds its configured threshold, THE Monitor SHALL flag the offending PID as suspicious.
3. WHEN a PID is flagged, THE Monitor SHALL either send `SIGSTOP` to suspend or `SIGKILL` to terminate the process, as configured.
4. WHEN a PID is flagged, THE Monitor SHALL write a structured alert to `logs/alerts.csv` containing: timestamp, PID, trigger reason, and all current metric values.
5. THE Monitor SHALL evaluate thresholds for all monitored processes concurrently (not sequentially one at a time).

---

### Requirement 7: Shared Data Structures

**User Story:** As a developer, I want well-defined shared data structures, so that the monitor and proc_reader components share a consistent data model.

#### Acceptance Criteria

1. THE codebase SHALL define a `ProcMetrics` struct in `include/metrics.h` with fields: `pid`, `name`, `state`, `vsize_bytes`, `read_bytes`, `write_bytes`.
2. THE codebase SHALL define a `FileEvent` struct in `include/metrics.h` with fields: `path`, `inotify_mask`, `timestamp`.
3. THE codebase SHALL define a `WindowStats` struct in `include/metrics.h` with fields for rolling per-second counts for all four monitored metrics.
4. THE codebase SHALL declare the `proc_reader` interface in `include/proc_reader.h` with functions for reading `ProcMetrics` from `/proc`.

---

### Requirement 8: Build System

**User Story:** As a course evaluator, I want a complete, warning-free build system, so that I can build both binaries with a single command.

#### Acceptance Criteria

1. THE Build System SHALL provide a `CMakeLists.txt` or `Makefile` that produces two binaries: `bin/simulator` and `bin/monitor`.
2. WHEN building, THE Build System SHALL compile all C++ sources with `-Wall -Wextra` and produce zero warnings.
3. THE Build System SHALL require no external C++ libraries beyond the standard library and POSIX headers.

---

### Requirement 9: CLI Dashboard

**User Story:** As a developer, I want a live in-place terminal dashboard, so that I can observe the monitor's metrics and alerts during development and testing without terminal scroll spam.

#### Acceptance Criteria

1. WHILE the Monitor is running, THE CLI Dashboard SHALL refresh the terminal display in place using ANSI escape codes without scrolling.
2. THE CLI Dashboard SHALL display a STATUS line at the top showing `[ NORMAL ]` in neon green (`#00ff88`) during normal operation and `[ !! ALERT !! ]` in flashing red (`#ff3333`) when an alert is active.
3. THE CLI Dashboard SHALL display animated ASCII metric bars for file-events/sec, process-spawns/sec, memory-delta/sec, and I/O bytes/sec that fill and shrink in real time.
4. THE CLI Dashboard SHALL display a rolling alert log at the bottom showing the last N alerts with timestamp, PID, trigger reason, and metric values, with the newest entry highlighted.
5. THE CLI Dashboard SHALL use zero external C++ dependencies — ANSI escape codes only.
6. THE CLI Dashboard SHALL use color-coded threat levels: green (normal), amber (`#ffcc00`, elevated), red (alert), matching the defined color palette.

---

### Requirement 10: Web Dashboard

**User Story:** As a student, I want a professional web dashboard, so that I can present a live, impressive demo during the viva on a projector.

#### Acceptance Criteria

1. THE Web Dashboard SHALL be launchable with the single command `python dashboard/app.py`.
2. THE Web Dashboard SHALL use a deep dark background (`#0a0a0f`) consistent with the defined color palette throughout.
3. THE Web Dashboard SHALL display a full-width hero status banner showing a pulsing green `● SYSTEM NORMAL` or a flashing red `⚠ ALERT DETECTED` with the triggering PID and reason inline, updating within 1 second of a detection event.
4. THE Web Dashboard SHALL display four real-time line charts (one per metric: file-events/sec, process-spawns/sec, memory-delta/sec, I/O bytes/sec) over a rolling 60-second window, using neon-colored lines on a dark canvas with clearly labelled axes.
5. THE Web Dashboard SHALL display a live process table showing: PID, process name, state, memory usage, and I/O rates, with rows highlighted amber on elevated metrics and red on a triggered alert.
6. THE Web Dashboard SHALL display a live alert log table with columns: Timestamp, PID, Process Name, Trigger Reason, Metric Values — rows auto-prepend as alerts arrive, rows older than 30 seconds dim to 50% opacity.
7. THE Web Dashboard SHALL use monospace fonts for all data values and process names.
8. THE Web Dashboard SHALL update all live elements without requiring a page refresh (polling interval ≤ 1 second).
9. THE Web Dashboard SHALL be responsive and readable at 1080p on a projector.

---

### Requirement 11: Optional ML Layer

**User Story:** As a student, I want an optional ML anomaly-scoring layer, so that I can demonstrate a bonus enhancement over the rule-based detector for extra credit.

#### Acceptance Criteria

1. WHERE the ML layer is implemented, `ml/export_features.py` SHALL convert `logs/` data into a CSV of feature vectors (file-events/sec, spawns/sec, memory-delta/sec, io-bytes/sec) per time window.
2. WHERE the ML layer is implemented, `ml/train_model.py` SHALL train an Isolation Forest model (scikit-learn) on baseline and simulated-attack data and save the trained model to disk.
3. WHERE the ML layer is implemented, `ml/score.py` SHALL load the trained model and score a new feature window as normal or anomalous, printing an anomaly score.
4. WHERE the ML layer is implemented, THE ML layer SHALL be explicitly framed as an optional enhancement — the core C++ rule-based detection SHALL function correctly with zero Python/ML involvement.
5. WHERE the ML layer is implemented, `ml/README.md` SHALL document precision and recall on a held-out test set of normal vs. simulated-attack windows.
