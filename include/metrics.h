#pragma once

// =============================================================================
// metrics.h — Shared data structures for the ransomware defense simulator.
//
// All structs used by both the simulator and monitor are defined here so there
// is a single source of truth. No magic numbers appear in detection logic —
// all tunable thresholds live in DetectionConfig below.
// =============================================================================

#include <cstdint>
#include <ctime>
#include <string>

// -----------------------------------------------------------------------------
// ProcMetrics — snapshot of a single process read from /proc/[pid]/stat,
// /proc/[pid]/status, and /proc/[pid]/io.
// -----------------------------------------------------------------------------
struct ProcMetrics {
    pid_t       pid         = 0;
    std::string name;                // comm field from /proc/[pid]/stat
    char        state       = '?';   // R, S, D, Z, T, I
    uint64_t    vsize_bytes = 0;     // virtual memory size in bytes (field 23 of stat)
    uint64_t    read_bytes  = 0;     // cumulative bytes read  (from /proc/[pid]/io)
    uint64_t    write_bytes = 0;     // cumulative bytes written (from /proc/[pid]/io)
};

// -----------------------------------------------------------------------------
// FileEvent — a single inotify event from the sandbox directory.
// -----------------------------------------------------------------------------
struct FileEvent {
    std::string path;            // full path of the affected file
    uint32_t    inotify_mask = 0; // IN_CREATE, IN_MODIFY, IN_MOVED_FROM, etc.
    time_t      timestamp    = 0; // unix epoch seconds at event receipt
};

// -----------------------------------------------------------------------------
// WindowStats — rolling per-second metric rates used by the threshold detector.
// Updated once per second by the Aggregator thread in the monitor.
// -----------------------------------------------------------------------------
struct WindowStats {
    double   file_events_per_sec   = 0.0;  // inotify events/sec in sandbox dir
    double   spawns_per_sec        = 0.0;  // new child processes/sec under monitored PIDs
    double   mem_delta_mb_per_sec  = 0.0;  // VmSize change rate in MB/sec
    double   io_bytes_per_sec      = 0.0;  // combined read+write throughput bytes/sec
    uint64_t window_start_epoch    = 0;    // unix epoch of this window's start
};

// -----------------------------------------------------------------------------
// Alert — a detection event written to logs/alerts.csv.
// -----------------------------------------------------------------------------
struct Alert {
    std::string timestamp;       // ISO-8601 (e.g. "2026-09-01T14:23:01Z")
    pid_t       pid        = 0;
    std::string proc_name;
    std::string trigger_reason;  // e.g. "file_events_per_sec", "spawns_per_sec"
    WindowStats metrics;         // metric values at the time of detection
};

// -----------------------------------------------------------------------------
// DetectionConfig — all configurable thresholds and response settings.
//
// These values are the ONLY place thresholds appear — monitor.cpp reads from
// this struct and never contains bare numeric literals for detection logic.
//
// TODO: tune the threshold values against your own baseline data before the
// final viva demo. The defaults below are chosen to be clearly exceeded by the
// simulator's default intensity (--files=100 --children=8 --mem-mb=128) while
// staying well above normal desktop activity on an idle Ubuntu VM.
// -----------------------------------------------------------------------------
struct DetectionConfig {
    // Threshold: inotify events per second in the sandbox directory.
    // A normal editor touching one file produces ~1-3 events/sec.
    // The simulator renames 100+ files in under a second → well above 20.
    double file_events_per_sec    = 20.0;

    // Threshold: new child process spawns per second under monitored PIDs.
    // Normal build tools may fork 2-4 times/sec. Simulator spawns 8+ rapidly.
    double spawns_per_sec         = 5.0;

    // Threshold: VmSize increase rate in MB per second.
    // Most processes are stable. Simulator allocates 128 MB in ~100ms → ~1280 MB/sec peak.
    double mem_delta_mb_per_sec   = 50.0;

    // Threshold: combined read+write I/O bytes per second.
    // 10 MB/sec is generous for an idle desktop; simulator's mass rename is lower,
    // so this threshold is most relevant for the memory-touch phase's write pattern.
    double io_bytes_per_sec       = 10.0 * 1024.0 * 1024.0;  // 10 MB/sec

    // Response action: false = SIGSTOP (suspend, reversible), true = SIGKILL (terminate).
    // SIGSTOP is the safer default for a demo — the process can be resumed manually.
    bool use_sigkill              = false;

    // Evaluation window size in seconds.
    int window_seconds            = 1;
};
