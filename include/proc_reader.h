#pragma once

// =============================================================================
// proc_reader.h — Interface for reading live process data from /proc.
//
// All functions return gracefully (empty/zero structs) when a process has
// exited mid-read rather than throwing. Callers must handle zero-pid returns.
// =============================================================================

#include "metrics.h"
#include <vector>
#include <sys/types.h>

// Read /proc/[pid]/stat and /proc/[pid]/status.
// Returns a zero-initialized ProcMetrics with pid=0 if the process is gone.
ProcMetrics read_proc_metrics(pid_t pid);

// Read /proc/[pid]/io and store read_bytes / write_bytes into m.
// No-op if the file is unreadable (process gone or permission denied).
void read_proc_io(pid_t pid, ProcMetrics& m);

// Return all direct child PIDs of parent_pid by scanning /proc/[pid]/status
// for "PPid:" lines matching parent_pid. Returns empty vector on any error.
std::vector<pid_t> get_children(pid_t parent_pid);

// Return a list of all numeric PIDs currently present in /proc.
// Used for initial scan and child-discovery sweeps.
std::vector<pid_t> list_all_pids();
