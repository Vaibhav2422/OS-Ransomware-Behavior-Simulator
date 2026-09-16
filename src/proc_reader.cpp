// =============================================================================
// proc_reader.cpp — /proc filesystem parser for the ransomware defense monitor.
//
// All functions handle missing or unreadable files gracefully — a process may
// exit between the time we discover its PID and the time we open its /proc
// entry. Zero-initialized or empty return values signal "process gone".
// =============================================================================

#include "proc_reader.h"
#include "metrics.h"

#include <dirent.h>
#include <sys/types.h>

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

// -----------------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------------

namespace {

// Returns true if every character in s is an ASCII digit.
bool all_digits(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

// Open /proc/<pid>/<file> and return the stream. Caller checks .good().
std::ifstream open_proc(pid_t pid, const std::string& file) {
    std::string path = "/proc/" + std::to_string(pid) + "/" + file;
    return std::ifstream(path);
}

} // namespace

// -----------------------------------------------------------------------------
// read_proc_metrics
//
// Parses /proc/[pid]/stat for state (field 3) and vsize (field 23).
// Field numbering follows the kernel docs (1-indexed).
//
// Format example (abbreviated):
//   1234 (bash) S 1000 1234 1234 34816 1234 4194304 ... <vsize> ...
//
// The comm field (2) is wrapped in parentheses and may contain spaces,
// so we locate the last ')' before parsing remaining fields.
// -----------------------------------------------------------------------------
ProcMetrics read_proc_metrics(pid_t pid) {
    ProcMetrics m;
    m.pid = pid;

    std::ifstream stat_stream = open_proc(pid, "stat");
    if (!stat_stream.good()) return m;  // process gone

    std::string line;
    if (!std::getline(stat_stream, line)) return m;

    // Skip past the comm field "(<name>)" — find last ')'.
    const std::string::size_type rparen = line.rfind(')');
    if (rparen == std::string::npos) return m;

    // Extract comm (between first '(' and last ')').
    const std::string::size_type lparen = line.find('(');
    if (lparen != std::string::npos && rparen > lparen + 1) {
        m.name = line.substr(lparen + 1, rparen - lparen - 1);
    }

    // Parse remaining space-separated fields starting after ')'.
    std::istringstream rest(line.substr(rparen + 1));
    // Fields (relative to position after comm, 1-indexed from kernel docs):
    //   1  = state
    //   2  = ppid
    //   ...
    //   21 = vsize  (field 23 overall = field 21 after comm+pid)
    std::string token;
    int field = 0;
    while (rest >> token) {
        ++field;
        if (field == 1) {
            // state
            if (!token.empty()) m.state = token[0];
        } else if (field == 21) {
            // vsize in bytes
            char* end = nullptr;
            const unsigned long long v = std::strtoull(token.c_str(), &end, 10);
            if (end != token.c_str()) m.vsize_bytes = static_cast<uint64_t>(v);
            break;
        }
    }

    return m;
}

// -----------------------------------------------------------------------------
// read_proc_io
//
// Parses /proc/[pid]/io for cumulative read_bytes and write_bytes.
// File format:
//   rchar: 12345
//   wchar: 67890
//   ...
//   read_bytes: 4096
//   write_bytes: 8192
//   ...
// We only care about read_bytes and write_bytes (actual storage I/O).
// -----------------------------------------------------------------------------
void read_proc_io(pid_t pid, ProcMetrics& m) {
    std::ifstream io_stream = open_proc(pid, "io");
    if (!io_stream.good()) return;  // process gone or no permission

    std::string line;
    while (std::getline(io_stream, line)) {
        if (line.compare(0, 11, "read_bytes:") == 0) {
            char* end = nullptr;
            const unsigned long long v =
                std::strtoull(line.c_str() + 11, &end, 10);
            if (end != line.c_str() + 11) {
                m.read_bytes = static_cast<uint64_t>(v);
            }
        } else if (line.compare(0, 12, "write_bytes:") == 0) {
            char* end = nullptr;
            const unsigned long long v =
                std::strtoull(line.c_str() + 12, &end, 10);
            if (end != line.c_str() + 12) {
                m.write_bytes = static_cast<uint64_t>(v);
            }
        }
    }
}

// -----------------------------------------------------------------------------
// get_children
//
// Scans all /proc/[pid]/status files looking for "PPid: <parent_pid>".
// Returns the list of PIDs whose PPid matches parent_pid.
// -----------------------------------------------------------------------------
std::vector<pid_t> get_children(pid_t parent_pid) {
    std::vector<pid_t> children;
    const std::vector<pid_t> all = list_all_pids();

    for (const pid_t candidate : all) {
        if (candidate == parent_pid) continue;

        std::ifstream status = open_proc(candidate, "status");
        if (!status.good()) continue;

        std::string line;
        while (std::getline(status, line)) {
            if (line.compare(0, 5, "PPid:") == 0) {
                char* end = nullptr;
                const long ppid = std::strtol(line.c_str() + 5, &end, 10);
                if (end != line.c_str() + 5 &&
                    static_cast<pid_t>(ppid) == parent_pid) {
                    children.push_back(candidate);
                }
                break;  // PPid line found — no need to read further
            }
        }
    }

    return children;
}

// -----------------------------------------------------------------------------
// list_all_pids
//
// Scans /proc for numeric directory entries and returns them as a vector.
// Entries that disappear between readdir() and the caller's use are handled
// gracefully by the individual read_proc_* functions.
// -----------------------------------------------------------------------------
std::vector<pid_t> list_all_pids() {
    std::vector<pid_t> pids;

    DIR* proc_dir = opendir("/proc");
    if (proc_dir == nullptr) return pids;

    struct dirent* entry = nullptr;
    while ((entry = readdir(proc_dir)) != nullptr) {
        const std::string name(entry->d_name);
        if (!all_digits(name)) continue;

        char* end = nullptr;
        const long pid = std::strtol(name.c_str(), &end, 10);
        if (end != name.c_str() && *end == '\0' && pid > 0) {
            pids.push_back(static_cast<pid_t>(pid));
        }
    }

    closedir(proc_dir);
    return pids;
}
