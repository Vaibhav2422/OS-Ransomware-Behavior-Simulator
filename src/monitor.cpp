// =============================================================================
// monitor.cpp — Ransomware Defense Monitor
//
// Three-thread design:
//   1. ProcPoller   — polls /proc every 500 ms for all tracked PIDs
//   2. InotifyReader — watches ./test_env/ via inotify (poll + drain loop)
//   3. Aggregator   — wakes every 1 s, drains queues, updates WindowStats,
//                     evaluates thresholds, fires response, renders dashboard,
//                     writes logs/metrics.json atomically
//
// All shared state is protected by a single std::mutex.
// No external C++ libraries — POSIX + STL only.
// =============================================================================

#include "metrics.h"
#include "proc_reader.h"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <poll.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <unistd.h>

// =============================================================================
// Global shutdown flag — set by SIGINT/SIGTERM handler
// =============================================================================
static std::atomic<bool> g_shutdown{false};

static void signal_handler(int /*sig*/) {
    g_shutdown.store(true, std::memory_order_relaxed);
}

// =============================================================================
// InotifyWatcher
// =============================================================================
class InotifyWatcher {
public:
    explicit InotifyWatcher(const std::string& path) {
        inotify_fd_ = inotify_init1(0);  // blocking fd
        if (inotify_fd_ < 0) {
            std::perror("inotify_init1");
            std::exit(1);
        }
        watch_descriptor_ = inotify_add_watch(
            inotify_fd_, path.c_str(),
            IN_CREATE | IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE);
        if (watch_descriptor_ < 0) {
            std::perror("inotify_add_watch");
            std::exit(1);
        }
    }

    ~InotifyWatcher() {
        if (inotify_fd_ >= 0) ::close(inotify_fd_);
    }

    // Poll up to timeout_ms, then drain all available events.
    // Returns empty vector on timeout — avoids spin-waiting and infinite block.
    std::vector<FileEvent> poll_events(int timeout_ms = 100) {
        std::vector<FileEvent> events;

        struct pollfd pfd{};
        pfd.fd     = inotify_fd_;
        pfd.events = POLLIN;

        const int ready = ::poll(&pfd, 1, timeout_ms);
        if (ready <= 0) return events;  // timeout or error

        char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
        const ssize_t n = ::read(inotify_fd_, buf, sizeof(buf));
        if (n <= 0) return events;

        const char* ptr = buf;
        const char* end = buf + n;
        while (ptr < end) {
            const auto* ev = reinterpret_cast<const struct inotify_event*>(ptr);
            FileEvent fe;
            fe.inotify_mask = ev->mask;
            fe.timestamp    = std::time(nullptr);
            if (ev->len > 0) {
                fe.path = "./test_env/" + std::string(ev->name);
            } else {
                fe.path = "./test_env/";
            }
            events.push_back(std::move(fe));
            ptr += sizeof(struct inotify_event) + ev->len;
        }
        return events;
    }

private:
    int inotify_fd_      = -1;
    int watch_descriptor_ = -1;
};

// =============================================================================
// Shared state
// =============================================================================
struct SharedState {
    std::mutex                      mtx;
    std::queue<ProcMetrics>         metrics_queue;
    std::queue<FileEvent>           file_queue;
    std::map<pid_t, ProcMetrics>    last_metrics;   // previous snapshot per PID
    std::set<pid_t>                 tracked_pids;
    WindowStats                     current_window;
    std::vector<Alert>              alert_log;
    bool                            alert_active  = false;
    pid_t                           alert_pid     = 0;
    std::string                     alert_reason;
};

// =============================================================================
// ISO-8601 timestamp helper
// =============================================================================
static std::string iso8601_now() {
    const auto now = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now());
    const std::tm* utc = std::gmtime(&now);
    if (!utc) return "1970-01-01T00:00:00Z";
    std::ostringstream oss;
    oss << std::put_time(utc, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

// =============================================================================
// Response engine — SIGSTOP or SIGKILL
// =============================================================================
static void respond(pid_t pid, const DetectionConfig& cfg,
                    const std::string& reason) {
    const int sig = cfg.use_sigkill ? SIGKILL : SIGSTOP;
    if (::kill(pid, sig) != 0) {
        std::cerr << "[monitor] kill(" << pid << ", " << sig
                  << ") failed: " << std::strerror(errno) << '\n';
    } else {
        std::cout << "[monitor] Sent " << (cfg.use_sigkill ? "SIGKILL" : "SIGSTOP")
                  << " to PID " << pid << " (" << reason << ")\n";
    }
}

// =============================================================================
// Alert CSV writer
// =============================================================================
static void write_alert_csv(const Alert& a) {
    std::ofstream csv("logs/alerts.csv", std::ios::app);
    if (!csv) return;
    // Write header if file is empty
    csv.seekp(0, std::ios::end);
    if (csv.tellp() == 0) {
        csv << "timestamp,pid,proc_name,trigger_reason,"
               "file_events_per_sec,spawns_per_sec,"
               "mem_delta_mb_per_sec,io_bytes_per_sec\n";
    }
    csv << a.timestamp << ','
        << a.pid << ','
        << a.proc_name << ','
        << a.trigger_reason << ','
        << a.metrics.file_events_per_sec << ','
        << a.metrics.spawns_per_sec << ','
        << a.metrics.mem_delta_mb_per_sec << ','
        << a.metrics.io_bytes_per_sec << '\n';
    csv.flush();
}

// =============================================================================
// metrics.json atomic writer
// =============================================================================
static void write_metrics_json(const WindowStats& ws, bool alert_active,
                               pid_t alert_pid, const std::string& alert_reason,
                               const std::map<pid_t, ProcMetrics>& procs) {
    std::ofstream tmp("logs/.metrics.json.tmp");
    if (!tmp) return;

    tmp << "{\n"
        << "  \"timestamp\": \"" << iso8601_now() << "\",\n"
        << "  \"status\": \"" << (alert_active ? "alert" : "normal") << "\",\n"
        << "  \"alert_pid\": " << (alert_active ? std::to_string(alert_pid) : "null") << ",\n"
        << "  \"alert_reason\": "
        << (alert_active ? ("\"" + alert_reason + "\"") : "null") << ",\n"
        << "  \"metrics\": {\n"
        << "    \"file_events_per_sec\": " << ws.file_events_per_sec << ",\n"
        << "    \"spawns_per_sec\": " << ws.spawns_per_sec << ",\n"
        << "    \"mem_delta_mb_per_sec\": " << ws.mem_delta_mb_per_sec << ",\n"
        << "    \"io_bytes_per_sec\": " << ws.io_bytes_per_sec << "\n"
        << "  },\n"
        << "  \"processes\": [\n";

    bool first = true;
    for (const auto& kv : procs) {
        if (!first) tmp << ",\n";
        first = false;
        const ProcMetrics& m = kv.second;
        tmp << "    {\"pid\": " << m.pid
            << ", \"name\": \"" << m.name << "\""
            << ", \"state\": \"" << m.state << "\""
            << ", \"vsize_mb\": " << (m.vsize_bytes / (1024.0 * 1024.0))
            << ", \"read_bytes\": " << m.read_bytes
            << ", \"write_bytes\": " << m.write_bytes << "}";
    }
    tmp << "\n  ]\n}\n";
    tmp.close();
    std::rename("logs/.metrics.json.tmp", "logs/metrics.json");
}

// =============================================================================
// metrics_history.jsonl append writer
// =============================================================================
static void append_metrics_history(const WindowStats& ws) {
    std::ofstream hist("logs/metrics_history.jsonl", std::ios::app);
    if (!hist) return;
    hist << "{\"timestamp\":\"" << iso8601_now() << "\""
         << ",\"file_events_per_sec\":" << ws.file_events_per_sec
         << ",\"spawns_per_sec\":" << ws.spawns_per_sec
         << ",\"mem_delta_mb_per_sec\":" << ws.mem_delta_mb_per_sec
         << ",\"io_bytes_per_sec\":" << ws.io_bytes_per_sec
         << "}\n";
    hist.flush();
}

// =============================================================================
// CLI Dashboard renderer
// =============================================================================
static void render_dashboard(const WindowStats& ws,
                             const DetectionConfig& cfg,
                             const std::vector<Alert>& alerts,
                             bool alert_active) {
    // In-place refresh
    std::cout << "\033[H\033[J";

    // Status line
    if (alert_active) {
        std::cout << "\033[91m\033[5m[ !! ALERT !! ]\033[0m";
    } else {
        std::cout << "\033[92m[ NORMAL ]\033[0m";
    }
    std::cout << "          " << iso8601_now() << "\n";
    std::cout << std::string(65, '-') << "\n";

    // Metric bar renderer
    auto bar = [](double value, double threshold) -> std::string {
        const double fraction = (threshold > 0.0) ? (value / threshold) : 0.0;
        const int filled = static_cast<int>(fraction * 20.0);
        const int clamped = (filled > 20) ? 20 : filled;
        std::string color;
        if (fraction >= 1.0)       color = "\033[91m";  // red
        else if (fraction >= 0.5)  color = "\033[93m";  // amber
        else                       color = "\033[96m";  // cyan
        return color + "[" +
               std::string(static_cast<std::size_t>(clamped), static_cast<char>(0xE2)) +
               std::string(static_cast<std::size_t>(20 - clamped), static_cast<char>(0xE2)) +
               "]\033[0m";
    };

    std::cout << "  File Events/sec    " << bar(ws.file_events_per_sec, cfg.file_events_per_sec)
              << "  " << ws.file_events_per_sec << " /s\n";
    std::cout << "  Process Spawns/s   " << bar(ws.spawns_per_sec, cfg.spawns_per_sec)
              << "  " << ws.spawns_per_sec << " /s\n";
    std::cout << "  Memory Delta MB/s  " << bar(ws.mem_delta_mb_per_sec, cfg.mem_delta_mb_per_sec)
              << "  " << ws.mem_delta_mb_per_sec << " MB/s\n";
    std::cout << "  I/O Bytes/sec      "
              << bar(ws.io_bytes_per_sec, cfg.io_bytes_per_sec)
              << "  " << (ws.io_bytes_per_sec / (1024.0 * 1024.0)) << " MB/s\n";

    std::cout << std::string(65, '-') << "\n";
    std::cout << "  ALERT LOG (last 5)\n";

    const std::size_t start = alerts.size() > 5 ? alerts.size() - 5 : 0;
    for (std::size_t i = start; i < alerts.size(); ++i) {
        const Alert& a = alerts[i];
        const bool newest = (i == alerts.size() - 1);
        if (newest) std::cout << "\033[97m";
        std::cout << "  " << a.timestamp
                  << "  PID " << a.pid
                  << "  " << a.trigger_reason
                  << "  file=" << a.metrics.file_events_per_sec << "/s"
                  << "  spawn=" << a.metrics.spawns_per_sec << "/s";
        if (newest) std::cout << "\033[0m";
        std::cout << "\n";
    }
    std::cout.flush();
}

// =============================================================================
// Thread 1: ProcPoller
// =============================================================================
static void proc_poller_thread(SharedState& state,
                               const DetectionConfig& /*cfg*/) {
    while (!g_shutdown.load(std::memory_order_relaxed)) {
        // Discover new children of all tracked PIDs
        std::set<pid_t> snapshot;
        {
            std::lock_guard<std::mutex> lock(state.mtx);
            snapshot = state.tracked_pids;
        }

        std::set<pid_t> new_pids;
        for (const pid_t pid : snapshot) {
            const std::vector<pid_t> children = get_children(pid);
            for (const pid_t child : children) {
                new_pids.insert(child);
            }
        }

        // Poll metrics for all tracked PIDs + new children
        std::vector<ProcMetrics> batch;
        {
            std::lock_guard<std::mutex> lock(state.mtx);
            for (const pid_t p : new_pids) state.tracked_pids.insert(p);
            for (const pid_t pid : state.tracked_pids) {
                ProcMetrics m = read_proc_metrics(pid);
                read_proc_io(pid, m);
                if (m.pid != 0) batch.push_back(m);
            }
        }

        {
            std::lock_guard<std::mutex> lock(state.mtx);
            for (auto& m : batch) state.metrics_queue.push(std::move(m));
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

// =============================================================================
// Thread 2: InotifyReader
// =============================================================================
static void inotify_reader_thread(SharedState& state) {
    InotifyWatcher watcher("./test_env");
    while (!g_shutdown.load(std::memory_order_relaxed)) {
        std::vector<FileEvent> events = watcher.poll_events(100);
        if (!events.empty()) {
            std::lock_guard<std::mutex> lock(state.mtx);
            for (auto& e : events) state.file_queue.push(std::move(e));
        }
    }
}

// =============================================================================
// Thread 3: Aggregator / Detector
// =============================================================================
static void aggregator_thread(SharedState& state, const DetectionConfig& cfg) {
    while (!g_shutdown.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::seconds(cfg.window_seconds));

        std::lock_guard<std::mutex> lock(state.mtx);

        // --- Drain file queue ---
        std::size_t file_event_count = 0;
        while (!state.file_queue.empty()) {
            state.file_queue.pop();
            ++file_event_count;
        }

        // --- Drain metrics queue and compute deltas ---
        std::size_t spawn_count    = 0;
        double      total_mem_delta = 0.0;
        double      total_io_delta  = 0.0;

        while (!state.metrics_queue.empty()) {
            ProcMetrics current = state.metrics_queue.front();
            state.metrics_queue.pop();

            auto it = state.last_metrics.find(current.pid);
            if (it != state.last_metrics.end()) {
                const ProcMetrics& prev = it->second;
                // Memory delta (MB/s over 0.5 s poll interval)
                if (current.vsize_bytes > prev.vsize_bytes) {
                    const double delta_bytes =
                        static_cast<double>(current.vsize_bytes - prev.vsize_bytes);
                    total_mem_delta += delta_bytes / (1024.0 * 1024.0) / 0.5;
                }
                // I/O delta (bytes/s)
                const uint64_t read_delta =
                    (current.read_bytes >= prev.read_bytes)
                        ? current.read_bytes - prev.read_bytes : 0;
                const uint64_t write_delta =
                    (current.write_bytes >= prev.write_bytes)
                        ? current.write_bytes - prev.write_bytes : 0;
                total_io_delta += static_cast<double>(read_delta + write_delta) / 0.5;
            } else {
                // First time seeing this PID = a spawn
                ++spawn_count;
            }
            state.last_metrics[current.pid] = current;
        }

        // --- Update WindowStats ---
        WindowStats& ws             = state.current_window;
        ws.file_events_per_sec      = static_cast<double>(file_event_count);
        ws.spawns_per_sec           = static_cast<double>(spawn_count);
        ws.mem_delta_mb_per_sec     = total_mem_delta;
        ws.io_bytes_per_sec         = total_io_delta;
        ws.window_start_epoch       =
            static_cast<uint64_t>(std::time(nullptr));

        // --- Threshold evaluation ---
        auto check = [&](double value, double threshold,
                         const std::string& name, pid_t pid) {
            if (value > threshold) {
                Alert a;
                a.timestamp      = iso8601_now();
                a.pid            = pid;
                a.trigger_reason = name;
                a.metrics        = ws;
                state.alert_log.push_back(a);
                state.alert_active = true;
                state.alert_pid    = pid;
                state.alert_reason = name;
                write_alert_csv(a);
                respond(pid, cfg, name);
            }
        };

        // Use the first tracked PID as the suspect (most recently added)
        const pid_t suspect = state.tracked_pids.empty()
                                  ? 0
                                  : *state.tracked_pids.begin();

        check(ws.file_events_per_sec,  cfg.file_events_per_sec,  "file_events_per_sec",  suspect);
        check(ws.spawns_per_sec,       cfg.spawns_per_sec,        "spawns_per_sec",        suspect);
        check(ws.mem_delta_mb_per_sec, cfg.mem_delta_mb_per_sec,  "mem_delta_mb_per_sec",  suspect);
        check(ws.io_bytes_per_sec,     cfg.io_bytes_per_sec,      "io_bytes_per_sec",      suspect);

        // Clear alert flag if all metrics are back below thresholds
        if (ws.file_events_per_sec  <= cfg.file_events_per_sec  &&
            ws.spawns_per_sec       <= cfg.spawns_per_sec        &&
            ws.mem_delta_mb_per_sec <= cfg.mem_delta_mb_per_sec  &&
            ws.io_bytes_per_sec     <= cfg.io_bytes_per_sec) {
            state.alert_active = false;
        }

        // --- Write metrics.json ---
        write_metrics_json(ws, state.alert_active, state.alert_pid,
                           state.alert_reason, state.last_metrics);
        append_metrics_history(ws);

        // --- Render CLI dashboard ---
        render_dashboard(ws, cfg, state.alert_log, state.alert_active);
    }
}

// =============================================================================
// main
// =============================================================================
int main(int argc, char* argv[]) {
    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    // Parse optional --pid=N argument to seed tracked PIDs
    DetectionConfig cfg;
    SharedState state;

    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        if (arg.compare(0, 6, "--pid=") == 0) {
            char* end = nullptr;
            const long pid = std::strtol(arg.c_str() + 6, &end, 10);
            if (end != arg.c_str() + 6 && pid > 0) {
                std::lock_guard<std::mutex> lock(state.mtx);
                state.tracked_pids.insert(static_cast<pid_t>(pid));
            }
        }
    }

    // If no PIDs specified, monitor all existing processes
    if (state.tracked_pids.empty()) {
        const std::vector<pid_t> all = list_all_pids();
        std::lock_guard<std::mutex> lock(state.mtx);
        for (const pid_t p : all) state.tracked_pids.insert(p);
    }

    std::cout << "[monitor] Starting — watching ./test_env/ and "
              << state.tracked_pids.size() << " initial PIDs\n";
    std::cout << "[monitor] Thresholds: file=" << cfg.file_events_per_sec
              << "/s  spawns=" << cfg.spawns_per_sec
              << "/s  mem=" << cfg.mem_delta_mb_per_sec
              << "MB/s  io=" << (cfg.io_bytes_per_sec / (1024*1024)) << "MB/s\n";

    std::thread poller(proc_poller_thread, std::ref(state), std::cref(cfg));
    std::thread watcher(inotify_reader_thread, std::ref(state));
    std::thread aggregator(aggregator_thread, std::ref(state), std::cref(cfg));

    poller.join();
    watcher.join();
    aggregator.join();

    std::cout << "\n[monitor] Shutdown complete.\n";
    return 0;
}
