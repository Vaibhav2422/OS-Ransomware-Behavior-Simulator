#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#include <unistd.h>

#if defined(__unix__) || defined(__APPLE__)
#include <limits.h>
#include <sys/wait.h>
#elif defined(_WIN32) || defined(__MINGW32__)
#include <windows.h>
extern "C" char* _fullpath(char*, const char*, std::size_t);
#endif

namespace {

class AuditLogger {
public:
    AuditLogger() : stream_("logs/simulator_actions.log", std::ios::app) {}

    void log(const std::string& message) {
        if (!stream_) {
            return;
        }

        const auto now = std::chrono::system_clock::to_time_t(
            std::chrono::system_clock::now());
        const std::tm* utc_time = std::gmtime(&now);
        if (utc_time == nullptr) {
            return;
        }

        stream_ << std::put_time(utc_time, "%Y-%m-%dT%H:%M:%SZ")
                << ' ' << message << '\n';
        stream_.flush();
    }

private:
    std::ofstream stream_;
};

struct SimulatorOptions {
    unsigned long files = 100;
    unsigned long children = 8;
    unsigned long mem_mb = 128;
    bool vm_override = false;
};

bool is_within_sandbox(const std::string& sandbox_path,
                       const std::string& target_path) {
    std::string normalized_sandbox = sandbox_path;
    std::string normalized_target = target_path;
    for (char& character : normalized_sandbox) {
        if (character == '\\') {
            character = '/';
        }
    }
    for (char& character : normalized_target) {
        if (character == '\\') {
            character = '/';
        }
    }
    const std::string prefix = normalized_sandbox.back() == '/'
                                   ? normalized_sandbox
                                   : normalized_sandbox + '/';
    return normalized_target == normalized_sandbox ||
           normalized_target.compare(0, prefix.size(), prefix) == 0;
}

bool resolve_existing_path(const std::string& path, std::string& resolved_path) {
#if defined(_WIN32) || defined(__MINGW32__)
    char resolved[4096];
    if (_fullpath(resolved, path.c_str(), sizeof(resolved)) == nullptr) {
        return false;
    }
    resolved_path = resolved;
    return true;
#else
    char resolved[PATH_MAX];
    if (realpath(path.c_str(), resolved) == nullptr) {
        return false;
    }
    resolved_path = resolved;
    return true;
#endif
}

}  // namespace

bool validate_sandbox_path(const std::string& target_path) {
    std::string sandbox_path;
    std::string resolved_target;
    if (!resolve_existing_path("./test_env", sandbox_path)) {
        return false;
    }

    if (!resolve_existing_path(target_path, resolved_target)) {
        const std::string::size_type separator = target_path.find_last_of("/\\");
        const std::string parent = separator == std::string::npos
                                       ? "."
                                       : target_path.substr(0, separator);
        const std::string name = separator == std::string::npos
                                     ? target_path
                                     : target_path.substr(separator + 1);
        std::string resolved_parent;
        if (name.empty() || !resolve_existing_path(parent, resolved_parent)) {
            return false;
        }
        resolved_target = resolved_parent + "/" + name;
    }
    return is_within_sandbox(sandbox_path, resolved_target);
}

namespace {

std::string dummy_path(unsigned long index, bool locked) {
    std::ostringstream filename;
    filename << "./test_env/dummy_" << std::setfill('0') << std::setw(3) << index;
    filename << ".dat" << (locked ? ".simlocked" : "");
    return filename.str();
}

AuditLogger& file_phase_logger() {
    static AuditLogger logger;
    return logger;
}

}  // namespace

bool populate_files(unsigned long count) {
    for (unsigned long index = 0; index < count; ++index) {
        const std::string path = dummy_path(index, false);
        if (!validate_sandbox_path(path)) {
            return false;
        }

        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        if (!file) {
            return false;
        }
        for (std::size_t byte = 0; byte < 4096; ++byte) {
            file.put(static_cast<char>(0xAB));
        }
        if (!file) {
            return false;
        }
        file.close();
        file_phase_logger().log("file_create path=" + path);
    }
    return true;
}

bool rename_files_locked(unsigned long count) {
    for (unsigned long index = 0; index < count; ++index) {
        const std::string source = dummy_path(index, false);
        const std::string destination = dummy_path(index, true);
        if (!validate_sandbox_path(source) || !validate_sandbox_path(destination)) {
            return false;
        }

        if (std::rename(source.c_str(), destination.c_str()) != 0) {
            return false;
        }
        file_phase_logger().log("file_rename source=" + source +
                                " destination=" + destination);
    }
    return true;
}

bool spawn_children(unsigned long count) {
#if defined(__unix__) || defined(__APPLE__)
    std::vector<pid_t> children;
    children.reserve(count);
    for (unsigned long index = 0; index < count; ++index) {
        const pid_t child_pid = fork();
        if (child_pid == -1) {
            for (const pid_t child : children) {
                waitpid(child, nullptr, 0);
            }
            return false;
        }
        if (child_pid == 0) {
            execl("/bin/sleep", "sleep", "1", static_cast<char*>(nullptr));
            _exit(127);
        }

        children.push_back(child_pid);
        file_phase_logger().log("child_fork pid=" + std::to_string(child_pid));
    }

    bool all_children_reaped = true;
    for (const pid_t child : children) {
        if (waitpid(child, nullptr, 0) == -1) {
            all_children_reaped = false;
        }
    }
    return all_children_reaped;
#else
    return count == 0;
#endif
}

bool allocate_and_touch(unsigned long megabytes) {
    constexpr std::size_t megabyte = 1024U * 1024U;
    if (megabytes > std::numeric_limits<std::size_t>::max() / megabyte) {
        return false;
    }

    const std::size_t allocation_size =
        static_cast<std::size_t>(megabytes) * megabyte;
    file_phase_logger().log("memory_alloc_start mb=" + std::to_string(megabytes));
    void* allocation = std::malloc(allocation_size);
    if (allocation == nullptr && allocation_size != 0) {
        return false;
    }

    auto* bytes = static_cast<unsigned char*>(allocation);
    for (std::size_t offset = 0; offset < allocation_size; offset += 4096U) {
        bytes[offset] = 0x01;
    }
    file_phase_logger().log("memory_alloc_complete mb=" + std::to_string(megabytes));
#if defined(__unix__) || defined(__APPLE__)
    sleep(2);
#else
    Sleep(2000);
#endif
    std::free(allocation);
    file_phase_logger().log("memory_free mb=" + std::to_string(megabytes));
    return true;
}

namespace {

#ifndef SIMULATOR_NO_MAIN
bool contains_virtual_machine_marker(const std::string& product_name) {
    const std::string markers[] = {
        "virtualbox", "vmware", "kvm", "qemu", "xen", "hyper-v", "parallels"
    };
    std::string lower_name = product_name;
    for (char& character : lower_name) {
        if (character >= 'A' && character <= 'Z') {
            character = static_cast<char>(character - 'A' + 'a');
        }
    }
    for (const std::string& marker : markers) {
        if (lower_name.find(marker) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool detect_vm() {
    std::ifstream product_file("/sys/class/dmi/id/product_name");
    std::string product_name;
    if (product_file && std::getline(product_file, product_name) &&
        contains_virtual_machine_marker(product_name)) {
        return true;
    }

#if defined(_WIN32) || defined(__MINGW32__)
    return false;
#else
    FILE* detector = popen("systemd-detect-virt 2>/dev/null", "r");
    if (detector == nullptr) {
        return false;
    }

    char output[128] = {};
    const bool read_output = std::fgets(output, sizeof(output), detector) != nullptr;
    int status = 0;
    status = pclose(detector);
    bool detector_succeeded = status != -1;
#if defined(__unix__) || defined(__APPLE__)
    detector_succeeded = detector_succeeded && WIFEXITED(status) && WEXITSTATUS(status) == 0;
#endif
    if (!read_output || !detector_succeeded) {
        return false;
    }

    std::string virtualization(output);
    while (!virtualization.empty() &&
           (virtualization.back() == '\n' || virtualization.back() == '\r' ||
            virtualization.back() == ' ' || virtualization.back() == '\t')) {
        virtualization.pop_back();
    }
    return !virtualization.empty() && virtualization != "none";
#endif
}

bool parse_positive_option(const std::string& argument,
                          const std::string& name,
                          unsigned long& value) {
    const std::string prefix = "--" + name + "=";
    if (argument.compare(0, prefix.size(), prefix) != 0) {
        return false;
    }

    const std::string number = argument.substr(prefix.size());
    if (number.empty() || number.front() == '-') {
        return false;
    }

    errno = 0;
    char* end = nullptr;
    const unsigned long parsed = std::strtoul(number.c_str(), &end, 10);
    if (errno == ERANGE || end == number.c_str() || *end != '\0') {
        return false;
    }
    value = parsed;
    return true;
}

bool parse_options(int argc, char* argv[], SimulatorOptions& options) {
    for (int index = 1; index < argc; ++index) {
        const std::string argument(argv[index]);
        if (argument == "--i-am-in-a-vm") {
            options.vm_override = true;
            continue;
        }

        unsigned long parsed_value = 0;
        if (parse_positive_option(argument, "files", parsed_value)) {
            options.files = parsed_value;
        } else if (parse_positive_option(argument, "children", parsed_value)) {
            options.children = parsed_value;
        } else if (parse_positive_option(argument, "mem-mb", parsed_value)) {
            options.mem_mb = parsed_value;
        } else {
            std::cerr << "Unknown or invalid option: " << argument << '\n'
                      << "Usage: " << argv[0]
                      << " [--files=N] [--children=N] [--mem-mb=N] [--i-am-in-a-vm]\n";
            return false;
        }
    }
    return true;
}
#endif

}  // namespace

#ifndef SIMULATOR_NO_MAIN
int main(int argc, char* argv[]) {
    AuditLogger logger;
    logger.log("simulator_start");

    SimulatorOptions options;
    if (!parse_options(argc, argv, options)) {
        logger.log("invalid_cli_options");
        return EXIT_FAILURE;
    }

    if (!validate_sandbox_path("./test_env")) {
        logger.log("sandbox_validation_failed");
        std::cerr << "Refusing to run: ./test_env is not a valid resolved sandbox path.\n";
        return EXIT_FAILURE;
    }

    if (!options.vm_override && !detect_vm()) {
        logger.log("vm_confirmation_failed");
        std::cerr << "WARNING: VM or sandbox execution could not be confirmed.\n"
                  << "Refusing to run without --i-am-in-a-vm.\n";
        return EXIT_FAILURE;
    }

    logger.log("safety_checks_passed");
    if (!populate_files(options.files) || !rename_files_locked(options.files)) {
        logger.log("file_phase_failed");
        std::cerr << "File phase failed inside the sandbox.\n";
        return EXIT_FAILURE;
    }
    logger.log("file_phase_completed files=" + std::to_string(options.files));
    if (!spawn_children(options.children)) {
        logger.log("spawn_phase_failed");
        std::cerr << "Process spawn phase failed.\n";
        return EXIT_FAILURE;
    }
    logger.log("spawn_phase_completed children=" + std::to_string(options.children));
    if (!allocate_and_touch(options.mem_mb)) {
        logger.log("memory_phase_failed");
        std::cerr << "Memory phase failed.\n";
        return EXIT_FAILURE;
    }
    logger.log("memory_phase_completed mb=" + std::to_string(options.mem_mb));
    std::cout << "Simulator phases completed successfully.\n"
              << "Configuration: files=" << options.files
              << ", children=" << options.children
              << ", mem-mb=" << options.mem_mb << '\n';
    return EXIT_SUCCESS;
}
#endif
