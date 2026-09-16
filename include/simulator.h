#pragma once

#include <string>

bool validate_sandbox_path(const std::string& target_path);
bool populate_files(unsigned long count);
bool rename_files_locked(unsigned long count);
bool spawn_children(unsigned long count);
bool allocate_and_touch(unsigned long megabytes);
