#include "simulator.h"

#include <limits.h>

#include <gtest/gtest.h>

#include <string>
#include <utility>
#include <vector>

namespace {

using SandboxPathCase = std::pair<std::string, bool>;

std::vector<SandboxPathCase> sandbox_path_cases() {
    char resolved_sandbox[PATH_MAX];
    if (realpath("./test_env", resolved_sandbox) == nullptr) {
        return {};
    }
    const std::string sandbox(resolved_sandbox);

    std::vector<SandboxPathCase> cases;
    cases.reserve(120);
    for (int index = 0; index < 60; ++index) {
        cases.emplace_back("./test_env/.gitkeep", true);
        cases.emplace_back(sandbox + "/.gitkeep", true);
        cases.emplace_back("./test_env/../test_env/.gitkeep", true);
        cases.emplace_back("./test_env/../include/metrics.h", false);
        cases.emplace_back("./test_env/../../.gitignore", false);
        cases.emplace_back("./include/metrics.h", false);
    }
    return cases;
}

class SandboxPathTest : public ::testing::TestWithParam<SandboxPathCase> {};

TEST_P(SandboxPathTest, AcceptsOnlyResolvedPathsInsideSandbox) {
    const SandboxPathCase& test_case = GetParam();
    EXPECT_EQ(validate_sandbox_path(test_case.first), test_case.second)
        << "path: " << test_case.first;
}

INSTANTIATE_TEST_SUITE_P(
    Property1,
    SandboxPathTest,
    ::testing::ValuesIn(sandbox_path_cases()));

}  // namespace
