#include "simulator.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <iterator>
#include <random>
#include <string>
#include <vector>

namespace {

std::vector<std::vector<unsigned char>> content_cases() {
    std::mt19937 generator(0x5EEDU);
    std::vector<std::vector<unsigned char>> cases;
    cases.reserve(100);
    for (std::size_t index = 0; index < 100; ++index) {
        const std::size_t length = (index * 83U) % 8193U;
        std::vector<unsigned char> content(length);
        for (unsigned char& byte : content) {
            byte = static_cast<unsigned char>(generator() & 0xFFU);
        }
        cases.push_back(std::move(content));
    }
    return cases;
}

class FileLockTest : public ::testing::TestWithParam<std::vector<unsigned char>> {};

TEST_P(FileLockTest, RenameRoundTripPreservesContent) {
    const std::vector<unsigned char>& expected = GetParam();
    const std::string source = "./test_env/property_roundtrip.dat";
    const std::string locked = source + ".simlocked";

    ASSERT_TRUE(validate_sandbox_path(source));
    ASSERT_TRUE(validate_sandbox_path(locked));

    {
        std::ofstream output(source, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(output);
        output.write(reinterpret_cast<const char*>(expected.data()),
                     static_cast<std::streamsize>(expected.size()));
        ASSERT_TRUE(output);
    }

    ASSERT_EQ(std::rename(source.c_str(), locked.c_str()), 0);
    ASSERT_EQ(std::rename(locked.c_str(), source.c_str()), 0);

    std::ifstream input(source, std::ios::binary);
    ASSERT_TRUE(input);
    const std::vector<unsigned char> actual(
        std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    EXPECT_EQ(actual, expected);
    input.close();
    EXPECT_EQ(std::remove(source.c_str()), 0);
}

INSTANTIATE_TEST_SUITE_P(
    Property2,
    FileLockTest,
    ::testing::ValuesIn(content_cases()));

}  // namespace
