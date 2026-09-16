CXX := g++

CPPFLAGS := -Iinclude
CXXFLAGS := -std=c++17 -Wall -Wextra -Wpedantic -pthread
LDFLAGS := -pthread

BIN_DIR := bin
SRC_DIR := src
TEST_DIR := tests

SIMULATOR_OBJECTS := $(BIN_DIR)/simulator.o
MONITOR_OBJECTS := $(BIN_DIR)/monitor.o $(BIN_DIR)/proc_reader.o
TEST_SOURCES := $(wildcard $(TEST_DIR)/*.cpp)
TEST_OBJECTS := $(patsubst $(TEST_DIR)/%.cpp,$(BIN_DIR)/tests_%.o,$(TEST_SOURCES))

.PHONY: all monitor proc_reader stage2 clean clean-sandbox

all: bin/simulator

monitor: bin/monitor

proc_reader: $(BIN_DIR)/proc_reader.o

stage2: bin/monitor

bin/simulator: $(SIMULATOR_OBJECTS) | $(BIN_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

bin/monitor: $(MONITOR_OBJECTS) | $(BIN_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

bin/tests: $(TEST_OBJECTS) $(BIN_DIR)/simulator_test.o | $(BIN_DIR)
	$(CXX) $(LDFLAGS) $^ -lgtest -lgtest_main -o $@

$(BIN_DIR)/simulator.o: $(SRC_DIR)/simulator.cpp | $(BIN_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

$(BIN_DIR)/monitor.o: $(SRC_DIR)/monitor.cpp | $(BIN_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

$(BIN_DIR)/proc_reader.o: $(SRC_DIR)/proc_reader.cpp | $(BIN_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

$(BIN_DIR)/simulator_test.o: $(SRC_DIR)/simulator.cpp | $(BIN_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -DSIMULATOR_NO_MAIN -c $< -o $@

$(BIN_DIR)/tests_%.o: $(TEST_DIR)/%.cpp | $(BIN_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

$(BIN_DIR):
	mkdir -p $@

clean:
	rm -rf $(BIN_DIR)

clean-sandbox:
	rm -rf test_env/* test_env/.[!.]* test_env/..?* logs/* logs/.[!.]* logs/..?*
	touch test_env/.gitkeep logs/.gitkeep