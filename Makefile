CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -pedantic  -Isrc -Isrc/ai_engine -Isrc/core -Isrc/api -Isrc/networking -Isrc/smart_contracts -Isrc/storage -I/usr/local/include 

SRC_DIR = src
BUILD_DIR = build

# Find all source files for the main application
APP_SRCS = $(shell find $(SRC_DIR) -name '*.cpp')
APP_OBJS = $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(APP_SRCS))

# Find all source files for the tests
TEST_SRC_DIR = tests
TEST_SRCS = $(shell find $(TEST_SRC_DIR) -name '*.cpp')
TEST_OBJS = $(patsubst $(TEST_SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(TEST_SRCS))

TARGET = $(BUILD_DIR)/platireum_node
TEST_EXECUTABLE = $(BUILD_DIR)/poc_tests

all: $(TARGET) $(TEST_EXECUTABLE)

$(TARGET): $(APP_OBJS)
	@mkdir -p $(@D)
	$(CXX) $(APP_OBJS) -o $@ $(CXXFLAGS) -lcrypto -lssl 

$(TEST_EXECUTABLE): $(TEST_OBJS) $(filter-out $(BUILD_DIR)/main.o, $(APP_OBJS))
	@mkdir -p $(@D)
	$(CXX) $(TEST_OBJS) $(filter-out $(BUILD_DIR)/main.o, $(APP_OBJS)) -o $@ $(CXXFLAGS) -lcrypto -lssl -L/usr/local/lib -lgtest -lgtest_main -pthread

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(TEST_SRC_DIR)/%.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean test

test: $(TEST_EXECUTABLE)
	@echo "\nRunning PoC Tests..."
	./$(TEST_EXECUTABLE)

