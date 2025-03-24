BINARY := fastscan

SRC_DIR := ./src
BUILD_DIR := ./build

CXX ?= clang++
SYSROOT ?= /

CXX_FLAGS := -std=c++20 -IThirdParty/fmt/include --sysroot=$(SYSROOT)
LDFLAGS := 

SRCS := $(shell find $(SRC_DIR) -name '*.cpp')
OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)

$(BUILD_DIR)/$(BINARY): $(OBJS)
	$(CXX) $(OBJS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.cpp.o: %.cpp
	mkdir -p $(dir $@)
	$(CXX) $(CXX_FLAGS) -c $< -o $@

run: $(BUILD_DIR)/$(BINARY)
	./$(BUILD_DIR)/$(BINARY)
install:
	install $(BUILD_DIR)/$(BINARY) $(SYSROOT)/bin

.PHONY: clean
clean:
	rm -r $(BUILD_DIR)

