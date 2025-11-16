# Compiler settings
CLANG := clang
LLC := llc
GCC := gcc

# Target architecture
ARCH := x86
TARGET_ARCH := -D__TARGET_ARCH_$(ARCH)

# Directories
SRC_DIR := src
BUILD_DIR := build
INCLUDE_DIR := include
LIB_DIR := lib

# Output files
BPF_OBJ := $(BUILD_DIR)/syscall_harvester_kern.o
USER_BIN := $(BUILD_DIR)/syscall_harvester

# BPF compilation flags
BPF_CFLAGS := -O2 \
	-target bpf \
	-g \
	$(TARGET_ARCH) \
	-I$(INCLUDE_DIR) \
	-I$(INCLUDE_DIR)/uapi \
	-Wall \
	-Wno-unused-value \
	-Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types

# Userspace compilation flags
USER_CFLAGS := -Wall \
	-O2 \
	-static \
	-I$(INCLUDE_DIR) \
	-I$(INCLUDE_DIR)/bpf

USER_LDFLAGS := -L$(LIB_DIR) \
	-l:libbpf.a \
	-lelf \
	-lz

.PHONY: all clean deploy test help

# Default target
all: $(BUILD_DIR) $(BPF_OBJ) $(USER_BIN)
	@echo "=========================================="
	@echo "Build complete!"
	@echo "  BPF object: $(BPF_OBJ)"
	@echo "  Binary:     $(USER_BIN)"
	@echo "=========================================="

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# Compile BPF program
$(BPF_OBJ): $(SRC_DIR)/syscall_harvester_kern.c | $(BUILD_DIR)
	@echo "Compiling BPF kernel program..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "✓ BPF compilation successful"

# Compile userspace program
$(USER_BIN): $(SRC_DIR)/syscall_harvester_user.c $(BPF_OBJ) | $(BUILD_DIR)
	@echo "Compiling userspace program..."
	$(GCC) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)
	@echo "Userspace compilation successful"

# Deploy to Android device/emulator
deploy: all
	@echo "Deploying to Android device..."
	@adb shell "mkdir -p /data/local/tmp/syscall-harvester" || true
	@adb push $(USER_BIN) /data/local/tmp/syscall-harvester/
	@adb push $(BPF_OBJ) /data/local/tmp/syscall-harvester/syscall_harvester_kern.o
	@adb shell "chmod +x /data/local/tmp/syscall-harvester/syscall_harvester"
	@echo "Deployment complete!"
	@echo ""
	@echo "To run on device:"
	@echo "  adb shell"
	@echo "  cd /data/local/tmp/syscall-harvester"
	@echo "  ./syscall_harvester"

# Test (requires device/emulator)
test: deploy
	@echo "Running test..."
	@./scripts/test.sh

# Clean build artifacts
clean:
	@echo "Cleaning artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete"