CLANG := clang
LLC := llc
GCC := gcc

ARCH := x86
TARGET_ARCH := -D__TARGET_ARCH_$(ARCH)

SRC_DIR := src
BPF_DIR := $(SRC_DIR)/bpf
USERSPACE_DIR := $(SRC_DIR)/userspace
BUILD_DIR := build
INCLUDE_DIR := include
LIB_DIR := lib

BPF_OBJ := $(BUILD_DIR)/syscall_harvester_kern.o
USER_BIN := $(BUILD_DIR)/syscall_harvester

BPF_SOURCE := $(SRC_DIR)/syscall_harvester_kern.c

USER_SOURCES := $(USERSPACE_DIR)/main.c $(USERSPACE_DIR)/bpf_loader.c $(USERSPACE_DIR)/output.c
USER_OBJECTS := $(patsubst $(USERSPACE_DIR)/%.c,$(BUILD_DIR)/%.o,$(USER_SOURCES))

BPF_CFLAGS := -O2 \
	-target bpf \
	-g \
	$(TARGET_ARCH) \
	-I$(INCLUDE_DIR) \
	-I$(INCLUDE_DIR)/uapi \
	-I$(SRC_DIR) \
	-Wall \
	-Wno-unused-value \
	-Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types

USER_CFLAGS := -Wall \
	-O2 \
	-static \
	-I$(INCLUDE_DIR) \
	-I$(INCLUDE_DIR)/bpf \
	-I$(SRC_DIR)

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

# Compile BPF kernel program
$(BPF_OBJ): $(BPF_SOURCE) $(BPF_DIR)/*.c $(BPF_DIR)/*.h $(SRC_DIR)/common.h | $(BUILD_DIR)
	@echo "Compiling BPF kernel program..."
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SOURCE) -o $@
	@echo "✓ BPF compilation successful"

# Compile userspace source files to object files
$(BUILD_DIR)/%.o: $(USERSPACE_DIR)/%.c $(USERSPACE_DIR)/*.h $(SRC_DIR)/common.h | $(BUILD_DIR)
	@echo "Compiling userspace: $<"
	$(GCC) $(USER_CFLAGS) -c $< -o $@

# Link userspace objects into final binary
$(USER_BIN): $(USER_OBJECTS) $(BPF_OBJ) | $(BUILD_DIR)
	@echo "Linking userspace binary..."
	$(GCC) $(USER_CFLAGS) $(USER_OBJECTS) -o $@ $(USER_LDFLAGS)
	@echo "✓ Userspace compilation successful"

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

clean:
	@echo "Cleaning artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete"