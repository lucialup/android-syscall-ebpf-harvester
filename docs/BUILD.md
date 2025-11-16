# Build Details

## Prerequisites

### Host Requirements
- **Linux** (tested on Ubuntu 20.04+)
- **clang** 10+ with BPF support
- **gcc** with static linking support
- **make**
- **adb** (Android Debug Bridge)

### Install Dependencies (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install clang llvm gcc make android-tools-adb libelf-dev zlib1g-dev
```

### Android Device/Emulator Requirements
- **BPF-enabled kernel** (Android 14+ recommended)
- **Root access** (for loading BPF programs)
- **Architecture**: x86_64 (can be adapted for ARM)

## Build Commands

### 1. Build
```bash
make clean
make
```

### 2. Build Output
```
build/
├── syscall_harvester_kern.o    # eBPF kernel program (17 KB)
└── syscall_harvester            # Userspace binary (1.6 MB, static)
```

### 3. Verify Build
```bash
file build/syscall_harvester_kern.o
file build/syscall_harvester
```

## Deployment

### Quick Deploy
```bash
make deploy
```

### Manual Deploy
```bash
adb shell "mkdir -p /data/local/tmp/syscall-harvester"

adb push build/syscall_harvester /data/local/tmp/syscall-harvester/
adb push build/syscall_harvester_kern.o /data/local/tmp/syscall-harvester/

adb shell "chmod +x /data/local/tmp/syscall-harvester/syscall_harvester"
```

## Running

```bash
adb shell

cd /data/local/tmp/syscall-harvester

./syscall_harvester
```