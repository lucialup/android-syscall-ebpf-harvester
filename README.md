# Android Syscall Harvester

**eBPF-based syscall tracer for building malware detection datasets on Android**

## Overview

This project uses eBPF (extended Berkeley Packet Filter) to capture syscall traces on Android OS for malware detection research. It hooks into the Linux kernel to monitor syscalls with minimal overhead.

## Purpose

Create labeled datasets of syscall behavior from:
- **Benign applications** - Normal Android apps from Play Store
- **Malware samples** - Known malicious applications

## Syscalls Monitored

- **open/openat** - File opens (path, flags, fd)
- **read** - File reads (path, fd, bytes requested/actual)
- **write** - File writes (path, fd, bytes requested/actual)
- **close** - File closes (path, fd)
- **clone** - Process/thread creation (parent PID, child PID, flags, type)
- **execve** - Program execution (path, argv array with up to 5 arguments)

## Architecture

```
┌─────────────────────────────────────────┐
│     Android App (Benign/Malware)       │
│         ↓ file I/O syscalls             │
├─────────────────────────────────────────┤
│          Linux Kernel                   │
│                                         │
│   open/read/write/close syscall hooks  │
│              ↓ kprobe                   │
│   ┌─────────────────────────────────┐  │
│   │  eBPF Program (kernel space)    │  │
│   │  - Capture metadata             │  │
│   │  - FD→path tracking             │  │
│   │  - Filter noise & rate limit    │  │
│   │  - Send to userspace            │  │
│   └─────────────────────────────────┘  │
│              ↓ perf buffer              │
├─────────────────────────────────────────┤
│   Userspace Tracer                      │
│   - Process events                      │
│   - Format & log to stdout/file         │
│   - Label: benign/malware               │
└─────────────────────────────────────────┘
```

## Improvements

### Filtering
- Self-PID filtering to prevent infinite loops
- Path-based filtering (/proc, /sys, /dev/urandom)
- Rate limiting for unknown file descriptors (3 events per FD)
- stdin/stdout/stderr exclusion for read syscalls

### FD Tracking
- Maps file descriptors to paths via open/openat
- Resolves paths for read/close operations
- Handles unknown FDs gracefully (inherited, sockets, pipes)

## Starting manual

### Prerequisites

- Android emulator or rooted device
- BPF-enabled kernel (Android 14+ recommended)
- adb installed
- Linux host system with clang and gcc

### Build

```bash
make
```

### Deploy to Emulator

```bash
make deploy
```

### Run

```bash
# On Android emulator
adb shell
cd /data/local/tmp/bpf
./syscall_harvester
```

## Output Format

```
ts=10:30:45.123456789 syscall=openat pid=5678 uid=10123 path="/data/app/config.db" fd=7 flags=0x0
ts=10:30:45.123567890 syscall=read pid=5678 uid=10123 path="/data/app/config.db" fd=7 count=4096 actual=2048
ts=10:30:45.123678901 syscall=write pid=5678 uid=10123 path="/data/app/config.db" fd=7 count=512 actual=512
ts=10:30:45.123789012 syscall=close pid=5678 uid=10123 path="/data/app/config.db" fd=7
ts=10:30:45.124001234 syscall=clone pid=5678 uid=10123 child_pid=5680 flags=0x1200011 type=process
ts=10:30:45.124112345 syscall=execve pid=5680 uid=10123 path="/system/bin/sh" argv=["/system/bin/sh", "-c", "rm -rf /data/app"]
```

**Fields:**
- `ts` - Timestamp (HH:MM:SS.nanoseconds)
- `syscall` - Syscall name (open/openat/read/write/close/clone/execve)
- `pid` - Process ID
- `uid` - User ID (Android app identifier: 0=root, 1000-1999=system, 10000+=apps)
- `path` - File path (empty for unknown FDs)
- `fd` - File descriptor number
- `flags` - Open flags (open/openat only) or clone flags (clone only)
- `count` - Bytes requested (read/write only)
- `actual` - Bytes actually read/written (read/write only)
- `child_pid` - Child process ID (clone only)
- `type` - Process creation type: process/thread/lightweight_process (clone only)
- `argv` - Command-line arguments as JSON array, up to 5 args (execve only)

## Project Structure

```
android-syscall-harvester/
├── src/
│   ├── syscall_harvester_kern.c    # eBPF kernel program
│   └── syscall_harvester_user.c    # Userspace collector
├── include/                         # Required headers
├── lib/                             # libbpf static library
├── Makefile                         # Build system
├── scripts/
│   ├── deploy.sh                   # Deploy to device
│   ├── collect_dataset.sh          # Automated collection
│   └── test.sh                     # Test script
├── docs/
│   ├── ARCHITECTURE.md
│   ├── DATASET_FORMAT.md
│   └── SYSCALLS.md
└── README.md
```


## License

GPL-2.0 (eBPF programs must be GPL-compatible)


## References

- [eBPF Documentation](https://ebpf.io/)
- [libbpf GitHub](https://github.com/libbpf/libbpf)
- [BPF Performance Tools](http://www.brendangregg.com/ebpf.html)
