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
- **close** - File closes (path, fd)

## Architecture

```
┌─────────────────────────────────────────┐
│     Android App (Benign/Malware)       │
│         ↓ file I/O syscalls             │
├─────────────────────────────────────────┤
│          Linux Kernel                   │
│                                         │
│   open/read/close syscall hooks        │
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
ts=10:30:45.123456789 syscall=openat pid=5678 path="/data/app/config.db" fd=7 flags=0x0
ts=10:30:45.123567890 syscall=read pid=5678 path="/data/app/config.db" fd=7 count=4096 actual=2048
ts=10:30:45.123678901 syscall=close pid=5678 path="/data/app/config.db" fd=7
```

**Fields:**
- `ts` - Timestamp (HH:MM:SS.nanoseconds)
- `syscall` - Syscall name (open/openat/read/close)
- `pid` - Process ID
- `path` - File path (empty for unknown FDs)
- `fd` - File descriptor number
- `flags` - Open flags (open/openat only)
- `count` - Bytes requested (read only)
- `actual` - Bytes actually read (read only)

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
