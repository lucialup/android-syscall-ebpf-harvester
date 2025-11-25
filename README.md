# Android Syscall Harvester

**eBPF-based syscall tracer for dynamic SBOM extraction on Android**

## Overview

This project uses eBPF (extended Berkeley Packet Filter) to capture syscall traces on Android OS for dynamic Software Bill of Materials (SBOM) extraction. It hooks into the Linux kernel to monitor syscalls with minimal overhead, capturing component behavior for AI-based dependency analysis.

## Purpose

Generate a syscall dataset from Android applications to enable:
- **Dynamic SBOM extraction** - Identify software components and dependencies at runtime
- **GNN-based analysis** - Use Graph Neural Networks to model component relationships
- **Dependency mapping** - Track which components access which resources

## Syscalls Monitored

- **open/openat** - File opens (pid, tid, uid, comm, path, flags, fd)
- **read** - File reads (pid, tid, uid, comm, path, fd, bytes requested/actual)
- **write** - File writes (pid, tid, uid, comm, path, fd, bytes requested/actual)
- **close** - File closes (pid, tid, uid, comm, path, fd)
- **clone** - Process/thread creation (tid, uid, comm, parent PID, child PID, flags, type)
- **execve** - Program execution (pid, tid, uid, comm, path, argv array with up to 5 arguments)
 
## Architecture

```
┌─────────────────────────────────────────┐
│          Android Application            │
│    (multiple threads & components)      │
│         ↓ syscalls                      │
├─────────────────────────────────────────┤
│          Linux Kernel                   │
│                                         │
│   open/read/write/close/clone/execve   │
│              ↓ kprobe                   │
│   ┌─────────────────────────────────┐  │
│   │  eBPF Program (kernel space)    │  │
│   │  - Capture pid/tid/uid/comm     │  │
│   │  - FD→path tracking             │  │
│   │  - Filter noise & rate limit    │  │
│   │  - Send to userspace            │  │
│   └─────────────────────────────────┘  │
│              ↓ perf buffer              │
├─────────────────────────────────────────┤
│   Userspace Tracer                      │
│   - Process events                      │
│   - Format & log to stdout/file         │
│   - Component-level tracking            │
└─────────────────────────────────────────┘
          ↓
┌─────────────────────────────────────────┐
│   AI/GNN Analysis                       │
│   - Build component dependency graph    │
│   - Extract dynamic SBOM                │
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
cd /data/local/tmp/syscall-harvester
./syscall_harvester
```

## Output Format

```
ts=10:30:45.123456789 syscall=openat pid=5678 tid=5680 uid=10123 comm="RenderThread" path="/data/app/config.db" fd=7 flags=0x0
ts=10:30:45.123567890 syscall=read pid=5678 tid=5680 uid=10123 comm="RenderThread" path="/data/app/config.db" fd=7 count=4096 actual=2048
ts=10:30:45.123678901 syscall=write pid=5678 tid=5681 uid=10123 comm="AsyncTask #1" path="/data/app/config.db" fd=7 count=512 actual=512
ts=10:30:45.123789012 syscall=close pid=5678 tid=5680 uid=10123 comm="RenderThread" path="/data/app/config.db" fd=7
ts=10:30:45.124001234 syscall=clone pid=5678 tid=5678 uid=10123 comm="main" child_pid=5682 flags=0x1200011 type=process
ts=10:30:45.124112345 syscall=execve pid=5682 tid=5682 uid=10123 comm="main" path="/system/bin/sh" argv=["/system/bin/sh", "-c", "ls"]
```

**Fields:**
- `ts` - Timestamp (HH:MM:SS.nanoseconds)
- `syscall` - Syscall name (open/openat/read/write/close/clone/execve)
- `pid` - Process ID (TGID - thread group ID)
- `tid` - Thread ID (unique per thread, useful for multi-threaded component tracking)
- `uid` - User ID (Android app identifier: 0=root, 1000-1999=system, 10000+=apps)
- `comm` - Task/thread name (e.g., "RenderThread", "AsyncTask #1", "OkHttp Dispatch")
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
│   ├── syscall_harvester_kern.c    # BPF main file (includes handlers)
│   ├── common.h                     # Shared type definitions (syscall_event struct)
│   ├── bpf/
│   │   ├── bpf_maps.h              # BPF map definitions
│   │   ├── bpf_utils.h             # Utilities & filters (init_event, filtering)
│   │   ├── file_syscalls.bpf.c    # File I/O handlers (open/read/write/close)
│   │   └── process_syscalls.bpf.c # Process lifecycle handlers (clone/execve)
│   └── userspace/
│       ├── bpf_loader.{c,h}        # BPF loading & management
│       ├── output.{c,h}            # Event formatting (tid/comm output)
│       └── main.c                  # Program entry point
├── include/                         # Required headers (libbpf, uapi)
├── lib/                             # libbpf static library
├── Makefile                         # Build system
├── scripts/
│   ├── deploy.sh                   # Deploy to device
│   └── test.sh                     # Test script
├── docs/
│   ├── BUILD.md                    # Build instructions
│   └── USAGE.md                    # Usage guide
└── README.md
```


## License

GPL-2.0 (eBPF programs must be GPL-compatible)


## References

- [eBPF Documentation](https://ebpf.io/)
- [libbpf GitHub](https://github.com/libbpf/libbpf)
- [BPF Performance Tools](http://www.brendangregg.com/ebpf.html)
