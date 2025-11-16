# Android Syscall Harvester

**eBPF-based syscall tracer for building malware detection datasets on Android**

## Overview

This project uses eBPF (extended Berkeley Packet Filter) to capture syscall traces on Android OS for malware detection research. It currently hooks into the Linux kernel to monitor `open()` and `openat()` syscalls with minimal overhead (to be extended).

## Purpose

Create labeled datasets of syscall behavior from:
- **Benign applications** - Normal Android apps from Play Store
- **Malware samples** - Known malicious applications

## Architecture

```
┌─────────────────────────────────────────┐
│     Android App (Benign/Malware)       │
│              ↓ syscalls                 │
├─────────────────────────────────────────┤
│          Linux Kernel                   │
│                                         │
│   open/openat syscall entry points     │
│              ↓ kprobe hook              │
│   ┌─────────────────────────────────┐  │
│   │  eBPF Program (kernel space)    │  │
│   │  - Capture PID, filename, flags │  │
│   │  - Filter noise                 │  │
│   │  - Send to userspace            │  │
│   └─────────────────────────────────┘  │
│              ↓ perf buffer              │
├─────────────────────────────────────────┤
│   Userspace Tracer                      │
│   - Read events                         │
│   - Format & log to file                │
│   - Label: benign/malware               │
└─────────────────────────────────────────┘
```

## Quick Start

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
