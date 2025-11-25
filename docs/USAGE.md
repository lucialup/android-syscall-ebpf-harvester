# Usage Guide

## Start Collecting Data

```bash
adb shell
cd /data/local/tmp/syscall-harvester
./syscall_harvester
```

## Output Example

```
=======================================================================
Tracing open/openat/close/read/write/clone/execve syscalls
Filtered out: /etc/localtime, /proc/*, /sys/*, /dev/urandom, PID 12345
Press Ctrl+C to stop.
=======================================================================

ts=14:23:45.123456789 syscall=openat pid=5678 tid=5680 uid=10123 comm="RenderThread" path="/data/app/com.example.app/base.apk" fd=7 flags=0x0
ts=14:23:45.234567890 syscall=read pid=5678 tid=5680 uid=10123 comm="RenderThread" path="/data/app/com.example.app/base.apk" fd=7 count=4096 actual=2048
ts=14:23:45.345678901 syscall=openat pid=5678 tid=5681 uid=10123 comm="OkHttp Dispatch" path="/data/data/com.example.app/cache/http" fd=8 flags=0x0
```

## Data Collection Workflow
