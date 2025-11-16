# Usage Guide

### Start Collecting data
```bash
adb shell
cd /data/local/tmp/syscall-harvester
./syscall_harvester
```

### Output Example
```
My PID: 12345 (will be filtered out)
Attempting to open: ./syscall_harvester_kern.o
Successfully opened BPF object file
Successfully loaded BPF program
Filter configured: excluding PID 12345
Successfully attached BPF programs

=======================================================================
Tracing open() syscalls with filters enabled
Filtered out: /etc/localtime, /proc/*, /sys/*, /dev/urandom, PID 12345
Press Ctrl+C to stop.
=======================================================================
TIMESTAMP            PID      FLAGS                          FILENAME
-----------------------------------------------------------------------
ts=14:23:45.123456789 pid=5678 flags=0x0 (O_RDONLY) filename="/data/app/com.example.app/base.apk"
ts=14:23:45.234567890 pid=5678 flags=0x241 (O_WRONLY|O_CREAT|O_TRUNC) filename="/sdcard/Download/suspicious.apk"
```


## Dataset Collection Workflow
