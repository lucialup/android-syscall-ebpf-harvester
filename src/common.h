#ifndef SYSCALL_HARVESTER_COMMON_H
#define SYSCALL_HARVESTER_COMMON_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <linux/types.h>
#endif

#define SYSCALL_OPEN    1
#define SYSCALL_OPENAT  2
#define SYSCALL_CLOSE   3
#define SYSCALL_READ    4
#define SYSCALL_WRITE   5
#define SYSCALL_CLONE   6
#define SYSCALL_EXECVE  7
#define SYSCALL_CONNECT 8
#define SYSCALL_MMAP    9
#define SYSCALL_SOCKET  10

#define MAX_PATH_LEN 256
#define EXECVE_PATH_MAX 80
#define EXECVE_ARG_MAX 30
#define EXECVE_ARGC_MAX 5

#define EXECVE_SEPARATOR_OFFSET 80
#define EXECVE_ARGV_START_OFFSET 83

#define CLONE_VM      0x00000100
#define CLONE_THREAD  0x00010000

#ifndef AF_UNIX
#define AF_UNIX       1
#endif
#ifndef AF_INET
#define AF_INET       2
#endif
#ifndef AF_INET6
#define AF_INET6      10
#endif

/* mmap protection flags */
#ifndef PROT_READ
#define PROT_READ     0x1
#endif
#ifndef PROT_WRITE
#define PROT_WRITE    0x2
#endif
#ifndef PROT_EXEC
#define PROT_EXEC     0x4
#endif

/* mmap flags */
#ifndef MAP_SHARED
#define MAP_SHARED    0x01
#endif
#ifndef MAP_PRIVATE
#define MAP_PRIVATE   0x02
#endif
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif

/* socket types */
#ifndef SOCK_STREAM
#define SOCK_STREAM   1
#endif
#ifndef SOCK_DGRAM
#define SOCK_DGRAM    2
#endif
#ifndef SOCK_RAW
#define SOCK_RAW      3
#endif

/*
 * The syscall structure uses fields differently based on syscall_type:
 *
 * File operations (open/read/write/close):
 *   - filename: file path
 *   - fd: file descriptor
 *   - flags: open flags (open/openat) or byte count (read/write)
 *   - actual_count: bytes read/written (read/write)
 *
 * Process operations (clone/execve):
 *   - filename: executable path + argv (execve)
 *   - flags: clone flags
 *   - actual_count: child PID (clone)
 *
 * Network operations (connect):
 *   - filename: IP address as raw bytes
 *   - fd: socket file descriptor
 *   - flags: address family (AF_INET=2, AF_INET6=10)
 *   - actual_count: port number
 *
 * Network operations (socket):
 *   - fd: returned socket file descriptor
 *   - flags: family (lower 32 bits) | type (upper 32 bits)
 *
 * Memory operations (mmap):
 *   - filename: file path (from fd_to_path) or empty for anonymous
 *   - fd: file descriptor (-1 for MAP_ANONYMOUS)
 *   - flags: prot (lower 32 bits) | mmap_flags (upper 32 bits)
 */
struct syscall_event {
	__u32 pid;
	__u32 tid;
	__u32 syscall_type;
	__u32 uid;
	__u64 ts;
	__u64 flags;
	int fd;
	__s64 actual_count;
	char comm[16];
	char filename[256];
} __attribute__((packed));

#endif /* SYSCALL_HARVESTER_COMMON_H */
