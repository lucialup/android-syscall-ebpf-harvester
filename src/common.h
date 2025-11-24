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

#define MAX_PATH_LEN 256
#define EXECVE_PATH_MAX 80
#define EXECVE_ARG_MAX 30
#define EXECVE_ARGC_MAX 5

#define EXECVE_SEPARATOR_OFFSET 80
#define EXECVE_ARGV_START_OFFSET 83

#define CLONE_VM      0x00000100
#define CLONE_THREAD  0x00010000

/*
 * The syscall structure uses a single char buffer (filename[256]) that has
 * different purposes depending on syscall_type:
 * - For file operations: stores path
 * - For execve: stores path + separator + argv array at fixed offsets
 */
struct syscall_event {
	__u32 pid;
	__u32 syscall_type;
	__u32 uid;
	__u32 _pad;
	__u64 ts;
	__u64 flags;     
	int fd;              
	__s64 actual_count;
	char filename[256];
} __attribute__((packed));

#endif /* SYSCALL_HARVESTER_COMMON_H */
