#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include "../common.h"
#include "output.h"

static const int argv_offsets[] = {83, 113, 143, 173, 203};


static const char *syscall_type_to_name(__u32 syscall_type)
{
	switch (syscall_type) {
	case SYSCALL_OPEN:
		return "open";
	case SYSCALL_OPENAT:
		return "openat";
	case SYSCALL_CLOSE:
		return "close";
	case SYSCALL_READ:
		return "read";
	case SYSCALL_WRITE:
		return "write";
	case SYSCALL_CLONE:
		return "clone";
	case SYSCALL_EXECVE:
		return "execve";
	case SYSCALL_CONNECT:
		return "connect";
	case SYSCALL_MMAP:
		return "mmap";
	default:
		return "unknown";
	}
}


static void print_timestamp(__u64 ts)
{
	time_t sec = ts / 1000000000ULL;
	long nsec = ts % 1000000000ULL;
	struct tm *tm_info = localtime(&sec);
	char timebuf[64];

	strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm_info);
	printf("ts=%s.%09ld ", timebuf, nsec);
}

static const char *get_clone_type(__u64 flags)
{
	if (flags & CLONE_THREAD) {
		return "thread";
	} else if (flags & CLONE_VM) {
		return "lightweight_process";
	} else {
		return "process";
	}
}

static const char *get_family_name(__u64 family)
{
	switch (family) {
	case AF_INET:
		return "ipv4";
	case AF_INET6:
		return "ipv6";
	case AF_UNIX:
		return "unix";
	default:
		return "unknown";
	}
}

static const char *format_mmap_prot(__u32 prot)
{
	static char buf[8];
	int pos = 0;

	if (prot == 0)
		return "NONE";

	if (prot & PROT_READ)
		buf[pos++] = 'r';
	if (prot & PROT_WRITE)
		buf[pos++] = 'w';
	if (prot & PROT_EXEC)
		buf[pos++] = 'x';

	buf[pos] = '\0';
	return buf;
}

static const char *get_mmap_flags_str(__u32 mmap_flags)
{
	int is_anon = mmap_flags & MAP_ANONYMOUS;
	int is_private = mmap_flags & MAP_PRIVATE;
	int is_shared = mmap_flags & MAP_SHARED;

	if (is_private && is_anon)
		return "private_anon";
	if (is_shared && is_anon)
		return "shared_anon";
	if (is_private)
		return "private";
	if (is_shared)
		return "shared";
	if (is_anon)
		return "anon";
	return "file";
}

static void format_ip_address(const char *raw_bytes, __u64 family, char *buf, size_t buf_size)
{
	const char *result = NULL;

	if (family == AF_INET)
		result = inet_ntop(AF_INET, raw_bytes, buf, buf_size);
	else if (family == AF_INET6)
		result = inet_ntop(AF_INET6, raw_bytes, buf, buf_size);

	if (!result)
		snprintf(buf, buf_size, "unknown");
}

/*
 * Handle and format syscall event for output
 * Called by perf buffer callback
 */
void output_event(const struct syscall_event *e)
{
	const char *syscall_name = syscall_type_to_name(e->syscall_type);

	print_timestamp(e->ts);

	switch (e->syscall_type) {
	case SYSCALL_OPEN:
	case SYSCALL_OPENAT:
		printf("syscall=%s pid=%u tid=%u uid=%u comm=\"%s\" path=\"%s\" fd=%d flags=0x%llx\n",
		       syscall_name, e->pid, e->tid, e->uid, e->comm, e->filename, e->fd,
		       (unsigned long long)e->flags);
		break;

	case SYSCALL_CLOSE:
		printf("syscall=%s pid=%u tid=%u uid=%u comm=\"%s\" path=\"%s\" fd=%d\n",
		       syscall_name, e->pid, e->tid, e->uid, e->comm, e->filename, e->fd);
		break;

	case SYSCALL_READ:
	case SYSCALL_WRITE:
		printf("syscall=%s pid=%u tid=%u uid=%u comm=\"%s\" path=\"%s\" fd=%d count=%llu actual=%lld\n",
		       syscall_name, e->pid, e->tid, e->uid, e->comm, e->filename, e->fd,
		       (unsigned long long)e->flags, (long long)e->actual_count);
		break;

	case SYSCALL_CLONE:
		printf("syscall=%s pid=%u tid=%u uid=%u comm=\"%s\" child_pid=%lld flags=0x%llx type=%s\n",
		       syscall_name, e->pid, e->tid, e->uid, e->comm, (long long)e->actual_count,
		       (unsigned long long)e->flags, get_clone_type(e->flags));
		break;

	case SYSCALL_EXECVE: {
		int first = 1;

		printf("syscall=%s pid=%u tid=%u uid=%u comm=\"%s\" path=\"%s\" argv=[",
		       syscall_name, e->pid, e->tid, e->uid, e->comm, e->filename);

		for (int i = 0; i < EXECVE_ARGC_MAX; i++) {
			if (e->filename[argv_offsets[i]]) {
				if (!first)
					printf(", ");
				printf("\"%s\"", &e->filename[argv_offsets[i]]);
				first = 0;
			}
		}

		printf("]\n");
		break;
	}

	case SYSCALL_CONNECT: {
		char ip_buf[64];
		format_ip_address(e->filename, e->flags, ip_buf, sizeof(ip_buf));

		printf("syscall=%s pid=%u tid=%u uid=%u comm=\"%s\" fd=%d family=\"%s\" ip=\"%s\" port=%lld\n",
		       syscall_name, e->pid, e->tid, e->uid, e->comm, e->fd,
		       get_family_name(e->flags), ip_buf, (long long)e->actual_count);
		break;
	}

	case SYSCALL_MMAP: {
		__u32 prot = (__u32)(e->flags & 0xFFFFFFFF);
		__u32 mmap_flags = (__u32)(e->flags >> 32);

		printf("syscall=%s pid=%u tid=%u uid=%u comm=\"%s\" path=\"%s\" fd=%d "
		       "prot=\"%s\" flags=\"%s\"\n",
		       syscall_name, e->pid, e->tid, e->uid, e->comm, e->filename, e->fd,
		       format_mmap_prot(prot), get_mmap_flags_str(mmap_flags));
		break;
	}

	default:
		printf("syscall=%s pid=%u tid=%u uid=%u comm=\"%s\" (unknown format)\n",
		       syscall_name, e->pid, e->tid, e->uid, e->comm);
		break;
	}
}


void output_lost_events(int cpu, unsigned long long lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}
