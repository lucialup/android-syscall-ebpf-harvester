#include <stdio.h>
#include <time.h>
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
