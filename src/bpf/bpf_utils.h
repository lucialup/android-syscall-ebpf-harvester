#ifndef BPF_UTILS_H
#define BPF_UTILS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_maps.h"

/*
Character-by-character comparison for BPF verifier compatibility
 */
static __always_inline int starts_with(const char *str, const char *prefix, int prefix_len)
{
	for (int i = 0; i < prefix_len && i < 255; i++) {
		if (str[i] != prefix[i])
			return 0;
		if (str[i] == '\0')
			return 0;
	}
	return 1;
}

static __always_inline int should_filter_file(const char *filename)
{
	if (starts_with(filename, "/etc/localtime", 14))
		return 1;

	if (starts_with(filename, "/proc/", 6))
		return 1;

	if (starts_with(filename, "/sys/", 5))
		return 1;

	if (starts_with(filename, "/dev/urandom", 12))
		return 1;
	if (starts_with(filename, "/dev/random", 11))
		return 1;

	return 0;
}

/*
 * Returns 1 if the PID should be filtered out (not traced)
 * Filters the tracer process itself to prevent infinite loops
 */
static __always_inline int should_filter_pid(__u32 pid)
{
	__u32 key = 0;
	__u32 *filter_pid_ptr;

	filter_pid_ptr = bpf_map_lookup_elem(&filter_pid, &key);
	if (filter_pid_ptr && *filter_pid_ptr == pid) {
		return 1;
	}

	return 0;
}


static __always_inline void init_event(struct syscall_event *event, __u32 pid, __u32 tid, __u32 syscall_type)
{
	event->pid = pid;
	event->tid = tid;
	event->uid = (__u32)bpf_get_current_uid_gid();
	event->syscall_type = syscall_type;
	event->ts = bpf_ktime_get_ns();
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
}

#endif /* BPF_UTILS_H */
