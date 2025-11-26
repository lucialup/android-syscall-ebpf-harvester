#ifndef BPF_MAPS_H
#define BPF_MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../common.h"

/*
 * Perf event array for sending events to userspace
 * bpf_perf_event_output() sends events through this map
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 0);
} events SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1);
} filter_pid SEC(".maps");

/*
 * open_inflight tracks open/openat calls between entry and exit
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(struct syscall_event));
	__uint(max_entries, 10240);
} open_inflight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(struct syscall_event));
	__uint(max_entries, 10240);
} read_inflight SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(struct syscall_event));
	__uint(max_entries, 10240);
} write_inflight SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(struct syscall_event));
	__uint(max_entries, 10240);
} clone_inflight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(struct syscall_event));
	__uint(max_entries, 10240);
} execve_inflight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(struct syscall_event));
	__uint(max_entries, 10240);
} mmap_inflight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(struct syscall_event));
	__uint(max_entries, 10240);
} socket_inflight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(struct syscall_event));
	__uint(max_entries, 10240);
} unlinkat_inflight SEC(".maps");

struct fd_key {
	__u32 pid;
	__u32 fd;
};

/*
 * Map file descriptors to their paths
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct fd_key));
	__uint(value_size, MAX_PATH_LEN);
	__uint(max_entries, 65536);
} fd_to_path SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct fd_key));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 10240);
} unknown_fd_count SEC(".maps");

#endif /* BPF_MAPS_H */
