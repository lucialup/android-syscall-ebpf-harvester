#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "../common.h"
#include "bpf_maps.h"
#include "bpf_utils.h"

struct sockaddr_in {
	__u16 sin_family;
	__u16 sin_port;
	__u32 sin_addr;
	__u8  sin_zero[8];
};

struct sockaddr_in6 {
	__u16 sin6_family;
	__u16 sin6_port;
	__u32 sin6_flowinfo;
	__u8  sin6_addr[16];
	__u32 sin6_scope_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(struct syscall_event));
	__uint(max_entries, 10240);
} connect_inflight SEC(".maps");

/*
 * Kprobe for connect syscall - entry point
 */
SEC("kprobe/__x64_sys_connect")
int trace_connect(struct pt_regs *ctx)
{
	struct syscall_event event = {};
	struct pt_regs *regs;
	__u32 pid, tid;
	__u64 pid_tgid;
	int sockfd;
	const void *addr_ptr;
	__u16 family;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	tid = (__u32)pid_tgid;

	if (should_filter_pid(pid))
		return 0;

	regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
	bpf_probe_read(&sockfd, sizeof(sockfd), &PT_REGS_PARM1(regs));
	bpf_probe_read(&addr_ptr, sizeof(addr_ptr), &PT_REGS_PARM2(regs));

	if (!addr_ptr)
		return 0;

	bpf_probe_read_user(&family, sizeof(family), addr_ptr);

	init_event(&event, pid, tid, SYSCALL_CONNECT);
	event.fd = sockfd;
	event.flags = family;

	if (family == AF_INET) {
		struct sockaddr_in addr4 = {};

		bpf_probe_read_user(&addr4, sizeof(addr4), addr_ptr);
		event.actual_count = bpf_ntohs(addr4.sin_port);
		__builtin_memcpy(event.filename, &addr4.sin_addr, sizeof(addr4.sin_addr));
	} else if (family == AF_INET6) {
		struct sockaddr_in6 addr6 = {};

		bpf_probe_read_user(&addr6, sizeof(addr6), addr_ptr);
		event.actual_count = bpf_ntohs(addr6.sin6_port);
		__builtin_memcpy(event.filename, addr6.sin6_addr, sizeof(addr6.sin6_addr));
	} else {
		return 0;
	}

	bpf_map_update_elem(&connect_inflight, &pid_tgid, &event, BPF_ANY);

	return 0;
}

/*
 * Kretprobe for connect syscall - return point
 * Log all connection attempts, successful or not
 */
SEC("kretprobe/__x64_sys_connect")
int trace_connect_ret(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct syscall_event *event;

	event = bpf_map_lookup_elem(&connect_inflight, &pid_tgid);
	if (!event)
		return 0;

	bpf_map_delete_elem(&connect_inflight, &pid_tgid);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      event, sizeof(*event));

	return 0;
}

/*
 * Kprobe for socket syscall - entry point
 */
SEC("kprobe/__x64_sys_socket")
int trace_socket(struct pt_regs *ctx)
{
	struct syscall_event event = {};
	struct pt_regs *regs;
	__u32 pid, tid;
	__u64 pid_tgid;
	int domain, type;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	tid = (__u32)pid_tgid;

	if (should_filter_pid(pid))
		return 0;

	regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
	bpf_probe_read(&domain, sizeof(domain), &PT_REGS_PARM1(regs));
	bpf_probe_read(&type, sizeof(type), &PT_REGS_PARM2(regs));

	if (domain != AF_INET && domain != AF_INET6 && domain != AF_UNIX)
		return 0;

	type &= 0xF;

	init_event(&event, pid, tid, SYSCALL_SOCKET);
	event.flags = ((__u64)type << 32) | (__u32)domain;

	bpf_map_update_elem(&socket_inflight, &pid_tgid, &event, BPF_ANY);

	return 0;
}

/*
 * Kretprobe for socket syscall - return point
 */
SEC("kretprobe/__x64_sys_socket")
int trace_socket_ret(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct syscall_event *event;
	int fd;

	event = bpf_map_lookup_elem(&socket_inflight, &pid_tgid);
	if (!event)
		return 0;

	fd = (int)PT_REGS_RC(ctx);
	if (fd < 0)
		goto cleanup;

	event->fd = fd;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      event, sizeof(*event));

cleanup:
	bpf_map_delete_elem(&socket_inflight, &pid_tgid);
	return 0;
}
