#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../common.h"
#include "bpf_maps.h"
#include "bpf_utils.h"


/*
 * Kprobe for openat syscall - entry point
 * Captures filename and flags
 */
SEC("kprobe/__x64_sys_openat")
int trace_openat(struct pt_regs *ctx)
{
	struct syscall_event event = {};
	struct pt_regs *regs;
	const char *filename;
	__u32 pid, tid;
	__u64 pid_tgid;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	tid = (__u32)pid_tgid;

	if (should_filter_pid(pid))
		return 0;

	regs = (struct pt_regs *)PT_REGS_PARM1(ctx);

	bpf_probe_read(&filename, sizeof(filename), &PT_REGS_PARM2(regs));
	bpf_probe_read(&event.flags, sizeof(event.flags), &PT_REGS_PARM3(regs));

	init_event(&event, pid, tid, SYSCALL_OPENAT);
	event.fd = -1;

	bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);

	if (should_filter_file(event.filename))
		return 0;

	bpf_map_update_elem(&open_inflight, &pid_tgid, &event, BPF_ANY);

	return 0;
}

/*
 * Kretprobe for openat syscall - return point
 */
SEC("kretprobe/__x64_sys_openat")
int trace_openat_ret(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	struct syscall_event *event;
	int fd;
	struct fd_key fdk = {};

	event = bpf_map_lookup_elem(&open_inflight, &pid_tgid);
	if (!event)
		return 0;

	fd = PT_REGS_RC(ctx);

	bpf_map_delete_elem(&open_inflight, &pid_tgid);

	if (fd < 0)
		return 0;

	event->fd = fd;

	/* Store fd -> path mapping for later use by read/write/close */
	fdk.pid = pid;
	fdk.fd = fd;
	bpf_map_update_elem(&fd_to_path, &fdk, event->filename, BPF_ANY);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      event, sizeof(*event));

	return 0;
}

/*
 * Kprobe for open syscall - entry point
 */
SEC("kprobe/__x64_sys_open")
int trace_open(struct pt_regs *ctx)
{
	struct syscall_event event = {};
	struct pt_regs *regs;
	const char *filename;
	__u32 pid, tid;
	__u64 pid_tgid;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	tid = (__u32)pid_tgid;

	if (should_filter_pid(pid))
		return 0;

	regs = (struct pt_regs *)PT_REGS_PARM1(ctx);

	bpf_probe_read(&filename, sizeof(filename), &PT_REGS_PARM1(regs));
	bpf_probe_read(&event.flags, sizeof(event.flags), &PT_REGS_PARM2(regs));

	init_event(&event, pid, tid, SYSCALL_OPEN);
	event.fd = -1;

	bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);

	if (should_filter_file(event.filename))
		return 0;

	bpf_map_update_elem(&open_inflight, &pid_tgid, &event, BPF_ANY);

	return 0;
}

/*
 * Kretprobe for open syscall - return point
 */
SEC("kretprobe/__x64_sys_open")
int trace_open_ret(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	struct syscall_event *event;
	int fd;
	struct fd_key fdk = {};

	event = bpf_map_lookup_elem(&open_inflight, &pid_tgid);
	if (!event)
		return 0;

	fd = PT_REGS_RC(ctx);

	bpf_map_delete_elem(&open_inflight, &pid_tgid);

	if (fd < 0)
		return 0;

	event->fd = fd;

	fdk.pid = pid;
	fdk.fd = fd;
	bpf_map_update_elem(&fd_to_path, &fdk, event->filename, BPF_ANY);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      event, sizeof(*event));

	return 0;
}


/*
 * Kprobe for close syscall
 */
SEC("kprobe/__x64_sys_close")
int trace_close(struct pt_regs *ctx)
{
	struct syscall_event event = {};
	struct pt_regs *regs;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct fd_key fdk = {};
	char *path_ptr;
	int fd;

	if (should_filter_pid(pid))
		return 0;

	regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
	bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(regs));

	fdk.pid = pid;
	fdk.fd = fd;
	path_ptr = bpf_map_lookup_elem(&fd_to_path, &fdk);
	if (!path_ptr)
		return 0;

	init_event(&event, pid, tid, SYSCALL_CLOSE);
	event.flags = 0;
	event.fd = fd;

	bpf_probe_read(event.filename, sizeof(event.filename), path_ptr);

	/* Clean up fd_to_path entry */
	bpf_map_delete_elem(&fd_to_path, &fdk);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

	return 0;
}


/*
 * Kprobe for read syscall - entry point
 * Captures fd and count (bytes to read)
 */
SEC("kprobe/__x64_sys_read")
int trace_read(struct pt_regs *ctx)
{
	struct syscall_event event = {};
	struct pt_regs *regs;
	__u32 pid, tid;
	__u64 pid_tgid;
	int fd;
	long count;
	struct fd_key fdk = {};
	char *path_ptr;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	tid = (__u32)pid_tgid;

	if (should_filter_pid(pid))
		return 0;

	regs = (struct pt_regs *)PT_REGS_PARM1(ctx);

	bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(regs));
	bpf_probe_read(&count, sizeof(count), &PT_REGS_PARM3(regs));

	/* Filter stdin/stdout/stderr to avoid console spam */
	if (fd <= 2)
		return 0;

	init_event(&event, pid, tid, SYSCALL_READ);
	event.fd = fd;
	event.flags = count;  /* Store requested count in flags */
	event.actual_count = 0;

	fdk.pid = pid;
	fdk.fd = fd;
	path_ptr = bpf_map_lookup_elem(&fd_to_path, &fdk);
	if (path_ptr) {
		if (should_filter_file(path_ptr))
			return 0;
		bpf_probe_read(event.filename, sizeof(event.filename), path_ptr);
	} else {
		/* Unknown FD - rate limit to 3 events per FD */
		__u32 *count_ptr = bpf_map_lookup_elem(&unknown_fd_count, &fdk);
		__u32 unknown_count = 0;

		if (count_ptr) {
			unknown_count = *count_ptr;
			if (unknown_count >= 3)
				return 0;
		}

		unknown_count++;
		bpf_map_update_elem(&unknown_fd_count, &fdk, &unknown_count, BPF_ANY);

		event.filename[0] = '\0';
	}

	bpf_map_update_elem(&read_inflight, &pid_tgid, &event, BPF_ANY);

	return 0;
}

/*
 * Kretprobe for read syscall - return point
 * Capturesac atual bytes read
 */
SEC("kretprobe/__x64_sys_read")
int trace_read_ret(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct syscall_event *event;
	long ret;

	event = bpf_map_lookup_elem(&read_inflight, &pid_tgid);
	if (!event)
		return 0;

	ret = PT_REGS_RC(ctx);

	bpf_map_delete_elem(&read_inflight, &pid_tgid);

	if (ret < 0)
		return 0;

	event->actual_count = ret;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      event, sizeof(*event));

	return 0;
}


/*
 * Kprobe for write syscall - entry point
 */
SEC("kprobe/__x64_sys_write")
int trace_write(struct pt_regs *ctx)
{
	struct syscall_event event = {};
	struct pt_regs *regs;
	__u32 pid, tid;
	__u64 pid_tgid;
	int fd;
	long count;
	struct fd_key fdk = {};
	char *path_ptr;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	tid = (__u32)pid_tgid;

	if (should_filter_pid(pid))
		return 0;

	regs = (struct pt_regs *)PT_REGS_PARM1(ctx);

	bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(regs));
	bpf_probe_read(&count, sizeof(count), &PT_REGS_PARM3(regs));

	if (fd <= 2)
		return 0;

	init_event(&event, pid, tid, SYSCALL_WRITE);
	event.fd = fd;
	event.flags = count;
	event.actual_count = 0;

	fdk.pid = pid;
	fdk.fd = fd;
	path_ptr = bpf_map_lookup_elem(&fd_to_path, &fdk);
	if (path_ptr) {
		if (should_filter_file(path_ptr))
			return 0;
		bpf_probe_read(event.filename, sizeof(event.filename), path_ptr);
	} else {
		__u32 *count_ptr = bpf_map_lookup_elem(&unknown_fd_count, &fdk);
		__u32 unknown_count = 0;

		if (count_ptr) {
			unknown_count = *count_ptr;
			if (unknown_count >= 3)
				return 0;
		}

		unknown_count++;
		bpf_map_update_elem(&unknown_fd_count, &fdk, &unknown_count, BPF_ANY);

		event.filename[0] = '\0';
	}

	bpf_map_update_elem(&write_inflight, &pid_tgid, &event, BPF_ANY);

	return 0;
}

/*
 * Kretprobe for write syscall - return point
 */
SEC("kretprobe/__x64_sys_write")
int trace_write_ret(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct syscall_event *event;
	long ret;

	event = bpf_map_lookup_elem(&write_inflight, &pid_tgid);
	if (!event)
		return 0;

	ret = PT_REGS_RC(ctx);

	bpf_map_delete_elem(&write_inflight, &pid_tgid);

	if (ret < 0)
		return 0;

	event->actual_count = ret;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      event, sizeof(*event));

	return 0;
}

char _license[] SEC("license") = "GPL";
