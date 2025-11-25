#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../common.h"
#include "bpf_maps.h"
#include "bpf_utils.h"

/*
 * Kprobe for clone syscall - entry point
 */
SEC("kprobe/__x64_sys_clone")
int trace_clone(struct pt_regs *ctx)
{
	struct syscall_event event = {};
	struct pt_regs *regs;
	__u32 pid, tid;
	__u64 pid_tgid;
	unsigned long clone_flags;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	tid = (__u32)pid_tgid;

	if (should_filter_pid(pid))
		return 0;

	regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
	bpf_probe_read(&clone_flags, sizeof(clone_flags), &PT_REGS_PARM1(regs));

	init_event(&event, pid, tid, SYSCALL_CLONE);
	event.flags = clone_flags;
	event.fd = 0;
	event.actual_count = 0;
	event.filename[0] = '\0';

	bpf_map_update_elem(&clone_inflight, &pid_tgid, &event, BPF_ANY);

	return 0;
}

/*
 * Kretprobe for clone syscall - return
 * Captures: child PID (return value)
 */
SEC("kretprobe/__x64_sys_clone")
int trace_clone_ret(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct syscall_event *event;
	long ret;

	event = bpf_map_lookup_elem(&clone_inflight, &pid_tgid);
	if (!event)
		return 0;

	ret = PT_REGS_RC(ctx);

	bpf_map_delete_elem(&clone_inflight, &pid_tgid);

	if (ret <= 0)
		return 0;

	/* Store child PID in actual_count field */
	event->actual_count = ret;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      event, sizeof(*event));

	return 0;
}

/* ========== EXECVE SYSCALL ========== */

/*
 * Kprobe for execve syscall - entry point
 *
 * Buffer layout:
 *   [0-79]:    Executable path
 *   [80-82]:   Separator " | "
 *   [83-112]:  argv[0]
 *   [113-142]: argv[1]
 *   [143-172]: argv[2]
 *   [173-202]: argv[3]
 *   [203-232]: argv[4]
 */
SEC("kprobe/__x64_sys_execve")
int trace_execve(struct pt_regs *ctx)
{
	struct syscall_event event = {};
	struct pt_regs *regs;
	const char *filename;
	const char **argv;
	const char *arg_ptr;
	__u32 pid, tid;
	__u64 pid_tgid;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	tid = (__u32)pid_tgid;

	if (should_filter_pid(pid))
		return 0;

	regs = (struct pt_regs *)PT_REGS_PARM1(ctx);

	bpf_probe_read(&filename, sizeof(filename), &PT_REGS_PARM1(regs));

	init_event(&event, pid, tid, SYSCALL_EXECVE);
	event.fd = 0;
	event.flags = 0;
	event.actual_count = 0;

	bpf_probe_read_user_str(&event.filename, EXECVE_PATH_MAX, filename);

	if (should_filter_file(event.filename))
		return 0;

	bpf_probe_read(&argv, sizeof(argv), &PT_REGS_PARM2(regs));

	event.filename[EXECVE_SEPARATOR_OFFSET] = ' ';
	event.filename[EXECVE_SEPARATOR_OFFSET + 1] = '|';
	event.filename[EXECVE_SEPARATOR_OFFSET + 2] = ' ';

	/*
	 * Concatenate up to EXECVE_ARGC_MAX argv strings at fixed offsets
	 * Each arg is placed at EXECVE_ARGV_START_OFFSET + i * EXECVE_ARG_MAX
	 */
	if (argv) {
		#pragma unroll
		for (int i = 0; i < EXECVE_ARGC_MAX; i++) {
			int offset = EXECVE_ARGV_START_OFFSET + (i * EXECVE_ARG_MAX);

			bpf_probe_read(&arg_ptr, sizeof(arg_ptr), &argv[i]);
			if (arg_ptr) {
				bpf_probe_read_user_str(&event.filename[offset], EXECVE_ARG_MAX, arg_ptr);
				if (i < EXECVE_ARGC_MAX - 1) {
					event.filename[offset + EXECVE_ARG_MAX - 1] = ' ';
				}
			}
		}
	}

	bpf_map_update_elem(&execve_inflight, &pid_tgid, &event, BPF_ANY);

	return 0;
}

/*
 * Kretprobe for execve syscall - return point
 */
SEC("kretprobe/__x64_sys_execve")
int trace_execve_ret(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct syscall_event *event;
	long ret;

	event = bpf_map_lookup_elem(&execve_inflight, &pid_tgid);
	if (!event)
		return 0;

	ret = PT_REGS_RC(ctx);

	bpf_map_delete_elem(&execve_inflight, &pid_tgid);

	if (ret != 0)
		return 0;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      event, sizeof(*event));

	return 0;
}
