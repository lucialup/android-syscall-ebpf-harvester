#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../common.h"
#include "bpf_maps.h"
#include "bpf_utils.h"

/*
 * Kprobe for mmap syscall - entry point
 */
SEC("kprobe/__x64_sys_mmap")
int trace_mmap(struct pt_regs *ctx)
{
	struct syscall_event event = {};
	struct pt_regs *regs;
	__u32 pid, tid, uid;
	__u64 pid_tgid;
	int fd;
	unsigned long prot;
	unsigned long mmap_flags;
	struct fd_key fdk = {};
	char *path_ptr;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	tid = (__u32)pid_tgid;

	if (should_filter_pid(pid))
		return 0;

	uid = (__u32)bpf_get_current_uid_gid();
	if (should_filter_uid(uid))
		return 0;

	regs = (struct pt_regs *)PT_REGS_PARM1(ctx);

	if (bpf_probe_read(&prot, sizeof(prot), &PT_REGS_PARM3(regs)) < 0)
		return 0;
	if (bpf_probe_read(&mmap_flags, sizeof(mmap_flags), &PT_REGS_PARM4(regs)) < 0)
		return 0;
	if (bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM5(regs)) < 0)
		return 0;

	init_event(&event, pid, tid, SYSCALL_MMAP);

	event.flags = ((__u64)(mmap_flags & 0xFFFFFFFF) << 32) | (prot & 0xFFFFFFFF);
	event.fd = fd;
	event.filename[0] = '\0';

	if (fd >= 0) {
		fdk.pid = pid;
		fdk.fd = fd;
		path_ptr = bpf_map_lookup_elem(&fd_to_path, &fdk);
		if (path_ptr) {
			if (should_filter_file(path_ptr))
				return 0;
			if (bpf_probe_read(event.filename, sizeof(event.filename), path_ptr) < 0)
				return 0;
		}
	} else {
		if (!(prot & PROT_EXEC))
			return 0;
	}

	bpf_map_update_elem(&mmap_inflight, &pid_tgid, &event, BPF_ANY);

	return 0;
}

/*
 * Kretprobe for mmap syscall - return point
 */
SEC("kretprobe/__x64_sys_mmap")
int trace_mmap_ret(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct syscall_event *event;
	unsigned long ret;

	event = bpf_map_lookup_elem(&mmap_inflight, &pid_tgid);
	if (!event)
		return 0;

	ret = PT_REGS_RC(ctx);

	bpf_map_delete_elem(&mmap_inflight, &pid_tgid);

	if (ret == (unsigned long)-1)
		return 0;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      event, sizeof(*event));

	return 0;
}
