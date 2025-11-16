#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct open_event {
	__u32 pid;
	__u64 ts;
	long flags;
	char filename[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 0);
} events SEC(".maps");

/* Map to store the PID of the openlog process itself */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1);
} filter_pid SEC(".maps");

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

/* Kprobe for openat syscall */
SEC("kprobe/__x64_sys_openat")
int trace_openat(struct pt_regs *ctx)
{
	struct open_event event = {};
	struct pt_regs *regs;
	const char *filename;
	__u32 pid;
	__u32 key = 0;
	__u32 *filter_pid_ptr;

	pid = bpf_get_current_pid_tgid() >> 32;

	filter_pid_ptr = bpf_map_lookup_elem(&filter_pid, &key);
	if (filter_pid_ptr && *filter_pid_ptr == pid) {
		return 0;
	}

	regs = (struct pt_regs *)PT_REGS_PARM1(ctx);

	bpf_probe_read(&filename, sizeof(filename), &PT_REGS_PARM2(regs));
	bpf_probe_read(&event.flags, sizeof(event.flags), &PT_REGS_PARM3(regs));

	event.pid = pid;
	event.ts = bpf_ktime_get_ns();

	bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);

	if (should_filter_file(event.filename))
		return 0;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

	return 0;
}

SEC("kprobe/__x64_sys_open")
int trace_open(struct pt_regs *ctx)
{
	struct open_event event = {};
	struct pt_regs *regs;
	const char *filename;
	__u32 pid;
	__u32 key = 0;
	__u32 *filter_pid_ptr;

	pid = bpf_get_current_pid_tgid() >> 32;

	filter_pid_ptr = bpf_map_lookup_elem(&filter_pid, &key);
	if (filter_pid_ptr && *filter_pid_ptr == pid) {
		return 0; 
	}

	regs = (struct pt_regs *)PT_REGS_PARM1(ctx);

	bpf_probe_read(&filename, sizeof(filename), &PT_REGS_PARM1(regs));
	bpf_probe_read(&event.flags, sizeof(event.flags), &PT_REGS_PARM2(regs));

	event.pid = pid;
	event.ts = bpf_ktime_get_ns();

	bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);

	if (should_filter_file(event.filename))
		return 0;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

	return 0;
}

char _license[] SEC("license") = "GPL";
