#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define SYSCALL_OPEN    1
#define SYSCALL_OPENAT  2
#define SYSCALL_CLOSE   3
#define SYSCALL_READ    4

struct open_event {
	__u32 pid;
	__u32 syscall_type;
	__u64 ts;
	long flags;
	int fd;
	long actual_count;
	char filename[256];
} __attribute__((packed));

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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64));  // pid_tgid
	__uint(value_size, sizeof(struct open_event));
	__uint(max_entries, 10240);
} open_inflight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64)); 
	__uint(value_size, sizeof(struct open_event));
	__uint(max_entries, 10240);
} read_inflight SEC(".maps");

struct fd_key {
	__u32 pid;
	__u32 fd;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct fd_key));
	__uint(value_size, 256);
	__uint(max_entries, 65536);
} fd_to_path SEC(".maps");

/* Rate limiting for unknown FDs: track read count per FD */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct fd_key));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 10240);
} unknown_fd_count SEC(".maps");

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

/* Kprobe for openat syscall - entry */
SEC("kprobe/__x64_sys_openat")
int trace_openat(struct pt_regs *ctx)
{
	struct open_event event = {};
	struct pt_regs *regs;
	const char *filename;
	__u32 pid;
	__u32 key = 0;
	__u32 *filter_pid_ptr;
	__u64 pid_tgid;

	pid = bpf_get_current_pid_tgid() >> 32;
	pid_tgid = bpf_get_current_pid_tgid();

	filter_pid_ptr = bpf_map_lookup_elem(&filter_pid, &key);
	if (filter_pid_ptr && *filter_pid_ptr == pid) {
		return 0;
	}

	regs = (struct pt_regs *)PT_REGS_PARM1(ctx);

	bpf_probe_read(&filename, sizeof(filename), &PT_REGS_PARM2(regs));
	bpf_probe_read(&event.flags, sizeof(event.flags), &PT_REGS_PARM3(regs));

	event.pid = pid;
	event.syscall_type = SYSCALL_OPENAT;
	event.ts = bpf_ktime_get_ns();
	event.fd = -1;

	bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);

	if (should_filter_file(event.filename))
		return 0;

	bpf_map_update_elem(&open_inflight, &pid_tgid, &event, BPF_ANY);

	return 0;
}

/* Kretprobe for openat syscall - return */
SEC("kretprobe/__x64_sys_openat")
int trace_openat_ret(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	struct open_event *event;
	int fd;
	struct fd_key fdk = {};

	event = bpf_map_lookup_elem(&open_inflight, &pid_tgid);
	if (!event)
		return 0;

	fd = PT_REGS_RC(ctx);

	bpf_map_delete_elem(&open_inflight, &pid_tgid);

	if (fd < 0) {
		return 0;
	}

	event->fd = fd;

	fdk.pid = pid;
	fdk.fd = fd;
	bpf_map_update_elem(&fd_to_path, &fdk, event->filename, BPF_ANY);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      event, sizeof(*event));

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
	__u64 pid_tgid;

	pid = bpf_get_current_pid_tgid() >> 32;
	pid_tgid = bpf_get_current_pid_tgid();

	filter_pid_ptr = bpf_map_lookup_elem(&filter_pid, &key);
	if (filter_pid_ptr && *filter_pid_ptr == pid) {
		return 0;
	}

	regs = (struct pt_regs *)PT_REGS_PARM1(ctx);

	bpf_probe_read(&filename, sizeof(filename), &PT_REGS_PARM1(regs));
	bpf_probe_read(&event.flags, sizeof(event.flags), &PT_REGS_PARM2(regs));

	event.pid = pid;
	event.syscall_type = SYSCALL_OPEN;
	event.ts = bpf_ktime_get_ns();
	event.fd = -1;

	bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);

	if (should_filter_file(event.filename))
		return 0;

	bpf_map_update_elem(&open_inflight, &pid_tgid, &event, BPF_ANY);

	return 0;
}

/* Kretprobe for open syscall - return */
SEC("kretprobe/__x64_sys_open")
int trace_open_ret(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	struct open_event *event;
	int fd;
	struct fd_key fdk = {};

	event = bpf_map_lookup_elem(&open_inflight, &pid_tgid);
	if (!event)
		return 0;

	fd = PT_REGS_RC(ctx);

	bpf_map_delete_elem(&open_inflight, &pid_tgid);

	if (fd < 0) {
		return 0;
	}

	event->fd = fd;

	fdk.pid = pid;
	fdk.fd = fd;
	bpf_map_update_elem(&fd_to_path, &fdk, event->filename, BPF_ANY);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      event, sizeof(*event));

	return 0;
}

SEC("kprobe/__x64_sys_close")
int trace_close(struct pt_regs *ctx)
{
	struct open_event event = {};  // Using open_event to match size
	struct pt_regs *regs;
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u32 key = 0;
	__u32 *filter_pid_ptr;
	struct fd_key fdk = {};
	char *path_ptr;
	int fd;

	filter_pid_ptr = bpf_map_lookup_elem(&filter_pid, &key);
	if (filter_pid_ptr && *filter_pid_ptr == pid) {
		return 0;
	}

	regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
	bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(regs));

	fdk.pid = pid;
	fdk.fd = fd;
	path_ptr = bpf_map_lookup_elem(&fd_to_path, &fdk);
	if (!path_ptr) {
		return 0;
	}

	event.pid = pid;
	event.syscall_type = SYSCALL_CLOSE;
	event.ts = bpf_ktime_get_ns();
	event.flags = 0;
	event.fd = fd;

	bpf_probe_read(event.filename, sizeof(event.filename), path_ptr);

	bpf_map_delete_elem(&fd_to_path, &fdk);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

	return 0;
}

/* Kprobe for read syscall - entry */
SEC("kprobe/__x64_sys_read")
int trace_read(struct pt_regs *ctx)
{
	struct open_event event = {};
	struct pt_regs *regs;
	__u32 pid;
	__u32 key = 0;
	__u32 *filter_pid_ptr;
	__u64 pid_tgid;
	int fd;
	long count;
	struct fd_key fdk = {};
	char *path_ptr;

	pid = bpf_get_current_pid_tgid() >> 32;
	pid_tgid = bpf_get_current_pid_tgid();

	filter_pid_ptr = bpf_map_lookup_elem(&filter_pid, &key);
	if (filter_pid_ptr && *filter_pid_ptr == pid) {
		return 0;
	}

	regs = (struct pt_regs *)PT_REGS_PARM1(ctx);

	bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(regs));
	bpf_probe_read(&count, sizeof(count), &PT_REGS_PARM3(regs));

	/* Filter stdin/stdout/stderr to avoid console spam */
	if (fd <= 2) {
		return 0;
	}

	event.pid = pid;
	event.syscall_type = SYSCALL_READ;
	event.ts = bpf_ktime_get_ns();
	event.fd = fd;
	event.flags = count; 
	event.actual_count = 0;

	fdk.pid = pid;
	fdk.fd = fd;
	path_ptr = bpf_map_lookup_elem(&fd_to_path, &fdk);
	if (path_ptr) {
		if (should_filter_file(path_ptr)) {
			return 0;
		}
		bpf_probe_read(event.filename, sizeof(event.filename), path_ptr);
	} else {
		__u32 *count_ptr = bpf_map_lookup_elem(&unknown_fd_count, &fdk);
		__u32 count = 0;

		if (count_ptr) {
			count = *count_ptr;
			if (count >= 3) {
				return 0;
			}
		}

		count++;
		bpf_map_update_elem(&unknown_fd_count, &fdk, &count, BPF_ANY);

		event.filename[0] = '\0';
	}

	bpf_map_update_elem(&read_inflight, &pid_tgid, &event, BPF_ANY);

	return 0;
}

/* Kretprobe for read syscall - return */
SEC("kretprobe/__x64_sys_read")
int trace_read_ret(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct open_event *event;
	long ret;

	event = bpf_map_lookup_elem(&read_inflight, &pid_tgid);
	if (!event)
		return 0;

	ret = PT_REGS_RC(ctx);

	bpf_map_delete_elem(&read_inflight, &pid_tgid);

	if (ret < 0) {
		return 0;
	}

	event->actual_count = ret;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      event, sizeof(*event));

	return 0;
}

char _license[] SEC("license") = "GPL";
