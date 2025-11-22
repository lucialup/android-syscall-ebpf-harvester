#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define SYSCALL_OPEN    1
#define SYSCALL_OPENAT  2
#define SYSCALL_CLOSE   3
#define SYSCALL_READ    4
#define SYSCALL_WRITE   5

// Number of BPF programs: openat, openat_ret, open, open_ret, close, read, read_ret, write, write_ret
#define NUM_BPF_PROGRAMS 9

struct open_event {
	__u32 pid;
	__u32 syscall_type;
	__u32 uid;
	__u32 _pad;
	__u64 ts;
	long flags;
	int fd;
	long actual_count;
	char filename[256];
} __attribute__((packed));

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static void print_flags(long flags)
{
	printf("flags=0x%lx (", flags);

	if (flags & O_RDONLY) printf("O_RDONLY|");
	if (flags & O_WRONLY) printf("O_WRONLY|");
	if (flags & O_RDWR) printf("O_RDWR|");
	if (flags & O_CREAT) printf("O_CREAT|");
	if (flags & O_EXCL) printf("O_EXCL|");
	if (flags & O_TRUNC) printf("O_TRUNC|");
	if (flags & O_APPEND) printf("O_APPEND|");
	if (flags & O_NONBLOCK) printf("O_NONBLOCK|");
	if (flags & O_SYNC) printf("O_SYNC|");
	if (flags & O_DIRECTORY) printf("O_DIRECTORY|");
	if (flags & O_CLOEXEC) printf("O_CLOEXEC|");

	printf("\b) ");
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

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	if (data_sz == sizeof(struct open_event)) {
		const struct open_event *e = data;
		const char *syscall_name;

		if (e->syscall_type == SYSCALL_CLOSE) {
			syscall_name = "close";
		} else if (e->syscall_type == SYSCALL_OPEN) {
			syscall_name = "open";
		} else if (e->syscall_type == SYSCALL_OPENAT) {
			syscall_name = "openat";
		} else if (e->syscall_type == SYSCALL_READ) {
			syscall_name = "read";
		} else if (e->syscall_type == SYSCALL_WRITE) {
			syscall_name = "write";
		} else {
			syscall_name = "unknown";
		}

		print_timestamp(e->ts);
		if (e->syscall_type == SYSCALL_CLOSE) {
			printf("syscall=%s pid=%u uid=%u path=\"%s\" fd=%d\n",
				   syscall_name, e->pid, e->uid, e->filename, e->fd);
		} else if (e->syscall_type == SYSCALL_READ || e->syscall_type == SYSCALL_WRITE) {
			printf("syscall=%s pid=%u uid=%u path=\"%s\" fd=%d count=%ld actual=%ld\n",
				   syscall_name, e->pid, e->uid, e->filename, e->fd, e->flags, e->actual_count);
		} else {
			printf("syscall=%s pid=%u uid=%u path=\"%s\" fd=%d flags=0x%lx\n",
				   syscall_name, e->pid, e->uid, e->filename, e->fd, e->flags);
		}
	}
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	struct bpf_object *obj = NULL;
	struct bpf_link *links[NUM_BPF_PROGRAMS] = {};
	struct perf_buffer *pb = NULL;
	struct bpf_program *prog;
	int map_fd, filter_map_fd, err = 0, i = 0;
	char filename[256];
	__u32 key = 0, my_pid;

	/* Set up libbpf errors and debug info callback (enable for debugging))
	Disable BTF mode */
	libbpf_set_print(NULL);
	libbpf_set_strict_mode(LIBBPF_STRICT_NONE);

	/* Bump RLIMIT_MEMLOCK for BPF sub-system */
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};
	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "WARNING: Failed to increase RLIMIT_MEMLOCK limit (may need root privileges)\n");
		fprintf(stderr, "Continuing anyway...\n");
	}

	my_pid = getpid();
	fprintf(stderr, "Self PID: %u (will be filtered out)\n", my_pid);

	/* Load the BPF object file */
	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	fprintf(stderr, "Attempting to open: %s\n", filename);
	if (access(filename, R_OK) != 0) {
		fprintf(stderr, "ERROR: Cannot access file %s: %s\n", filename, strerror(errno));
		goto cleanup;
	}

	/* Open with options to disable BTF requirement */
	struct bpf_object_open_opts opts = {
		.sz = sizeof(struct bpf_object_open_opts),
	};

	obj = bpf_object__open_file(filename, &opts);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "ERROR: opening BPF object file failed: %ld (%s)\n", err, strerror(errno));
		obj = NULL;
		goto cleanup;
	}

	fprintf(stderr, "Successfully opened BPF object file\n");

	/* Disable BTF requirement for loading */
	bpf_object__for_each_program(prog, obj) {
		bpf_program__set_autoload(prog, true);
	}
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	fprintf(stderr, "Successfully loaded BPF program\n");

	/* Find and configure the filter_pid map */
	filter_map_fd = bpf_object__find_map_fd_by_name(obj, "filter_pid");
	if (filter_map_fd < 0) {
		fprintf(stderr, "WARNING: Could not find filter_pid map, continuing without PID filter\n");
	} else {
		if (bpf_map_update_elem(filter_map_fd, &key, &my_pid, BPF_ANY) < 0) {
			fprintf(stderr, "WARNING: Could not set filter PID: %s\n", strerror(errno));
		} else {
			fprintf(stderr, "Filter configured: excluding PID %u\n", my_pid);
		}
	}

	bpf_object__for_each_program(prog, obj) {
		const char *prog_name = bpf_program__name(prog);
		fprintf(stderr, "Attaching program: %s\n", prog_name);
		links[i] = bpf_program__attach(prog);
		if (libbpf_get_error(links[i])) {
			fprintf(stderr, "ERROR: bpf_program__attach failed for %s\n", prog_name);
			links[i] = NULL;
			goto cleanup;
		}
		fprintf(stderr, "  -> Successfully attached %s\n", prog_name);
		i++;
	}

	fprintf(stderr, "Successfully attached %d BPF programs\n", i);

	map_fd = bpf_object__find_map_fd_by_name(obj, "events");
	if (map_fd < 0) {
		fprintf(stderr, "ERROR: finding events map in obj file failed\n");
		goto cleanup;
	}

	/* Set up perf buffer to receive events */
	pb = perf_buffer__new(map_fd, 64, handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -1;
		fprintf(stderr, "ERROR: failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	/* Set up signal handler */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	printf("Tracing open/openat/close/read/write syscalls with active filters\n");
	printf("Filtered out: /etc/localtime, /proc/*, /sys/*, /dev/urandom, PID %u\n", my_pid);
	printf("=======================================================================\n");
	printf("%-20s %-8s %-30s %s\n", "TIMESTAMP", "PID", "SYSCALL/PARAMS", "FILENAME");
	printf("-----------------------------------------------------------------------\n");

	while (!exiting) {
		err = perf_buffer__poll(pb, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "ERROR: polling perf buffer: %d\n", err);
			break;
		}
		err = 0;
	}

cleanup:
	printf("\nDetaching and cleaning up...\n");
	perf_buffer__free(pb);
	for (i = 0; i < NUM_BPF_PROGRAMS; i++)
		bpf_link__destroy(links[i]);
	bpf_object__close(obj);

	return err != 0;
}
