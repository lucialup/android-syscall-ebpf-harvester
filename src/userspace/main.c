#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "../common.h"
#include "bpf_loader.h"
#include "output.h"

static volatile sig_atomic_t exiting = 0;


static void sig_handler(int sig)
{
	exiting = 1;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	if (data_sz == sizeof(struct syscall_event)) {
		const struct syscall_event *e = data;
		output_event(e);
	}
}


static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	output_lost_events(cpu, lost_cnt);
}


int main(int argc, char **argv)
{
	struct perf_buffer *pb = NULL;
	char obj_filename[256];
	int events_fd;
	int err = 0;
	__u32 my_pid;

	my_pid = getpid();

	if (bpf_loader_init() < 0) {
		fprintf(stderr, "ERROR: BPF initialization failed\n");
		return 1;
	}

	snprintf(obj_filename, sizeof(obj_filename), "%s_kern.o", argv[0]);

	if (bpf_loader_load(obj_filename) < 0) {
		fprintf(stderr, "ERROR: Failed to load BPF object\n");
		return 1;
	}

	if (bpf_loader_set_filter_pid(my_pid) < 0) {
		fprintf(stderr, "WARNING: PID filter not set (continuing anyway)\n");
	}

	if (bpf_loader_attach_all() < 0) {
		fprintf(stderr, "ERROR: Failed to attach BPF programs\n");
		err = 1;
		goto cleanup;
	}

	events_fd = bpf_loader_get_events_fd();
	if (events_fd < 0) {
		fprintf(stderr, "ERROR: Failed to get events map fd\n");
		err = 1;
		goto cleanup;
	}

	pb = perf_buffer__new(events_fd, 64, handle_event, handle_lost_events,
	                      NULL, NULL);
	if (!pb) {
		fprintf(stderr, "ERROR: Failed to open perf buffer\n");
		err = 1;
		goto cleanup;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Print header */
	fprintf(stderr, "\n");
	fprintf(stderr, "=======================================================================\n");
	fprintf(stderr, "Tracing open/openat/close/read/write/clone/execve/connect/mmap/socket/unlinkat syscalls\n");
	fprintf(stderr, "Filtered out: /etc/localtime, /proc/*, /sys/*, /dev/urandom, PID %u\n", my_pid);
	fprintf(stderr, "Press Ctrl+C to stop.\n");
	fprintf(stderr, "=======================================================================\n");
	fprintf(stderr, "\n");

	while (!exiting) {
		err = perf_buffer__poll(pb, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "ERROR: Polling perf buffer: %d\n", err);
			break;
		}
		err = 0;
	}

cleanup:
	if (pb)
		perf_buffer__free(pb);
	bpf_loader_cleanup();

	return err != 0;
}
