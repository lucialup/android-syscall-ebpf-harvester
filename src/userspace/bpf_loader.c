#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "bpf_loader.h"

#define MAX_BPF_PROGRAMS 20

static struct bpf_object *obj = NULL;
static struct bpf_link *links[MAX_BPF_PROGRAMS] = {NULL};
static int num_attached = 0;

int bpf_loader_init(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	/* Bump RLIMIT_MEMLOCK for BPF sub-system */
	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "WARNING: Failed to increase RLIMIT_MEMLOCK limit\n");
		fprintf(stderr, "         (may need root privileges)\n");
		fprintf(stderr, "         Continuing anyway...\n");
	}

	/* Disable libbpf debug output and set compatibility mode */
	libbpf_set_print(NULL);
	libbpf_set_strict_mode(LIBBPF_STRICT_NONE);

	return 0;
}

int bpf_loader_load(const char *obj_path)
{
	struct bpf_object_open_opts opts = {
		.sz = sizeof(struct bpf_object_open_opts),
	};
	struct bpf_program *prog;
	int err;

	fprintf(stderr, "Attempting to open: %s\n", obj_path);

	if (access(obj_path, R_OK) != 0) {
		fprintf(stderr, "ERROR: Cannot access file %s: %s\n",
		        obj_path, strerror(errno));
		return -1;
	}

	obj = bpf_object__open_file(obj_path, &opts);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "ERROR: Opening BPF object file failed: %s\n",
		        strerror(-err));
		obj = NULL;
		return -1;
	}

	fprintf(stderr, "Successfully opened BPF object file\n");

	bpf_object__for_each_program(prog, obj) {
		bpf_program__set_autoload(prog, true);
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: Loading BPF object file failed\n");
		bpf_object__close(obj);
		obj = NULL;
		return -1;
	}

	fprintf(stderr, "Successfully loaded BPF program\n");

	return 0;
}


int bpf_loader_set_filter_pid(__u32 pid)
{
	int filter_map_fd;
	__u32 key = 0;

	if (!obj) {
		fprintf(stderr, "ERROR: BPF object not loaded\n");
		return -1;
	}

	filter_map_fd = bpf_object__find_map_fd_by_name(obj, "filter_pid");
	if (filter_map_fd < 0) {
		fprintf(stderr, "WARNING: Could not find filter_pid map\n");
		return -1;
	}

	if (bpf_map_update_elem(filter_map_fd, &key, &pid, BPF_ANY) < 0) {
		fprintf(stderr, "WARNING: Could not set filter PID: %s\n", strerror(errno));
		return -1;
	}

	fprintf(stderr, "Filter configured: excluding PID %u\n", pid);

	return 0;
}

/*
 * Attach all BPF programs to their respective hooks
 * Returns 0 for success, -1 for error
 */
int bpf_loader_attach_all(void)
{
	struct bpf_program *prog;
	int i = 0;

	if (!obj) {
		fprintf(stderr, "ERROR: BPF object not loaded\n");
		return -1;
	}

	bpf_object__for_each_program(prog, obj) {
		const char *prog_name = bpf_program__name(prog);

		if (i >= MAX_BPF_PROGRAMS) {
			fprintf(stderr, "ERROR: Too many BPF programs (max %d)\n", MAX_BPF_PROGRAMS);
			return -1;
		}

		fprintf(stderr, "Attaching program: %s\n", prog_name);

		links[i] = bpf_program__attach(prog);
		if (libbpf_get_error(links[i])) {
			fprintf(stderr, "ERROR: bpf_program__attach failed for %s\n",
			        prog_name);
			links[i] = NULL;
			return -1;
		}

		fprintf(stderr, "  -> Successfully attached %s\n", prog_name);
		i++;
	}

	num_attached = i;
	fprintf(stderr, "Successfully attached %d BPF programs\n", num_attached);

	return 0;
}

/*
 * Get file descriptor for events map (for perf buffer setup)
 */
int bpf_loader_get_events_fd(void)
{
	int map_fd;

	if (!obj) {
		fprintf(stderr, "ERROR: BPF object not loaded\n");
		return -1;
	}

	map_fd = bpf_object__find_map_fd_by_name(obj, "events");
	if (map_fd < 0) {
		fprintf(stderr, "ERROR: Finding events map in obj file failed\n");
		return -1;
	}

	return map_fd;
}

void bpf_loader_cleanup(void)
{
	int i;

	fprintf(stderr, "\nDetaching and cleaning up...\n");

	for (i = 0; i < MAX_BPF_PROGRAMS; i++) {
		if (links[i]) {
			bpf_link__destroy(links[i]);
			links[i] = NULL;
		}
	}

	if (obj) {
		bpf_object__close(obj);
		obj = NULL;
	}

	num_attached = 0;
}
