#ifndef BPF_LOADER_H
#define BPF_LOADER_H

#include "../common.h"

int bpf_loader_init(void);

int bpf_loader_load(const char *obj_path);

int bpf_loader_set_filter_pid(__u32 pid);

int bpf_loader_attach_all(void);

int bpf_loader_get_events_fd(void);

void bpf_loader_cleanup(void);

#endif /* BPF_LOADER_H */
