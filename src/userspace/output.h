#ifndef OUTPUT_H
#define OUTPUT_H

#include "../common.h"

void output_event(const struct syscall_event *e);

void output_lost_events(int cpu, unsigned long long lost_cnt);

#endif /* OUTPUT_H */
