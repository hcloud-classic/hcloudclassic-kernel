#ifndef __GPM_PID_H__
#define __GPM_PID_H__

#include <linux/types.h>
#include <hcc/sys/types.h>

/* Used by checkpoint/restart */
int reserve_pid(pid_t pid);
int hcc_pid_link_task(pid_t pid);
int __hcc_pid_link_task(pid_t pid);
int end_pid_reservation(pid_t pid);

void pid_wait_quiescent(void);

int pidmap_map_alloc(hcc_node_t node);

#endif /* __GPM_PID_H__ */
