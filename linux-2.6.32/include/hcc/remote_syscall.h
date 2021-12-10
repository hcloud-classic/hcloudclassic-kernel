#ifndef __REMOTE_SYSCALL_H__
#define __REMOTE_SYSCALL_H__

#include <linux/types.h>

struct grpc_desc;
struct pid;
struct cred;

struct grpc_desc *hcc_remote_syscall_begin(int req, pid_t pid,
					  const void *msg, size_t size);
void hcc_remote_syscall_end(struct grpc_desc *desc, pid_t pid);
int hcc_remote_syscall_simple(int req, pid_t pid, const void *msg, size_t size);

struct pid *hcc_handle_remote_syscall_begin(struct grpc_desc *desc,
					    const void *_msg, size_t size,
					    void *msg,
					    const struct cred **old_cred);
void hcc_handle_remote_syscall_end(struct pid *pid,
				   const struct cred *old_cred);

void remote_signals_init(void);
void remote_sched_init(void);
void remote_sys_init(void);

#endif /* __REMOTE_SYSCALL_H__ */
