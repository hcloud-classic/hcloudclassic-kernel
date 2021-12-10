#ifndef __GPM_NETWORK_GHOST_H__
#define __GPM_NETWORK_GHOST_H__

struct grpc_desc;
struct task_struct;
struct pt_regs;
struct gpm_action;

pid_t send_task(struct grpc_desc *desc,
		struct task_struct *tsk,
		struct pt_regs *task_regs,
		struct gpm_action *action);
struct task_struct *recv_task(struct grpc_desc *desc, struct gpm_action *action);

#endif /* __GPM_NETWORK_GHOST_H__ */
