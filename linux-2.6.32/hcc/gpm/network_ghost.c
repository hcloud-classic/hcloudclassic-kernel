/*
 *  hcc/gpm/network_ghost.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/sched.h>
#include <hcc/pid.h>
#include <hcc/action.h>
#include <hcc/ghost.h>
#include <net/grpc/grpc.h>
#include "ghost.h"

pid_t send_task(struct grpc_desc *desc,
		struct task_struct *tsk,
		struct pt_regs *task_regs,
		struct gpm_action *action)
{
	pid_t pid_remote_task = -1;
	ghost_t *ghost;
	int err;

	ghost = create_network_ghost(GHOST_WRITE | GHOST_READ, desc);
	if (IS_ERR(ghost)) {
		err = PTR_ERR(ghost);
		goto out;
	}

	err = grpc_pack_type(desc, *action);
	if (err)
		goto out_close;

	err = export_process(action, ghost, tsk, task_regs);
	if (err)
		goto out_close;

	err = grpc_unpack_type(desc, pid_remote_task);
	post_export_process(action, ghost, tsk);
	if (err) {
		if (err == GRPC_EPIPE)
			err = -EPIPE;
		BUG_ON(err > 0);
	}

out_close:
	ghost_close(ghost);

out:
	return err ? err : pid_remote_task;
}

struct task_struct *recv_task(struct grpc_desc *desc, struct gpm_action *action)
{
	struct task_struct *new_tsk;
	ghost_t *ghost;
	pid_t pid;
	int err;

	ghost = create_network_ghost(GHOST_READ | GHOST_WRITE, desc);
	if (IS_ERR(ghost))
		goto err_ghost;

	new_tsk = import_process(action, ghost);
	if (IS_ERR(new_tsk))
		goto err_close;

	pid = task_pid_knr(new_tsk);
	err = grpc_pack_type(desc, pid);
	if (err)
		goto err_close;

	ghost_close(ghost);

	return new_tsk;

err_close:
	ghost_close(ghost);
err_ghost:
	/* TODO: send a custom error code */
	return NULL;
}
