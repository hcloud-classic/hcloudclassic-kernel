/*
 *  hcc/gpm/restart.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

/**
 *  Process restart.
 *  @file restart.c
 *
 *  @author Innogrid HCC
 */

#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/pid_namespace.h>
#include <hcc/pid.h>
#include <hcc/application.h>
#include <hcc/action.h>
#include <hcc/ghost.h>
#include <hcc/ghost_helpers.h>
#include "ghost.h"
#include "pid.h"
#include "restart.h"

/**
 *  Load the process information saved in a checkpoint-file
 *  @author	Innogrid HCC
 *
 *  @param action	Restart descriptor
 *  @param pid		Pid of the task to restart
 *  @param ghost	Ghost to restart the task from
 *
 *  @return		New Tasks's UNIX PID if success, NULL if failure
 */
static
struct task_struct *restart_task_from_ghost(struct gpm_action *action,
					    pid_t pid,
					    ghost_t *ghost)
{
	struct task_struct *newTsk = NULL;
	int err;

	/* Recreate the process */
	newTsk = import_process(action, ghost);
	if (IS_ERR(newTsk))
		goto exit;
	BUG_ON(!newTsk);

	/* Link pid gdm object and task gdm obj */
	err = hcc_pid_link_task(pid);
	if (err) {
		newTsk = ERR_PTR(err);
		goto exit;
	}

exit:
	return newTsk;
}

/**
 *  Load the process information saved in a checkpoint-file
 *  @author       Innogrid HCC
 *
 *  @param action	Restart descriptor
 *  @param pid		Pid of the task to restart
 *  @param app_id	Application id
 *  @param chkpt_sn	Sequence number of the checkpoint
 *
 *  @return		New task if success, PTR_ERR if failure
 */
static
struct task_struct *restart_task_from_disk(struct gpm_action *action,
					   pid_t pid,
					   long app_id,
					   int chkpt_sn)
{
	int r;
	ghost_t *ghost;
	struct task_struct *task;

	ghost = create_file_ghost(GHOST_READ, app_id, chkpt_sn,
				  "task_%d.bin", pid);

	if (IS_ERR(ghost)) {
		r = PTR_ERR(ghost);
		ckpt_err(action, r,
			 "Fail to open file /var/chkpt/%ld/v%d/task_%d.bin to "
			 "restart process %d",
			 app_id, chkpt_sn, pid, pid);
		return ERR_PTR(r);
	}

	/* Recreate the process */

	task = restart_task_from_ghost(action, pid, ghost);

	ghost_close(ghost);

	return task;
}

/**
 *  Load the process information saved
 *  @author      Innogrid HCC
 *
 *  @param action	Restart descriptor
 *  @param pid		Pid of the task to restart
 *  @param app_id	Application id
 *  @param chkpt_sn	Sequence number of the checkpoint
 *
 *  @return		New task if success, PTR_ERR if failure
 */
static
struct task_struct *restart_task(struct gpm_action *action,
				 pid_t pid, long app_id,
				 int chkpt_sn)
{
	struct task_struct *task = NULL;
	ghost_fs_t oldfs;

	__set_ghost_fs(&oldfs);

	task = restart_task_from_disk(action, pid, app_id, chkpt_sn);

	unset_ghost_fs(&oldfs);
	return task;
}

/**
 *  Main kernel entry function to restart a checkpointed task.
 *  @author Innogrid HCC
 *
 *  @param app          Application
 *  @param pid		Pid of the task to restart
 *  @param flags	Option flags
 *
 *  @return		New task if success, PTR_ERR if failure
 */
struct task_struct *restart_process(struct app_struct *app, pid_t pid,
				    int flags)
{
	struct gpm_action action;
	struct task_struct *task;

	/* Check if the process has not been already restarted */
	if (find_task_by_kpid(pid) != NULL)
		return ERR_PTR(-EALREADY);

	action.type = GPM_CHECKPOINT;
	action.restart.shared = CR_LINK_ONLY;
	action.restart.app = app;
	action.restart.flags = flags;

	BUG_ON(!action.restart.app);

	task = restart_task(&action, pid, app->app_id, app->chkpt_sn);
	if (IS_ERR(task))
		ckpt_err(&action, PTR_ERR(task),
			 "Fail to restart process %d",
			 pid);

	return task;
}
