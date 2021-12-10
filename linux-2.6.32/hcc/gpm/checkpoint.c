/*
 *  hcc/gpm/checkpoint.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

/**
 *  Process checkpointing.
 *  @file checkpoint.c
 *
 *  @author Innogrid HCC
 */

#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/file.h>
#include <linux/cred.h>
#include <linux/kernel.h>
#include <hcc/pid.h>
#include <hcc/application.h>
#include <hcc/hcc_signal.h>
#include <hcc/ghotplug.h>
#include <hcc/action.h>
#include <hcc/ghost.h>
#include <hcc/ghost_helpers.h>
#include <hcc/remote_cred.h>
#include <hcc/debug.h>
#include "ghost.h"
#include "gpm_internal.h"
#include "checkpoint.h"

/*****************************************************************************/
/*                                                                           */
/*                              TOOLS FUNCTIONS                              */
/*                                                                           */
/*****************************************************************************/

int can_be_checkpointed(struct task_struct *task_to_checkpoint)
{
	struct nsproxy *nsp;

	/* Task must live in the HCC container. */
	rcu_read_lock();
	nsp = rcu_dereference(task_to_checkpoint->nsproxy);
	if (!nsp || !nsp->hcc_ns) {
		rcu_read_unlock();
		goto exit;
	}
	rcu_read_unlock();

	/* Check permissions */
	if (!permissions_ok(task_to_checkpoint))
		goto exit;

	/* Check capabilities */
	if (!can_use_hcc_gcap(task_to_checkpoint, GCAP_CHECKPOINTABLE))
		goto exit;

	return 1; /* means true */

exit:
	return 0; /* means false */
}

/*****************************************************************************/
/*                                                                           */
/*                            CHECKPOINT FUNCTIONS                           */
/*                                                                           */
/*****************************************************************************/

/**
 *  This function save the process information in a ghost
 *  @author Innogrid HCC
 *
 *  @param task_to_checkpoint	Pointer on the task to checkpoint
 *
 *  @return			0 if everythink ok, negative value otherwise.
 */
static int checkpoint_task_to_ghost(struct gpm_action *action,
				    ghost_t *ghost,
				    struct task_struct *task_to_checkpoint,
				    struct pt_regs *regs)
{
	int r = -EINVAL;

	if (task_to_checkpoint == NULL) {
		PANIC("Task to checkpoint is NULL!!\n");
		goto exit;
	}

	if (regs == NULL) {
		PANIC("Regs are NULL!!\n");
		goto exit;
	}

	r = export_process(action, ghost, task_to_checkpoint, regs);
	if (!r)
		post_export_process(action, ghost, task_to_checkpoint);

exit:
	return r;
}

/**
 *  This function saves the process information in a file
 *  @author Innogrid HCC
 *
 *  @param task_to_checkpoint	Pointer to the task to checkpoint
 *
 *  @return 0			if everythink ok, negative value otherwise.
 */
static
int checkpoint_task_on_disk(struct gpm_action *action,
			    struct task_struct *task_to_checkpoint,
			    struct pt_regs *regs)
{
	ghost_t *ghost;
	int r = -EINVAL;

	struct app_struct *app = task_to_checkpoint->application;
	BUG_ON(!app);

	ghost = get_task_chkpt_ghost(app, task_to_checkpoint);
	if (!ghost) {
		__WARN();
		return r;
	}

	/* Do the process ghosting */
	return checkpoint_task_to_ghost(action, ghost,
				        task_to_checkpoint, regs);
}

/**
 *  This function saves the process information
 *  @author Innogrid HCC
 *
 *  @param task_to_checkpoint	Pointer to the task to checkpoint
 *
 *  @return 0			if everythink ok, negative value otherwise.
 */
static int checkpoint_task(struct gpm_action *action,
			   struct task_struct *task_to_checkpoint,
			   struct pt_regs *regs)
{
	int r;
	struct app_struct *app = task_to_checkpoint->application;
	ghost_fs_t oldfs;

	BUG_ON(!action);
	BUG_ON(!task_to_checkpoint);
	BUG_ON(!regs);
	BUG_ON(!app);

	r = set_ghost_fs(&oldfs, app->cred->fsuid, app->cred->fsgid);
	if (r)
		goto out;

	/* Do the process ghosting */
	r = checkpoint_task_on_disk(action, task_to_checkpoint, regs);

	unset_ghost_fs(&oldfs);

	if (r)
		ckpt_err(action, r,
			 "Fail to checkpoint process %d (%s)",
			 task_pid_knr(task_to_checkpoint),
			 task_to_checkpoint->comm);
out:
	return r;
}

/*****************************************************************************/
/*                                                                           */
/*                             REQUEST HELPER FUNCTIONS                      */
/*                                                                           */
/*****************************************************************************/

/* Checkpoint signal handler */
static void hcc_task_checkpoint(int sig, struct siginfo *info,
				struct pt_regs *regs)
{
	struct gpm_action action;
	task_state_t *current_state;
	int r = 0;

	/*
	 * process must not be frozen while its father
	 * waiting in vfork
	 */
	if (current->vfork_done) {
		mutex_lock(&current->application->mutex);
		r = -EAGAIN;
		ckpt_err(NULL, r,
			 "Application %ld can not be frozen because process "
			 "%d (%s) has been created by vfork() and has not yet "
			 "called exec(). Thus, its parent process is blocked.",
			 current->application->app_id,
			 task_pid_knr(current), current->comm);
		__set_task_result(current, r);
		mutex_unlock(&current->application->mutex);
		goto out;
	}

	/* freeze */
	current_state = set_result_wait(PCUS_OPERATION_OK);
	if (IS_ERR(current_state))
		goto out;

	/*
	 * checkpoint may be requested several times once
	 * application is frozen.
	 */
	while (current_state->checkpoint.ghost) {
		action.type = GPM_CHECKPOINT;
		action.checkpoint.shared = CR_SAVE_LATER;
		r = checkpoint_task(&action, current, regs);

		/* PCUS_OPERATION_OK == 0 */
		current_state = set_result_wait(r);
	}

out:
	return;
}

void register_checkpoint_hooks(void)
{
	hook_register(&hcc_handler[HCC_SIG_CHECKPOINT], hcc_task_checkpoint);
}
