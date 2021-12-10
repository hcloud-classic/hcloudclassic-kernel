/*
 * Management of incompatibilities between HCC actions and
 * some Linux facilities
 */

#ifndef __HCC_ACTION_H__
#define __HCC_ACTION_H__

#ifdef CONFIG_HCC_GPM

#include <linux/sched.h>
#include <linux/time.h>
#include <hcc/sys/types.h>
#include <hcc/sys/checkpoint.h>

typedef enum {
	GPM_NO_ACTION,
	GPM_MIGRATE,
	GPM_REMOTE_CLONE,
	GPM_CHECKPOINT,
	GPM_ACTION_MAX	   /* Always in last position */
} hcc_gpm_action_t;

typedef enum {
	CR_SAVE_NOW,
	CR_SAVE_LATER
} c_shared_obj_option_t;

typedef enum {
	CR_LOAD_NOW,
	CR_LINK_ONLY
} r_shared_obj_option_t;

#define APP_REPLACE_PGRP	1
#define APP_REPLACE_SID		2

struct task_struct;
struct completion;

struct gpm_action {
	hcc_gpm_action_t type;
	union {
		struct {
			pid_t pid;
			hcc_node_t source;
			hcc_node_t target;
			struct timespec start_date;
			struct timespec end_date;
		} migrate;
		struct {
			pid_t from_pid;
			pid_t from_tgid;
			hcc_node_t source;
			hcc_node_t target;
			unsigned long clone_flags;
			unsigned long stack_start;
			unsigned long stack_size;
			int *parent_tidptr;
			int *child_tidptr;
			struct completion *vfork;
		} remote_clone;
		struct {
			c_shared_obj_option_t shared;
		} checkpoint;
		struct {
			r_shared_obj_option_t shared;
			struct app_struct * app;
			int flags;
		} restart;
	};
};

static inline hcc_node_t gpm_target_node(struct gpm_action *action)
{
	switch (action->type) {
	case GPM_MIGRATE:
		return action->migrate.target;
	case GPM_REMOTE_CLONE:
		return action->remote_clone.target;
	case GPM_CHECKPOINT:
		return HCC_NODE_ID_NONE;
	default:
		BUG();
	}
}

/*
 * Nests inside and outside of read_lock(&taskslist_lock), but neither inside
 * nor outside write_lock(_irq)(&tasklist_lock).
 * Nests outside sighand->lock.
 */
extern rwlock_t hcc_action_lock;

static inline void hcc_action_block_all(void)
{
	read_lock(&hcc_action_lock);
}

static inline void hcc_action_unblock_all(void)
{
	read_unlock(&hcc_action_lock);
}

static inline int hcc_action_any_pending(struct task_struct *task)
{
	return task->hcc_action_flags;
}

static inline int hcc_action_block_any(struct task_struct *task)
{
	int pending;

	hcc_action_block_all();
	pending = hcc_action_any_pending(task);
	if (pending)
		hcc_action_unblock_all();
	return !pending;
}

static inline void hcc_action_unblock_any(struct task_struct *task)
{
	hcc_action_unblock_all();
}

int hcc_action_disable(struct task_struct *task, hcc_gpm_action_t action,
		       int inheritable);
int hcc_action_enable(struct task_struct *task, hcc_gpm_action_t action,
		      int inheritable);

int hcc_action_start(struct task_struct *task, hcc_gpm_action_t action);
int hcc_action_stop(struct task_struct *task, hcc_gpm_action_t action);

int hcc_action_pending(struct task_struct *task, hcc_gpm_action_t action);

#endif /* CONFIG_HCC_GPM */

#endif /* __HCC_ACTION_H__ */
