/*
 *  hcc/gpm/action.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */
/*
 * Management of incompatibilities between HCC actions and
 * some Linux facilities
 */

#include <linux/sched.h>
#include <linux/spinlock.h>
#include <asm/atomic.h>
#include <hcc/capabilities.h>
#include <hcc/action.h>

static int action_to_cap_mapping[] = {
	[GPM_MIGRATE] = GCAP_CAN_MIGRATE,
	[GPM_REMOTE_CLONE] = GCAP_DISTANT_FORK,
	[GPM_CHECKPOINT] = GCAP_CHECKPOINTABLE,
};

DEFINE_RWLOCK(hcc_action_lock);

static inline void action_lock_lock(void)
{
	lockdep_off();
	write_lock(&hcc_action_lock);
}

static inline void action_lock_unlock(void)
{
	write_unlock(&hcc_action_lock);
	lockdep_on();
}

static inline int action_to_flag(hcc_gpm_action_t action)
{
	if (unlikely(action <= GPM_NO_ACTION || action >= GPM_ACTION_MAX))
		return 0;
	else
		return 1 << action;
}

static inline int action_to_cap(hcc_gpm_action_t action)
{
	if (unlikely(action <= GPM_NO_ACTION || action >= GPM_ACTION_MAX))
		return -1;
	else
		return action_to_cap_mapping[action];
}

int hcc_action_disable(struct task_struct *task, hcc_gpm_action_t action,
		       int inheritable)
{
	unsigned long flag;
	int retval = 0;

	flag = action_to_flag(action);
	if (unlikely(!flag))
		return -EINVAL;

	action_lock_lock();
	if (unlikely(task->hcc_action_flags & flag))
		retval = -EAGAIN;
	else {
		atomic_t *array;

		if (inheritable)
			array = task->hcc_gcap_unavailable;
		else
			array = task->hcc_gcap_unavailable_private;
		atomic_inc(&array[action_to_cap(action)]);
	}
	action_lock_unlock();

	return retval;
}

int hcc_action_enable(struct task_struct *task, hcc_gpm_action_t action,
		      int inheritable)
{
	atomic_t *array;
	int cap;

	cap = action_to_cap(action);
	if (unlikely(cap < 0))
		return -EINVAL;

	if (inheritable)
		array = task->hcc_gcap_unavailable;
	else
		array = task->hcc_gcap_unavailable_private;
	if (unlikely(atomic_add_negative(-1, &array[cap])))
		BUG();

	return 0;
}

int hcc_action_start(struct task_struct *task, hcc_gpm_action_t action)
{
	unsigned long flag;
	int retval = 0;

	flag = action_to_flag(action);
	if (unlikely(!flag))
		return -EINVAL;

	action_lock_lock();
	if (!can_use_hcc_gcap(task, action_to_cap(action)))
		retval = -EPERM;
	else if (unlikely(task->hcc_action_flags & flag))
		retval = -EALREADY;
	else if (unlikely(task->hcc_action_flags))
		retval = -EAGAIN;
	else
		task->hcc_action_flags |= flag;
	action_lock_unlock();

	return retval;
}

int hcc_action_stop(struct task_struct *task, hcc_gpm_action_t action)
{
	unsigned long flag;
	int retval = 0;

	flag = action_to_flag(action);
	if (unlikely(!flag))
		return -EINVAL;

	action_lock_lock();
	task->hcc_action_flags &= ~flag;
	action_lock_unlock();

	return retval;
}

int hcc_action_pending(struct task_struct *task, hcc_gpm_action_t action)
{
	unsigned long flag;
	int retval;

	flag = action_to_flag(action);
	if (unlikely(!flag))
		return 0;

	action_lock_lock();
	retval = task->hcc_action_flags & flag;
	action_lock_unlock();

	return retval;
}
