/*
 *  hcc/proc/task.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

/** On each node the system manage a table to know the
 *  location of migrated process.
 *  It is interesting to globally manage signal : e.g. when a signal
 *  arrive from a remote node, the system can find the old local
 *  process pid and so the process'father.
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/personality.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/cred.h>
#include <linux/rwsem.h>
#include <linux/lockdep.h>
#include <linux/rcupdate.h>
#include <linux/kref.h>
#include <linux/slab.h>
#include <hcc/task.h>
#include <hcc/pid.h>

#include <net/grpc/grpc.h>
#include <hcc/libproc.h>
#include <gdm/gdm.h>

static struct kmem_cache *task_gdm_obj_cachep;

/* gdm set of pid location and task struct */
static struct gdm_set *task_gdm_set;

void hcc_task_get(struct task_gdm_object *obj)
{
	if (obj)
		kref_get(&obj->kref);
}

static void task_free(struct kref *kref)
{
	struct task_gdm_object *obj;

	obj = container_of(kref, struct task_gdm_object, kref);
	BUG_ON(!obj);

	kmem_cache_free(task_gdm_obj_cachep, obj);
}

void hcc_task_put(struct task_gdm_object *obj)
{
	if (obj)
		kref_put(&obj->kref, task_free);
}

/*
 * @author Innogrid HCC
 */
static int task_alloc_object(struct gdm_obj *obj_entry,
			     struct gdm_set *set, objid_t objid)
{
	struct task_gdm_object *p;

	p = kmem_cache_alloc(task_gdm_obj_cachep, GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	p->node = HCC_NODE_ID_NONE;
	p->task = NULL;
	p->pid = objid;
	p->parent_node = HCC_NODE_ID_NONE;
	/*
	 * If the group leader is another thread, this
	 * will be fixed later. Before that this is
	 * only needed to check local/global pids.
	 */
	p->group_leader = objid;
#ifdef CONFIG_HCC_GPM
	p->pid_obj = NULL;
#endif
	init_rwsem(&p->sem);
	p->write_locked = 0;

	p->alive = 1;
	kref_init(&p->kref);
	obj_entry->object = p;

	return 0;
}

/*
 * @author Innogrid HCC
 */
static int task_first_touch(struct gdm_obj *obj_entry,
			    struct gdm_set *set, objid_t objid, int flags)
{
	return task_alloc_object(obj_entry, set, objid);
}

/*
 * @author Innogrid HCC
 */
static int task_import_object(struct grpc_desc *desc,
			      struct gdm_set *set,
			      struct gdm_obj *obj_entry,
			      objid_t objid,
			      int flags)
{
	struct task_gdm_object *dest = obj_entry->object;
	struct task_gdm_object src;
	int retval;

	retval = grpc_unpack_type(desc, src);
	if (retval)
		return retval;

	tasklist_write_lock_irq();

	dest->state = src.state;
	dest->flags = src.flags;
	dest->ptrace = src.ptrace;
	dest->exit_state = src.exit_state;
	dest->exit_code = src.exit_code;
	dest->exit_signal = src.exit_signal;

	dest->node = src.node;
	dest->self_exec_id = src.self_exec_id;
	dest->thread_group_empty = src.thread_group_empty;

	dest->parent = src.parent;
	dest->parent_node = src.parent_node;
	dest->real_parent = src.real_parent;
	dest->real_parent_tgid = src.real_parent_tgid;
	dest->group_leader = src.group_leader;

	dest->uid = src.uid;
	dest->euid = src.euid;
	dest->egid = src.egid;

	dest->utime = src.utime;
	dest->stime = src.stime;

	dest->dumpable = src.dumpable;

	write_unlock_irq(&tasklist_lock);

	return 0;
}

/*
 * Assumes either tasklist_lock read locked with appropriate task_lock held, or
 * tasklist_lock write locked.
 */
static void task_update_object(struct task_gdm_object *obj)
{
	struct task_struct *tsk = obj->task;
	const struct cred *cred;

	if (tsk) {
		BUG_ON(tsk->task_obj != obj);

		obj->state = tsk->state;
		obj->flags = tsk->flags;
		obj->ptrace = tsk->ptrace;
		obj->exit_state = tsk->exit_state;
		obj->exit_code = tsk->exit_code;
		obj->exit_signal = tsk->exit_signal;

		obj->self_exec_id = tsk->self_exec_id;

		BUG_ON(obj->node != hcc_node_id &&
		       obj->node != HCC_NODE_ID_NONE);

		rcu_read_lock();
		cred = __task_cred(tsk);
		obj->uid = cred->uid;
		obj->euid = cred->euid;
		obj->egid = cred->egid;
		rcu_read_unlock();

		task_times(tsk, &obj->utime, &obj->stime);

		obj->dumpable = (tsk->mm && get_dumpable(tsk->mm) == 1);

		obj->thread_group_empty = thread_group_empty(tsk);
	}
}

/*
 * @author Innogrid HCC
 */
static int task_export_object(struct grpc_desc *desc,
			      struct gdm_set *set,
			      struct gdm_obj *obj_entry,
			      objid_t objid,
			      int flags)
{
	struct task_gdm_object *src = obj_entry->object;
	struct task_struct *tsk;

	read_lock(&tasklist_lock);
	tsk = src->task;
	if (likely(tsk)) {
		task_lock(tsk);
		task_update_object(src);
		task_unlock(tsk);
	}
	read_unlock(&tasklist_lock);

	return grpc_pack_type(desc, *src);
}

static void delayed_task_put(struct rcu_head *rhp)
{
	struct task_gdm_object *obj =
		container_of(rhp, struct task_gdm_object, rcu);

	hcc_task_put(obj);
}

/**
 *  @author Innogrid HCC
 */
static int task_remove_object(void *object,
			      struct gdm_set *set, objid_t objid)
{
	struct task_gdm_object *obj = object;

	hcc_task_unlink(obj, 0);

#ifdef CONFIG_HCC_GPM
	rcu_read_lock();
	hcc_pid_unlink_task(rcu_dereference(obj->pid_obj));
	rcu_read_unlock();
	BUG_ON(obj->pid_obj);
#endif

	obj->alive = 0;
	call_rcu(&obj->rcu, delayed_task_put);

	return 0;
}

static struct iolinker_struct task_io_linker = {
	.first_touch   = task_first_touch,
	.linker_name   = "task ",
	.linker_id     = TASK_LINKER,
	.alloc_object  = task_alloc_object,
	.export_object = task_export_object,
	.import_object = task_import_object,
	.remove_object = task_remove_object,
	.default_owner = global_pid_default_owner,
};

int hcc_task_alloc(struct task_struct *task, struct pid *pid)
{
	struct task_gdm_object *obj;
	int nr = pid_knr(pid);

	task->task_obj = NULL;
	if (!task->nsproxy->hcc_ns)
		return 0;
#ifdef CONFIG_HCC_GPM
	if (hcc_current)
		return 0;
#endif
	/* Exclude kernel threads and local pids from using task gdm objects. */
	/*
	 * At this stage, current->mm points the mm of the task being duplicated
	 * instead of the mm of task for which this struct is being allocated,
	 * but we only need to know whether it is NULL or not, which will be the
	 * same after copy_mm.
	 */
	if (!(nr & GLOBAL_PID_MASK) || !current->mm)
		return 0;

	obj = hcc_task_create_writelock(nr);
	if (!obj)
		return -ENOMEM;

	/* Set the link between task gdm object and tsk */
	obj->task = task;
	task->task_obj = obj;

	return 0;
}

void hcc_task_fill(struct task_struct *task, unsigned long clone_flags)
{
	struct task_gdm_object *obj = task->task_obj;

	BUG_ON((task_tgid_knr(task) & GLOBAL_PID_MASK)
	       != (task_pid_knr(task) & GLOBAL_PID_MASK));

#ifdef CONFIG_HCC_GPM
	if (hcc_current)
		return;
#endif
	if (!obj)
		return;

	obj->node = hcc_node_id;
#ifdef CONFIG_HCC_GPM
	if (task->real_parent == baby_sitter) {
		BUG_ON(!current->task_obj);
		if (clone_flags & (CLONE_PARENT|CLONE_THREAD)) {
			struct task_gdm_object *cur_obj = current->task_obj;
			obj->real_parent = cur_obj->real_parent;
			obj->real_parent_tgid = cur_obj->real_parent_tgid;
		} else {
			obj->real_parent = task_pid_knr(current);
			obj->real_parent_tgid = task_tgid_knr(current);
		}
	} else
#endif
	{
		obj->real_parent = task_pid_knr(task->real_parent);
		obj->real_parent_tgid = task_tgid_knr(task->real_parent);
	}
	/* Keep parent same as real_parent until ptrace is better supported */
	obj->parent = obj->real_parent;
#ifdef CONFIG_HCC_GPM
	/* Distributed threads are not supported yet. */
	BUG_ON(task->group_leader == baby_sitter);
#endif
	obj->group_leader = task_tgid_knr(task);
}

void hcc_task_commit(struct task_struct *task)
{
	if (task->task_obj)
		__hcc_task_unlock(task);
}

void hcc_task_abort(struct task_struct *task)
{
	struct task_gdm_object *obj = task->task_obj;

#ifdef CONFIG_HCC_GPM
	if (hcc_current)
		return;
#endif

	if (!obj)
		return;

	obj->write_locked = 2;
	up_write(&obj->sem);

	_gdm_remove_frozen_object(task_gdm_set, obj->pid);
}

void __hcc_task_free(struct task_struct *task)
{
	_gdm_remove_object(task_gdm_set, task_pid_knr(task));
}

void hcc_task_free(struct task_struct *task)
{
	/* If the pointer is NULL and the object exists, this is a BUG! */
	if (!task->task_obj)
		return;

	__hcc_task_free(task);
}

/* Expects tasklist write locked */
void __hcc_task_unlink(struct task_gdm_object *obj, int need_update)
{
	BUG_ON(!obj);

	if (obj->task) {
		if (need_update)
			task_update_object(obj);
		rcu_assign_pointer(obj->task->task_obj, NULL);
		rcu_assign_pointer(obj->task, NULL);
	}
}

void hcc_task_unlink(struct task_gdm_object *obj, int need_update)
{
	tasklist_write_lock_irq();
	__hcc_task_unlink(obj, need_update);
	write_unlock_irq(&tasklist_lock);
}

int hcc_task_alive(struct task_gdm_object *obj)
{
	return obj && obj->alive;
}

/**
 * @author Innogrid HCC
 */
struct task_gdm_object *hcc_task_readlock(pid_t pid)
{
	struct task_gdm_object *obj;

	/* Filter well known cases of no task gdm object. */
	if (!(pid & GLOBAL_PID_MASK))
		return NULL;

	obj = _gdm_get_object_no_ft(task_gdm_set, pid);
	if (likely(obj)) {
		down_read(&obj->sem);
		if (obj->write_locked == 2) {
			/* Dying object */
			up_read(&obj->sem);
			_gdm_put_object(task_gdm_set, pid);
			return NULL;
		}
		/* Marker for unlock. Dirty but temporary. */
		obj->write_locked = 0;
	}

	return obj;
}

struct task_gdm_object *__hcc_task_readlock(struct task_struct *task)
{
	return hcc_task_readlock(task_pid_knr(task));
}

/**
 * @author Innogrid HCC
 */
static struct task_gdm_object *task_writelock(pid_t pid, int nested)
{
	struct task_gdm_object *obj;

	/* Filter well known cases of no task gdm object. */
	if (!(pid & GLOBAL_PID_MASK))
		return NULL;

	obj = _gdm_grab_object_no_ft(task_gdm_set, pid);
	if (likely(obj)) {
		if (!nested)
			down_write(&obj->sem);
		else
			down_write_nested(&obj->sem, SINGLE_DEPTH_NESTING);
		if (obj->write_locked == 2) {
			/* Dying object */
			up_write(&obj->sem);
			_gdm_put_object(task_gdm_set, pid);
			return NULL;
		}
		/* Marker for unlock. Dirty but temporary. */
		obj->write_locked = 1;
	}

	return obj;
}

struct task_gdm_object *hcc_task_writelock(pid_t pid)
{
	return task_writelock(pid, 0);
}

struct task_gdm_object *__hcc_task_writelock(struct task_struct *task)
{
	return task_writelock(task_pid_knr(task), 0);
}

struct task_gdm_object *hcc_task_writelock_nested(pid_t pid)
{
	return task_writelock(pid, 1);
}

struct task_gdm_object *__hcc_task_writelock_nested(struct task_struct *task)
{
	return task_writelock(task_pid_knr(task), 1);
}

/**
 * @author Innogrid HCC
 */
struct task_gdm_object *hcc_task_create_writelock(pid_t pid)
{
	struct task_gdm_object *obj;

	/* Filter well known cases of no task gdm object. */
	/* The exact filter is expected to be implemented by the caller. */
	BUG_ON(!(pid & GLOBAL_PID_MASK));

	obj = _gdm_grab_object(task_gdm_set, pid);
	if (likely(obj && !IS_ERR(obj))) {
		down_write(&obj->sem);
		/* No dying object race or this is really smelly */
		BUG_ON(obj->write_locked == 2);
		/* Marker for unlock. Dirty but temporary. */
		obj->write_locked = 1;
	} else {
		_gdm_put_object(task_gdm_set, pid);
	}

	return obj;
}

/**
 * @author Innogrid HCC
 */
void hcc_task_unlock(pid_t pid)
{
	/* Filter well known cases of no task gdm object. */
	if (!(pid & GLOBAL_PID_MASK))
		return;

	{
		/*
		 * Dirty tricks here. Hopefully it should be temporary waiting
		 * for gdm to implement locking on a task basis.
		 */
		struct task_gdm_object *obj;

		obj = _gdm_find_object(task_gdm_set, pid);
		if (likely(obj)) {
			_gdm_put_object(task_gdm_set, pid);
			if (obj->write_locked)
				up_write(&obj->sem);
			else
				up_read(&obj->sem);
		}
	}
	_gdm_put_object(task_gdm_set, pid);
}

void __hcc_task_unlock(struct task_struct *task)
{
	hcc_task_unlock(task_pid_knr(task));
}

#ifdef CONFIG_HCC_GPM
/**
 * @author Innogrid HCC
 * Set (or update) the location of pid
 */
int hcc_set_pid_location(struct task_struct *task)
{
	struct task_gdm_object *p;

	p = __hcc_task_writelock(task);
	if (likely(p))
		p->node = hcc_node_id;
	__hcc_task_unlock(task);

	return 0;
}

int hcc_unset_pid_location(struct task_struct *task)
{
	struct task_gdm_object *p;

	BUG_ON(!(task_pid_knr(task) & GLOBAL_PID_MASK));

	p = __hcc_task_writelock(task);
	BUG_ON(p == NULL);
	p->node = HCC_NODE_ID_NONE;
	__hcc_task_unlock(task);

	return 0;
}
#endif /* CONFIG_HCC_GPM */

hcc_node_t hcc_lock_pid_location(pid_t pid)
{
	hcc_node_t node = HCC_NODE_ID_NONE;
	struct task_gdm_object *obj;
#ifdef CONFIG_HCC_GPM
	struct timespec back_off_time = {
		.tv_sec = 0,
		.tv_nsec = 1000000 /* 1 ms */
	};
#endif

	if (!(pid & GLOBAL_PID_MASK))
		goto out;

	for (;;) {
		obj = hcc_task_readlock(pid);
		if (likely(obj)) {
			node = obj->node;
		} else {
			hcc_task_unlock(pid);
			break;
		}
#ifdef CONFIG_HCC_GPM
		if (likely(node != HCC_NODE_ID_NONE))
			break;
		/*
		 * Task is migrating.
		 * Back off and hope that it will stop migrating.
		 */
		hcc_task_unlock(pid);
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(timespec_to_jiffies(&back_off_time) + 1);
#else
		break;
#endif
	}

out:
	return node;
}

void hcc_unlock_pid_location(pid_t pid)
{
	hcc_task_unlock(pid);
}

/**
 * @author Innogrid HCC
 */
void proc_task_start(void)
{
	unsigned long cache_flags = SLAB_PANIC;

#ifdef CONFIG_DEBUG_SLAB
	cache_flags |= SLAB_POISON;
#endif
	task_gdm_obj_cachep = KMEM_CACHE(task_gdm_object, cache_flags);

	register_io_linker(TASK_LINKER, &task_io_linker);

	task_gdm_set = create_new_gdm_set(gdm_def_ns, TASK_GDM_ID,
					    TASK_LINKER,
					    GDM_CUSTOM_DEF_OWNER,
					    0, 0);
	if (IS_ERR(task_gdm_set))
		OOM;

}

/**
 * @author Innogrid HCC
 */
void proc_task_exit(void)
{
}
