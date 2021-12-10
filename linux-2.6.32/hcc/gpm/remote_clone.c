/*
 *  hcc/gpm/remote_clone.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <hcc/hcc_init.h>
#include <hcc/sys/types.h>
#include <hcc/pid.h>
#include <hcc/ghotplug.h>
#include <hcc/action.h>
#include <hcc/ghost.h>
#ifdef CONFIG_HCC_GSCHED
#include <hcc/gscheduler/placement.h>
#endif
#include <net/grpc/grpcid.h>
#include <net/grpc/grpc.h>
#include "network_ghost.h"

struct vfork_done_proxy {
	struct completion *waiter_vfork_done;
	hcc_node_t waiter_node;
};

static struct kmem_cache *vfork_done_proxy_cachep;

static void *cluster_started;

extern int wait_for_vfork_done(struct task_struct *child,
				struct completion *vfork);

int hcc_do_fork(unsigned long clone_flags,
		unsigned long stack_start,
		struct pt_regs *regs,
		unsigned long stack_size,
		int __user *parent_tidptr,
		int __user *child_tidptr,
		int trace)
{
	struct task_struct *task = current;
#ifdef CONFIG_HCC_GSCHED
	hcc_node_t distant_node;
#else
	static hcc_node_t distant_node = -1;
#endif
	struct gpm_action remote_clone;
	struct grpc_desc *desc;
	struct completion vfork;
	pid_t remote_pid = -1;
	int retval = -ENOSYS;

	if (!cluster_started)
		goto out;

	if ((clone_flags &
	     ~(CSIGNAL |
	       CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID |
	       CLONE_VFORK | CLONE_SYSVSEM | CLONE_UNTRACED))
	    || trace)
		/* Unsupported clone flags are requested. Abort */
		goto out;

	if (!task->sighand->hcc_objid || !task->signal->hcc_objid
	    || !task->task_obj || !task->children_obj) {
		retval = -EPERM;
		goto out;
	}

	retval = hcc_action_start(task, GPM_REMOTE_CLONE);
	if (retval)
		goto out;

#ifdef CONFIG_HCC_GSCHED
	distant_node = new_task_node(task);
#else
	if (distant_node < 0)
		distant_node = hcc_node_id;
	distant_node = hcc_node_next_online_in_ring(distant_node);
#endif
	if (distant_node < 0 || distant_node == hcc_node_id)
		goto out_action_stop;

	retval = -ENOMEM;
	desc = grpc_begin(GRPC_GPM_REMOTE_CLONE, distant_node);
	if (!desc)
		goto out_action_stop;

	remote_clone.type = GPM_REMOTE_CLONE;
	remote_clone.remote_clone.source = hcc_node_id;
	remote_clone.remote_clone.target = distant_node;
	remote_clone.remote_clone.clone_flags = clone_flags;
	remote_clone.remote_clone.stack_start = stack_start;
	remote_clone.remote_clone.stack_size = stack_size;
	remote_clone.remote_clone.from_pid = task_pid_knr(task);
	remote_clone.remote_clone.from_tgid = task_tgid_knr(task);
	remote_clone.remote_clone.parent_tidptr = parent_tidptr;
	remote_clone.remote_clone.child_tidptr = child_tidptr;
	if (clone_flags & CLONE_VFORK) {
		remote_clone.remote_clone.vfork = &vfork;
		init_completion(&vfork);
		get_task_struct(task);
	}

	remote_pid = send_task(desc, task, regs, &remote_clone);

	if (remote_pid < 0)
		grpc_cancel(desc);
	else {
		task->gpm_type = GPM_REMOTE_CLONE;
		task->gpm_target = distant_node;
	}
	grpc_end(desc, 0);

	if (remote_pid > 0 && (clone_flags & CLONE_VFORK))
		wait_for_vfork_done(task, &vfork);

out_action_stop:
	hcc_action_stop(task, GPM_REMOTE_CLONE);

out:
	return remote_pid;
}

static void handle_remote_clone(struct grpc_desc *desc, void *msg, size_t size)
{
	struct gpm_action *action = msg;
	struct task_struct *task;

	task = recv_task(desc, action);
	if (!task) {
		grpc_cancel(desc);
		return;
	}

	hcc_action_stop(task, GPM_REMOTE_CLONE);

	task->gpm_type = action->type;
	task->gpm_source = action->remote_clone.source;
	task->gpm_target = action->remote_clone.target;

	wake_up_new_task(task, CLONE_VM);
}

bool in_hcc_do_fork(void)
{
	return task_tgid_knr(hcc_current) != hcc_current->signal->hcc_objid;
}

static inline struct vfork_done_proxy *vfork_done_proxy_alloc(void)
{
	return kmem_cache_alloc(vfork_done_proxy_cachep, GFP_KERNEL);
}

static inline void vfork_done_proxy_free(struct vfork_done_proxy *proxy)
{
	kmem_cache_free(vfork_done_proxy_cachep, proxy);
}

int export_vfork_done(struct gpm_action *action,
		      ghost_t *ghost, struct task_struct *task)
{
	struct vfork_done_proxy proxy;
	int retval = 0;

	switch (action->type) {
	case GPM_MIGRATE:
		if (!task->vfork_done)
			break;
		if (task->remote_vfork_done) {
			proxy = *(struct vfork_done_proxy *)task->vfork_done;
		} else {
			proxy.waiter_vfork_done = task->vfork_done;
			proxy.waiter_node = hcc_node_id;
		}
		retval = ghost_write(ghost, &proxy, sizeof(proxy));
		break;
	case GPM_REMOTE_CLONE:
		if (action->remote_clone.clone_flags & CLONE_VFORK) {
			proxy.waiter_vfork_done = action->remote_clone.vfork;
			proxy.waiter_node = hcc_node_id;
			retval = ghost_write(ghost, &proxy, sizeof(proxy));
		}
		break;
	default:
		if (task->vfork_done)
			retval = -ENOSYS;
	}

	return retval;
}

static int vfork_done_proxy_install(struct task_struct *task,
				    struct vfork_done_proxy *proxy)
{
	struct vfork_done_proxy *p = vfork_done_proxy_alloc();
	int retval = -ENOMEM;

	if (!p)
		goto out;
	*p = *proxy;
	task->vfork_done = (struct completion *)p;
	task->remote_vfork_done = 1;
	retval = 0;

out:
	return retval;
}

int import_vfork_done(struct gpm_action *action,
		      ghost_t *ghost, struct task_struct *task)
{
	struct vfork_done_proxy tmp_proxy;
	int retval = 0;

	switch (action->type) {
	case GPM_MIGRATE:
		if (!task->vfork_done)
			break;

		retval = ghost_read(ghost, &tmp_proxy, sizeof(tmp_proxy));
		if (unlikely(retval))
			goto out;

		if (tmp_proxy.waiter_node == hcc_node_id) {
			task->vfork_done = tmp_proxy.waiter_vfork_done;
			task->remote_vfork_done = 0;
			break;
		}

		retval = vfork_done_proxy_install(task, &tmp_proxy);
		break;
	case GPM_REMOTE_CLONE:
		if (action->remote_clone.clone_flags & CLONE_VFORK) {
			retval = ghost_read(ghost, &tmp_proxy, sizeof(tmp_proxy));
			if (unlikely(retval))
				goto out;
			retval = vfork_done_proxy_install(task, &tmp_proxy);
			break;
		}
		/* Fallthrough */
	default:
		task->vfork_done = NULL;
	}

out:
	return retval;
}

void unimport_vfork_done(struct task_struct *task)
{
	struct completion *vfork_done = task->vfork_done;
	if (vfork_done && task->remote_vfork_done)
		vfork_done_proxy_free((struct vfork_done_proxy *)vfork_done);
}

/* Called after having successfuly migrated out task */
void cleanup_vfork_done(struct task_struct *task)
{
	struct completion *vfork_done;

	task_lock(task);
	vfork_done = task->vfork_done;
	if (likely(vfork_done)) {
		task->vfork_done = NULL;
		if (task->remote_vfork_done)
			vfork_done_proxy_free((struct vfork_done_proxy *)vfork_done);
	}
	task_unlock(task);
}

static void handle_vfork_done(struct grpc_desc *desc, void *data, size_t size)
{
	struct completion *vfork_done = *(struct completion **)data;

	complete(vfork_done);
}

void hcc_vfork_done(struct completion *vfork_done)
{
	struct vfork_done_proxy *proxy = (struct vfork_done_proxy *)vfork_done;

	grpc_async(PROC_VFORK_DONE, proxy->waiter_node,
		  &proxy->waiter_vfork_done, sizeof(proxy->waiter_vfork_done));
	vfork_done_proxy_free(proxy);
}

void register_remote_clone_hooks(void)
{
	hook_register(&cluster_started, (void *)true);
}

int gpm_remote_clone_start(void)
{
	vfork_done_proxy_cachep = KMEM_CACHE(vfork_done_proxy, SLAB_PANIC);

	if (grpc_register_void(GRPC_GPM_REMOTE_CLONE, handle_remote_clone, 0))
		BUG();
	if (grpc_register_void(PROC_VFORK_DONE, handle_vfork_done, 0))
		BUG();

	return 0;
}

void gpm_remote_clone_exit(void)
{
}
