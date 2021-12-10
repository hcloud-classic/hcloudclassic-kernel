/*
 *  hcc/ghotplug/namespace.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/nsproxy.h>
#include <linux/utsname.h>
#include <linux/ipc_namespace.h>
#include <linux/mnt_namespace.h>
#include <linux/pid_namespace.h>
#include <linux/user_namespace.h>
#include <net/net_namespace.h>
#include <hcc/namespace.h>
#include <hcc/hcc_services.h>
#include <hcc/hcc_syscalls.h>

static struct hcc_namespace *hcc_ns;
static DEFINE_SPINLOCK(hcc_ns_lock);

int copy_hcc_ns(struct task_struct *task, struct nsproxy *new)
{
	struct hcc_namespace *ns = task->nsproxy->hcc_ns;
	struct user_namespace *user_ns = __task_cred(task)->user->user_ns;
	int retval = 0;

	if (!ns && current->create_hcc_ns) {
		ns = kmalloc(sizeof(*ns), GFP_KERNEL);

		spin_lock_irq(&hcc_ns_lock);
		/* Only one hcc_ns can live at once. */
		if (!hcc_ns) {
			if (ns) {
				atomic_set(&ns->count, 1);

				atomic_set(&ns->root_nsproxy.count, 1);
				get_uts_ns(new->uts_ns);
				ns->root_nsproxy.uts_ns = new->uts_ns;
				get_ipc_ns(new->ipc_ns);
				ns->root_nsproxy.ipc_ns = new->ipc_ns;
				get_mnt_ns(new->mnt_ns);
				ns->root_nsproxy.mnt_ns = new->mnt_ns;
				get_pid_ns(new->pid_ns);
				ns->root_nsproxy.pid_ns = new->pid_ns;
				get_net(new->net_ns);
				ns->root_nsproxy.net_ns = new->net_ns;
				ns->root_nsproxy.hcc_ns = ns;

				get_user_ns(user_ns);
				ns->root_user_ns = user_ns;

				get_task_struct(task);
				ns->root_task = task;

				BUG_ON(ns->root_nsproxy.pid_ns->hcc_ns_root);
				ns->root_nsproxy.pid_ns->hcc_ns_root =
					ns->root_nsproxy.pid_ns;

				rcu_assign_pointer(hcc_ns, ns);
			} else {
				retval = -ENOMEM;
			}
		} else {
			kfree(ns);
			ns = NULL;
		}
		spin_unlock_irq(&hcc_ns_lock);
	} else if (ns) {
		get_hcc_ns(ns);
	}

	new->hcc_ns = ns;

	return retval;
}

static void delayed_free_hcc_ns(struct rcu_head *rcu)
{
	struct hcc_namespace *ns = container_of(rcu, struct hcc_namespace, rcu);

	BUG_ON(atomic_read(&ns->root_nsproxy.count) != 1);
	if (ns->root_nsproxy.uts_ns)
		put_uts_ns(ns->root_nsproxy.uts_ns);
	if (ns->root_nsproxy.ipc_ns)
		put_ipc_ns(ns->root_nsproxy.ipc_ns);
	if (ns->root_nsproxy.mnt_ns)
		put_mnt_ns(ns->root_nsproxy.mnt_ns);
	if (ns->root_nsproxy.pid_ns)
		put_pid_ns(ns->root_nsproxy.pid_ns);
	if (ns->root_nsproxy.net_ns)
		put_net(ns->root_nsproxy.net_ns);
	if (ns->root_user_ns)
		put_user_ns(ns->root_user_ns);

	put_task_struct(ns->root_task);

	kfree(ns);
}

void free_hcc_ns(struct hcc_namespace *ns)
{
	unsigned long flags;

	spin_lock_irqsave(&hcc_ns_lock, flags);
	BUG_ON(ns != hcc_ns);
	rcu_assign_pointer(hcc_ns, NULL);
	spin_unlock_irqrestore(&hcc_ns_lock, flags);

	call_rcu(&ns->rcu, delayed_free_hcc_ns);
}

struct hcc_namespace *find_get_hcc_ns(void)
{
	struct hcc_namespace *ns;

	rcu_read_lock();
	ns = rcu_dereference(hcc_ns);
	if (ns)
		if (!atomic_add_unless(&ns->count, 1, 0))
			ns = NULL;
	rcu_read_unlock();

	return ns;
}

bool can_create_hcc_ns(unsigned long flags)
{
	return current->create_hcc_ns
#ifdef CONFIG_HCC_GIPC
		&& (flags & CLONE_NEWIPC)
#endif
#ifdef CONFIG_HCC_PROC
		&& (flags & CLONE_NEWPID)
#endif
		;
}

int hcc_set_cluster_creator(void __user *arg)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	current->create_hcc_ns = !!arg;
	return 0;
}

int ghotplug_namespace_init(void)
{
	return __register_proc_service(HCC_SYS_GHOTPLUG_SET_CREATOR,
				       hcc_set_cluster_creator, false);
}
