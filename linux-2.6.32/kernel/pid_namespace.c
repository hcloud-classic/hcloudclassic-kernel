/*
 * Pid namespaces
 *
 * Authors:
 *    (C) 2007 Pavel Emelyanov <xemul@openvz.org>, OpenVZ, SWsoft Inc.
 *    (C) 2007 Sukadev Bhattiprolu <sukadev@us.ibm.com>, IBM
 *     Many thanks to Oleg Nesterov for comments and help
 *
 */

#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/syscalls.h>
#include <linux/err.h>
#include <linux/acct.h>
#include <linux/proc_fs.h>
#include <linux/reboot.h>

#ifdef CONFIG_HCC_PROC
#include <linux/module.h>
#include <hcc/namespace.h>
#endif

#define BITS_PER_PAGE		(PAGE_SIZE*8)

struct pid_cache {
	int nr_ids;
	char name[16];
	struct kmem_cache *cachep;
	struct list_head list;
};

static LIST_HEAD(pid_caches_lh);
static DEFINE_MUTEX(pid_caches_mutex);
static struct kmem_cache *pid_ns_cachep;

/*
 * creates the kmem cache to allocate pids from.
 * @nr_ids: the number of numerical ids this pid will have to carry
 */

static struct kmem_cache *create_pid_cachep(int nr_ids)
{
	struct pid_cache *pcache;
	struct kmem_cache *cachep;

	mutex_lock(&pid_caches_mutex);
	list_for_each_entry(pcache, &pid_caches_lh, list)
		if (pcache->nr_ids == nr_ids)
			goto out;

	pcache = kmalloc(sizeof(struct pid_cache), GFP_KERNEL);
	if (pcache == NULL)
		goto err_alloc;

	snprintf(pcache->name, sizeof(pcache->name), "pid_%d", nr_ids);
	cachep = kmem_cache_create(pcache->name,
			sizeof(struct pid) + (nr_ids - 1) * sizeof(struct upid),
			0, SLAB_HWCACHE_ALIGN, NULL);
	if (cachep == NULL)
		goto err_cachep;

	pcache->nr_ids = nr_ids;
	pcache->cachep = cachep;
	list_add(&pcache->list, &pid_caches_lh);
out:
	mutex_unlock(&pid_caches_mutex);
	return pcache->cachep;

err_cachep:
	kfree(pcache);
err_alloc:
	mutex_unlock(&pid_caches_mutex);
	return NULL;
}

static void proc_cleanup_work(struct work_struct *work)
{
	struct pid_namespace *ns = container_of(work, struct pid_namespace, proc_work);
	pid_ns_release_proc(ns);
}

#ifndef CONFIG_HCC_GPM
static
#endif
struct pid_namespace *create_pid_namespace(struct pid_namespace *parent_pid_ns)
{
	struct pid_namespace *ns;
#ifdef CONFIG_HCC_GPM
	unsigned int level = 0;
#else
	unsigned int level = parent_pid_ns->level + 1;
#endif
	int i, err = -ENOMEM;

#ifdef CONFIG_HCC_GPM
	if (parent_pid_ns)
		level = parent_pid_ns->level + 1;
#endif

	ns = kmem_cache_zalloc(pid_ns_cachep, GFP_KERNEL);
	if (ns == NULL)
		goto out;

	ns->pidmap[0].page = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!ns->pidmap[0].page)
		goto out_free;

	ns->pid_cachep = create_pid_cachep(level + 1);
	if (ns->pid_cachep == NULL)
		goto out_free_map;

	err = proc_alloc_inum(&ns->proc_inum);
	if (err)
		goto out_free_map;

	kref_init(&ns->kref);
	ns->level = level;
#ifdef CONFIG_HCC_PROC
	if (parent_pid_ns) {
		ns->global = parent_pid_ns->global;
		ns->global |= current->create_hcc_ns;
		if (parent_pid_ns->hcc_ns_root)
			get_pid_ns(parent_pid_ns->hcc_ns_root);
		ns->hcc_ns_root = parent_pid_ns->hcc_ns_root;
		ns->parent = get_pid_ns(parent_pid_ns);
	}
#else
	ns->parent = get_pid_ns(parent_pid_ns);
#endif
	ns->nr_hashed = PIDNS_HASH_ADDING;
	INIT_WORK(&ns->proc_work, proc_cleanup_work);

	set_bit(0, ns->pidmap[0].page);
	atomic_set(&ns->pidmap[0].nr_free, BITS_PER_PAGE - 1);

	for (i = 1; i < PIDMAP_ENTRIES; i++)
		atomic_set(&ns->pidmap[i].nr_free, BITS_PER_PAGE);

	return ns;

out_free_map:
	kfree(ns->pidmap[0].page);
out_free:
	kmem_cache_free(pid_ns_cachep, ns);
out:
	return ERR_PTR(err);
}

static void destroy_pid_namespace(struct pid_namespace *ns)
{
	int i;

#ifdef CONFIG_HCC_PROC
	if (ns->hcc_ns_root && ns->hcc_ns_root != ns)
		put_pid_ns(ns->hcc_ns_root);
#endif
	proc_free_inum(ns->proc_inum);
	for (i = 0; i < PIDMAP_ENTRIES; i++)
		kfree(ns->pidmap[i].page);
	kmem_cache_free(pid_ns_cachep, ns);
}

struct pid_namespace *copy_pid_ns(unsigned long flags, struct pid_namespace *old_ns)
{
	if (!(flags & CLONE_NEWPID))
		return get_pid_ns(old_ns);
	if (task_active_pid_ns(current) != old_ns)
		return ERR_PTR(-EINVAL);
	return create_pid_namespace(old_ns);
}

void free_pid_ns(struct kref *kref)
{
	struct pid_namespace *ns, *parent;

	ns = container_of(kref, struct pid_namespace, kref);

	parent = ns->parent;
	destroy_pid_namespace(ns);

	if (parent != NULL)
		put_pid_ns(parent);
}
#ifdef CONFIG_HCC_PROC
EXPORT_SYMBOL(free_pid_ns);
#endif

void zap_pid_ns_processes(struct pid_namespace *pid_ns)
{
	int nr;
	int rc;
	struct task_struct *task, *me = current;
	int init_pids = thread_group_leader(me) ? 1 : 2;

	/* Don't allow any more processes into the pid namespace */
	disable_pid_allocation(pid_ns);

	/* Ignore SIGCHLD causing any terminated children to autoreap */
	spin_lock_irq(&me->sighand->siglock);
	me->sighand->action[SIGCHLD - 1].sa.sa_handler = SIG_IGN;
	spin_unlock_irq(&me->sighand->siglock);

	/*
	 * The last thread in the cgroup-init thread group is terminating.
	 * Find remaining pid_ts in the namespace, signal and wait for them
	 * to exit.
	 *
	 * Note:  This signals each threads in the namespace - even those that
	 * 	  belong to the same thread group, To avoid this, we would have
	 * 	  to walk the entire tasklist looking a processes in this
	 * 	  namespace, but that could be unnecessarily expensive if the
	 * 	  pid namespace has just a few processes. Or we need to
	 * 	  maintain a tasklist for each pid namespace.
	 *
	 */
	read_lock(&tasklist_lock);
	nr = next_pidmap(pid_ns, 1);
	while (nr > 0) {
		rcu_read_lock();

		/*
		 * Use force_sig() since it clears SIGNAL_UNKILLABLE ensuring
		 * any nested-container's init processes don't ignore the
		 * signal
		 */
		task = pid_task(find_vpid(nr), PIDTYPE_PID);
		if (task)
			force_sig(SIGKILL, task);

		rcu_read_unlock();

		nr = next_pidmap(pid_ns, nr);
	}
	read_unlock(&tasklist_lock);

	/* Firstly reap the EXIT_ZOMBIE children we may have. */
	do {
		clear_thread_flag(TIF_SIGPENDING);
		rc = sys_wait4(-1, NULL, __WALL, NULL);
	} while (rc != -ECHILD);

	/*
	 * sys_wait4() above can't reap the TASK_DEAD children.
	 * Make sure they all go away, see free_pid().
	 */
	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (pid_ns->nr_hashed == init_pids)
			break;
		schedule();
	}
	__set_current_state(TASK_RUNNING);

	if (pid_ns->reboot)
		current->signal->group_exit_code = pid_ns->reboot;

	acct_exit_ns(pid_ns);
	return;
}

#ifdef CONFIG_HCC_PROC
struct pid_namespace *find_get_hcc_pid_ns(void)
{
	struct hcc_namespace *hcc_ns = find_get_hcc_ns();
	struct pid_namespace *ns = get_pid_ns(hcc_ns->root_nsproxy.pid_ns);
	put_hcc_ns(hcc_ns);
	return ns;
}
EXPORT_SYMBOL(find_get_hcc_pid_ns);
#endif

int reboot_pid_ns(struct pid_namespace *pid_ns, int cmd)
{
	if (pid_ns == &init_pid_ns)
		return 0;

	switch (cmd) {
	case LINUX_REBOOT_CMD_RESTART2:
	case LINUX_REBOOT_CMD_RESTART:
		pid_ns->reboot = SIGHUP;
		break;

	case LINUX_REBOOT_CMD_POWER_OFF:
	case LINUX_REBOOT_CMD_HALT:
		pid_ns->reboot = SIGINT;
		break;
	default:
		return -EINVAL;
	}

	read_lock(&tasklist_lock);
	force_sig(SIGKILL, pid_ns->child_reaper);
	read_unlock(&tasklist_lock);

	do_exit(0);

	/* Not reached */
	return 0;
}

static void *pidns_get(struct task_struct *task)
{
	struct pid_namespace *ns;

	rcu_read_lock();
	ns = task_active_pid_ns(task);
	if (ns)
		get_pid_ns(ns);
	rcu_read_unlock();

	return ns;
}

static void pidns_put(void *ns)
{
	put_pid_ns(ns);
}

static int pidns_install(struct nsproxy *nsproxy, void *ns)
{
	struct pid_namespace *active = task_active_pid_ns(current);
	struct pid_namespace *ancestor, *new = ns;

	/*
	 * Only allow entering the current active pid namespace
	 * or a child of the current active pid namespace.
	 *
	 * This is required for fork to return a usable pid value and
	 * this maintains the property that processes and their
	 * children can not escape their current pid namespace.
	 */
	if (new->level < active->level)
		return -EINVAL;

	ancestor = new;
	while (ancestor->level > active->level)
		ancestor = ancestor->parent;
	if (ancestor != active)
		return -EINVAL;

	put_pid_ns(nsproxy->pid_ns);
	nsproxy->pid_ns = get_pid_ns(new);
	return 0;
}

static unsigned int pidns_inum(void *ns)
{
	struct pid_namespace *pid_ns = ns;
	return pid_ns->proc_inum;
}

const struct proc_ns_operations pidns_operations = {
	.name		= "pid",
	.type		= CLONE_NEWPID,
	.get		= pidns_get,
	.put		= pidns_put,
	.install	= pidns_install,
	.inum		= pidns_inum,
};

static __init int pid_namespaces_init(void)
{
	pid_ns_cachep = KMEM_CACHE(pid_namespace, SLAB_PANIC);
	return 0;
}

__initcall(pid_namespaces_init);
