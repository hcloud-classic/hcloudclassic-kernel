/*
 *  hcc/proc/hcc_exit.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/personality.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/rcupdate.h>
#include <hcc/task.h>
#ifdef CONFIG_HCC_GPM
#include <linux/uaccess.h>
#include <linux/tracehook.h>
#include <linux/task_io_accounting_ops.h>
#include <hcc/sys/types.h>
#include <hcc/hcc_init.h>
#include <hcc/pid.h>
#include <hcc/children.h>
#include <hcc/signal.h>
#include <hcc/application.h>
#include <hcc/hcc_nodemask.h>
#include <asm/cputime.h>
#endif
#ifdef CONFIG_HCC_GSCHED
#include <hcc/gscheduler/info.h>
#endif

#ifdef CONFIG_HCC_GPM
#include <hcc/workqueue.h>
#endif
#include <net/grpc/grpcid.h>
#include <net/grpc/grpc.h>
#include <hcc/task.h>
#include <hcc/hcc_exit.h>
#ifdef CONFIG_HCC_GPM
#include <hcc/action.h>
#include <hcc/migration.h>
#endif

#ifdef CONFIG_HCC_GPM

static void delay_release_task_worker(struct work_struct *work);
static DECLARE_WORK(delay_release_task_work, delay_release_task_worker);
static LIST_HEAD(tasks_to_release);
static DEFINE_SPINLOCK(tasks_to_release_lock);

struct notify_parent_request {
	pid_t parent_pid;
	unsigned int ptrace;
	struct siginfo info;
};

static void handle_do_notify_parent(struct grpc_desc *desc,
				    void *msg, size_t size)
{
	struct notify_parent_request *req = msg;
	struct task_struct *parent;
	struct sighand_struct *psig;
	int sig = req->info.si_signo;
	int err, ret;

	ret = sig;

	read_lock(&tasklist_lock);
	parent = find_task_by_kpid(req->parent_pid);
	BUG_ON(!parent);

	/* Adapted from do_notify_parent() for a remote child */

	psig = parent->sighand;
	spin_lock_irq(&psig->siglock);
	if (!req->ptrace && sig == SIGCHLD &&
	    (psig->action[SIGCHLD-1].sa.sa_handler == SIG_IGN ||
	     (psig->action[SIGCHLD-1].sa.sa_flags & SA_NOCLDWAIT))) {
		/*
		 * We are exiting and our parent doesn't care.  POSIX.1
		 * defines special semantics for setting SIGCHLD to SIG_IGN
		 * or setting the SA_NOCLDWAIT flag: we should be reaped
		 * automatically and not left for our parent's wait4 call.
		 * Rather than having the parent do it as a magic kind of
		 * signal handler, we just set this to tell do_exit that we
		 * can be cleaned up without becoming a zombie.  Note that
		 * we still call __wake_up_parent in this case, because a
		 * blocked sys_wait4 might now return -ECHILD.
		 *
		 * Whether we send SIGCHLD or not for SA_NOCLDWAIT
		 * is implementation-defined: we do (if you don't want
		 * it, just use SIG_IGN instead).
		 */
		ret = -1;
		if (psig->action[SIGCHLD-1].sa.sa_handler == SIG_IGN)
			sig = -1;
	}
	if (valid_signal(sig) && sig > 0)
		__hcc_group_send_sig_info(sig, &req->info, parent);
	wake_up_interruptible_sync(&parent->signal->wait_chldexit);
	spin_unlock_irq(&psig->siglock);

	read_unlock(&tasklist_lock);

	err = grpc_pack_type(desc, ret);
	if (err)
		grpc_cancel(desc);
}

/*
 * Expects task->task_obj locked and up to date regarding parent and
 * parent_node
 */
int hcc_do_notify_parent(struct task_struct *task, struct siginfo *info)
{
	struct notify_parent_request req;
	int ret;
	hcc_node_t parent_node = task->task_obj->parent_node;
	struct grpc_desc *desc;
	int err = -ENOMEM;

	BUG_ON(task->parent != baby_sitter);
	BUG_ON(parent_node == HCC_NODE_ID_NONE);
	BUG_ON(parent_node == hcc_node_id);

	req.parent_pid = task->task_obj->parent;
	req.ptrace = task->ptrace;
	req.info = *info;

	desc = grpc_begin(PROC_DO_NOTIFY_PARENT, parent_node);
	if (!desc)
		goto err;
	err = grpc_pack_type(desc, req);
	if (err)
		goto err_cancel;
	err = grpc_unpack_type(desc, ret);
	if (err)
		goto err_cancel;
	grpc_end(desc, 0);

out:
	if (!err)
		return ret;
	return 0;

err_cancel:
	grpc_cancel(desc);
	grpc_end(desc, 0);
err:
	printk(KERN_ERR "error: child %d cannot notify remote parent %d\n",
	       task_pid_knr(task), req.parent_pid);
	goto out;
}

/*
 * If return value is not NULL, all variables are set, and the children gdm
 * object will have to be unlocked with hcc_children_unlock(@return),
 * and parent pid location will have to be unlocked with
 * hcc_unlock_pid_location(*parent_pid_p)
 *
 * If return value is NULL, parent has no children gdm object. It is up to the
 * caller to know whether original parent died or is still alive and never had a
 * children gdm object.
 */
static
struct children_gdm_object *
parent_children_writelock_pid_location_lock(struct task_struct *task,
					    pid_t *real_parent_tgid_p,
					    pid_t *real_parent_pid_p,
					    pid_t *parent_pid_p,
					    hcc_node_t *parent_node_p)
{
	struct children_gdm_object *children_obj;
	pid_t real_parent_tgid;
	pid_t real_parent_pid;
	pid_t parent_pid;
	struct task_gdm_object *obj;
	hcc_node_t parent_node = HCC_NODE_ID_NONE;
	struct timespec backoff_time = {
		.tv_sec = 1,
		.tv_nsec = 0
	};	/* 1 second */

	/*
	 * Similar to hcc_lock_pid_location but we need to acquire
	 * parent_children_writelock at the same time without deadlocking with
	 * migration
	 */
	for (;;) {
		children_obj = hcc_parent_children_writelock(task,
							     &real_parent_tgid);
		if (!children_obj)
			break;
		hcc_get_parent(children_obj, task,
			       &parent_pid, &real_parent_pid);
		obj = hcc_task_readlock(parent_pid);
		BUG_ON(!obj);
		parent_node = obj->node;
		if (parent_node != HCC_NODE_ID_NONE)
			break;
		hcc_task_unlock(parent_pid);
		hcc_children_unlock(children_obj);

		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(timespec_to_jiffies(&backoff_time) + 1);
	}
	BUG_ON(children_obj && parent_node == HCC_NODE_ID_NONE);

	/*
	 * If children_obj is not NULL, then children_obj is write-locked and
	 * obj is read-locked,
	 * otherwise none is locked.
	 */
	if (children_obj) {
		*real_parent_tgid_p = real_parent_tgid;
		*real_parent_pid_p = real_parent_pid;
		*parent_pid_p = parent_pid;
		*parent_node_p = parent_node;
	}
	return children_obj;
}

int hcc_delayed_notify_parent(struct task_struct *leader)
{
	struct children_gdm_object *parent_children_obj;
	pid_t real_parent_tgid;
	pid_t parent_pid, real_parent_pid;
	hcc_node_t parent_node;
	int zap_leader;

	parent_children_obj = parent_children_writelock_pid_location_lock(
				leader,
				&real_parent_tgid,
				&real_parent_pid,
				&parent_pid,
				&parent_node);
	__hcc_task_writelock_nested(leader);

	tasklist_write_lock_irq();
	BUG_ON(task_detached(leader));
	/*
	 * Needed to check whether we were reparented to init, and to
	 * know which task to notify in case parent is still remote
	 */
	hcc_update_parents(leader, parent_children_obj,
			   parent_pid, real_parent_pid, parent_node);

	do_notify_parent(leader, leader->exit_signal);

	zap_leader = task_detached(leader);
	if (zap_leader)
		leader->exit_state = EXIT_DEAD;
	leader->flags &= ~PF_DELAY_NOTIFY;
	write_unlock_irq(&tasklist_lock);

	__hcc_task_unlock(leader);
	if (parent_children_obj) {
		hcc_unlock_pid_location(parent_pid);
		if (zap_leader)
			/*
			 * Parent was not interested by notification,
			 * but may have been woken up in do_wait and
			 * should not see leader as a child
			 * anymore. Remove leader from its children gdm
			 * object before parent can access it again.
			 */
			hcc_remove_child(parent_children_obj, leader);
		hcc_children_unlock(parent_children_obj);
	}

	return zap_leader;
}

struct wait_task_request {
	pid_t pid;
	pid_t real_parent_tgid;
	int options;
};

struct wait_task_result {
	struct siginfo info;
	int status;
	struct rusage ru;
	cputime_t cutime, cstime, cgtime;
	unsigned long cmin_flt, cmaj_flt;
	unsigned long cnvcsw, cnivcsw;
	unsigned long cinblock, coublock;
	unsigned long cmaxrss;
	struct task_io_accounting ioac;
};

static void handle_wait_task_zombie(struct grpc_desc *desc,
				    void *_msg, size_t size)
{
	struct wait_task_request *req = _msg;
	struct task_struct *p;
	struct signal_struct *sig;
	struct wait_task_result res;
	struct wait_opts wo;
	int retval;
	int err = -ENOMEM;

	read_lock(&tasklist_lock);
	p = find_task_by_kpid(req->pid);
	/*
	 * Child could be reaped by a another (parent's or child's) thread,
	 * and its pid could be even already reused.
	 * Also do not try to reap now if group leader having not-fully-released
	 * sub-threads.
	 */
	if (!p
	    || !p->task_obj
	    || p->task_obj->real_parent_tgid != req->real_parent_tgid
	    || delay_group_leader(p)) {
		read_unlock(&tasklist_lock);
		retval = 0;
		goto out_send_res;
	}

	/*
	 * Sample resource counters now since wait_task_zombie() may release p.
	 */
	if (!(req->options & WNOWAIT)) {
		unsigned long maxrss;
		cputime_t tgutime, tgstime;

		sig = p->signal;

		thread_group_times(p, &tgutime, &tgstime);
		res.cutime = cputime_add(tgutime, sig->cutime);
		res.cstime = cputime_add(tgstime, sig->cstime);
		res.cgtime = cputime_add(p->gtime,
					 cputime_add(sig->gtime, sig->cgtime));
		res.cmin_flt = p->min_flt + sig->min_flt + sig->cmin_flt;
		res.cmaj_flt = p->maj_flt + sig->maj_flt + sig->cmaj_flt;
		res.cnvcsw = p->nvcsw + sig->nvcsw + sig->cnvcsw;
		res.cnivcsw = p->nivcsw + sig->nivcsw + sig->cnivcsw;
		res.cinblock = task_io_get_inblock(p) +
				sig->inblock + sig->cinblock;
		res.coublock = task_io_get_oublock(p) +
				sig->oublock + sig->coublock;
		maxrss = max(sig->maxrss, sig->cmaxrss);
		res.cmaxrss = maxrss;
		res.ioac = p->ioac;
		task_io_accounting_add(&res.ioac, &sig->ioac);
	}

	wo.wo_flags	= req->options;
	wo.wo_info	= &res.info;
	wo.wo_stat	= &res.status;
	wo.wo_rusage	= &res.ru;
	retval = wait_task_zombie(&wo, p);
	if (!retval)
		read_unlock(&tasklist_lock);

out_send_res:
	err = grpc_pack_type(desc, retval);
	if (err)
		goto err_cancel;
	if (retval) {
		BUG_ON(retval < 0);
		err = grpc_pack_type(desc, res);
		if (err)
			goto err_cancel;
	}

	return;

err_cancel:
	grpc_cancel(desc);
}

int hcc_wait_task_zombie(struct wait_opts *wo,
			 struct remote_child *child)
{
	struct wait_task_request req;
	int retval;
	struct wait_task_result res;
	struct grpc_desc *desc;
	struct siginfo __user *infop;
	bool noreap = wo->wo_flags & WNOWAIT;
	int err;

	/*
	 * Zombie's location does not need to remain locked since it won't
	 * change afterwards, but this will be needed to support hot removal of
	 * nodes with zombie migration.
	 */
	BUG_ON(!hcc_node_online(child->node));

	desc = grpc_begin(PROC_WAIT_TASK_ZOMBIE, child->node);
	if (!desc)
		return -ENOMEM;

	req.pid = child->pid;
	/* True as long as no remote ptrace is allowed */
	req.real_parent_tgid = task_tgid_knr(current);
	req.options = wo->wo_flags;
	err = grpc_pack_type(desc, req);
	if (err)
		goto err_cancel;

	err = grpc_unpack_type(desc, retval);
	if (err)
		goto err_cancel;
	if (retval) {
		BUG_ON(retval < 0);
		err = grpc_unpack_type(desc, res);
		if (err)
			goto err_cancel;

		if (likely(!noreap)) {
			struct signal_struct *psig;

			spin_lock_irq(&current->sighand->siglock);
			psig = current->signal;
			psig->cutime = cputime_add(psig->cutime,
						   res.cutime);
			psig->cstime = cputime_add(psig->cstime,
						   res.cstime);
			psig->cgtime = cputime_add(psig->cgtime,
						   res.cgtime);
			psig->cmin_flt += res.cmin_flt;
			psig->cmaj_flt += res.cmaj_flt;
			psig->cnvcsw += res.cnvcsw;
			psig->cnivcsw += res.cnivcsw;
			psig->cinblock += res.cinblock;
			psig->coublock += res.coublock;
			psig->cmaxrss = res.cmaxrss;
			task_io_accounting_add(&psig->ioac, &res.ioac);
			spin_unlock_irq(&current->sighand->siglock);
		}

		retval = 0;
		if (wo->wo_rusage)
			retval = copy_to_user(wo->wo_rusage, &res.ru, sizeof(res.ru)) ?
				-EFAULT : 0;
		if (!retval && wo->wo_stat && likely(!noreap))
			retval = put_user(res.status, wo->wo_stat);

		infop = wo->wo_info;
		if (!retval && infop) {
			retval = put_user(res.info.si_signo, &infop->si_signo);
			if (!retval)
				retval = put_user(res.info.si_errno,
						  &infop->si_errno);
			if (!retval)
				retval = put_user(res.info.si_code,
						  &infop->si_code);
			if (!retval)
				retval = put_user(res.info.si_status,
						  &infop->si_status);
			if (!retval)
				retval = put_user(res.info.si_pid,
						  &infop->si_pid);
			if (!retval)
				retval = put_user(res.info.si_uid,
						  &infop->si_uid);
		}
		if (!retval)
			retval = child->pid;
	}
out:
	grpc_end(desc, 0);

	return retval;

err_cancel:
	grpc_cancel(desc);
	if (err > 0)
		err = -EPIPE;
	retval = err;
	goto out;
}

struct children_gdm_object *
hcc_prepare_exit_ptrace_task(struct task_struct *tracer,
			     struct task_struct *task)
{
	struct children_gdm_object *obj;
	pid_t real_parent_tgid, real_parent_pid, parent_pid;
	hcc_node_t parent_node;

	/* Prepare a call to do_notify_parent() in __ptrace_detach() */

	/*
	 * Note: real parent should be locked, not parent. However the children
	 * object only records real parent, so it's ok.
	 */
	obj = rcu_dereference(task->parent_children_obj);
	if (obj)
		obj = parent_children_writelock_pid_location_lock(
			task,
			&real_parent_tgid,
			&real_parent_pid,
			&parent_pid,
			&parent_node);
	if (obj)
		__hcc_task_writelock_nested(task);
	else
		__hcc_task_writelock(task);

	hcc_set_child_ptraced(obj, task, 0);

	tasklist_write_lock_irq();
	BUG_ON(!task->ptrace);

	hcc_update_parents(task, obj, parent_pid, real_parent_pid, parent_node);

	return obj;
}

void hcc_finish_exit_ptrace_task(struct task_struct *task,
				 struct children_gdm_object *obj,
				 bool dead)
{
	pid_t parent_pid;

	if (task->real_parent == baby_sitter)
		parent_pid = task->task_obj->parent;
	else
		parent_pid = task_pid_knr(task->real_parent);

	write_unlock_irq(&tasklist_lock);

	if (obj) {
		hcc_unlock_pid_location(parent_pid);
		if (dead)
			hcc_remove_child(obj, task);
		hcc_children_unlock(obj);
	}
	__hcc_task_unlock(task);
}

#endif /* CONFIG_HCC_GPM */

void *hcc_prepare_exit_notify(struct task_struct *task)
{
	void *cookie = NULL;
#ifdef CONFIG_HCC_GPM
	pid_t real_parent_tgid = 0;
	pid_t real_parent_pid = 0;
	pid_t parent_pid = 0;
	hcc_node_t parent_node = HCC_NODE_ID_NONE;
#endif

#ifdef CONFIG_HCC_GPM
	if (rcu_dereference(task->parent_children_obj))
		cookie = parent_children_writelock_pid_location_lock(
				task,
				&real_parent_tgid,
				&real_parent_pid,
				&parent_pid,
				&parent_node);
#endif /* CONFIG_HCC_GPM */

	if (task->task_obj) {
		if (cookie)
			__hcc_task_writelock_nested(task);
		else
			__hcc_task_writelock(task);

#ifdef CONFIG_HCC_GPM
		tasklist_write_lock_irq();
		hcc_update_parents(task, cookie, parent_pid, real_parent_pid,
				   parent_node);
		write_unlock_irq(&tasklist_lock);
#endif /* CONFIG_HCC_GPM */
	}

	return cookie;
}

void hcc_finish_exit_notify(struct task_struct *task, int signal, void *cookie)
{
#ifdef CONFIG_HCC_GPM
	if (cookie) {
		struct children_gdm_object *parent_children_obj = cookie;
		pid_t parent_pid;

		if (task->task_obj)
			parent_pid = task->task_obj->parent;
		else
			parent_pid = task_pid_knr(task->parent);
		hcc_unlock_pid_location(parent_pid);

		if (signal == DEATH_REAP) {
			/*
			 * Parent was not interested by notification, but may
			 * have been woken up in do_wait and should not see tsk
			 * as a child anymore. Remove tsk from its children gdm
			 * object before parent can access it again.
			 */
			hcc_remove_child(parent_children_obj, task);
		} else {
			hcc_set_child_exit_signal(parent_children_obj, task);
			hcc_set_child_exit_state(parent_children_obj, task);
			hcc_set_child_location(parent_children_obj, task);
		}
		hcc_children_unlock(parent_children_obj);
	}
#endif /* CONFIG_HCC_GPM */

	if (task->task_obj)
		__hcc_task_unlock(task);
}

void hcc_release_task(struct task_struct *p)
{
#ifdef CONFIG_HCC_GPM
	hcc_exit_application(p);
	hcc_unhash_process(p);
	if (p->exit_state != EXIT_MIGRATION) {
#endif /* CONFIG_HCC_GPM */
		hcc_task_free(p);
#ifdef CONFIG_HCC_GPM
		if (hcc_action_pending(p, GPM_MIGRATE))
			/* Migration aborted because p died before */
			migration_aborted(p);
	}
#endif /* CONFIG_HCC_GPM */
}

#ifdef CONFIG_HCC_GPM

/*
 * To chain the tasks to release in the worker, we overload the children field
 * of the task_struct, which is no more used once a task is ready to release.
 */
static void delay_release_task_worker(struct work_struct *work)
{
	struct task_struct *task;

	for (;;) {
		task = NULL;
		spin_lock(&tasks_to_release_lock);
		if (!list_empty(&tasks_to_release)) {
			task = list_entry(tasks_to_release.next,
					  struct task_struct, children);
			list_del_init(&task->children);
		}
		spin_unlock(&tasks_to_release_lock);
		if (!task)
			break;
		release_task(task);
	}
}

int hcc_delay_release_task(struct task_struct *task)
{
	int delayed;

	BUG_ON(!list_empty(&task->children));

	/*
	 * No need to lock tasklist since if task is current
	 * thread_group_leader() is safe
	 */
	delayed = !thread_group_leader(task) && task == current;
	if (delayed) {
		spin_lock(&tasks_to_release_lock);
		list_add_tail(&task->children, &tasks_to_release);
		spin_unlock(&tasks_to_release_lock);

		queue_work(hcc_wq, &delay_release_task_work);
	}

	return delayed;
}

struct notify_remote_child_reaper_msg {
	pid_t zombie_pid;
};

static void handle_notify_remote_child_reaper(struct grpc_desc *desc,
					      void *_msg,
					      size_t size)
{
	struct notify_remote_child_reaper_msg *msg = _msg;
	struct task_struct *zombie;
	bool release = false;

	hcc_task_writelock(msg->zombie_pid);
	tasklist_write_lock_irq();

	zombie = find_task_by_kpid(msg->zombie_pid);
	BUG_ON(!zombie);

	/* Real parent died and let us reparent zombie to local init. */
	hcc_reparent_to_local_child_reaper(zombie);

	BUG_ON(zombie->exit_state != EXIT_ZOMBIE);
	BUG_ON(zombie->exit_signal == -1);
	if (!zombie->ptrace && thread_group_empty(zombie)) {
		do_notify_parent(zombie, zombie->exit_signal);
		if (task_detached(zombie)) {
			zombie->exit_state = EXIT_DEAD;
			release = true;
		}
	}

	write_unlock_irq(&tasklist_lock);
	hcc_task_unlock(msg->zombie_pid);

	if (release)
		release_task(zombie);
}

void notify_remote_child_reaper(pid_t zombie_pid,
				hcc_node_t zombie_location)
{
	struct notify_remote_child_reaper_msg msg = {
		.zombie_pid = zombie_pid
	};

	BUG_ON(zombie_location == HCC_NODE_ID_NONE);
	BUG_ON(zombie_location == hcc_node_id);

	grpc_async(PROC_NOTIFY_REMOTE_CHILD_REAPER, zombie_location,
		  &msg, sizeof(msg));
}

#endif /* CONFIG_HCC_GPM */

/**
 * @author Innogrid HCC
 */
void proc_hcc_exit_start(void)
{
#ifdef CONFIG_HCC_GPM
	grpc_register_void(PROC_DO_NOTIFY_PARENT, handle_do_notify_parent, 0);
	grpc_register_void(PROC_NOTIFY_REMOTE_CHILD_REAPER,
			  handle_notify_remote_child_reaper, 0);
	grpc_register_void(PROC_WAIT_TASK_ZOMBIE, handle_wait_task_zombie, 0);
#endif
}

/**
 * @author Innogrid HCC
 */
void proc_hcc_exit_exit(void)
{
}
