/*
 *  linux/fs/proc/base.c
 *
 *  Copyright (C) 1991, 1992 Linus Torvalds
 *
 *  proc base directory handling functions
 *
 *  1999, Al Viro. Rewritten. Now it covers the whole per-process part.
 *  Instead of using magical inumbers to determine the kind of object
 *  we allocate and fill in-core inodes upon lookup. They don't even
 *  go into icache. We cache the reference to task_struct upon lookup too.
 *  Eventually it should become a filesystem in its own. We don't use the
 *  rest of procfs anymore.
 *
 *
 *  Changelog:
 *  17-Jan-2005
 *  Allan Bezerra
 *  Bruna Moreira <bruna.moreira@indt.org.br>
 *  Edjard Mota <edjard.mota@indt.org.br>
 *  Ilias Biris <ilias.biris@indt.org.br>
 *  Mauricio Lin <mauricio.lin@indt.org.br>
 *
 *  Embedded Linux Lab - 10LE Instituto Nokia de Tecnologia - INdT
 *
 *  A new process specific entry (smaps) included in /proc. It shows the
 *  size of rss for each memory area. The maps entry lacks information
 *  about physical memory size (rss) for each mapped file, i.e.,
 *  rss information for executables and library files.
 *  This additional information is useful for any tools that need to know
 *  about physical memory consumption for a process specific library.
 *
 *  Changelog:
 *  21-Feb-2005
 *  Embedded Linux Lab - 10LE Instituto Nokia de Tecnologia - INdT
 *  Pud inclusion in the page table walking.
 *
 *  ChangeLog:
 *  10-Mar-2005
 *  10LE Instituto Nokia de Tecnologia - INdT:
 *  A better way to walks through the page table as suggested by Hugh Dickins.
 *
 *  Simo Piiroinen <simo.piiroinen@nokia.com>:
 *  Smaps information related to shared, private, clean and dirty pages.
 *
 *  Paul Mundt <paul.mundt@nokia.com>:
 *  Overall revision about smaps.
 */

#include <asm/uaccess.h>

#include <linux/errno.h>
#include <linux/time.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/init.h>
#include <linux/capability.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/string.h>
#include <linux/seq_file.h>
#include <linux/namei.h>
#include <linux/mnt_namespace.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/rcupdate.h>
#include <linux/kallsyms.h>
#include <linux/stacktrace.h>
#include <linux/resource.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/security.h>
#include <linux/ptrace.h>
#include <linux/tracehook.h>
#include <linux/cgroup.h>
#include <linux/cpuset.h>
#include <linux/audit.h>
#include <linux/poll.h>
#include <linux/nsproxy.h>
#include <linux/oom.h>
#include <linux/elf.h>
#include <linux/pid_namespace.h>
#include <linux/fs_struct.h>

#ifdef CONFIG_HCC_GPM
#include <hcc/action.h>
#endif
#ifdef CONFIG_HCC_GDM
#include <hcc/hcc_nodemask.h>
#include <gdm/gdm.h>
#endif
#if defined(CONFIG_HCC_PROCFS) && defined(CONFIG_HCC_PROC)
#include <hcc/pid.h>
#endif
#ifdef CONFIG_HCC_FAF
#include <hcc/faf.h>
#endif

#include "internal.h"

/* NOTE:
 *	Implementing inode permission operations in /proc is almost
 *	certainly an error.  Permission checks need to happen during
 *	each system call not at open time.  The reason is that most of
 *	what we wish to check for permissions in /proc varies at runtime.
 *
 *	The classic example of a problem is opening file descriptors
 *	in /proc for a task before it execs a suid executable.
 */

struct pid_entry {
	char *name;
	int len;
	mode_t mode;
	const struct inode_operations *iop;
	const struct file_operations *fop;
	union proc_op op;
};

#define NOD(NAME, MODE, IOP, FOP, OP) {			\
	.name = (NAME),					\
	.len  = sizeof(NAME) - 1,			\
	.mode = MODE,					\
	.iop  = IOP,					\
	.fop  = FOP,					\
	.op   = OP,					\
}

#define DIR(NAME, MODE, iops, fops)	\
	NOD(NAME, (S_IFDIR|(MODE)), &iops, &fops, {} )
#define LNK(NAME, get_link)					\
	NOD(NAME, (S_IFLNK|S_IRWXUGO),				\
		&proc_pid_link_inode_operations, NULL,		\
		{ .proc_get_link = get_link } )
#define REG(NAME, MODE, fops)				\
	NOD(NAME, (S_IFREG|(MODE)), NULL, &fops, {})
#define INF(NAME, MODE, read)				\
	NOD(NAME, (S_IFREG|(MODE)), 			\
		NULL, &proc_info_file_operations,	\
		{ .proc_read = read } )
#define ONE(NAME, MODE, show)				\
	NOD(NAME, (S_IFREG|(MODE)), 			\
		NULL, &proc_single_file_operations,	\
		{ .proc_show = show } )

static ssize_t proc_info_read(struct file * file, char __user * buf,
			  size_t count, loff_t *ppos);
/*
 * Count the number of hardlinks for the pid_entry table, excluding the .
 * and .. links.
 */
static unsigned int pid_entry_count_dirs(const struct pid_entry *entries,
	unsigned int n)
{
	unsigned int i;
	unsigned int count;

	count = 0;
	for (i = 0; i < n; ++i) {
		if (S_ISDIR(entries[i].mode))
			++count;
	}

	return count;
}

static int get_fs_path(struct task_struct *task, struct path *path, bool root)
{
	struct fs_struct *fs;
	int result = -ENOENT;

	task_lock(task);
	fs = task->fs;
	if (fs) {
		read_lock(&fs->lock);
		*path = root ? fs->root : fs->pwd;
		path_get(path);
		read_unlock(&fs->lock);
		result = 0;
	}
	task_unlock(task);
	return result;
}

int get_nr_threads(struct task_struct *tsk)
{
	unsigned long flags;
	int count = 0;

	if (lock_task_sighand(tsk, &flags)) {
		count = atomic_read(&tsk->signal->count);
		unlock_task_sighand(tsk, &flags);
	}
	return count;
}

static int proc_cwd_link(struct inode *inode, struct path *path)
{
	struct task_struct *task = get_proc_task(inode);
	int result = -ENOENT;

	if (task) {
		result = get_fs_path(task, path, 0);
		put_task_struct(task);
	}
	return result;
}

static int proc_root_link(struct inode *inode, struct path *path)
{
	struct task_struct *task = get_proc_task(inode);
	int result = -ENOENT;

	if (task) {
		result = get_fs_path(task, path, 1);
		put_task_struct(task);
	}
	return result;
}

static struct mm_struct *__check_mem_permission(struct task_struct *task)
{
	struct mm_struct *mm;

	mm = get_task_mm(task);
	if (!mm)
		return ERR_PTR(-EINVAL);

	/*
	 * A task can always look at itself, in case it chooses
	 * to use system calls instead of load instructions.
	 */
	if (task == current)
		return mm;

	/*
	 * If current is actively ptrace'ing, and would also be
	 * permitted to freshly attach with ptrace now, permit it.
	 */
	if (task_is_stopped_or_traced(task)) {
		int match;
		rcu_read_lock();
		match = (tracehook_tracer_task(task) == current);
		rcu_read_unlock();
		if (match && ptrace_may_access(task, PTRACE_MODE_ATTACH))
			return mm;
	}

	/*
	 * Noone else is allowed.
	 */
	mmput(mm);
	return ERR_PTR(-EPERM);
}

/*
 * If current may access user memory in @task return a reference to the
 * corresponding mm, otherwise ERR_PTR.
 */
static struct mm_struct *check_mem_permission(struct task_struct *task)
{
	struct mm_struct *mm;
	int err;

	/*
	 * Avoid racing if task exec's as we might get a new mm but validate
	 * against old credentials.
	 */
	err = mutex_lock_killable(&task->cred_guard_mutex);
	if (err)
		return ERR_PTR(err);

	mm = __check_mem_permission(task);
	mutex_unlock(&task->cred_guard_mutex);

	return mm;
}

struct mm_struct *mm_for_maps(struct task_struct *task)
{
	struct mm_struct *mm;
	int err;

	err =  mutex_lock_killable(&task->cred_guard_mutex);
	if (err)
		return ERR_PTR(err);

	mm = get_task_mm(task);
	if (mm && mm != current->mm &&
			!ptrace_may_access(task, PTRACE_MODE_READ)) {
		mmput(mm);
		mm = ERR_PTR(-EACCES);
	}
	mutex_unlock(&task->cred_guard_mutex);

	return mm;
}

#if !defined(CONFIG_HCC_PROCFS) || !defined(CONFIG_HCC_PROC)
static
#endif
int proc_pid_cmdline(struct task_struct *task, char *buffer)
{
	int res = 0;
	unsigned int len;
	struct mm_struct *mm = get_task_mm(task);
	if (!mm)
		goto out;
	if (!mm->arg_end)
		goto out_mm;	/* Shh! No looking before we're done */

	len = mm->arg_end - mm->arg_start;

	if (len > PAGE_SIZE)
		len = PAGE_SIZE;

	res = access_process_vm(task, mm->arg_start, buffer, len, 0);

	// If the nul at the end of args has been overwritten, then
	// assume application is using setproctitle(3).
	if (res > 0 && buffer[res-1] != '\0' && len < PAGE_SIZE) {
		len = strnlen(buffer, res);
		if (len < res) {
		    res = len;
		} else {
			len = mm->env_end - mm->env_start;
			if (len > PAGE_SIZE - res)
				len = PAGE_SIZE - res;
			res += access_process_vm(task, mm->env_start, buffer+res, len, 0);
			res = strnlen(buffer, res);
		}
	}
out_mm:
	mmput(mm);
out:
	return res;
}

#if !defined(CONFIG_HCC_PROCFS) || !defined(CONFIG_HCC_PROC)
static
#endif
int proc_pid_auxv(struct task_struct *task, char *buffer)
{
	struct mm_struct *mm = mm_for_maps(task);
	int res = PTR_ERR(mm);
	if (mm && !IS_ERR(mm)) {
		unsigned int nwords = 0;
		do {
			nwords += 2;
		} while (mm->saved_auxv[nwords - 2] != 0); /* AT_NULL */
		res = nwords * sizeof(mm->saved_auxv[0]);
		if (res > PAGE_SIZE)
			res = PAGE_SIZE;
		memcpy(buffer, mm->saved_auxv, res);
		mmput(mm);
	}
	return res;
}


#ifdef CONFIG_KALLSYMS
/*
 * Provides a wchan file via kallsyms in a proper one-value-per-file format.
 * Returns the resolved symbol.  If that fails, simply return the address.
 */
#if !defined(CONFIG_HCC_PROCFS) || !defined(CONFIG_HCC_PROC)
static
#endif
int proc_pid_wchan(struct task_struct *task, char *buffer)
{
	unsigned long wchan;
	char symname[KSYM_NAME_LEN];

	wchan = get_wchan(task);

	if (lookup_symbol_name(wchan, symname) < 0)
		if (!ptrace_may_access(task, PTRACE_MODE_READ))
			return 0;
		else
			return sprintf(buffer, "%lu", wchan);
	else
		return sprintf(buffer, "%s", symname);
}
#endif /* CONFIG_KALLSYMS */

static int lock_trace(struct task_struct *task)
{
	int err = mutex_lock_killable(&task->cred_guard_mutex);
	if (err)
		return err;
	if (!ptrace_may_access(task, PTRACE_MODE_ATTACH)) {
		mutex_unlock(&task->cred_guard_mutex);
		return -EPERM;
	}
	return 0;
}

static void unlock_trace(struct task_struct *task)
{
	mutex_unlock(&task->cred_guard_mutex);
}

#ifdef CONFIG_STACKTRACE

#define MAX_STACK_TRACE_DEPTH	64

#if !defined(CONFIG_HCC_PROCFS) || !defined(CONFIG_HCC_PROC)
static
#endif
int proc_pid_stack(struct seq_file *m, struct pid_namespace *ns,
			  struct pid *pid, struct task_struct *task)
{
	struct stack_trace trace;
	unsigned long *entries;
	int err;
	int i;

	/*
	 * The ability to racily run the kernel stack unwinder on a running task
	 * and then observe the unwinder output is scary; while it is useful for
	 * debugging kernel issues, it can also allow an attacker to leak kernel
	 * stack contents.
	 * Doing this in a manner that is at least safe from races would require
	 * some work to ensure that the remote task can not be scheduled; and
	 * even then, this would still expose the unwinder as local attack
	 * surface.
	 * Therefore, this interface is restricted to root.
	 */
	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	entries = kmalloc(MAX_STACK_TRACE_DEPTH * sizeof(*entries), GFP_KERNEL);
	if (!entries)
		return -ENOMEM;

	trace.nr_entries	= 0;
	trace.max_entries	= MAX_STACK_TRACE_DEPTH;
	trace.entries		= entries;
	trace.skip		= 0;

	err = lock_trace(task);
	if (!err) {
		save_stack_trace_tsk(task, &trace);

		for (i = 0; i < trace.nr_entries; i++) {
			seq_printf(m, "[<%p>] %pS\n",
				   (void *)entries[i], (void *)entries[i]);
		}
		unlock_trace(task);
	}
	kfree(entries);

	return err;
}
#endif

#ifdef CONFIG_SCHEDSTATS
/*
 * Provides /proc/PID/schedstat
 */
#if !defined(CONFIG_HCC_PROCFS) || !defined(CONFIG_HCC_PROC)
static
#endif
int proc_pid_schedstat(struct task_struct *task, char *buffer)
{
	return sprintf(buffer, "%llu %llu %lu\n",
			(unsigned long long)task->se.sum_exec_runtime,
			(unsigned long long)task->sched_info.run_delay,
			task->sched_info.pcount);
}
#endif

#ifdef CONFIG_LATENCYTOP
static int lstats_show_proc(struct seq_file *m, void *v)
{
	int i;
	struct inode *inode = m->private;
	struct task_struct *task = get_proc_task(inode);

	if (!task)
		return -ESRCH;
	seq_puts(m, "Latency Top version : v0.1\n");
	for (i = 0; i < 32; i++) {
		if (task->latency_record[i].backtrace[0]) {
			int q;
			seq_printf(m, "%i %li %li ",
				task->latency_record[i].count,
				task->latency_record[i].time,
				task->latency_record[i].max);
			for (q = 0; q < LT_BACKTRACEDEPTH; q++) {
				char sym[KSYM_SYMBOL_LEN];
				char *c;
				if (!task->latency_record[i].backtrace[q])
					break;
				if (task->latency_record[i].backtrace[q] == ULONG_MAX)
					break;
				sprint_symbol(sym, task->latency_record[i].backtrace[q]);
				c = strchr(sym, '+');
				if (c)
					*c = 0;
				seq_printf(m, "%s ", sym);
			}
			seq_printf(m, "\n");
		}

	}
	put_task_struct(task);
	return 0;
}

static int lstats_open(struct inode *inode, struct file *file)
{
	return single_open(file, lstats_show_proc, inode);
}

static ssize_t lstats_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *offs)
{
	struct task_struct *task = get_proc_task(file->f_dentry->d_inode);

	if (!task)
		return -ESRCH;
	clear_all_latency_tracing(task);
	put_task_struct(task);

	return count;
}

static const struct file_operations proc_lstats_operations = {
	.open		= lstats_open,
	.read		= seq_read,
	.write		= lstats_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

#endif

#if !defined(CONFIG_HCC_PROCFS) || !defined(CONFIG_HCC_PROC)
static
#endif
int proc_oom_score(struct task_struct *task, char *buffer)
{
	unsigned long points = 0;

	read_lock(&tasklist_lock);
	if (pid_alive(task))
		points = oom_badness(task, NULL, NULL,
					totalram_pages + total_swap_pages);
	read_unlock(&tasklist_lock);
	return sprintf(buffer, "%lu\n", points);
}

struct limit_names {
	char *name;
	char *unit;
};

static const struct limit_names lnames[RLIM_NLIMITS] = {
	[RLIMIT_CPU] = {"Max cpu time", "seconds"},
	[RLIMIT_FSIZE] = {"Max file size", "bytes"},
	[RLIMIT_DATA] = {"Max data size", "bytes"},
	[RLIMIT_STACK] = {"Max stack size", "bytes"},
	[RLIMIT_CORE] = {"Max core file size", "bytes"},
	[RLIMIT_RSS] = {"Max resident set", "bytes"},
	[RLIMIT_NPROC] = {"Max processes", "processes"},
	[RLIMIT_NOFILE] = {"Max open files", "files"},
	[RLIMIT_MEMLOCK] = {"Max locked memory", "bytes"},
	[RLIMIT_AS] = {"Max address space", "bytes"},
	[RLIMIT_LOCKS] = {"Max file locks", "locks"},
	[RLIMIT_SIGPENDING] = {"Max pending signals", "signals"},
	[RLIMIT_MSGQUEUE] = {"Max msgqueue size", "bytes"},
	[RLIMIT_NICE] = {"Max nice priority", NULL},
	[RLIMIT_RTPRIO] = {"Max realtime priority", NULL},
	[RLIMIT_RTTIME] = {"Max realtime timeout", "us"},
};

/* Display limits for a process */
#if !defined(CONFIG_HCC_PROCFS) || !defined(CONFIG_HCC_PROC)
static
#endif
int proc_pid_limits(struct task_struct *task, char *buffer)
{
	unsigned int i;
	int count = 0;
	unsigned long flags;
	char *bufptr = buffer;

	struct rlimit rlim[RLIM_NLIMITS];

	if (!lock_task_sighand(task, &flags))
		return 0;
	memcpy(rlim, task->signal->rlim, sizeof(struct rlimit) * RLIM_NLIMITS);
	unlock_task_sighand(task, &flags);

	/*
	 * print the file header
	 */
	count += sprintf(&bufptr[count], "%-25s %-20s %-20s %-10s\n",
			"Limit", "Soft Limit", "Hard Limit", "Units");

	for (i = 0; i < RLIM_NLIMITS; i++) {
		if (rlim[i].rlim_cur == RLIM_INFINITY)
			count += sprintf(&bufptr[count], "%-25s %-20s ",
					 lnames[i].name, "unlimited");
		else
			count += sprintf(&bufptr[count], "%-25s %-20lu ",
					 lnames[i].name, rlim[i].rlim_cur);

		if (rlim[i].rlim_max == RLIM_INFINITY)
			count += sprintf(&bufptr[count], "%-20s ", "unlimited");
		else
			count += sprintf(&bufptr[count], "%-20lu ",
					 rlim[i].rlim_max);

		if (lnames[i].unit)
			count += sprintf(&bufptr[count], "%-10s\n",
					 lnames[i].unit);
		else
			count += sprintf(&bufptr[count], "\n");
	}

	return count;
}

static ssize_t limits_write(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos)
{
	struct task_struct *task = get_proc_task(file->f_path.dentry->d_inode);
	char str[32 + 1 + 16 + 1 + 16 + 1], *delim, *next;
	struct rlimit new_rlimit;
	unsigned int i;
	int ret;

	if (!task) {
		count = -ESRCH;
		goto out;
	}
	if (copy_from_user(str, buf, min(count, sizeof(str) - 1))) {
		count = -EFAULT;
		goto put_task;
	}

	str[min(count, sizeof(str) - 1)] = 0;

	delim = strchr(str, '=');
	if (!delim) {
		count = -EINVAL;
		goto put_task;
	}
	*delim++ = 0; /* for easy 'str' usage */
	new_rlimit.rlim_cur = simple_strtoul(delim, &next, 0);
	if (*next != ':') {
		if (strncmp(delim, "unlimited:", 10)) {
			count = -EINVAL;
			goto put_task;
		}
		new_rlimit.rlim_cur = RLIM_INFINITY;
		next = delim + 9; /* move to ':' */
	}
	delim = next + 1;
	new_rlimit.rlim_max = simple_strtoul(delim, &next, 0);
	if (*next != 0) {
		if (strcmp(delim, "unlimited")) {
			count = -EINVAL;
			goto put_task;
		}
		new_rlimit.rlim_max = RLIM_INFINITY;
	}

	for (i = 0; i < RLIM_NLIMITS; i++)
		if (!strcmp(str, lnames[i].name))
			break;
	if (i >= RLIM_NLIMITS) {
		count = -EINVAL;
		goto put_task;
	}

	ret = setrlimit(task, i, &new_rlimit);
	if (ret)
		count = ret;

put_task:
	put_task_struct(task);
out:
	return count;
}

static const struct file_operations proc_pid_limits_operations = {
	.read		= proc_info_read,
	.write		= limits_write,
};

#ifdef CONFIG_HAVE_ARCH_TRACEHOOK
#if !defined(CONFIG_HCC_PROCFS) || !defined(CONFIG_HCC_PROC)
static
#endif
int proc_pid_syscall(struct task_struct *task, char *buffer)
{
	long nr;
	unsigned long args[6], sp, pc;
	int res = lock_trace(task);
	if (res)
		return res;

	if (task_current_syscall(task, &nr, args, 6, &sp, &pc))
		res = sprintf(buffer, "running\n");
	else if (nr < 0)
		res = sprintf(buffer, "%ld 0x%lx 0x%lx\n", nr, sp, pc);
	else
		res = sprintf(buffer,
		       "%ld 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx\n",
		       nr,
		       args[0], args[1], args[2], args[3], args[4], args[5],
		       sp, pc);
	unlock_trace(task);
	return res;
}
#endif /* CONFIG_HAVE_ARCH_TRACEHOOK */

#ifdef CONFIG_HCC_GPM
int gpm_type_show(struct task_struct *task, char *buffer)
{
	int res = 0;

	task_lock(task);
	switch (task->gpm_type)
	{
	case GPM_NO_ACTION:
		res = sprintf(buffer, "GPM_NO_ACTION\n");
		break;
	case GPM_MIGRATE:
		res = sprintf(buffer, "GPM_MIGRATE\n");
		break;
	case GPM_REMOTE_CLONE:
		res = sprintf(buffer, "GPM_REMOTE_CLONE\n");
		break;
	default:
		res = -EINVAL;
		break;
	}
	task_unlock(task);

	return res;
}

int gpm_source_show(struct task_struct *task, char *buffer)
{
	int res = 0;

	task_lock(task);
	res = sprintf(buffer, "%d\n", task->gpm_source);
	task_unlock(task);

	return res;
}

int gpm_target_show(struct task_struct *task, char *buffer)
{
	int res = 0;

	task_lock(task);
	res = sprintf(buffer, "%d\n", task->gpm_target);
	task_unlock(task);

	return res;
}
#endif

#ifdef CONFIG_HCC_GDM

static int proc_gdm_print_wq(char *buffer, wait_queue_head_t *q)
{
	wait_queue_t *curr;
	int len = 0;

	list_for_each_entry(curr, &q->task_list, task_list) {
		struct task_struct *tsk = curr->private;

		len += sprintf (buffer +len, "%s (%d) ", tsk->comm, tsk->pid);
	}
	return len;
}

static int proc_tid_gdm(struct task_struct *task, char *buffer)
{
	struct gdm_info_struct info;
	struct gdm_set *set;
	struct gdm_obj *obj_entry;
	int len = 0;

	if (!task->gdm_info)
		goto done;
	info = *task->gdm_info;

	len += sprintf (buffer + len, "Get Object:          %ld\n",
			info.get_object_counter);

	len += sprintf (buffer + len, "Grab Object:         %ld\n",
			info.grab_object_counter);

	len += sprintf (buffer + len, "Remove Object:       %ld\n",
			info.remove_object_counter);

	len += sprintf (buffer + len, "Flush Object:        %ld\n",
			info.flush_object_counter);


	obj_entry = get_gdm_obj_entry(info.ns_id, info.set_id, info.obj_id,
				       &set);
	if (!set)
		goto done;
	if (!obj_entry || obj_entry != info.wait_obj)
		goto unlock;

	len += sprintf (buffer + len, "Process wait on object "
			"(%d;%ld;%ld) %p with state %s\n",
			info.ns_id, info.set_id,
			info.obj_id, obj_entry,
			STATE_NAME (OBJ_STATE(obj_entry)));

	len += sprintf (buffer + len, "  * Probe owner:   %d\n",
			get_prob_owner(obj_entry));
	len += sprintf (buffer + len, "  * Frozen count:  %d\n",
			atomic_read(&obj_entry->frozen_count));
	len += sprintf (buffer + len, "  * Sleeper count: %d\n",
			atomic_read(&obj_entry->sleeper_count));
	len += sprintf (buffer + len, "  * Object:        %p\n",
			obj_entry->object);
	len += sprintf (buffer + len, "  * Copy set: ");
	len += hcc_nodemask_scnprintf(buffer + len, PAGE_SIZE - len,
				     obj_entry->master_obj.copyset);
	len += sprintf (buffer + len, "\n  * Remove set: ");
	len += hcc_nodemask_scnprintf(buffer + len, PAGE_SIZE - len,
				     obj_entry->master_obj.copyset);
	len += sprintf (buffer + len, "\n  * Waiting processes: ");
	len += proc_gdm_print_wq (buffer + len, &obj_entry->waiting_tsk);
	len += sprintf (buffer + len, "\n");
unlock:
	put_gdm_obj_entry(set, obj_entry, info.obj_id);
done:

	return len;
}

#endif /* CONFIG_HCC_GDM */

/************************************************************************/
/*                       Here the fs part begins                        */
/************************************************************************/

/* permission checks */
static int proc_fd_access_allowed(struct inode *inode)
{
	struct task_struct *task;
	int allowed = 0;
	/* Allow access to a task's file descriptors if it is us or we
	 * may use ptrace attach to the process and find out that
	 * information.
	 */
	task = get_proc_task(inode);
	if (task) {
		allowed = ptrace_may_access(task, PTRACE_MODE_READ);
		put_task_struct(task);
	}
	return allowed;
}

#if !defined(CONFIG_HCC_PROCFS) || !defined(CONFIG_HCC_PROC)
static
#endif
int proc_setattr(struct dentry *dentry, struct iattr *attr)
{
	int error;
	struct inode *inode = dentry->d_inode;

	if (attr->ia_valid & ATTR_MODE)
		return -EPERM;

	error = inode_change_ok(inode, attr);
	if (!error)
		error = inode_setattr(inode, attr);
	return error;
}

/*
 * May current process learn task's sched/cmdline info (for hide_pid_min=1)
 * or euid/egid (for hide_pid_min=2)?
 */
static bool has_pid_permissions(struct pid_namespace *pid,
				 struct task_struct *task,
				 int hide_pid_min)
{
	if (pid->hide_pid < hide_pid_min)
		return true;
	if (in_group_p(pid->pid_gid))
		return true;
	return ptrace_may_access(task, PTRACE_MODE_READ);
}


static int proc_pid_permission(struct inode *inode, int mask)
{
	struct pid_namespace *pid = inode->i_sb->s_fs_info;
	struct task_struct *task;
	bool has_perms;

	task = get_proc_task(inode);
	if (!task)
		return -ESRCH;
	has_perms = has_pid_permissions(pid, task, 1);
	put_task_struct(task);

	if (!has_perms) {
		if (pid->hide_pid == 2) {
			/*
			 * Let's make getdents(), stat(), and open()
			 * consistent with each other.  If a process
			 * may not stat() a file, it shouldn't be seen
			 * in procfs at all.
			 */
			return -ENOENT;
		}

		return -EPERM;
	}
	return generic_permission(inode, mask, NULL);
}



#if !defined(CONFIG_HCC_PROCFS) || !defined(CONFIG_HCC_PROC)
static
#endif
const struct inode_operations proc_def_inode_operations = {
	.setattr	= proc_setattr,
};

static int mounts_open_common(struct inode *inode, struct file *file,
			      const struct seq_operations *op)
{
	struct task_struct *task = get_proc_task(inode);
	struct nsproxy *nsp;
	struct mnt_namespace *ns = NULL;
	struct path root;
	struct proc_mounts *p;
	int ret = -EINVAL;

	if (task) {
		rcu_read_lock();
		nsp = task_nsproxy(task);
		if (nsp) {
			ns = nsp->mnt_ns;
			if (ns)
				get_mnt_ns(ns);
		}
		rcu_read_unlock();
		if (ns && get_fs_path(task, &root, 1) == 0)
			ret = 0;
		put_task_struct(task);
	}

	if (!ns)
		goto err;
	if (ret)
		goto err_put_ns;

	ret = -ENOMEM;
	p = kmalloc(sizeof(struct proc_mounts), GFP_KERNEL);
	if (!p)
		goto err_put_path;

	file->private_data = &p->m;
	ret = seq_open(file, op);
	if (ret)
		goto err_free;

	p->m.private = p;
	p->ns = ns;
	p->root = root;
	p->event = ns->event;

	return 0;

 err_free:
	kfree(p);
 err_put_path:
	path_put(&root);
 err_put_ns:
	put_mnt_ns(ns);
 err:
	return ret;
}

static int mounts_release(struct inode *inode, struct file *file)
{
	struct proc_mounts *p = file->private_data;
	path_put(&p->root);
	put_mnt_ns(p->ns);
	return seq_release(inode, file);
}

static unsigned mounts_poll(struct file *file, poll_table *wait)
{
	struct proc_mounts *p = file->private_data;
	struct mnt_namespace *ns = p->ns;
	unsigned res = POLLIN | POLLRDNORM;

	poll_wait(file, &ns->poll, wait);

	spin_lock(&vfsmount_lock);
	if (p->event != ns->event) {
		p->event = ns->event;
		res |= POLLERR | POLLPRI;
	}
	spin_unlock(&vfsmount_lock);

	return res;
}

static int mounts_open(struct inode *inode, struct file *file)
{
	return mounts_open_common(inode, file, &mounts_op);
}

static const struct file_operations proc_mounts_operations = {
	.open		= mounts_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= mounts_release,
	.poll		= mounts_poll,
};

static int mountinfo_open(struct inode *inode, struct file *file)
{
	return mounts_open_common(inode, file, &mountinfo_op);
}

static const struct file_operations proc_mountinfo_operations = {
	.open		= mountinfo_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= mounts_release,
	.poll		= mounts_poll,
};

static int mountstats_open(struct inode *inode, struct file *file)
{
	return mounts_open_common(inode, file, &mountstats_op);
}

static const struct file_operations proc_mountstats_operations = {
	.open		= mountstats_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= mounts_release,
};

#define PROC_BLOCK_SIZE	(3*1024)		/* 4K page size but our output routines use some slack for overruns */

static ssize_t proc_info_read(struct file * file, char __user * buf,
			  size_t count, loff_t *ppos)
{
	struct inode * inode = file->f_path.dentry->d_inode;
	unsigned long page;
	ssize_t length;
	struct task_struct *task = get_proc_task(inode);

	length = -ESRCH;
	if (!task)
		goto out_no_task;

	if (count > PROC_BLOCK_SIZE)
		count = PROC_BLOCK_SIZE;

	length = -ENOMEM;
	if (!(page = __get_free_page(GFP_TEMPORARY)))
		goto out;

	length = PROC_I(inode)->op.proc_read(task, (char*)page);

	if (length >= 0)
		length = simple_read_from_buffer(buf, count, ppos, (char *)page, length);
	free_page(page);
out:
	put_task_struct(task);
out_no_task:
	return length;
}

static const struct file_operations proc_info_file_operations = {
	.read		= proc_info_read,
};

static int proc_single_show(struct seq_file *m, void *v)
{
	struct inode *inode = m->private;
	struct pid_namespace *ns;
	struct pid *pid;
	struct task_struct *task;
	int ret;

	ns = inode->i_sb->s_fs_info;
	pid = proc_pid(inode);
	task = get_pid_task(pid, PIDTYPE_PID);
	if (!task)
		return -ESRCH;

	ret = PROC_I(inode)->op.proc_show(m, ns, pid, task);

	put_task_struct(task);
	return ret;
}

static int proc_single_open(struct inode *inode, struct file *filp)
{
	int ret;
	ret = single_open(filp, proc_single_show, NULL);
	if (!ret) {
		struct seq_file *m = filp->private_data;

		m->private = inode;
	}
	return ret;
}

static const struct file_operations proc_single_file_operations = {
	.open		= proc_single_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int mem_open(struct inode* inode, struct file* file)
{
	file->private_data = (void*)((long)current->self_exec_id);
	return 0;
}

static ssize_t mem_read(struct file * file, char __user * buf,
			size_t count, loff_t *ppos)
{
	struct task_struct *task = get_proc_task(file->f_path.dentry->d_inode);
	char *page;
	unsigned long src = *ppos;
	int ret = -ESRCH;
	struct mm_struct *mm;

	if (!task)
		goto out_no_task;

	ret = -ENOMEM;
	page = (char *)__get_free_page(GFP_TEMPORARY);
	if (!page)
		goto out;

	mm = check_mem_permission(task);
	ret = PTR_ERR(mm);
	if (IS_ERR(mm))
		goto out_free;

	ret = -EIO;
 
	if (file->private_data != (void*)((long)current->self_exec_id))
		goto out_put;

	ret = 0;
 
	while (count > 0) {
		int this_len, retval;

		this_len = (count > PAGE_SIZE) ? PAGE_SIZE : count;
		retval = access_remote_vm(mm, src, page, this_len, 0);
		if (!retval) {
			if (!ret)
				ret = -EIO;
			break;
		}

		if (copy_to_user(buf, page, retval)) {
			ret = -EFAULT;
			break;
		}
 
		ret += retval;
		src += retval;
		buf += retval;
		count -= retval;
	}
	*ppos = src;

out_put:
	mmput(mm);
out_free:
	free_page((unsigned long) page);
out:
	put_task_struct(task);
out_no_task:
	return ret;
}

#define mem_write NULL

#ifndef mem_write
/* This is a security hazard */
static ssize_t mem_write(struct file * file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
	int copied;
	char *page;
	struct task_struct *task = get_proc_task(file->f_path.dentry->d_inode);
	unsigned long dst = *ppos;
	struct mm_struct *mm;

	copied = -ESRCH;
	if (!task)
		goto out_no_task;

	mm = check_mem_permission(task);
	copied = PTR_ERR(mm);
	if (IS_ERR(mm))
		goto out_task;

	copied = -EIO;
	if (file->private_data != (void *)((long)current->self_exec_id))
		goto out_mm;

	copied = -ENOMEM;
	page = (char *)__get_free_page(GFP_TEMPORARY);
	if (!page)
		goto out_mm;

	copied = 0;
	while (count > 0) {
		int this_len, retval;

		this_len = (count > PAGE_SIZE) ? PAGE_SIZE : count;
		if (copy_from_user(page, buf, this_len)) {
			copied = -EFAULT;
			break;
		}
		retval = access_remote_vm(mm, dst, page, this_len, 1);
		if (!retval) {
			if (!copied)
				copied = -EIO;
			break;
		}
		copied += retval;
		buf += retval;
		dst += retval;
		count -= retval;			
	}
	*ppos = dst;
	free_page((unsigned long) page);
out_mm:
	mmput(mm);
out_task:
	put_task_struct(task);
out_no_task:
	return copied;
}
#endif

loff_t mem_lseek(struct file *file, loff_t offset, int orig)
{
	switch (orig) {
	case 0:
		file->f_pos = offset;
		break;
	case 1:
		file->f_pos += offset;
		break;
	default:
		return -EINVAL;
	}
	force_successful_syscall_return();
	return file->f_pos;
}

static const struct file_operations proc_mem_operations = {
	.llseek		= mem_lseek,
	.read		= mem_read,
	.write		= mem_write,
	.open		= mem_open,
};

static ssize_t environ_read(struct file *file, char __user *buf,
			size_t count, loff_t *ppos)
{
	struct task_struct *task = get_proc_task(file->f_dentry->d_inode);
	char *page;
	unsigned long src = *ppos;
	int ret = -ESRCH;
	struct mm_struct *mm;

	if (!task)
		goto out_no_task;

	ret = -ENOMEM;
	page = (char *)__get_free_page(GFP_TEMPORARY);
	if (!page)
		goto out;


	mm = mm_for_maps(task);
	ret = PTR_ERR(mm);
	if (!mm || IS_ERR(mm))
		goto out_free;

	ret = 0;
	while (count > 0) {
		int this_len, retval, max_len;

		this_len = mm->env_end - (mm->env_start + src);

		if (this_len <= 0)
			break;

		max_len = (count > PAGE_SIZE) ? PAGE_SIZE : count;
		this_len = (this_len > max_len) ? max_len : this_len;

		retval = access_process_vm(task, (mm->env_start + src),
			page, this_len, 0);

		if (retval <= 0) {
			ret = retval;
			break;
		}

		if (copy_to_user(buf, page, retval)) {
			ret = -EFAULT;
			break;
		}

		ret += retval;
		src += retval;
		buf += retval;
		count -= retval;
	}
	*ppos = src;

	mmput(mm);
out_free:
	free_page((unsigned long) page);
out:
	put_task_struct(task);
out_no_task:
	return ret;
}

static const struct file_operations proc_environ_operations = {
	.read		= environ_read,
};

static ssize_t oom_adjust_read(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	struct task_struct *task = get_proc_task(file->f_path.dentry->d_inode);
	char buffer[PROC_NUMBUF];
	size_t len;
	int oom_adjust = OOM_DISABLE;
	unsigned long flags;

	if (!task)
		return -ESRCH;

	if (lock_task_sighand(task, &flags)) {
		oom_adjust = task->signal->oom_adj;
		unlock_task_sighand(task, &flags);
	}

	put_task_struct(task);

	len = snprintf(buffer, sizeof(buffer), "%i\n", oom_adjust);

	return simple_read_from_buffer(buf, count, ppos, buffer, len);
}

static ssize_t oom_adjust_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	struct task_struct *task;
	char buffer[PROC_NUMBUF];
	long oom_adjust;
	unsigned long flags;
	int err;

	memset(buffer, 0, sizeof(buffer));
	if (count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;
	if (copy_from_user(buffer, buf, count)) {
		err = -EFAULT;
		goto out;
	}

	err = strict_strtol(strstrip(buffer), 0, &oom_adjust);
	if (err)
		goto out;
	if ((oom_adjust < OOM_ADJUST_MIN || oom_adjust > OOM_ADJUST_MAX) &&
	     oom_adjust != OOM_DISABLE) {
		err = -EINVAL;
		goto out;
	}

	task = get_proc_task(file->f_path.dentry->d_inode);
	if (!task) {
		err = -ESRCH;
		goto out;
	}

	task_lock(task);
	if (!task->mm) {
		err = -EINVAL;
		goto err_task_lock;
	}

	if (!lock_task_sighand(task, &flags)) {
		err = -ESRCH;
		goto err_task_lock;
	}

	if (oom_adjust < task->signal->oom_adj && !capable(CAP_SYS_RESOURCE)) {
		err = -EACCES;
		goto err_sighand;
	}

	if (oom_adjust != task->signal->oom_adj) {
		if (oom_adjust == OOM_DISABLE)
			atomic_inc(&task->mm->oom_disable_count);
		if (task->signal->oom_adj == OOM_DISABLE)
			atomic_dec(&task->mm->oom_disable_count);
	}

	task->signal->oom_adj = oom_adjust;
	/*
	 * Scale /proc/pid/oom_score_adj appropriately ensuring that a maximum
	 * value is always attainable.
	 */
	if (task->signal->oom_adj == OOM_ADJUST_MAX)
		task->signal->oom_score_adj = OOM_SCORE_ADJ_MAX;
	else
		task->signal->oom_score_adj = (oom_adjust * OOM_SCORE_ADJ_MAX) /
								-OOM_DISABLE;
err_sighand:
	unlock_task_sighand(task, &flags);
err_task_lock:
	task_unlock(task);
	put_task_struct(task);
out:
	return err < 0 ? err : count;
}

static const struct file_operations proc_oom_adjust_operations = {
	.read		= oom_adjust_read,
	.write		= oom_adjust_write,
};

static ssize_t oom_score_adj_read(struct file *file, char __user *buf,
					size_t count, loff_t *ppos)
{
	struct task_struct *task = get_proc_task(file->f_path.dentry->d_inode);
	char buffer[PROC_NUMBUF];
	int oom_score_adj = OOM_SCORE_ADJ_MIN;
	unsigned long flags;
	size_t len;

	if (!task)
		return -ESRCH;
	if (lock_task_sighand(task, &flags)) {
		oom_score_adj = task->signal->oom_score_adj;
		unlock_task_sighand(task, &flags);
	}
	put_task_struct(task);
	len = snprintf(buffer, sizeof(buffer), "%d\n", oom_score_adj);
	return simple_read_from_buffer(buf, count, ppos, buffer, len);
}

static ssize_t oom_score_adj_write(struct file *file, const char __user *buf,
					size_t count, loff_t *ppos)
{
	struct task_struct *task;
	char buffer[PROC_NUMBUF];
	unsigned long flags;
	long oom_score_adj;
	int err;

	memset(buffer, 0, sizeof(buffer));
	if (count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;
	if (copy_from_user(buffer, buf, count)) {
		err = -EFAULT;
		goto out;
	}

	err = strict_strtol(strstrip(buffer), 0, &oom_score_adj);
	if (err)
		goto out;
	if (oom_score_adj < OOM_SCORE_ADJ_MIN ||
			oom_score_adj > OOM_SCORE_ADJ_MAX) {
		err = -EINVAL;
		goto out;
	}

	task = get_proc_task(file->f_path.dentry->d_inode);
	if (!task) {
		err = -ESRCH;
		goto out;
	}

	task_lock(task);
	if (!task->mm) {
		err = -EINVAL;
		goto err_task_lock;
	}

	if (!lock_task_sighand(task, &flags)) {
		err = -ESRCH;
		goto err_task_lock;
	}

	if (oom_score_adj < task->signal->oom_score_adj_min &&
			!capable(CAP_SYS_RESOURCE)) {
		err = -EACCES;
		goto err_sighand;
	}

	if (oom_score_adj != task->signal->oom_score_adj) {
		if (oom_score_adj == OOM_SCORE_ADJ_MIN)
			atomic_inc(&task->mm->oom_disable_count);
		if (task->signal->oom_score_adj == OOM_SCORE_ADJ_MIN)
			atomic_dec(&task->mm->oom_disable_count);
	}
	task->signal->oom_score_adj = oom_score_adj;
	if (has_capability_noaudit(current, CAP_SYS_RESOURCE))
		task->signal->oom_score_adj_min = oom_score_adj;
	/*
	 * Scale /proc/pid/oom_adj appropriately ensuring that OOM_DISABLE is
	 * always attainable.
	 */
	if (task->signal->oom_score_adj == OOM_SCORE_ADJ_MIN)
		task->signal->oom_adj = OOM_DISABLE;
	else
		task->signal->oom_adj = (oom_score_adj * OOM_ADJUST_MAX) /
							OOM_SCORE_ADJ_MAX;
err_sighand:
	unlock_task_sighand(task, &flags);
err_task_lock:
	task_unlock(task);
	put_task_struct(task);
out:
	return err < 0 ? err : count;
}

static const struct file_operations proc_oom_score_adj_operations = {
	.read		= oom_score_adj_read,
	.write		= oom_score_adj_write,
};

#ifdef CONFIG_AUDITSYSCALL
#define TMPBUFLEN 21
static ssize_t proc_loginuid_read(struct file * file, char __user * buf,
				  size_t count, loff_t *ppos)
{
	struct inode * inode = file->f_path.dentry->d_inode;
	struct task_struct *task = get_proc_task(inode);
	ssize_t length;
	char tmpbuf[TMPBUFLEN];

	if (!task)
		return -ESRCH;
	length = scnprintf(tmpbuf, TMPBUFLEN, "%u",
				audit_get_loginuid(task));
	put_task_struct(task);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static ssize_t proc_loginuid_write(struct file * file, const char __user * buf,
				   size_t count, loff_t *ppos)
{
	struct inode * inode = file->f_path.dentry->d_inode;
	char *page, *tmp;
	ssize_t length;
	uid_t loginuid;

	if (!capable(CAP_AUDIT_CONTROL))
		return -EPERM;

	if (current != pid_task(proc_pid(inode), PIDTYPE_PID))
		return -EPERM;

	if (count >= PAGE_SIZE)
		count = PAGE_SIZE - 1;

	if (*ppos != 0) {
		/* No partial writes. */
		return -EINVAL;
	}
	page = (char*)__get_free_page(GFP_TEMPORARY);
	if (!page)
		return -ENOMEM;
	length = -EFAULT;
	if (copy_from_user(page, buf, count))
		goto out_free_page;

	page[count] = '\0';
	loginuid = simple_strtoul(page, &tmp, 10);
	if (tmp == page) {
		length = -EINVAL;
		goto out_free_page;

	}
	length = audit_set_loginuid(current, loginuid);
	if (likely(length == 0))
		length = count;

out_free_page:
	free_page((unsigned long) page);
	return length;
}

static const struct file_operations proc_loginuid_operations = {
	.read		= proc_loginuid_read,
	.write		= proc_loginuid_write,
};

static ssize_t proc_sessionid_read(struct file * file, char __user * buf,
				  size_t count, loff_t *ppos)
{
	struct inode * inode = file->f_path.dentry->d_inode;
	struct task_struct *task = get_proc_task(inode);
	ssize_t length;
	char tmpbuf[TMPBUFLEN];

	if (!task)
		return -ESRCH;
	length = scnprintf(tmpbuf, TMPBUFLEN, "%u",
				audit_get_sessionid(task));
	put_task_struct(task);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static const struct file_operations proc_sessionid_operations = {
	.read		= proc_sessionid_read,
};
#endif

#ifdef CONFIG_FAULT_INJECTION
static ssize_t proc_fault_inject_read(struct file * file, char __user * buf,
				      size_t count, loff_t *ppos)
{
	struct task_struct *task = get_proc_task(file->f_dentry->d_inode);
	char buffer[PROC_NUMBUF];
	size_t len;
	int make_it_fail;

	if (!task)
		return -ESRCH;
	make_it_fail = task->make_it_fail;
	put_task_struct(task);

	len = snprintf(buffer, sizeof(buffer), "%i\n", make_it_fail);

	return simple_read_from_buffer(buf, count, ppos, buffer, len);
}

static ssize_t proc_fault_inject_write(struct file * file,
			const char __user * buf, size_t count, loff_t *ppos)
{
	struct task_struct *task;
	char buffer[PROC_NUMBUF], *end;
	int make_it_fail;

	if (!capable(CAP_SYS_RESOURCE))
		return -EPERM;
	memset(buffer, 0, sizeof(buffer));
	if (count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;
	if (copy_from_user(buffer, buf, count))
		return -EFAULT;
	make_it_fail = simple_strtol(strstrip(buffer), &end, 0);
	if (*end)
		return -EINVAL;
	task = get_proc_task(file->f_dentry->d_inode);
	if (!task)
		return -ESRCH;
	task->make_it_fail = make_it_fail;
	put_task_struct(task);

	return count;
}

static const struct file_operations proc_fault_inject_operations = {
	.read		= proc_fault_inject_read,
	.write		= proc_fault_inject_write,
};
#endif


#ifdef CONFIG_SCHED_DEBUG
/*
 * Print out various scheduling related per-task fields:
 */
static int sched_show(struct seq_file *m, void *v)
{
	struct inode *inode = m->private;
	struct task_struct *p;

	p = get_proc_task(inode);
	if (!p)
		return -ESRCH;
	proc_sched_show_task(p, m);

	put_task_struct(p);

	return 0;
}

static ssize_t
sched_write(struct file *file, const char __user *buf,
	    size_t count, loff_t *offset)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct task_struct *p;

	p = get_proc_task(inode);
	if (!p)
		return -ESRCH;
	proc_sched_set_task(p);

	put_task_struct(p);

	return count;
}

static int sched_open(struct inode *inode, struct file *filp)
{
	int ret;

	ret = single_open(filp, sched_show, NULL);
	if (!ret) {
		struct seq_file *m = filp->private_data;

		m->private = inode;
	}
	return ret;
}

static const struct file_operations proc_pid_sched_operations = {
	.open		= sched_open,
	.read		= seq_read,
	.write		= sched_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

#endif

#ifdef CONFIG_SCHED_AUTOGROUP
/*
 * Print out autogroup related information:
 */
static int sched_autogroup_show(struct seq_file *m, void *v)
{
	struct inode *inode = m->private;
	struct task_struct *p;

	p = get_proc_task(inode);
	if (!p)
		return -ESRCH;
	proc_sched_autogroup_show_task(p, m);

	put_task_struct(p);

	return 0;
}

static ssize_t
sched_autogroup_write(struct file *file, const char __user *buf,
	    size_t count, loff_t *offset)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct task_struct *p;
	char buffer[PROC_NUMBUF];
	long nice;
	int err;

	memset(buffer, 0, sizeof(buffer));
	if (count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;
	if (copy_from_user(buffer, buf, count))
		return -EFAULT;

	err = strict_strtol(strstrip(buffer), 0, &nice);
	if (err)
		return -EINVAL;

	p = get_proc_task(inode);
	if (!p)
		return -ESRCH;

	err = nice;
	err = proc_sched_autogroup_set_nice(p, &err);
	if (err)
		count = err;

	put_task_struct(p);

	return count;
}

static int sched_autogroup_open(struct inode *inode, struct file *filp)
{
	int ret;

	ret = single_open(filp, sched_autogroup_show, NULL);
	if (!ret) {
		struct seq_file *m = filp->private_data;

		m->private = inode;
	}
	return ret;
}

static const struct file_operations proc_pid_sched_autogroup_operations = {
	.open		= sched_autogroup_open,
	.read		= seq_read,
	.write		= sched_autogroup_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

#endif /* CONFIG_SCHED_AUTOGROUP */

static ssize_t comm_write(struct file *file, const char __user *buf,
				size_t count, loff_t *offset)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct task_struct *p;
	char buffer[TASK_COMM_LEN];

	memset(buffer, 0, sizeof(buffer));
	if (count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;
	if (copy_from_user(buffer, buf, count))
		return -EFAULT;

	p = get_proc_task(inode);
	if (!p)
		return -ESRCH;

	if (same_thread_group(current, p))
		set_task_comm(p, buffer);
	else
		count = -EINVAL;

	put_task_struct(p);

	return count;
}

static int comm_show(struct seq_file *m, void *v)
{
	struct inode *inode = m->private;
	struct task_struct *p;

	p = get_proc_task(inode);
	if (!p)
		return -ESRCH;

	task_lock(p);
	seq_printf(m, "%s\n", p->comm);
	task_unlock(p);

	put_task_struct(p);

	return 0;
}

static int comm_open(struct inode *inode, struct file *filp)
{
	int ret;

	ret = single_open(filp, comm_show, NULL);
	if (!ret) {
		struct seq_file *m = filp->private_data;

		m->private = inode;
	}
	return ret;
}

static const struct file_operations proc_pid_set_comm_operations = {
	.open		= comm_open,
	.read		= seq_read,
	.write		= comm_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/*
 * We added or removed a vma mapping the executable. The vmas are only mapped
 * during exec and are not mapped with the mmap system call.
 * Callers must hold down_write() on the mm's mmap_sem for these
 */
void added_exe_file_vma(struct mm_struct *mm)
{
	mm->num_exe_file_vmas++;
}

void removed_exe_file_vma(struct mm_struct *mm)
{
	mm->num_exe_file_vmas--;
	if ((mm->num_exe_file_vmas == 0) && mm->exe_file){
		fput(mm->exe_file);
		mm->exe_file = NULL;
	}

}

void set_mm_exe_file(struct mm_struct *mm, struct file *new_exe_file)
{
	if (new_exe_file)
		get_file(new_exe_file);
	if (mm->exe_file)
		fput(mm->exe_file);
	mm->exe_file = new_exe_file;
	mm->num_exe_file_vmas = 0;
}

struct file *get_mm_exe_file(struct mm_struct *mm)
{
	struct file *exe_file;

	/* We need mmap_sem to protect against races with removal of
	 * VM_EXECUTABLE vmas */
	down_read(&mm->mmap_sem);
	exe_file = mm->exe_file;
	if (exe_file)
		get_file(exe_file);
	up_read(&mm->mmap_sem);
	return exe_file;
}

void dup_mm_exe_file(struct mm_struct *oldmm, struct mm_struct *newmm)
{
	/* It's safe to write the exe_file pointer without exe_file_lock because
	 * this is called during fork when the task is not yet in /proc */
	newmm->exe_file = get_mm_exe_file(oldmm);
}

static int proc_exe_link(struct inode *inode, struct path *exe_path)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct file *exe_file;

	task = get_proc_task(inode);
	if (!task)
		return -ENOENT;
	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm)
		return -ENOENT;
	exe_file = get_mm_exe_file(mm);
	mmput(mm);
	if (exe_file) {
		*exe_path = exe_file->f_path;
		path_get(&exe_file->f_path);
		fput(exe_file);
		return 0;
	} else
		return -ENOENT;
}

static void *proc_pid_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct inode *inode = dentry->d_inode;
	int error = -EACCES;

	/* We don't need a base pointer in the /proc filesystem */
	path_put(&nd->path);

	/* Are we allowed to snoop on the tasks file descriptors? */
	if (!proc_fd_access_allowed(inode))
		goto out;

	error = PROC_I(inode)->op.proc_get_link(inode, &nd->path);
out:
	return ERR_PTR(error);
}

#if !defined(CONFIG_HCC_PROCFS) || !defined(CONFIG_HCC_PROC)
static
#endif
int do_proc_readlink(struct path *path, char __user *buffer, int buflen)
{
	char *tmp = (char*)__get_free_page(GFP_TEMPORARY);
	char *pathname;
	int len;

	if (!tmp)
		return -ENOMEM;

#ifdef CONFIG_HCC_FAF
	if (!path->dentry && path->mnt)
		pathname = hcc_faf_d_path((struct file *)path->mnt, tmp, PAGE_SIZE, NULL);
	else
#endif
	pathname = d_path(path, tmp, PAGE_SIZE);
	len = PTR_ERR(pathname);
	if (IS_ERR(pathname))
		goto out;
	len = tmp + PAGE_SIZE - 1 - pathname;

	if (len > buflen)
		len = buflen;
	if (copy_to_user(buffer, pathname, len))
		len = -EFAULT;
 out:
	free_page((unsigned long)tmp);
	return len;
}

static int proc_pid_readlink(struct dentry * dentry, char __user * buffer, int buflen)
{
	int error = -EACCES;
	struct inode *inode = dentry->d_inode;
	struct path path;

	/* Are we allowed to snoop on the tasks file descriptors? */
	if (!proc_fd_access_allowed(inode))
		goto out;

	error = PROC_I(inode)->op.proc_get_link(inode, &path);
	if (error)
		goto out;

	error = do_proc_readlink(&path, buffer, buflen);
#ifdef CONFIG_HCC_FAF
	if (!path.dentry && path.mnt) {
		fput((struct file *)path.mnt);
		goto out;
	}
#endif
	path_put(&path);
out:
	return error;
}

static const struct inode_operations proc_pid_link_inode_operations = {
	.readlink	= proc_pid_readlink,
	.follow_link	= proc_pid_follow_link,
	.setattr	= proc_setattr,
};


/* building an inode */

static int task_dumpable(struct task_struct *task)
{
	int dumpable = 0;
	struct mm_struct *mm;

	task_lock(task);
	mm = task->mm;
	if (mm)
		dumpable = get_dumpable(mm);
	task_unlock(task);
	if(dumpable == 1)
		return 1;
	return 0;
}

struct inode *proc_pid_make_inode(struct super_block * sb, struct task_struct *task)
{
	struct inode * inode;
	struct proc_inode *ei;
	const struct cred *cred;

	/* We need a new inode */

	inode = new_inode(sb);
	if (!inode)
		goto out;

	/* Common stuff */
	ei = PROC_I(inode);
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
	inode->i_op = &proc_def_inode_operations;

	/*
	 * grab the reference to task.
	 */
	ei->pid = get_task_pid(task, PIDTYPE_PID);
	if (!ei->pid)
		goto out_unlock;

	if (task_dumpable(task)) {
		rcu_read_lock();
		cred = __task_cred(task);
		inode->i_uid = cred->euid;
		inode->i_gid = cred->egid;
		rcu_read_unlock();
	}
	security_task_to_inode(task, inode);

out:
	return inode;

out_unlock:
	iput(inode);
	return NULL;
}

int pid_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat)
{
	struct inode *inode = dentry->d_inode;
	struct task_struct *task;
	const struct cred *cred;
	struct pid_namespace *pid = dentry->d_sb->s_fs_info;

	generic_fillattr(inode, stat);

	rcu_read_lock();
	stat->uid = 0;
	stat->gid = 0;
	task = pid_task(proc_pid(inode), PIDTYPE_PID);
	if (task) {
		if (!has_pid_permissions(pid, task, 2)) {
			rcu_read_unlock();
			/*
			 * This doesn't prevent learning whether PID exists,
			 * it only makes getattr() consistent with readdir().
			 */
			return -ENOENT;
		}
		if ((inode->i_mode == (S_IFDIR|S_IRUGO|S_IXUGO)) ||
		    task_dumpable(task)) {
			cred = __task_cred(task);
			stat->uid = cred->euid;
			stat->gid = cred->egid;
		}
	}
	rcu_read_unlock();
	return 0;
}

/* dentry stuff */

/*
 *	Exceptional case: normally we are not allowed to unhash a busy
 * directory. In this case, however, we can do it - no aliasing problems
 * due to the way we treat inodes.
 *
 * Rewrite the inode's ownerships here because the owning task may have
 * performed a setuid(), etc.
 *
 * Before the /proc/pid/status file was created the only way to read
 * the effective uid of a /process was to stat /proc/pid.  Reading
 * /proc/pid/status is slow enough that procps and other packages
 * kept stating /proc/pid.  To keep the rules in /proc simple I have
 * made this apply to all per process world readable and executable
 * directories.
 */
int pid_revalidate(struct dentry *dentry, struct nameidata *nd)
{
	struct inode *inode = dentry->d_inode;
	struct task_struct *task = get_proc_task(inode);
	const struct cred *cred;

#if defined(CONFIG_HCC_PROCFS) && defined(CONFIG_HCC_GPM)
	if (task && task->exit_state != EXIT_MIGRATION) {
#else
	if (task) {
#endif
		if ((inode->i_mode == (S_IFDIR|S_IRUGO|S_IXUGO)) ||
		    task_dumpable(task)) {
			rcu_read_lock();			
			cred = __task_cred(task);			
			inode->i_uid = cred->euid;
			inode->i_gid = cred->egid;
			rcu_read_unlock();
		} else {
			inode->i_uid = 0;
			inode->i_gid = 0;
		}
		inode->i_mode &= ~(S_ISUID | S_ISGID);
		security_task_to_inode(task, inode);
		put_task_struct(task);
		return 1;
	}
	d_drop(dentry);
	return 0;
}

static int pid_delete_dentry(struct dentry * dentry)
{
	/* Is the task we represent dead?
	 * If so, then don't put the dentry on the lru list,
	 * kill it immediately.
	 */
	return !proc_pid(dentry->d_inode)->tasks[PIDTYPE_PID].first;
}

const struct dentry_operations pid_dentry_operations =
{
	.d_revalidate	= pid_revalidate,
	.d_delete	= pid_delete_dentry,
};

/* Lookups */

/*
 * Fill a directory entry.
 *
 * If possible create the dcache entry and derive our inode number and
 * file type from dcache entry.
 *
 * Since all of the proc inode numbers are dynamically generated, the inode
 * numbers do not exist until the inode is cache.  This means creating the
 * the dcache entry in readdir is necessary to keep the inode numbers
 * reported by readdir in sync with the inode numbers reported
 * by stat.
 */
int proc_fill_cache(struct file *filp, void *dirent, filldir_t filldir,
	const char *name, int len,
	instantiate_t instantiate, struct task_struct *task, const void *ptr)
{
	struct dentry *child, *dir = filp->f_path.dentry;
	struct inode *inode;
	struct qstr qname;
	ino_t ino = 0;
	unsigned type = DT_UNKNOWN;

	qname.name = name;
	qname.len  = len;
	qname.hash = full_name_hash(name, len);

	child = d_lookup(dir, &qname);
	if (!child) {
		struct dentry *new;
		new = d_alloc(dir, &qname);
		if (new) {
			child = instantiate(dir->d_inode, new, task, ptr);
			if (child)
				dput(new);
			else
				child = new;
		}
	}
	if (!child || IS_ERR(child) || !child->d_inode)
		goto end_instantiate;
	inode = child->d_inode;
	if (inode) {
		ino = inode->i_ino;
		type = inode->i_mode >> 12;
	}
	dput(child);
end_instantiate:
	if (!ino)
		ino = find_inode_number(dir, &qname);
	if (!ino)
		ino = 1;
	return filldir(dirent, name, len, filp->f_pos, ino, type);
}

static unsigned name_to_int(struct dentry *dentry)
{
	const char *name = dentry->d_name.name;
	int len = dentry->d_name.len;
	unsigned n = 0;

	if (len > 1 && *name == '0')
		goto out;
	while (len-- > 0) {
		unsigned c = *name++ - '0';
		if (c > 9)
			goto out;
		if (n >= (~0U-9)/10)
			goto out;
		n *= 10;
		n += c;
	}
	return n;
out:
	return ~0U;
}

#define PROC_FDINFO_MAX 64

static int proc_fd_info(struct inode *inode, struct path *path, char *info)
{
	struct task_struct *task = get_proc_task(inode);
	struct files_struct *files = NULL;
	struct file *file;
	int fd = proc_fd(inode);

	if (task) {
		files = get_files_struct(task);
		put_task_struct(task);
	}
	if (files) {
		/*
		 * We are not taking a ref to the file structure, so we must
		 * hold ->file_lock.
		 */
		spin_lock(&files->file_lock);
		file = fcheck_files(files, fd);
		if (file) {
			if (path) {
				*path = file->f_path;
				path_get(&file->f_path);
#ifdef CONFIG_HCC_FAF
				if (file->f_flags & O_FAF_CLT) {
					get_file(file);
					path->mnt = (struct vfsmount *)file;
					/* path->dentry = NULL; */
				}
#endif
			}
			if (info)
#ifdef CONFIG_HCC_FAF
				snprintf(info, PROC_FDINFO_MAX,
					 "pos:\t%lli\n"
					 "flags:\t0%o\n",
					 (long long) file->f_pos,
					 (unsigned int)(file->f_flags & ~(unsigned long)O_HCC_FLAGS));
#else
				snprintf(info, PROC_FDINFO_MAX,
					 "pos:\t%lli\n"
					 "flags:\t0%o\n",
					 (long long) file->f_pos,
					 file->f_flags);
#endif
			spin_unlock(&files->file_lock);
			put_files_struct(files);
			return 0;
		}
		spin_unlock(&files->file_lock);
		put_files_struct(files);
	}
	return -ENOENT;
}

static int proc_fd_link(struct inode *inode, struct path *path)
{
	return proc_fd_info(inode, path, NULL);
}

static int tid_fd_revalidate(struct dentry *dentry, struct nameidata *nd)
{
	struct inode *inode = dentry->d_inode;
	struct task_struct *task = get_proc_task(inode);
	int fd = proc_fd(inode);
	struct files_struct *files;
	const struct cred *cred;

	if (task) {
		files = get_files_struct(task);
		if (files) {
			rcu_read_lock();
			if (fcheck_files(files, fd)) {
				rcu_read_unlock();
				put_files_struct(files);
				if (task_dumpable(task)) {
					rcu_read_lock();
					cred = __task_cred(task);
					inode->i_uid = cred->euid;
					inode->i_gid = cred->egid;
					rcu_read_unlock();
				} else {
					inode->i_uid = 0;
					inode->i_gid = 0;
				}
				inode->i_mode &= ~(S_ISUID | S_ISGID);
				security_task_to_inode(task, inode);
				put_task_struct(task);
				return 1;
			}
			rcu_read_unlock();
			put_files_struct(files);
		}
		put_task_struct(task);
	}
	d_drop(dentry);
	return 0;
}

static const struct dentry_operations tid_fd_dentry_operations =
{
	.d_revalidate	= tid_fd_revalidate,
	.d_delete	= pid_delete_dentry,
};

static struct dentry *proc_fd_instantiate(struct inode *dir,
	struct dentry *dentry, struct task_struct *task, const void *ptr)
{
	unsigned fd = *(const unsigned *)ptr;
	struct file *file;
	struct files_struct *files;
 	struct inode *inode;
 	struct proc_inode *ei;
	struct dentry *error = ERR_PTR(-ENOENT);

	inode = proc_pid_make_inode(dir->i_sb, task);
	if (!inode)
		goto out;
	ei = PROC_I(inode);
	ei->fd = fd;
	files = get_files_struct(task);
	if (!files)
		goto out_iput;
	inode->i_mode = S_IFLNK;

	/*
	 * We are not taking a ref to the file structure, so we must
	 * hold ->file_lock.
	 */
	spin_lock(&files->file_lock);
	file = fcheck_files(files, fd);
	if (!file)
		goto out_unlock;
	if (file->f_mode & FMODE_READ)
		inode->i_mode |= S_IRUSR | S_IXUSR;
	if (file->f_mode & FMODE_WRITE)
		inode->i_mode |= S_IWUSR | S_IXUSR;
	spin_unlock(&files->file_lock);
	put_files_struct(files);

	inode->i_op = &proc_pid_link_inode_operations;
	inode->i_size = 64;
	ei->op.proc_get_link = proc_fd_link;
	dentry->d_op = &tid_fd_dentry_operations;
	d_add(dentry, inode);
	/* Close the race of the process dying before we return the dentry */
	if (tid_fd_revalidate(dentry, NULL))
		error = NULL;

 out:
	return error;
out_unlock:
	spin_unlock(&files->file_lock);
	put_files_struct(files);
out_iput:
	iput(inode);
	goto out;
}

static struct dentry *proc_lookupfd_common(struct inode *dir,
					   struct dentry *dentry,
					   instantiate_t instantiate)
{
	struct task_struct *task = get_proc_task(dir);
	unsigned fd = name_to_int(dentry);
	struct dentry *result = ERR_PTR(-ENOENT);

	if (!task)
		goto out_no_task;
	if (fd == ~0U)
		goto out;

	result = instantiate(dir, dentry, task, &fd);
out:
	put_task_struct(task);
out_no_task:
	return result;
}

static int proc_readfd_common(struct file * filp, void * dirent,
			      filldir_t filldir, instantiate_t instantiate)
{
	struct dentry *dentry = filp->f_path.dentry;
	struct inode *inode = dentry->d_inode;
	struct task_struct *p = get_proc_task(inode);
	unsigned int fd, ino;
	int retval;
	struct files_struct * files;

	retval = -ENOENT;
	if (!p)
		goto out_no_task;
	retval = 0;

	fd = filp->f_pos;
	switch (fd) {
		case 0:
			if (filldir(dirent, ".", 1, 0, inode->i_ino, DT_DIR) < 0)
				goto out;
			filp->f_pos++;
		case 1:
			ino = parent_ino(dentry);
			if (filldir(dirent, "..", 2, 1, ino, DT_DIR) < 0)
				goto out;
			filp->f_pos++;
		default:
			files = get_files_struct(p);
			if (!files)
				goto out;
			rcu_read_lock();
			for (fd = filp->f_pos-2;
			     fd < files_fdtable(files)->max_fds;
			     fd++, filp->f_pos++) {
				char name[PROC_NUMBUF];
				int len;

				if (!fcheck_files(files, fd))
					continue;
				rcu_read_unlock();

				len = snprintf(name, sizeof(name), "%d", fd);
				if (proc_fill_cache(filp, dirent, filldir,
						    name, len, instantiate,
						    p, &fd) < 0) {
					rcu_read_lock();
					break;
				}
				rcu_read_lock();
			}
			rcu_read_unlock();
			put_files_struct(files);
	}
out:
	put_task_struct(p);
out_no_task:
	return retval;
}

static struct dentry *proc_lookupfd(struct inode *dir, struct dentry *dentry,
				    struct nameidata *nd)
{
	return proc_lookupfd_common(dir, dentry, proc_fd_instantiate);
}

static int proc_readfd(struct file *filp, void *dirent, filldir_t filldir)
{
	return proc_readfd_common(filp, dirent, filldir, proc_fd_instantiate);
}

static ssize_t proc_fdinfo_read(struct file *file, char __user *buf,
				      size_t len, loff_t *ppos)
{
	char tmp[PROC_FDINFO_MAX];
	int err = proc_fd_info(file->f_path.dentry->d_inode, NULL, tmp);
	if (!err)
		err = simple_read_from_buffer(buf, len, ppos, tmp, strlen(tmp));
	return err;
}

static const struct file_operations proc_fdinfo_file_operations = {
	.open		= nonseekable_open,
	.read		= proc_fdinfo_read,
};

static const struct file_operations proc_fd_operations = {
	.read		= generic_read_dir,
	.readdir	= proc_readfd,
};

/*
 * /proc/pid/fd needs a special permission handler so that a process can still
 * access /proc/self/fd after it has executed a setuid().
 */
static int proc_fd_permission(struct inode *inode, int mask)
{
	int rv;

	rv = generic_permission(inode, mask, NULL);
	if (rv == 0)
		return 0;
	if (task_tgid(current) == proc_pid(inode))
		rv = 0;
	return rv;
}

/*
 * proc directories can do almost nothing..
 */
static const struct inode_operations proc_fd_inode_operations = {
	.lookup		= proc_lookupfd,
	.permission	= proc_fd_permission,
	.setattr	= proc_setattr,
};

static struct dentry *proc_fdinfo_instantiate(struct inode *dir,
	struct dentry *dentry, struct task_struct *task, const void *ptr)
{
	unsigned fd = *(unsigned *)ptr;
 	struct inode *inode;
 	struct proc_inode *ei;
	struct dentry *error = ERR_PTR(-ENOENT);

	inode = proc_pid_make_inode(dir->i_sb, task);
	if (!inode)
		goto out;
	ei = PROC_I(inode);
	ei->fd = fd;
	inode->i_mode = S_IFREG | S_IRUSR;
	inode->i_fop = &proc_fdinfo_file_operations;
	dentry->d_op = &tid_fd_dentry_operations;
	d_add(dentry, inode);
	/* Close the race of the process dying before we return the dentry */
	if (tid_fd_revalidate(dentry, NULL))
		error = NULL;

 out:
	return error;
}

static struct dentry *proc_lookupfdinfo(struct inode *dir,
					struct dentry *dentry,
					struct nameidata *nd)
{
	return proc_lookupfd_common(dir, dentry, proc_fdinfo_instantiate);
}

static int proc_readfdinfo(struct file *filp, void *dirent, filldir_t filldir)
{
	return proc_readfd_common(filp, dirent, filldir,
				  proc_fdinfo_instantiate);
}

static const struct file_operations proc_fdinfo_operations = {
	.read		= generic_read_dir,
	.readdir	= proc_readfdinfo,
};

/*
 * proc directories can do almost nothing..
 */
static const struct inode_operations proc_fdinfo_inode_operations = {
	.lookup		= proc_lookupfdinfo,
	.setattr	= proc_setattr,
};


static struct dentry *proc_pident_instantiate(struct inode *dir,
	struct dentry *dentry, struct task_struct *task, const void *ptr)
{
	const struct pid_entry *p = ptr;
	struct inode *inode;
	struct proc_inode *ei;
	struct dentry *error = ERR_PTR(-ENOENT);

	inode = proc_pid_make_inode(dir->i_sb, task);
	if (!inode)
		goto out;

	ei = PROC_I(inode);
	inode->i_mode = p->mode;
	if (S_ISDIR(inode->i_mode))
		inode->i_nlink = 2;	/* Use getattr to fix if necessary */
	if (p->iop)
		inode->i_op = p->iop;
	if (p->fop)
		inode->i_fop = p->fop;
	ei->op = p->op;
	dentry->d_op = &pid_dentry_operations;
	d_add(dentry, inode);
	/* Close the race of the process dying before we return the dentry */
	if (pid_revalidate(dentry, NULL))
		error = NULL;
out:
	return error;
}

static struct dentry *proc_pident_lookup(struct inode *dir, 
					 struct dentry *dentry,
					 const struct pid_entry *ents,
					 unsigned int nents)
{
	struct dentry *error;
	struct task_struct *task = get_proc_task(dir);
	const struct pid_entry *p, *last;

	error = ERR_PTR(-ENOENT);

	if (!task)
		goto out_no_task;

	/*
	 * Yes, it does not scale. And it should not. Don't add
	 * new entries into /proc/<tgid>/ without very good reasons.
	 */
	last = &ents[nents - 1];
	for (p = ents; p <= last; p++) {
		if (p->len != dentry->d_name.len)
			continue;
		if (!memcmp(dentry->d_name.name, p->name, p->len))
			break;
	}
	if (p > last)
		goto out;

	error = proc_pident_instantiate(dir, dentry, task, p);
out:
	put_task_struct(task);
out_no_task:
	return error;
}

static int proc_pident_fill_cache(struct file *filp, void *dirent,
	filldir_t filldir, struct task_struct *task, const struct pid_entry *p)
{
	return proc_fill_cache(filp, dirent, filldir, p->name, p->len,
				proc_pident_instantiate, task, p);
}

static int proc_pident_readdir(struct file *filp,
		void *dirent, filldir_t filldir,
		const struct pid_entry *ents, unsigned int nents)
{
	int i;
	struct dentry *dentry = filp->f_path.dentry;
	struct inode *inode = dentry->d_inode;
	struct task_struct *task = get_proc_task(inode);
	const struct pid_entry *p, *last;
	ino_t ino;
	int ret;

	ret = -ENOENT;
	if (!task)
		goto out_no_task;

	ret = 0;
	i = filp->f_pos;
	switch (i) {
	case 0:
		ino = inode->i_ino;
		if (filldir(dirent, ".", 1, i, ino, DT_DIR) < 0)
			goto out;
		i++;
		filp->f_pos++;
		/* fall through */
	case 1:
		ino = parent_ino(dentry);
		if (filldir(dirent, "..", 2, i, ino, DT_DIR) < 0)
			goto out;
		i++;
		filp->f_pos++;
		/* fall through */
	default:
		i -= 2;
		if (i >= nents) {
			ret = 1;
			goto out;
		}
		p = ents + i;
		last = &ents[nents - 1];
		while (p <= last) {
			if (proc_pident_fill_cache(filp, dirent, filldir, task, p) < 0)
				goto out;
			filp->f_pos++;
			p++;
		}
	}

	ret = 1;
out:
	put_task_struct(task);
out_no_task:
	return ret;
}

#ifdef CONFIG_SECURITY
static ssize_t proc_pid_attr_read(struct file * file, char __user * buf,
				  size_t count, loff_t *ppos)
{
	struct inode * inode = file->f_path.dentry->d_inode;
	char *p = NULL;
	ssize_t length;
	struct task_struct *task = get_proc_task(inode);

	if (!task)
		return -ESRCH;

	length = security_getprocattr(task,
				      (char*)file->f_path.dentry->d_name.name,
				      &p);
	put_task_struct(task);
	if (length > 0)
		length = simple_read_from_buffer(buf, count, ppos, p, length);
	kfree(p);
	return length;
}

static ssize_t proc_pid_attr_write(struct file * file, const char __user * buf,
				   size_t count, loff_t *ppos)
{
	struct inode * inode = file->f_path.dentry->d_inode;
	char *page;
	ssize_t length;
	struct task_struct *task = get_proc_task(inode);

	length = -ESRCH;
	if (!task)
		goto out_no_task;
	if (count > PAGE_SIZE)
		count = PAGE_SIZE;

	/* No partial writes. */
	length = -EINVAL;
	if (*ppos != 0)
		goto out;

	length = -ENOMEM;
	page = (char*)__get_free_page(GFP_TEMPORARY);
	if (!page)
		goto out;

	length = -EFAULT;
	if (copy_from_user(page, buf, count))
		goto out_free;

	/* Guard against adverse ptrace interaction */
	length = mutex_lock_interruptible(&task->cred_guard_mutex);
	if (length < 0)
		goto out_free;

	length = security_setprocattr(task,
				      (char*)file->f_path.dentry->d_name.name,
				      (void*)page, count);
	mutex_unlock(&task->cred_guard_mutex);
out_free:
	free_page((unsigned long) page);
out:
	put_task_struct(task);
out_no_task:
	return length;
}

static const struct file_operations proc_pid_attr_operations = {
	.read		= proc_pid_attr_read,
	.write		= proc_pid_attr_write,
};

static const struct pid_entry attr_dir_stuff[] = {
	REG("current",    S_IRUGO|S_IWUGO, proc_pid_attr_operations),
	REG("prev",       S_IRUGO,	   proc_pid_attr_operations),
	REG("exec",       S_IRUGO|S_IWUGO, proc_pid_attr_operations),
	REG("fscreate",   S_IRUGO|S_IWUGO, proc_pid_attr_operations),
	REG("keycreate",  S_IRUGO|S_IWUGO, proc_pid_attr_operations),
	REG("sockcreate", S_IRUGO|S_IWUGO, proc_pid_attr_operations),
};

static int proc_attr_dir_readdir(struct file * filp,
			     void * dirent, filldir_t filldir)
{
	return proc_pident_readdir(filp,dirent,filldir,
				   attr_dir_stuff,ARRAY_SIZE(attr_dir_stuff));
}

static const struct file_operations proc_attr_dir_operations = {
	.read		= generic_read_dir,
	.readdir	= proc_attr_dir_readdir,
};

static struct dentry *proc_attr_dir_lookup(struct inode *dir,
				struct dentry *dentry, struct nameidata *nd)
{
	return proc_pident_lookup(dir, dentry,
				  attr_dir_stuff, ARRAY_SIZE(attr_dir_stuff));
}

static const struct inode_operations proc_attr_dir_inode_operations = {
	.lookup		= proc_attr_dir_lookup,
	.getattr	= pid_getattr,
	.setattr	= proc_setattr,
};

#endif

#if defined(USE_ELF_CORE_DUMP) && defined(CONFIG_ELF_CORE)
static ssize_t proc_coredump_filter_read(struct file *file, char __user *buf,
					 size_t count, loff_t *ppos)
{
	struct task_struct *task = get_proc_task(file->f_dentry->d_inode);
	struct mm_struct *mm;
	char buffer[PROC_NUMBUF];
	size_t len;
	int ret;

	if (!task)
		return -ESRCH;

	ret = 0;
	mm = get_task_mm(task);
	if (mm) {
		len = snprintf(buffer, sizeof(buffer), "%08lx\n",
			       ((mm->flags & MMF_DUMP_FILTER_MASK) >>
				MMF_DUMP_FILTER_SHIFT));
		mmput(mm);
		ret = simple_read_from_buffer(buf, count, ppos, buffer, len);
	}

	put_task_struct(task);

	return ret;
}

static ssize_t proc_coredump_filter_write(struct file *file,
					  const char __user *buf,
					  size_t count,
					  loff_t *ppos)
{
	struct task_struct *task;
	struct mm_struct *mm;
	char buffer[PROC_NUMBUF], *end;
	unsigned int val;
	int ret;
	int i;
	unsigned long mask;

	ret = -EFAULT;
	memset(buffer, 0, sizeof(buffer));
	if (count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;
	if (copy_from_user(buffer, buf, count))
		goto out_no_task;

	ret = -EINVAL;
	val = (unsigned int)simple_strtoul(buffer, &end, 0);
	if (*end == '\n')
		end++;
	if (end - buffer == 0)
		goto out_no_task;

	ret = -ESRCH;
	task = get_proc_task(file->f_dentry->d_inode);
	if (!task)
		goto out_no_task;

	ret = end - buffer;
	mm = get_task_mm(task);
	if (!mm)
		goto out_no_mm;

	for (i = 0, mask = 1; i < MMF_DUMP_FILTER_BITS; i++, mask <<= 1) {
		if (val & mask)
			set_bit(i + MMF_DUMP_FILTER_SHIFT, &mm->flags);
		else
			clear_bit(i + MMF_DUMP_FILTER_SHIFT, &mm->flags);
	}

	mmput(mm);
 out_no_mm:
	put_task_struct(task);
 out_no_task:
	return ret;
}

static const struct file_operations proc_coredump_filter_operations = {
	.read		= proc_coredump_filter_read,
	.write		= proc_coredump_filter_write,
};
#endif

/*
 * /proc/self:
 */
static int proc_self_readlink(struct dentry *dentry, char __user *buffer,
			      int buflen)
{
	struct pid_namespace *ns = dentry->d_sb->s_fs_info;
	pid_t tgid = task_tgid_nr_ns(current, ns);
	char tmp[PROC_NUMBUF];
	if (!tgid)
		return -ENOENT;
	sprintf(tmp, "%d", tgid);
	return vfs_readlink(dentry,buffer,buflen,tmp);
}

static void *proc_self_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct pid_namespace *ns = dentry->d_sb->s_fs_info;
	pid_t tgid = task_tgid_nr_ns(current, ns);
	char *name = ERR_PTR(-ENOENT);
	if (tgid) {
		/* 11 for max length of signed int in decimal + NULL term */
		name = kmalloc(12, GFP_KERNEL);
		if (!name)
			name = ERR_PTR(-ENOMEM);
		else
			sprintf(name, "%d", tgid);
	}
	nd_set_link(nd, name);
	return NULL;
}

static void proc_self_put_link(struct dentry *dentry, struct nameidata *nd,
				void *cookie)
{
	char *s = nd_get_link(nd);
	if (!IS_ERR(s))
		kfree(s);
}

static const struct inode_operations proc_self_inode_operations = {
	.readlink	= proc_self_readlink,
	.follow_link	= proc_self_follow_link,
	.put_link	= proc_self_put_link,
};

/*
 * proc base
 *
 * These are the directory entries in the root directory of /proc
 * that properly belong to the /proc filesystem, as they describe
 * describe something that is process related.
 */
static const struct pid_entry proc_base_stuff[] = {
	NOD("self", S_IFLNK|S_IRWXUGO,
		&proc_self_inode_operations, NULL, {}),
};

/*
 *	Exceptional case: normally we are not allowed to unhash a busy
 * directory. In this case, however, we can do it - no aliasing problems
 * due to the way we treat inodes.
 */
static int proc_base_revalidate(struct dentry *dentry, struct nameidata *nd)
{
	struct inode *inode = dentry->d_inode;
	struct task_struct *task = get_proc_task(inode);
	if (task) {
		put_task_struct(task);
		return 1;
	}
	d_drop(dentry);
	return 0;
}

static const struct dentry_operations proc_base_dentry_operations =
{
	.d_revalidate	= proc_base_revalidate,
	.d_delete	= pid_delete_dentry,
};

static struct dentry *proc_base_instantiate(struct inode *dir,
	struct dentry *dentry, struct task_struct *task, const void *ptr)
{
	const struct pid_entry *p = ptr;
	struct inode *inode;
	struct proc_inode *ei;
	struct dentry *error = ERR_PTR(-EINVAL);

	/* Allocate the inode */
	error = ERR_PTR(-ENOMEM);
	inode = new_inode(dir->i_sb);
	if (!inode)
		goto out;

	/* Initialize the inode */
	ei = PROC_I(inode);
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;

	/*
	 * grab the reference to the task.
	 */
	ei->pid = get_task_pid(task, PIDTYPE_PID);
	if (!ei->pid)
		goto out_iput;

	inode->i_mode = p->mode;
	if (S_ISDIR(inode->i_mode))
		inode->i_nlink = 2;
	if (S_ISLNK(inode->i_mode))
		inode->i_size = 64;
	if (p->iop)
		inode->i_op = p->iop;
	if (p->fop)
		inode->i_fop = p->fop;
	ei->op = p->op;
	dentry->d_op = &proc_base_dentry_operations;
	d_add(dentry, inode);
	error = NULL;
out:
	return error;
out_iput:
	iput(inode);
	goto out;
}

static struct dentry *proc_base_lookup(struct inode *dir, struct dentry *dentry)
{
	struct dentry *error;
	struct task_struct *task = get_proc_task(dir);
	const struct pid_entry *p, *last;

	error = ERR_PTR(-ENOENT);

	if (!task)
		goto out_no_task;

	/* Lookup the directory entry */
	last = &proc_base_stuff[ARRAY_SIZE(proc_base_stuff) - 1];
	for (p = proc_base_stuff; p <= last; p++) {
		if (p->len != dentry->d_name.len)
			continue;
		if (!memcmp(dentry->d_name.name, p->name, p->len))
			break;
	}
	if (p > last)
		goto out;

	error = proc_base_instantiate(dir, dentry, task, p);

out:
	put_task_struct(task);
out_no_task:
	return error;
}

static int proc_base_fill_cache(struct file *filp, void *dirent,
	filldir_t filldir, struct task_struct *task, const struct pid_entry *p)
{
	return proc_fill_cache(filp, dirent, filldir, p->name, p->len,
				proc_base_instantiate, task, p);
}

#ifdef CONFIG_TASK_IO_ACCOUNTING
static int do_io_accounting(struct task_struct *task, char *buffer, int whole)
{
	struct task_io_accounting acct = task->ioac;
	unsigned long flags;

	if (!ptrace_may_access(task, PTRACE_MODE_READ))
		return -EACCES;

	if (whole && lock_task_sighand(task, &flags)) {
		struct task_struct *t = task;

		task_io_accounting_add(&acct, &task->signal->ioac);
		while_each_thread(task, t)
			task_io_accounting_add(&acct, &t->ioac);

		unlock_task_sighand(task, &flags);
	}
	return sprintf(buffer,
			"rchar: %llu\n"
			"wchar: %llu\n"
			"syscr: %llu\n"
			"syscw: %llu\n"
			"read_bytes: %llu\n"
			"write_bytes: %llu\n"
			"cancelled_write_bytes: %llu\n",
			(unsigned long long)acct.rchar,
			(unsigned long long)acct.wchar,
			(unsigned long long)acct.syscr,
			(unsigned long long)acct.syscw,
			(unsigned long long)acct.read_bytes,
			(unsigned long long)acct.write_bytes,
			(unsigned long long)acct.cancelled_write_bytes);
}

static int proc_tid_io_accounting(struct task_struct *task, char *buffer)
{
	return do_io_accounting(task, buffer, 0);
}

#if !defined(CONFIG_HCC_PROCFS) || !defined(CONFIG_HCC_PROC)
static
#endif
int proc_tgid_io_accounting(struct task_struct *task, char *buffer)
{
	return do_io_accounting(task, buffer, 1);
}
#endif /* CONFIG_TASK_IO_ACCOUNTING */

#if !defined(CONFIG_HCC_PROCFS) || !defined(CONFIG_HCC_PROC)
static
#endif
int proc_pid_personality(struct seq_file *m, struct pid_namespace *ns,
				struct pid *pid, struct task_struct *task)
{
	int err = lock_trace(task);
	if (!err) {
		seq_printf(m, "%08x\n", task->personality);
		unlock_trace(task);
	}
	return err;
}

/*
 * Thread groups
 */
static const struct file_operations proc_task_operations;
static const struct inode_operations proc_task_inode_operations;

static const struct pid_entry tgid_base_stuff[] = {
	DIR("task",       S_IRUGO|S_IXUGO, proc_task_inode_operations, proc_task_operations),
	DIR("fd",         S_IRUSR|S_IXUSR, proc_fd_inode_operations, proc_fd_operations),
	DIR("fdinfo",     S_IRUSR|S_IXUSR, proc_fdinfo_inode_operations, proc_fdinfo_operations),
	DIR("ns",	  S_IRUSR|S_IXUGO, proc_ns_dir_inode_operations, proc_ns_dir_operations),
#ifdef CONFIG_NET
	DIR("net",        S_IRUGO|S_IXUGO, proc_net_inode_operations, proc_net_operations),
#endif
	REG("environ",    S_IRUSR, proc_environ_operations),
	INF("auxv",       S_IRUSR, proc_pid_auxv),
	ONE("status",     S_IRUGO, proc_pid_status),
	ONE("personality", S_IRUGO, proc_pid_personality),
	NOD("limits",	  S_IFREG|S_IRUSR|S_IWUSR, NULL,
			&proc_pid_limits_operations,
			{ .proc_read = proc_pid_limits }),
#ifdef CONFIG_SCHED_DEBUG
	REG("sched",      S_IRUGO|S_IWUSR, proc_pid_sched_operations),
#endif
#ifdef CONFIG_SCHED_AUTOGROUP
	REG("autogroup",  S_IRUGO|S_IWUSR, proc_pid_sched_autogroup_operations),
#endif
	REG("comm",      S_IRUGO|S_IWUSR, proc_pid_set_comm_operations),
#ifdef CONFIG_HAVE_ARCH_TRACEHOOK
	INF("syscall",    S_IRUGO, proc_pid_syscall),
#endif
	INF("cmdline",    S_IRUGO, proc_pid_cmdline),
	ONE("stat",       S_IRUGO, proc_tgid_stat),
	ONE("statm",      S_IRUGO, proc_pid_statm),
#ifdef CONFIG_HCC_GPM
	INF("gpm_type",  S_IRUGO, gpm_type_show),
	INF("gpm_source",S_IRUGO, gpm_source_show),
	INF("gpm_target",S_IRUGO, gpm_target_show),
#endif
	REG("maps",       S_IRUGO, proc_maps_operations),
#ifdef CONFIG_NUMA
	REG("numa_maps",  S_IRUGO, proc_numa_maps_operations),
#endif
	REG("mem",        S_IRUSR|S_IWUSR, proc_mem_operations),
	LNK("cwd",        proc_cwd_link),
	LNK("root",       proc_root_link),
	LNK("exe",        proc_exe_link),
	REG("mounts",     S_IRUGO, proc_mounts_operations),
	REG("mountinfo",  S_IRUGO, proc_mountinfo_operations),
	REG("mountstats", S_IRUSR, proc_mountstats_operations),
#ifdef CONFIG_PROC_PAGE_MONITOR
	REG("clear_refs", S_IWUSR, proc_clear_refs_operations),
	REG("smaps",      S_IRUGO, proc_smaps_operations),
	REG("pagemap",    S_IRUGO, proc_pagemap_operations),
#endif
#ifdef CONFIG_SECURITY
	DIR("attr",       S_IRUGO|S_IXUGO, proc_attr_dir_inode_operations, proc_attr_dir_operations),
#endif
#ifdef CONFIG_KALLSYMS
	INF("wchan",      S_IRUGO, proc_pid_wchan),
#endif
#ifdef CONFIG_STACKTRACE
	ONE("stack",      S_IRUGO, proc_pid_stack),
#endif
#ifdef CONFIG_SCHEDSTATS
	INF("schedstat",  S_IRUGO, proc_pid_schedstat),
#endif
#ifdef CONFIG_LATENCYTOP
	REG("latency",  S_IRUGO, proc_lstats_operations),
#endif
#ifdef CONFIG_PROC_PID_CPUSET
	REG("cpuset",     S_IRUGO, proc_cpuset_operations),
#endif
#ifdef CONFIG_CGROUPS
	REG("cgroup",  S_IRUGO, proc_cgroup_operations),
#endif
	INF("oom_score",  S_IRUGO, proc_oom_score),
	REG("oom_adj",    S_IRUGO|S_IWUSR, proc_oom_adjust_operations),
	REG("oom_score_adj", S_IRUGO|S_IWUSR, proc_oom_score_adj_operations),
#ifdef CONFIG_AUDITSYSCALL
	REG("loginuid",   S_IWUSR|S_IRUGO, proc_loginuid_operations),
	REG("sessionid",  S_IRUGO, proc_sessionid_operations),
#endif
#ifdef CONFIG_FAULT_INJECTION
	REG("make-it-fail", S_IRUGO|S_IWUSR, proc_fault_inject_operations),
#endif
#if defined(USE_ELF_CORE_DUMP) && defined(CONFIG_ELF_CORE)
	REG("coredump_filter", S_IRUGO|S_IWUSR, proc_coredump_filter_operations),
#endif
#ifdef CONFIG_TASK_IO_ACCOUNTING
	INF("io",	S_IRUSR, proc_tgid_io_accounting),
#endif
};

static int proc_tgid_base_readdir(struct file * filp,
			     void * dirent, filldir_t filldir)
{
	return proc_pident_readdir(filp,dirent,filldir,
				   tgid_base_stuff,ARRAY_SIZE(tgid_base_stuff));
}

static const struct file_operations proc_tgid_base_operations = {
	.read		= generic_read_dir,
	.readdir	= proc_tgid_base_readdir,
};

static struct dentry *proc_tgid_base_lookup(struct inode *dir, struct dentry *dentry, struct nameidata *nd){
	return proc_pident_lookup(dir, dentry,
				  tgid_base_stuff, ARRAY_SIZE(tgid_base_stuff));
}

static const struct inode_operations proc_tgid_base_inode_operations = {
	.lookup		= proc_tgid_base_lookup,
	.getattr	= pid_getattr,
	.setattr	= proc_setattr,
	.permission	= proc_pid_permission,
};

/*
 * Pin all proc_mnt so that detached tasks can safely call proc_flush_task()
 * after container init calls itself proc_flush_task().
 */
void proc_new_task(struct task_struct *task)
{
	struct pid *pid;
	int i;

	if (!task->pid)
		return;

	pid = task_pid(task);
	for (i = 0; i <= pid->level; i++)
		mntget(pid->numbers[i].ns->proc_mnt);
}

static void proc_flush_task_mnt(struct vfsmount *mnt, pid_t pid, pid_t tgid)
{
	struct dentry *dentry, *leader, *dir;
	char buf[PROC_NUMBUF];
	struct qstr name;

	name.name = buf;
	name.len = snprintf(buf, sizeof(buf), "%d", pid);
	dentry = d_hash_and_lookup(mnt->mnt_root, &name);
	if (dentry) {
		shrink_dcache_parent(dentry);
		d_drop(dentry);
		dput(dentry);
	}

	name.name = buf;
	name.len = snprintf(buf, sizeof(buf), "%d", tgid);
	leader = d_hash_and_lookup(mnt->mnt_root, &name);
	if (!leader)
		goto out;

	name.name = "task";
	name.len = strlen(name.name);
	dir = d_hash_and_lookup(leader, &name);
	if (!dir)
		goto out_put_leader;

	name.name = buf;
	name.len = snprintf(buf, sizeof(buf), "%d", pid);
	dentry = d_hash_and_lookup(dir, &name);
	if (dentry) {
		shrink_dcache_parent(dentry);
		d_drop(dentry);
		dput(dentry);
	}

	dput(dir);
out_put_leader:
	dput(leader);
out:
	return;
}

/**
 * proc_flush_task -  Remove dcache entries for @task from the /proc dcache.
 * @task: task that should be flushed.
 *
 * When flushing dentries from proc, one needs to flush them from global
 * proc (proc_mnt) and from all the namespaces' procs this task was seen
 * in. This call is supposed to do all of this job.
 *
 * Looks in the dcache for
 * /proc/@pid
 * /proc/@tgid/task/@pid
 * if either directory is present flushes it and all of it'ts children
 * from the dcache.
 *
 * It is safe and reasonable to cache /proc entries for a task until
 * that task exits.  After that they just clog up the dcache with
 * useless entries, possibly causing useful dcache entries to be
 * flushed instead.  This routine is proved to flush those useless
 * dcache entries at process exit time.
 *
 * NOTE: This routine is just an optimization so it does not guarantee
 *       that no dcache entries will exist at process exit time it
 *       just makes it very unlikely that any will persist.
 */

void proc_flush_task(struct task_struct *task)
{
	int i;
	struct pid *pid, *tgid;
	struct upid *upid;

	pid = task_pid(task);
	tgid = task_tgid(task);

	for (i = 0; i <= pid->level; i++) {
		upid = &pid->numbers[i];
		proc_flush_task_mnt(upid->ns->proc_mnt, upid->nr,
					tgid->numbers[i].nr);
		mntput(upid->ns->proc_mnt);
	}
}

static struct dentry *proc_pid_instantiate(struct inode *dir,
					   struct dentry * dentry,
					   struct task_struct *task, const void *ptr)
{
	struct dentry *error = ERR_PTR(-ENOENT);
	struct inode *inode;

	inode = proc_pid_make_inode(dir->i_sb, task);
	if (!inode)
		goto out;

	inode->i_mode = S_IFDIR|S_IRUGO|S_IXUGO;
	inode->i_op = &proc_tgid_base_inode_operations;
	inode->i_fop = &proc_tgid_base_operations;
	inode->i_flags|=S_IMMUTABLE;

	inode->i_nlink = 2 + pid_entry_count_dirs(tgid_base_stuff,
		ARRAY_SIZE(tgid_base_stuff));

	dentry->d_op = &pid_dentry_operations;

	d_add(dentry, inode);
	/* Close the race of the process dying before we return the dentry */
	if (pid_revalidate(dentry, NULL))
		error = NULL;
out:
	return error;
}

struct dentry *proc_pid_lookup(struct inode *dir, struct dentry * dentry, struct nameidata *nd)
{
	struct dentry *result = ERR_PTR(-ENOENT);
	struct task_struct *task;
	unsigned tgid;
	struct pid_namespace *ns;

	result = proc_base_lookup(dir, dentry);
	if (!IS_ERR(result) || PTR_ERR(result) != -ENOENT)
		goto out;

	tgid = name_to_int(dentry);
	if (tgid == ~0U)
		goto out;

	ns = dentry->d_sb->s_fs_info;
	rcu_read_lock();
	task = find_task_by_pid_ns(tgid, ns);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();
	if (!task)
#if defined(CONFIG_HCC_PROCFS) && defined(CONFIG_HCC_PROC)
	{
		if (current->nsproxy->hcc_ns
		    && is_hcc_pid_ns_root(ns) && (tgid & GLOBAL_PID_MASK))
			result = hcc_proc_pid_lookup(dir, dentry, tgid);
#endif
                goto out;
#if defined(CONFIG_HCC_PROCFS) && defined(CONFIG_HCC_PROC)
	}
#endif

	result = proc_pid_instantiate(dir, dentry, task, NULL);
#if defined(CONFIG_HCC_PROCFS) && defined(CONFIG_HCC_GPM)
	if (current->nsproxy->hcc_ns
	    && IS_ERR(result) && task->exit_state == EXIT_MIGRATION) {
		/*
		 * proc_pid_instantiate() may have instantiated dentry, but we
		 * don't know, so restart with a fresh one.
		 */
		result = ERR_PTR(-ENOMEM);
		dentry = d_alloc(dentry->d_parent, &dentry->d_name);
		if (dentry) {
			result = hcc_proc_pid_lookup(dir, dentry, tgid);
			if (!result)
				result = dentry;
			else
				dput(dentry);
		}
	}
#endif
	put_task_struct(task);
out:
	return result;
}

/*
 * Find the first task with tgid >= tgid
 *
 */
#if !defined(CONFIG_HCC_PROCFS) || !defined(CONFIG_HCC_PROC)
struct tgid_iter {
	unsigned int tgid;
	struct task_struct *task;
};
#else
/* moved into include/linux/procfs_internal.h */
#endif
static struct tgid_iter next_tgid(struct pid_namespace *ns, struct tgid_iter iter)
{
	struct pid *pid;

	if (iter.task)
		put_task_struct(iter.task);
	rcu_read_lock();
retry:
	iter.task = NULL;
	pid = find_ge_pid(iter.tgid, ns);
	if (pid) {
		iter.tgid = pid_nr_ns(pid, ns);
		iter.task = pid_task(pid, PIDTYPE_PID);
		/* What we to know is if the pid we have find is the
		 * pid of a thread_group_leader.  Testing for task
		 * being a thread_group_leader is the obvious thing
		 * todo but there is a window when it fails, due to
		 * the pid transfer logic in de_thread.
		 *
		 * So we perform the straight forward test of seeing
		 * if the pid we have found is the pid of a thread
		 * group leader, and don't worry if the task we have
		 * found doesn't happen to be a thread group leader.
		 * As we don't care in the case of readdir.
		 */
		if (!iter.task || !has_group_leader_pid(iter.task)) {
			iter.tgid += 1;
			goto retry;
		}
		get_task_struct(iter.task);
	}
	rcu_read_unlock();
	return iter;
}

#define TGID_OFFSET (FIRST_PROCESS_ENTRY + ARRAY_SIZE(proc_base_stuff))

#if !defined(CONFIG_HCC_PROCFS) || !defined(CONFIG_HCC_PROC)
static
#endif
int proc_pid_fill_cache(struct file *filp, void *dirent, filldir_t filldir,
	struct tgid_iter iter)
{
	char name[PROC_NUMBUF];
	int len = snprintf(name, sizeof(name), "%d", iter.tgid);
	return proc_fill_cache(filp, dirent, filldir, name, len,
				proc_pid_instantiate, iter.task, NULL);
}

static int fake_filldir(void *buf, const char *name, int namelen,
			loff_t offset, u64 ino, unsigned d_type)
{
	return 0;
}

/* for the /proc/ directory itself, after non-process stuff has been done */
int proc_pid_readdir(struct file * filp, void * dirent, filldir_t filldir)
{
	unsigned int nr;
	struct task_struct *reaper;
	struct tgid_iter iter;
	struct pid_namespace *ns;
	filldir_t __filldir;

	if (filp->f_pos >= PID_MAX_LIMIT + TGID_OFFSET)
		goto out_no_task;
	nr = filp->f_pos - FIRST_PROCESS_ENTRY;

	reaper = get_proc_task(filp->f_path.dentry->d_inode);
	if (!reaper)
		goto out_no_task;

	for (; nr < ARRAY_SIZE(proc_base_stuff); filp->f_pos++, nr++) {
		const struct pid_entry *p = &proc_base_stuff[nr];
		if (proc_base_fill_cache(filp, dirent, filldir, reaper, p) < 0)
			goto out;
	}

	ns = filp->f_dentry->d_sb->s_fs_info;
	iter.task = NULL;
	iter.tgid = filp->f_pos - TGID_OFFSET;
#if defined(CONFIG_HCC_PROCFS) && defined(CONFIG_HCC_PROC)
	if (current->nsproxy->hcc_ns && is_hcc_pid_ns_root(ns)) {
		/* All filling is done by hcc_proc_pid_readdir */
		if (hcc_proc_pid_readdir(filp, dirent, filldir, TGID_OFFSET))
			goto out;
	} else
#endif
	for (iter = next_tgid(ns, iter);
	     iter.task;
	     iter.tgid += 1, iter = next_tgid(ns, iter)) {
		if (has_pid_permissions(ns, iter.task, 2))
			__filldir = filldir;
		else
			__filldir = fake_filldir;

		filp->f_pos = iter.tgid + TGID_OFFSET;
		if (proc_pid_fill_cache(filp, dirent, __filldir, iter) < 0) {
			put_task_struct(iter.task);
			goto out;
		}
	}
#if defined(CONFIG_HCC_PROCFS) && defined(CONFIG_HCC_PROC)
	filp->f_pos = HCC_PID_MAX_LIMIT + TGID_OFFSET;
#else
	filp->f_pos = PID_MAX_LIMIT + TGID_OFFSET;
#endif
out:
	put_task_struct(reaper);
out_no_task:
	return 0;
}

/*
 * Tasks
 */
static const struct pid_entry tid_base_stuff[] = {
	DIR("fd",        S_IRUSR|S_IXUSR, proc_fd_inode_operations, proc_fd_operations),
	DIR("fdinfo",    S_IRUSR|S_IXUSR, proc_fdinfo_inode_operations, proc_fdinfo_operations),
	DIR("ns",	 S_IRUSR|S_IXUGO, proc_ns_dir_inode_operations, proc_ns_dir_operations),
	REG("environ",   S_IRUSR, proc_environ_operations),
	INF("auxv",      S_IRUSR, proc_pid_auxv),
	ONE("status",    S_IRUGO, proc_pid_status),
	ONE("personality", S_IRUGO, proc_pid_personality),
	NOD("limits",	  S_IFREG|S_IRUSR|S_IWUSR, NULL,
			&proc_pid_limits_operations,
			{ .proc_read = proc_pid_limits }),
#ifdef CONFIG_SCHED_DEBUG
	REG("sched",     S_IRUGO|S_IWUSR, proc_pid_sched_operations),
#endif
	REG("comm",      S_IRUGO|S_IWUSR, proc_pid_set_comm_operations),
#ifdef CONFIG_HAVE_ARCH_TRACEHOOK
	INF("syscall",   S_IRUGO, proc_pid_syscall),
#endif
	INF("cmdline",   S_IRUGO, proc_pid_cmdline),
	ONE("stat",      S_IRUGO, proc_tid_stat),
	ONE("statm",     S_IRUGO, proc_pid_statm),
#ifdef CONFIG_HCC_GPM
	INF("gpm_type",  S_IRUGO, gpm_type_show),
	INF("gpm_source",S_IRUGO, gpm_source_show),
	INF("gpm_target",S_IRUGO, gpm_target_show),
#endif
#ifdef CONFIG_HCC_GDM
	INF("gdm",      S_IRUGO, proc_tid_gdm),
#endif
	REG("maps",      S_IRUGO, proc_maps_operations),
#ifdef CONFIG_NUMA
	REG("numa_maps", S_IRUGO, proc_numa_maps_operations),
#endif
	REG("mem",       S_IRUSR|S_IWUSR, proc_mem_operations),
	LNK("cwd",       proc_cwd_link),
	LNK("root",      proc_root_link),
	LNK("exe",       proc_exe_link),
	REG("mounts",    S_IRUGO, proc_mounts_operations),
	REG("mountinfo",  S_IRUGO, proc_mountinfo_operations),
#ifdef CONFIG_PROC_PAGE_MONITOR
	REG("clear_refs", S_IWUSR, proc_clear_refs_operations),
	REG("smaps",     S_IRUGO, proc_smaps_operations),
	REG("pagemap",    S_IRUGO, proc_pagemap_operations),
#endif
#ifdef CONFIG_SECURITY
	DIR("attr",      S_IRUGO|S_IXUGO, proc_attr_dir_inode_operations, proc_attr_dir_operations),
#endif
#ifdef CONFIG_KALLSYMS
	INF("wchan",     S_IRUGO, proc_pid_wchan),
#endif
#ifdef CONFIG_STACKTRACE
	ONE("stack",      S_IRUGO, proc_pid_stack),
#endif
#ifdef CONFIG_SCHEDSTATS
	INF("schedstat", S_IRUGO, proc_pid_schedstat),
#endif
#ifdef CONFIG_LATENCYTOP
	REG("latency",  S_IRUGO, proc_lstats_operations),
#endif
#ifdef CONFIG_PROC_PID_CPUSET
	REG("cpuset",    S_IRUGO, proc_cpuset_operations),
#endif
#ifdef CONFIG_CGROUPS
	REG("cgroup",  S_IRUGO, proc_cgroup_operations),
#endif
	INF("oom_score", S_IRUGO, proc_oom_score),
	REG("oom_adj",   S_IRUGO|S_IWUSR, proc_oom_adjust_operations),
	REG("oom_score_adj", S_IRUGO|S_IWUSR, proc_oom_score_adj_operations),
#ifdef CONFIG_AUDITSYSCALL
	REG("loginuid",  S_IWUSR|S_IRUGO, proc_loginuid_operations),
	REG("sessionid",  S_IRUGO, proc_sessionid_operations),
#endif
#ifdef CONFIG_FAULT_INJECTION
	REG("make-it-fail", S_IRUGO|S_IWUSR, proc_fault_inject_operations),
#endif
#ifdef CONFIG_TASK_IO_ACCOUNTING
	INF("io",	S_IRUSR, proc_tid_io_accounting),
#endif
};

static int proc_tid_base_readdir(struct file * filp,
			     void * dirent, filldir_t filldir)
{
	return proc_pident_readdir(filp,dirent,filldir,
				   tid_base_stuff,ARRAY_SIZE(tid_base_stuff));
}

static struct dentry *proc_tid_base_lookup(struct inode *dir, struct dentry *dentry, struct nameidata *nd){
	return proc_pident_lookup(dir, dentry,
				  tid_base_stuff, ARRAY_SIZE(tid_base_stuff));
}

static const struct file_operations proc_tid_base_operations = {
	.read		= generic_read_dir,
	.readdir	= proc_tid_base_readdir,
};

static const struct inode_operations proc_tid_base_inode_operations = {
	.lookup		= proc_tid_base_lookup,
	.getattr	= pid_getattr,
	.setattr	= proc_setattr,
};

static struct dentry *proc_task_instantiate(struct inode *dir,
	struct dentry *dentry, struct task_struct *task, const void *ptr)
{
	struct dentry *error = ERR_PTR(-ENOENT);
	struct inode *inode;
	inode = proc_pid_make_inode(dir->i_sb, task);

	if (!inode)
		goto out;
	inode->i_mode = S_IFDIR|S_IRUGO|S_IXUGO;
	inode->i_op = &proc_tid_base_inode_operations;
	inode->i_fop = &proc_tid_base_operations;
	inode->i_flags|=S_IMMUTABLE;

	inode->i_nlink = 2 + pid_entry_count_dirs(tid_base_stuff,
		ARRAY_SIZE(tid_base_stuff));

	dentry->d_op = &pid_dentry_operations;

	d_add(dentry, inode);
	/* Close the race of the process dying before we return the dentry */
	if (pid_revalidate(dentry, NULL))
		error = NULL;
out:
	return error;
}

static struct dentry *proc_task_lookup(struct inode *dir, struct dentry * dentry, struct nameidata *nd)
{
	struct dentry *result = ERR_PTR(-ENOENT);
	struct task_struct *task;
	struct task_struct *leader = get_proc_task(dir);
	unsigned tid;
	struct pid_namespace *ns;

	if (!leader)
		goto out_no_task;

	tid = name_to_int(dentry);
	if (tid == ~0U)
		goto out;

	ns = dentry->d_sb->s_fs_info;
	rcu_read_lock();
	task = find_task_by_pid_ns(tid, ns);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();
	if (!task)
		goto out;
	if (!same_thread_group(leader, task))
		goto out_drop_task;

	result = proc_task_instantiate(dir, dentry, task, NULL);
out_drop_task:
	put_task_struct(task);
out:
	put_task_struct(leader);
out_no_task:
	return result;
}

/*
 * Find the first tid of a thread group to return to user space.
 *
 * Usually this is just the thread group leader, but if the users
 * buffer was too small or there was a seek into the middle of the
 * directory we have more work todo.
 *
 * In the case of a short read we start with find_task_by_pid.
 *
 * In the case of a seek we start with the leader and walk nr
 * threads past it.
 */
static struct task_struct *first_tid(struct task_struct *leader,
		int tid, int nr, struct pid_namespace *ns)
{
	struct task_struct *pos;

	rcu_read_lock();
	/* Attempt to start with the pid of a thread */
	if (tid && (nr > 0)) {
		pos = find_task_by_pid_ns(tid, ns);
		if (pos && (pos->group_leader == leader))
			goto found;
	}

	/* If nr exceeds the number of threads there is nothing todo */
	pos = NULL;
	if (nr && nr >= get_nr_threads(leader))
		goto out;

	/* If we haven't found our starting place yet start
	 * with the leader and walk nr threads forward.
	 */
	for (pos = leader; nr > 0; --nr) {
		pos = next_thread(pos);
		if (pos == leader) {
			pos = NULL;
			goto out;
		}
	}
found:
	get_task_struct(pos);
out:
	rcu_read_unlock();
	return pos;
}

/*
 * Find the next thread in the thread list.
 * Return NULL if there is an error or no next thread.
 *
 * The reference to the input task_struct is released.
 */
static struct task_struct *next_tid(struct task_struct *start)
{
	struct task_struct *pos = NULL;
	rcu_read_lock();
	if (pid_alive(start)) {
		pos = next_thread(start);
		if (thread_group_leader(pos))
			pos = NULL;
		else
			get_task_struct(pos);
	}
	rcu_read_unlock();
	put_task_struct(start);
	return pos;
}

static int proc_task_fill_cache(struct file *filp, void *dirent, filldir_t filldir,
	struct task_struct *task, int tid)
{
	char name[PROC_NUMBUF];
	int len = snprintf(name, sizeof(name), "%d", tid);
	return proc_fill_cache(filp, dirent, filldir, name, len,
				proc_task_instantiate, task, NULL);
}

/* for the /proc/TGID/task/ directories */
static int proc_task_readdir(struct file * filp, void * dirent, filldir_t filldir)
{
	struct dentry *dentry = filp->f_path.dentry;
	struct inode *inode = dentry->d_inode;
	struct task_struct *leader = NULL;
	struct task_struct *task;
	int retval = -ENOENT;
	ino_t ino;
	int tid;
	struct pid_namespace *ns;

	task = get_proc_task(inode);
	if (!task)
		goto out_no_task;
	rcu_read_lock();
	if (pid_alive(task)) {
		leader = task->group_leader;
		get_task_struct(leader);
	}
	rcu_read_unlock();
	put_task_struct(task);
	if (!leader)
		goto out_no_task;
	retval = 0;

	switch ((unsigned long)filp->f_pos) {
	case 0:
		ino = inode->i_ino;
		if (filldir(dirent, ".", 1, filp->f_pos, ino, DT_DIR) < 0)
			goto out;
		filp->f_pos++;
		/* fall through */
	case 1:
		ino = parent_ino(dentry);
		if (filldir(dirent, "..", 2, filp->f_pos, ino, DT_DIR) < 0)
			goto out;
		filp->f_pos++;
		/* fall through */
	}

	/* f_version caches the tgid value that the last readdir call couldn't
	 * return. lseek aka telldir automagically resets f_version to 0.
	 */
	ns = filp->f_dentry->d_sb->s_fs_info;
	tid = (int)filp->f_version;
	filp->f_version = 0;
	for (task = first_tid(leader, tid, filp->f_pos - 2, ns);
	     task;
	     task = next_tid(task), filp->f_pos++) {
		tid = task_pid_nr_ns(task, ns);
		if (proc_task_fill_cache(filp, dirent, filldir, task, tid) < 0) {
			/* returning this tgid failed, save it as the first
			 * pid for the next readir call */
			filp->f_version = (u64)tid;
			put_task_struct(task);
			break;
		}
	}
out:
	put_task_struct(leader);
out_no_task:
	return retval;
}

static int proc_task_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat)
{
	struct inode *inode = dentry->d_inode;
	struct task_struct *p = get_proc_task(inode);
	generic_fillattr(inode, stat);

	if (p) {
		stat->nlink += get_nr_threads(p);
		put_task_struct(p);
	}

	return 0;
}

static const struct inode_operations proc_task_inode_operations = {
	.lookup		= proc_task_lookup,
	.getattr	= proc_task_getattr,
	.setattr	= proc_setattr,
	.permission	= proc_pid_permission,
};

static const struct file_operations proc_task_operations = {
	.read		= generic_read_dir,
	.readdir	= proc_task_readdir,
};
