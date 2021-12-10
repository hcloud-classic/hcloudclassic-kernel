/** Global /proc/<pid>/<file> management
 *  @file proc_pid_file.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/proc_fs.h>
#include <linux/procfs_internal.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/seq_file.h>
#include <linux/anon_inodes.h>
#include <linux/syscalls.h>
#include <linux/pid_namespace.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/gfp.h>

#include <hcc/sys/types.h>
#include <hcc/pid.h>
#include <hcc/remote_cred.h>

#include <net/grpc/grpcid.h>
#include <net/grpc/grpc.h>
#include <hcc/task.h>
#include "proc_pid.h"

/* REG() entries */

struct environ_read_msg {
	pid_t pid;
	size_t count;
	loff_t pos;
};

static int do_handle_environ_read(struct task_struct *task,
				  char *buf, size_t count, loff_t *ppos)
{
	struct pid_namespace *ns = find_get_hcc_pid_ns();
	struct vfsmount *mnt = ns->proc_mnt;
	struct file *file;
	struct nameidata nd;
	char str_buf[PROC_NUMBUF + sizeof("/environ")];
	int ret;

	sprintf(str_buf, "%d/environ", task_pid_nr_ns(task, ns));
	ret = vfs_path_lookup(mnt->mnt_root, mnt, str_buf, 0, &nd);
	if (ret)
		goto out;

	file = dentry_open(nd.path.dentry,
			   nd.path.mnt,
			   O_RDONLY,
			   current_cred());
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		/* dentry_open() dropped nd.path ref counts */
		goto out;
	}

	ret = vfs_read(file, buf, count, ppos);

	/* Drops nd.path == file->f_path ref counts */
	fput(file);

out:
	put_pid_ns(ns);
	return ret;
}

static void handle_read_proc_pid_environ(struct grpc_desc *desc,
					 void *_msg, size_t size)
{
	struct environ_read_msg *msg = _msg;
	struct task_struct *tsk;
	const struct cred *old_cred;
	unsigned long page = 0;
	int res;
	int err;

	rcu_read_lock();
	tsk = find_task_by_kpid(msg->pid);
	BUG_ON(!tsk);
	get_task_struct(tsk);
	rcu_read_unlock();

	old_cred = unpack_override_creds(desc);
	if (IS_ERR(old_cred)) {
		err = PTR_ERR(old_cred);
		goto out_err_cancel;
	}

	page = __get_free_page(GFP_TEMPORARY);
	if (!page)
		res = -ENOMEM;
	else
		res = do_handle_environ_read(tsk,
					     (char *)page, msg->count,
					     &msg->pos);

	revert_creds(old_cred);

	err = grpc_pack_type(desc, res);
	if (err)
		goto out_err_cancel;
	if (res > 0) {
		err = grpc_pack(desc, 0, (char *)page, res);
		if (err)
			goto out_err_cancel;
	}
	err = grpc_pack_type(desc, msg->pos);
	if (err)
		goto out_err_cancel;

out:
	put_task_struct(tsk);
	if (page)
		free_page(page);
	if (err)
		res = err;
	return;

out_err_cancel:
	grpc_cancel(desc);
	goto out;
}

static int do_environ_read(struct file *file, struct proc_distant_pid_info *task,
			   char *buf, size_t count, loff_t *ppos)
{
	struct environ_read_msg msg;
	struct grpc_desc *desc;
	int bytes_read;
	loff_t new_pos;
	int err;

	BUG_ON(task->prob_node == HCC_NODE_ID_NONE);

	msg.pid = task->pid;
	msg.count = count;
	msg.pos = *ppos;

	err = -ENOMEM;
	desc = grpc_begin(REQ_PROC_PID_ENVIRON, task->prob_node);
	if (!desc)
		goto out_err;

	err = grpc_pack_type(desc, msg);
	if (err)
		goto out_err_cancel;
	err = pack_creds(desc, current_cred());
	if (err)
		goto out_err_cancel;

	err = grpc_unpack_type(desc, bytes_read);
	if (err)
		goto out_err_cancel;
	if (bytes_read > 0) {
		BUG_ON(bytes_read > count);
		err = grpc_unpack(desc, 0, buf, bytes_read);
	}
	if (err)
		goto out_err_cancel;
	err = grpc_unpack_type(desc, new_pos);
	if (err)
		goto out_err_cancel;
	*ppos = new_pos;

	grpc_end(desc, 0);

out:
	return bytes_read;

out_err_cancel:
	if (err > 0)
		err = -EPIPE;
	grpc_cancel(desc);
	grpc_end(desc, 0);
out_err:
	bytes_read = err;
	goto out;
}

static ssize_t hcc_proc_pid_environ_read(struct file *file, char __user *buf,
					 size_t count, loff_t *ppos)
{
	struct proc_distant_pid_info *task =
		get_hcc_proc_task(file->f_dentry->d_inode);
	unsigned long page;
	size_t c = count;
	loff_t pos = *ppos;
	int ret = -ESRCH;

	if (!current->nsproxy->hcc_ns)
		goto out_no_task;

	/* TODO: if pid is reused in between, we may think the entry is still
	 * valid! */
	task->prob_node = hcc_lock_pid_location(task->pid);
	if (task->prob_node == HCC_NODE_ID_NONE)
		/* Task is dead. */
		goto out_no_task;

	ret = -ENOMEM;
	if (!(page = __get_free_page(GFP_TEMPORARY)))
		goto out;

	while (c) {
		ret = do_environ_read(file, task,
				      (char *)page, min(c, (size_t)PAGE_SIZE),
				      &pos);
		if (ret > 0)
			if (copy_to_user(buf, (void *)page, ret))
				ret = -EFAULT;
		if (ret < 0)
			goto out_free;
		*ppos = pos;
		if (!ret)
			break;
		c -= ret;
	}
	ret = count - c;

out_free:
	free_page(page);
out:
	hcc_unlock_pid_location(task->pid);
out_no_task:
	return ret;
}

const struct file_operations hcc_proc_pid_environ_operations = {
	.read		= hcc_proc_pid_environ_read,
};

/* INF() entries */

/* Common part */

#define PROC_BLOCK_SIZE (3*1024)	/* 4K page size but our output routines use some slack for overruns */

static ssize_t hcc_proc_info_read(struct file *file, char *buf,
				  size_t count, loff_t *ppos)
{
	struct inode *inode = file->f_dentry->d_inode;
	unsigned long page;
	ssize_t length;
	struct proc_distant_pid_info *task = get_hcc_proc_task(inode);

	length = -ESRCH;
	if (!current->nsproxy->hcc_ns)
		goto out_no_task;

	/*
	 * TODO: if pid is reused in between, we may think the entry is still
	 * valid!
	 */
	task->prob_node = hcc_lock_pid_location(task->pid);
	if (task->prob_node == HCC_NODE_ID_NONE)
		/* Task is dead. */
		goto out_no_task;

	if (count > PROC_BLOCK_SIZE)
		count = PROC_BLOCK_SIZE;

	length = -ENOMEM;
	if (!(page = __get_free_page(GFP_TEMPORARY)))
		goto out;

	length = task->op.proc_read(task, (char *)page);

	if (length >= 0)
		length = simple_read_from_buffer(buf, count, ppos, (char *)page, length);

	free_page(page);
out:
	hcc_unlock_pid_location(task->pid);
out_no_task:
	return length;
}

const struct file_operations hcc_proc_info_file_operations = {
	.read = hcc_proc_info_read,
};

/* Helpers */

struct generic_proc_read_msg {
	pid_t pid;
};

typedef int proc_read_t(struct task_struct *task, char *buffer);

static void handle_generic_proc_read(struct grpc_desc *desc, void *_msg,
				     proc_read_t *proc_read,
				     enum grpcid REQ)
{
	struct generic_proc_read_msg *msg = _msg;
	struct task_struct *tsk;
	const struct cred *old_cred = NULL;
	unsigned long page = 0;
	int res;
	int err;

	rcu_read_lock();
	tsk = find_task_by_kpid(msg->pid);
	BUG_ON(!tsk);
	get_task_struct(tsk);
	rcu_read_unlock();

	old_cred = unpack_override_creds(desc);
	if (IS_ERR(old_cred)) {
		err = res = PTR_ERR(old_cred);
		old_cred = NULL;
		if (res == -ENOMEM)
			goto out_res;
		goto out_err_cancel;
	}

	page = __get_free_page(GFP_TEMPORARY);
	if (!page)
		res = -ENOMEM;
	else
		res = proc_read(tsk, (char *)page);

out_res:
	err = grpc_pack_type(desc, res);
	if (err)
		goto out_err_cancel;
	if (res > 0) {
		err = grpc_pack(desc, 0, (char *)page, res);
		if (err)
			goto out_err_cancel;
	}

out:
	put_task_struct(tsk);
	if (page)
		free_page(page);
	if (old_cred)
		revert_creds(old_cred);
	if (err)
		res = err;
	return;

out_err_cancel:
	grpc_cancel(desc);
	goto out;
}

static int generic_proc_read(struct proc_distant_pid_info *task,
			     char *buffer, enum grpcid req)
{
	struct generic_proc_read_msg msg;
	struct grpc_desc *desc;
	int bytes_read;
	int err;

	BUG_ON(task->prob_node == HCC_NODE_ID_NONE);

	msg.pid = task->pid;

	err = -ENOMEM;
	desc = grpc_begin(req, task->prob_node);
	if (!desc)
		goto out_err;

	err = grpc_pack_type(desc, msg);
	if (err)
		goto out_err_cancel;
	err = pack_creds(desc, current_cred());
	if (err)
		goto out_err_cancel;

	err = grpc_unpack_type(desc, bytes_read);
	if (err)
		goto out_err_cancel;
	if (bytes_read > 0)
		err = grpc_unpack(desc, 0, buffer, bytes_read);
	if (err)
		goto out_err_cancel;

	grpc_end(desc, 0);

out:
	return bytes_read;

out_err_cancel:
	if (err > 0)
		err = -EPIPE;
	grpc_cancel(desc);
	grpc_end(desc, 0);
out_err:
	bytes_read = err;
	goto out;
}

/* Entries */

static void handle_read_proc_pid_cmdline(struct grpc_desc *desc,
					 void *_msg, size_t size)
{
	handle_generic_proc_read(desc, _msg, proc_pid_cmdline,
				 REQ_PROC_PID_CMDLINE);
}

int hcc_proc_pid_cmdline(struct proc_distant_pid_info *task, char *buffer)
{
	return generic_proc_read(task, buffer, REQ_PROC_PID_CMDLINE);
}

static void handle_read_proc_pid_auxv(struct grpc_desc *desc,
				      void *_msg, size_t size)
{
	handle_generic_proc_read(desc, _msg, proc_pid_auxv,
				 REQ_PROC_PID_CMDLINE);
}

int hcc_proc_pid_auxv(struct proc_distant_pid_info *task, char *buffer)
{
	return generic_proc_read(task, buffer, REQ_PROC_PID_AUXV);
}

static void handle_read_proc_pid_limits(struct grpc_desc *desc,
					void *_msg, size_t size)
{
	handle_generic_proc_read(desc, _msg, proc_pid_limits,
				 REQ_PROC_PID_LIMITS);
}

int hcc_proc_pid_limits(struct proc_distant_pid_info *task, char *buffer)
{
	return generic_proc_read(task, buffer, REQ_PROC_PID_LIMITS);
}

#ifdef CONFIG_HAVE_ARCH_TRACEHOOK
static void handle_read_proc_pid_syscall(struct grpc_desc *desc,
					 void *_msg, size_t size)
{
	handle_generic_proc_read(desc, _msg, proc_pid_syscall,
				 REQ_PROC_PID_SYSCALL);
}

int hcc_proc_pid_syscall(struct proc_distant_pid_info *task, char *buffer)
{
	return generic_proc_read(task, buffer, REQ_PROC_PID_SYSCALL);
}
#endif

#ifdef CONFIG_KALLSYMS
static void handle_read_proc_pid_wchan(struct grpc_desc *desc,
				       void *_msg, size_t size)
{
	handle_generic_proc_read(desc, _msg, proc_pid_wchan,
				 REQ_PROC_PID_WCHAN);
}

int hcc_proc_pid_wchan(struct proc_distant_pid_info *task, char *buffer)
{
	return generic_proc_read(task, buffer, REQ_PROC_PID_WCHAN);
}
#endif

#ifdef CONFIG_SCHEDSTATS
static void handle_read_proc_pid_schedstat(struct grpc_desc *desc,
					   void *_msg, size_t size)
{
	handle_generic_proc_read(desc, _msg, proc_pid_schedstat,
				 REQ_PROC_PID_SCHEDSTAT);
}

int hcc_proc_pid_schedstat(struct proc_distant_pid_info *task, char *buffer)
{
	return generic_proc_read(task, buffer, REQ_PROC_PID_SCHEDSTAT);
}
#endif

static void handle_read_proc_pid_oom_score(struct grpc_desc *desc,
					   void *_msg, size_t size)
{
	handle_generic_proc_read(desc, _msg, proc_oom_score,
				 REQ_PROC_PID_OOM_SCORE);
}

int hcc_proc_pid_oom_score(struct proc_distant_pid_info *task, char *buffer)
{
	return generic_proc_read(task, buffer, REQ_PROC_PID_OOM_SCORE);
}

#ifdef CONFIG_TASK_IO_ACCOUNTING
static void handle_read_proc_tgid_io_accounting(struct grpc_desc *desc,
						void *_msg, size_t size)
{
	handle_generic_proc_read(desc, _msg, proc_tgid_io_accounting,
				 REQ_PROC_TGID_IO_ACCOUNTING);
}

int hcc_proc_tgid_io_accounting(struct proc_distant_pid_info *task, char *buffer)
{
	return generic_proc_read(task, buffer, REQ_PROC_TGID_IO_ACCOUNTING);
}
#endif

#ifdef CONFIG_HCC_GPM
static void handle_read_gpm_type_show(struct grpc_desc *desc,
						void *_msg, size_t size)
{
	handle_generic_proc_read(desc, _msg, gpm_type_show,
				 REQ_PROC_GPM_TYPE_SHOW);
}

int hcc_proc_gpm_type_show(struct proc_distant_pid_info *task, char *buffer)
{
	return generic_proc_read(task, buffer, REQ_PROC_GPM_TYPE_SHOW);
}

static void handle_read_gpm_source_show(struct grpc_desc *desc,
						void *_msg, size_t size)
{
	handle_generic_proc_read(desc, _msg, gpm_source_show,
				 REQ_PROC_GPM_SOURCE_SHOW);
}

int hcc_proc_gpm_source_show(struct proc_distant_pid_info *task, char *buffer)
{
	return generic_proc_read(task, buffer, REQ_PROC_GPM_SOURCE_SHOW);
}

static void handle_read_gpm_target_show(struct grpc_desc *desc,
						void *_msg, size_t size)
{
	handle_generic_proc_read(desc, _msg, gpm_target_show,
				 REQ_PROC_GPM_TARGET_SHOW);
}

int hcc_proc_gpm_target_show(struct proc_distant_pid_info *task, char *buffer)
{
	return generic_proc_read(task, buffer, REQ_PROC_GPM_TARGET_SHOW);
}
#endif

/* ONE() entries */

/* Common part */
static ssize_t hcc_proc_single_read(struct file *file, char __user *buf,
				    size_t count, loff_t *ppos)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct pid_namespace *ns;
	struct proc_distant_pid_info *task = get_hcc_proc_task(inode);
	unsigned long page;
	size_t c = count;
	ssize_t length;

	ns = inode->i_sb->s_fs_info;
	BUG_ON(!is_hcc_pid_ns_root(ns));

	length = -ESRCH;
	if (!current->nsproxy->hcc_ns)
		goto out_no_task;

	/*
	 * TODO: if pid is reused in between, we may think the entry is still
	 * valid!
	 */
	task->prob_node = hcc_lock_pid_location(task->pid);
	if (task->prob_node == HCC_NODE_ID_NONE)
		/* Task is dead. */
		goto out_no_task;

	length = -ENOMEM;
	if (!(page = __get_free_page(GFP_TEMPORARY)))
		goto out;

	while (c) {
		length = task->op.proc_show(file, task,
					    (char *)page,
					    min(c, (size_t)PAGE_SIZE));
		if (length > 0)
			length = simple_read_from_buffer(buf, count, ppos, (char *)page, length);
		if (length < 0)
			goto out_free;
		if (!length)
			break;
		c -= length;
	}
	length = count - c;

out_free:
	free_page(page);

out:
	hcc_unlock_pid_location(task->pid);
out_no_task:
	return length;
}

struct hcc_proc_single_private {
	void (*release)(struct inode *inode, struct file *file);
	void *data;
};

int hcc_proc_single_release(struct inode *inode, struct file *file)
{
	struct hcc_proc_single_private *private = file->private_data;

	if (private)
		private->release(inode, file);
	return 0;
}

const struct file_operations hcc_proc_single_file_operations = {
	.read = hcc_proc_single_read,
	.release = hcc_proc_single_release,
};

/* Helpers */
struct generic_proc_show_msg {
	pid_t pid;
};

typedef int proc_show_t(struct seq_file *,
			struct pid_namespace *, struct pid *,
			struct task_struct *);

struct anonymous_proc_single_data {
	struct task_struct *task;
	struct pid_namespace *ns;
	proc_show_t *proc_show;
};

static int hcc_proc_handler_single_show(struct seq_file *m, void *v)
{
	struct anonymous_proc_single_data *data = m->private;
	struct task_struct *task = data->task;

	return data->proc_show(m, data->ns, task_pid(task), task);
}

static
int hcc_proc_handler_single_release(struct inode *inode, struct file *file)
{
	struct seq_file *m = file->private_data;
	struct anonymous_proc_single_data *data = m->private;

	put_pid_ns(data->ns);
	put_task_struct(data->task);
	kfree(data);
	return single_release(inode, file);
}

static const struct file_operations hcc_proc_handler_single_file_operations = {
	.read = seq_read,
	.llseek = seq_lseek,
	.release = hcc_proc_handler_single_release,
};

static int hcc_proc_handler_single_getfd(struct task_struct *task,
					 struct pid_namespace *ns,
					 proc_show_t *proc_show)
{
	struct anonymous_proc_single_data *data;
	struct file *file;
	int fd, err;

	fd = -ENOMEM;
	data = kmalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		goto out;
	get_task_struct(task);
	data->task = task;
	get_pid_ns(ns);
	data->ns = ns;
	data->proc_show = proc_show;

	fd = anon_inode_getfd("hcc-proc-handler-single",
			      &hcc_proc_handler_single_file_operations,
			      NULL,
			      O_RDWR);
	if (fd < 0)
		goto err_free_data;

	file = fget(fd);
	BUG_ON(!file);
	err = single_open(file, hcc_proc_handler_single_show, data);
	fput(file);
	if (err) {
		sys_close(fd);
		fd = err;
		goto err_free_data;
	}

out:
	return fd;

err_free_data:
	put_pid_ns(ns);
	put_task_struct(data->task);
	kfree(data);
	goto out;
}

static void handle_generic_proc_show(struct grpc_desc *desc, void *_msg,
				     proc_show_t *proc_show,
				     enum grpcid REQ)
{
	struct generic_proc_show_msg *msg = _msg;
	struct pid_namespace *ns = find_get_hcc_pid_ns();
	struct task_struct *tsk;
	const struct cred *old_cred = NULL;
	unsigned long page = 0;
	int fd = -1;
	size_t count;
	int res;
	int err;

	rcu_read_lock();
	tsk = find_task_by_pid_ns(msg->pid, ns);
	BUG_ON(!tsk);
	get_task_struct(tsk);
	rcu_read_unlock();

	old_cred = unpack_override_creds(desc);
	if (IS_ERR(old_cred)) {
		res = PTR_ERR(old_cred);
		old_cred = NULL;
		goto out_err;
	}

	page = __get_free_page(GFP_KERNEL);
	if (!page)
		goto out_err;

	res = hcc_proc_handler_single_getfd(tsk, ns, proc_show);
	if (res < 0)
		goto out_err;
	fd = res;

	for (;;) {
		err = grpc_unpack_type(desc, count);
		if (err)
			goto out_err_cancel;
		if (!count)
			break;

		res = sys_read(fd, (void *)page, count);

		err = grpc_pack_type(desc, res);
		if (err)
			goto out_err_cancel;
		if (res > 0) {
			err = grpc_pack(desc, 0, (char *)page, res);
			if (err)
				goto out_err_cancel;
		}
	}

out:
	if (fd >= 0)
		sys_close(fd);
	if (page)
		free_page(page);
	if (old_cred)
		revert_creds(old_cred);
	put_task_struct(tsk);
	put_pid_ns(ns);
	if (err)
		res = err;
	return;

out_err_cancel:
	if (err > 0)
		err = -EPIPE;
	grpc_cancel(desc);
	goto out;

out_err:
	err = grpc_pack_type(desc, res);
	if (err)
		goto out_err_cancel;
	goto out;
}

static void generic_proc_show_release(struct inode *inode, struct file *file)
{
	struct hcc_proc_single_private *private = file->private_data;
	struct grpc_desc *desc = private->data;
	size_t count = 0;
	int err;

	err = grpc_pack_type(desc, count);
	if (err)
		grpc_cancel(desc);
	grpc_end(desc, 0);
	kfree(private);
}

static int generic_proc_show(struct file *file,
			     struct proc_distant_pid_info *task,
			     char *buf, size_t count,
			     enum grpcid req)
{
	struct generic_proc_show_msg msg;
	struct hcc_proc_single_private *private = file->private_data;
	struct pid_namespace *ns = file->f_dentry->d_sb->s_fs_info;
	struct grpc_desc *desc;
	int bytes_read;
	int err;

	BUG_ON(task->prob_node == HCC_NODE_ID_NONE);
	BUG_ON(!is_hcc_pid_ns_root(ns));

	msg.pid = task->pid;

	if (!private) {
		err = -ENOMEM;
		private = kmalloc(sizeof(*private), GFP_KERNEL);
		if (!private)
			goto out_err;
		desc = grpc_begin(req, task->prob_node);
		if (!desc) {
			kfree(private);
			goto out_err;
		}
		private->release = generic_proc_show_release;
		private->data = desc;
		file->private_data = private;

		err = grpc_pack_type(desc, msg);
		if (err)
			goto out_err_cancel;
		err = pack_creds(desc, current_cred());
		if (err)
			goto out_err_cancel;
	} else {
		desc = private->data;
	}

	err = grpc_pack_type(desc, count);
	if (err)
		goto out_err_cancel;
	err = grpc_unpack_type(desc, bytes_read);
	if (err)
		goto out_err_cancel;
	if (bytes_read > 0) {
		BUG_ON(bytes_read > count);
		err = grpc_unpack(desc, 0, buf, bytes_read);
	}
	if (err)
		goto out_err_cancel;

out:
	return bytes_read;

out_err_cancel:
	if (err > 0)
		err = -EPIPE;
	grpc_cancel(desc);
out_err:
	bytes_read = err;
	goto out;
}

/* Entries */

static void handle_read_proc_pid_status(struct grpc_desc *desc,
					void *_msg, size_t size)
{
	handle_generic_proc_show(desc, _msg, proc_pid_status,
				 REQ_PROC_PID_STATUS);
}

int hcc_proc_pid_status(struct file *file, struct proc_distant_pid_info *task,
			char *buf, size_t count)
{
	return generic_proc_show(file, task, buf, count, REQ_PROC_PID_STATUS);
}

static void handle_read_proc_pid_personality(struct grpc_desc *desc,
					     void *_msg, size_t size)
{
	handle_generic_proc_show(desc, _msg, proc_pid_personality,
				 REQ_PROC_PID_PERSONALITY);
}

int hcc_proc_pid_personality(struct file *file,
			     struct proc_distant_pid_info *task,
			     char *buf, size_t count)
{
	return generic_proc_show(file, task, buf, count, REQ_PROC_PID_PERSONALITY);
}

static void handle_read_proc_tgid_stat(struct grpc_desc *desc,
				       void *_msg, size_t size)
{
	handle_generic_proc_show(desc, _msg, proc_tgid_stat,
				 REQ_PROC_TGID_STAT);
}

int hcc_proc_tgid_stat(struct file *file, struct proc_distant_pid_info *task,
		       char *buf, size_t count)
{
	return generic_proc_show(file, task, buf, count, REQ_PROC_TGID_STAT);
}

static void handle_read_proc_pid_statm(struct grpc_desc *desc,
				       void *_msg, size_t size)
{
	handle_generic_proc_show(desc, _msg, proc_pid_statm,
				 REQ_PROC_PID_STATM);
}

int hcc_proc_pid_statm(struct file *file, struct proc_distant_pid_info *task,
		       char *buf, size_t count)
{
	return generic_proc_show(file, task, buf, count, REQ_PROC_PID_STATM);
}

#ifdef CONFIG_STACKTRACE
static void handle_read_proc_pid_stack(struct grpc_desc *desc,
				       void *_msg, size_t size)
{
	handle_generic_proc_show(desc, _msg, proc_pid_stack,
				 REQ_PROC_PID_STACK);
}

int hcc_proc_pid_stack(struct file *file, struct proc_distant_pid_info *task,
		       char *buf, size_t count)
{
	return generic_proc_show(file, task, buf, count, REQ_PROC_PID_STACK);
}
#endif

void proc_pid_file_init(void)
{
	/* REG() entries */
	grpc_register_void(REQ_PROC_PID_ENVIRON, handle_read_proc_pid_environ, 0);
	/* INF() entries */
	grpc_register_void(REQ_PROC_PID_CMDLINE, handle_read_proc_pid_cmdline, 0);
	grpc_register_void(REQ_PROC_PID_AUXV, handle_read_proc_pid_auxv, 0);
	grpc_register_void(REQ_PROC_PID_LIMITS, handle_read_proc_pid_limits, 0);
#ifdef CONFIG_HAVE_ARCH_TRACEHOOK
	grpc_register_void(REQ_PROC_PID_SYSCALL, handle_read_proc_pid_syscall, 0);
#endif
#ifdef CONFIG_KALLSYMS
	grpc_register_void(REQ_PROC_PID_WCHAN, handle_read_proc_pid_wchan, 0);
#endif
#ifdef CONFIG_SCHEDSTATS
	grpc_register_void(REQ_PROC_PID_SCHEDSTAT, handle_read_proc_pid_schedstat, 0);
#endif
	grpc_register_void(REQ_PROC_PID_OOM_SCORE, handle_read_proc_pid_oom_score, 0);
#ifdef CONFIG_TASK_IO_ACCOUNTING
	grpc_register_void(REQ_PROC_TGID_IO_ACCOUNTING,
			  handle_read_proc_tgid_io_accounting, 0);
#endif
#ifdef CONFIG_HCC_GPM
	grpc_register_void(REQ_PROC_GPM_TYPE_SHOW, handle_read_gpm_type_show, 0);
	grpc_register_void(REQ_PROC_GPM_SOURCE_SHOW, handle_read_gpm_source_show, 0);
	grpc_register_void(REQ_PROC_GPM_TARGET_SHOW, handle_read_gpm_target_show, 0);
#endif
	/* ONE() entries */
	grpc_register_void(REQ_PROC_PID_STATUS, handle_read_proc_pid_status, 0);
	grpc_register_void(REQ_PROC_PID_PERSONALITY,
			  handle_read_proc_pid_personality, 0);
	grpc_register_void(REQ_PROC_TGID_STAT, handle_read_proc_tgid_stat, 0);
	grpc_register_void(REQ_PROC_PID_STATM, handle_read_proc_pid_statm, 0);
#ifdef CONFIG_STACKTRACE
	grpc_register_void(REQ_PROC_PID_STACK, handle_read_proc_pid_stack, 0);
#endif
}

void proc_pid_file_finalize(void)
{
}
