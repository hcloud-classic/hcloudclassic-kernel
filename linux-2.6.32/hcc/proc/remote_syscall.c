/*
 *  hcc/proc/remote_syscall.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */
#include <net/grpc/grpc.h>
#include <linux/cred.h>
#include <hcc/remote_cred.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/pid.h>
#include <hcc/pid.h>
#include <hcc/ghotplug.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <asm/current.h>

#include <hcc/remote_syscall.h>

static void *cluster_started;

struct remote_syscall_header {
	pid_t pid;
	size_t payload;
};

struct grpc_desc *hcc_remote_syscall_begin(int req, pid_t pid,
					  const void *msg, size_t size)
{
	struct remote_syscall_header hdr;
	struct grpc_desc *desc;
	hcc_node_t node;
	int err = -ESRCH;

	if (!cluster_started)
		goto err;

	if (!current->nsproxy->hcc_ns)
		goto err;

	if (!is_hcc_pid_ns_root(task_active_pid_ns(current)))
		goto err;

	if (pid < 0 || !(pid & GLOBAL_PID_MASK))
		goto err;

	node = hcc_lock_pid_location(pid);
	if (node == HCC_NODE_ID_NONE)
		goto err;

	err = -ENOMEM;
	desc = grpc_begin(req, node);
	if (!desc)
		goto err_unlock;

	hdr.pid = pid;
	hdr.payload = size;
	err = grpc_pack_type(desc, hdr);
	if (err)
		goto err_cancel;
	if (size) {
		err = grpc_pack(desc, 0, msg, size);
		if (err)
			goto err_cancel;
	}
	err = pack_creds(desc, current_cred());
	if (err)
		goto err_cancel;

	return desc;

err_cancel:
	grpc_cancel(desc);
	grpc_end(desc, 0);
err_unlock:
	hcc_unlock_pid_location(pid);
err:
	return ERR_PTR(err);
}

void hcc_remote_syscall_end(struct grpc_desc *desc, pid_t pid)
{
	grpc_end(desc, 0);
	hcc_unlock_pid_location(pid);
}

int hcc_remote_syscall_simple(int req, pid_t pid, const void *msg, size_t size)
{
	struct grpc_desc *desc;
	int ret, err;

	desc = hcc_remote_syscall_begin(req, pid, msg, size);
	if (IS_ERR(desc)) {
		ret = PTR_ERR(desc);
		goto out;
	}
	err = grpc_unpack_type(desc, ret);
	if (err)
		ret = err;
	hcc_remote_syscall_end(desc, pid);

out:
	return ret;
}

struct pid *hcc_handle_remote_syscall_begin(struct grpc_desc *desc,
					    const void *_msg, size_t size,
					    void *msg,
					    const struct cred **old_cred)
{
	const struct remote_syscall_header *hdr = _msg;
	struct pid *pid;
	int err;

	if (hdr->payload) {
		err = grpc_unpack(desc, 0, msg, hdr->payload);
		if (err)
			goto err_cancel;
	}

	*old_cred = unpack_override_creds(desc);
	if (IS_ERR(*old_cred)) {
		err = PTR_ERR(*old_cred);
		goto err_cancel;
	}

	rcu_read_lock();
	pid = get_pid(find_kpid(hdr->pid));
	rcu_read_unlock();
	BUG_ON(!pid);

	return pid;

err_cancel:
	if (err > 0)
		err = -EPIPE;
	grpc_cancel(desc);
	return ERR_PTR(err);
}

void hcc_handle_remote_syscall_end(struct pid *pid, const struct cred *old_cred)
{
	revert_creds(old_cred);
	put_pid(pid);
}

void register_remote_syscalls_hooks(void)
{
	hook_register(&cluster_started, (void *)true);
}

void proc_remote_syscalls_start(void)
{
	remote_signals_init();
	remote_sched_init();
	remote_sys_init();
}
