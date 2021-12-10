/*
 *  hcc/gpm/app_frontier.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/sched.h>
#include <linux/list.h>
#include <linux/cred.h>
#include <hcc/remote_cred.h>
#include <hcc/sys/types.h>
#include <hcc/hcc_init.h>
#include <hcc/pid.h>
#include <hcc/application.h>
#include <net/grpc/grpcid.h>
#include <net/grpc/grpc.h>
#include "../checkpoint.h"

/*--------------------------------------------------------------------------*
 *                                                                          *
 *       USEFULL TO TRAVERSE FILIATION TREE                                 *
 *                                                                          *
 *--------------------------------------------------------------------------*/

static inline struct task_struct *p_cptr(struct task_struct *task)
{
	if (list_empty(&task->children))
		return NULL;

	return list_entry((&(task->children))->next, struct task_struct,
			  sibling);
}

static inline struct task_struct *p_osptr(struct task_struct *task)
{
	return list_entry(task->sibling.next, struct task_struct, sibling);
}

static inline int no_more_brother(struct task_struct *task)
{
	return ((task->sibling.next) == &((task->parent)->children));
}

#define begin_for_each_son_recursive(task,son) \
{					       \
	int gone_up = 0;                       \
	son = task;                            \
	while ( !(son==task && gone_up) ) {    \
		if (!gone_up) {

#define end_for_each_son_recursive(task,son);	       \
		}				       \
		if (p_cptr(son) != NULL && !gone_up) { \
			son = p_cptr(son);	       \
			gone_up = 0;		       \
		} else if (son != task) {	       \
			if ( no_more_brother(son) ) {  \
				son = son->parent;     \
				gone_up = 1;	       \
			} else {		       \
				son = p_osptr(son);    \
				gone_up = 0;	       \
			}			       \
		} else break;			       \
	} son = NULL;				       \
}

/*--------------------------------------------------------------------------*
 *--------------------------------------------------------------------------*/

static inline long __get_appid_from_task(struct task_struct *task)
{
	long r = 0;

	if (!can_be_checkpointed(task)) {
		r = -EPERM;
		goto exit;
	}

	if (!task->application)
		r = create_application(task);

	if (r)
		goto exit;

	BUG_ON(!task->application);
	r = task->application->app_id;
exit:
	return r;
}

struct getappid_request_msg {
	hcc_node_t requester;
	pid_t pid;
};

static inline long __get_appid_from_local_pid(pid_t pid)
{
	struct task_struct * task;

	rcu_read_lock();
	task = find_task_by_kpid(pid);
	rcu_read_unlock();
	if (task)
		return __get_appid_from_task(task);

	return -ESRCH;
}

long get_appid_from_pid(pid_t pid)
{
	struct grpc_desc *desc;
	hcc_node_t n = HCC_NODE_ID_NONE;
	struct getappid_request_msg msg;
	long app_id;
	int err = 0;

	/* lock the task to be sure it does not exit */
	n = hcc_lock_pid_location(pid);
	if (n == HCC_NODE_ID_NONE)
		return -ESRCH;

	/* the task is local */
	if (n == hcc_node_id) {
		app_id =  __get_appid_from_local_pid(pid);
		if (app_id < 0)
			err = app_id;
		goto out_unlock;
	}

	err = -ENOMEM;
	msg.requester = hcc_node_id;
	msg.pid = pid;

	desc = grpc_begin(APP_REMOTE_CHKPT, n);
	if (!desc)
		goto out_unlock;
	err = grpc_pack_type(desc, msg);
	if (err)
		goto err;
	err = pack_creds(desc, current_cred());
	if (err)
		goto err;

	err = grpc_unpack_type(desc, app_id);
	if (err)
		goto err;
out_end:
	grpc_end(desc, 0);

out_unlock:
	hcc_unlock_pid_location(pid);
	if (err)
		return err;
	return app_id;

err:
	grpc_cancel(desc);
	goto out_end;
}

static
void handle_get_appid_from_pid(struct grpc_desc *desc, void *_msg, size_t size)
{
	struct getappid_request_msg *msg = _msg;
	long app_id;
	const struct cred *old_cred;
	int err;

	old_cred = unpack_override_creds(desc);
	if (IS_ERR(old_cred)) {
		err = PTR_ERR(old_cred);
		goto out;
	}

	app_id = __get_appid_from_local_pid(msg->pid);

	revert_creds(old_cred);

	err = grpc_pack_type(desc, app_id);

out:
	if (err)
		grpc_cancel(desc);
}

void application_frontier_grpc_init(void)
{
	grpc_register_void(APP_REMOTE_CHKPT, handle_get_appid_from_pid, 0);
}
