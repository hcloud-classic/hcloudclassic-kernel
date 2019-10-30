#ifndef __HCC_NAMESPACE_H__
#define __HCC_NAMESPACE_H__

#include <linux/nsproxy.h>
#include <linux/rcupdate.h>
#include <asm/atomic.h>

struct task_struct;

struct hcc_namespace {
	atomic_t count;
	struct nsproxy root_nsproxy;
	struct user_namespace *root_user_ns;
	struct task_struct *root_task;
	struct rcu_head rcu;
};
