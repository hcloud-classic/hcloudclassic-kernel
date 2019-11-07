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


struct hcc_namespace *find_get_hcc_ns(void);

static inline void get_hcc_ns(struct hcc_namespace *ns)
{
	atomic_inc(&ns->count);
}
