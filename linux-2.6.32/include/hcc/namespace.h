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

int copy_hcc_ns(struct task_struct *task, struct nsproxy *new);
void free_hcc_ns(struct hcc_namespace *ns);

struct hcc_namespace *find_get_hcc_ns(void);

static inline void get_hcc_ns(struct hcc_namespace *ns)
{
	atomic_inc(&ns->count);
}

static inline void put_hcc_ns(struct hcc_namespace *ns)
{
	if (atomic_dec_and_test(&ns->count))
		free_hcc_ns(ns);
}

bool can_create_hcc_ns(unsigned long flags);

void hcc_ns_root_exit(struct hcc_namespace *ns);

#endif /* __HCC_NAMESPACE_H__ */
