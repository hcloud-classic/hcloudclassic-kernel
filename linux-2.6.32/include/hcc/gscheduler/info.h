#ifndef __HCC_GSCHEDULER_INFO_H__
#define __HCC_GSCHEDULER_INFO_H__

#ifdef CONFIG_HCC_GSCHED

#include <linux/list.h>

struct module;
struct task_struct;
struct gpm_action;
struct ghost;

struct hcc_gsched_module_info_type {
	struct list_head list;		/* reserved for hcc_gsched_info */
	struct list_head instance_head;	/* subsystem internal */
	const char *name;
	struct module *owner;
	/* can block */
	struct hcc_gsched_module_info *(*copy)(struct task_struct *,
					      struct hcc_gsched_module_info *);
	/* may be called from interrupt context */
	void (*free)(struct hcc_gsched_module_info *);
	/* can block */
	int (*export)(struct gpm_action *, struct ghost *,
		      struct hcc_gsched_module_info *);
	/* can block */
	struct hcc_gsched_module_info *(*import)(struct gpm_action *,
						struct ghost *,
						struct task_struct *);
};

/* struct to include in module specific task hcc_gsched_info struct */
/* modification is reserved for hcc_gsched_info subsystem internal */
struct hcc_gsched_module_info {
	struct list_head info_list;
	struct list_head instance_list;
	struct hcc_gsched_module_info_type *type;
};

int hcc_gsched_module_info_register(struct hcc_gsched_module_info_type *type);
/*
 * must only be called at module unloading (See comment in
 * hcc_gsched_info_copy())
 */
void hcc_gsched_module_info_unregister(struct hcc_gsched_module_info_type *type);
/* Must be called under rcu_read_lock() */
struct hcc_gsched_module_info *
hcc_gsched_module_info_get(struct task_struct *task,
			  struct hcc_gsched_module_info_type *type);

/* fork() / exit() */
extern int hcc_gsched_info_copy(struct task_struct *tsk);
extern void hcc_gsched_info_free(struct task_struct *tsk);

#endif /* CONFIG_HCC_GSCHED */

#endif /* __HCC_GSCHEDULER_INFO_H__ */
