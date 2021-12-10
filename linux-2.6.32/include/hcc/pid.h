#ifndef __HCC_PID_H__
#define __HCC_PID_H__

#ifdef CONFIG_HCC_PROC

#include <asm/page.h> /* Needed by linux/threads.h */
#include <linux/pid_namespace.h>
#include <linux/threads.h>
#include <linux/types.h>
#include <hcc/sys/types.h>
#include <hcc/hcc_init.h>
#include <hcc/hcc_nodemask.h>

/*
 * WARNING: procfs and futex need at least the 2 MSbits free (in procfs: 1 for
 * sign, 1 for upper pid limit; in futex: see linux/futex.h)
 */

#define GLOBAL_PID_MASK PID_MAX_LIMIT
#define PID_NODE_SHIFT (NR_BITS_PID_MAX_LIMIT + 1)
#define INTERNAL_PID_MASK (PID_MAX_LIMIT - 1)

#define GLOBAL_PID_NODE(pid, node) \
	(((node) << PID_NODE_SHIFT)|GLOBAL_PID_MASK|((pid) & INTERNAL_PID_MASK))
#define GLOBAL_PID(pid) GLOBAL_PID_NODE(pid, hcc_node_id)

/** extract the original linux kernel pid of a HCC PID */
#define SHORT_PID(pid) ((pid) & INTERNAL_PID_MASK)
/** extract the original node id of a HCC PID */
#define ORIG_NODE(pid) ((pid) >> PID_NODE_SHIFT)

#define HCC_PID_MAX_LIMIT GLOBAL_PID_NODE(0, HCC_MAX_NODES)

/* HCC container's PID numbers */
static inline pid_t pid_knr(struct pid *pid)
{
	struct pid_namespace *ns = ns_of_pid(pid);
	if (ns && ns->hcc_ns_root)
		return pid_nr_ns(pid, ns->hcc_ns_root);
	return 0;
}

static inline pid_t task_pid_knr(struct task_struct *task)
{
	return pid_knr(task_pid(task));
}

static inline pid_t task_tgid_knr(struct task_struct *task)
{
	return pid_knr(task_tgid(task));
}

static inline pid_t task_pgrp_knr(struct task_struct *task)
{
	return pid_knr(task_pgrp(task));
}

static inline pid_t task_session_knr(struct task_struct *task)
{
	return pid_knr(task_session(task));
}

static inline struct pid *find_kpid(int nr)
{
	struct pid_namespace *ns = find_get_hcc_pid_ns();
	struct pid *pid = find_pid_ns(nr, ns);
	put_pid_ns(ns);
	return pid;
}

static inline struct task_struct *find_task_by_kpid(pid_t pid)
{
	return pid_task(find_kpid(pid), PIDTYPE_PID);
}

/* PID location */
#ifdef CONFIG_HCC_GPM
int hcc_set_pid_location(struct task_struct *task);
int hcc_unset_pid_location(struct task_struct *task);
#endif
hcc_node_t hcc_lock_pid_location(pid_t pid);
void hcc_unlock_pid_location(pid_t pid);

/* Global PID, foreign pidmap aware iterator */
struct pid *hcc_find_ge_pid(int nr, struct pid_namespace *pid_ns,
			    struct pid_namespace *pidmap_ns);

#else /* !CONFIG_HCC_PROC */

static inline pid_t pid_knr(struct pid *pid)
{
	return pid_nr(pid);
}

static
inline pid_t __task_pid_knr(struct task_struct *task, enum pid_type type)
{
	return __task_pid_nr_ns(task, type, &init_pid_ns);
}

static inline pid_t task_pid_knr(struct task_struct *task)
{
	return task->pid;
}

static inline pid_t task_tgid_knr(struct task_struct *task)
{
	return task->tgid;
}

static inline pid_t task_pgrp_knr(struct task_struct *task)
{
	return __task_pid_knr(task, PIDTYPE_PGID);
}

static inline pid_t task_session_knr(struct task_struct *task)
{
	return __task_pid_knr(task, PIDTYPE_SID);
}

static inline struct pid *find_kpid(int nr)
{
	return find_pid_ns(nr, &init_pid_ns);
}

static inline struct task_struct *find_task_by_kpid(pid_t pid)
{
	return find_task_by_pid_ns(pid, &init_pid_ns);
}

#endif /* !CONFIG_HCC_PROC */

#ifdef CONFIG_HCC_GPM

/* Task GDM object link */
struct pid_gdm_object;
struct task_gdm_object;
struct pid;

/* Must be called under rcu_read_lock() */
struct task_gdm_object *hcc_pid_task(struct pid *pid);

/* Must be called under rcu_read_lock() */
void hcc_pid_unlink_task(struct pid_gdm_object *obj);

/* Pid reference tracking */
struct pid *hcc_get_pid(int nr);
void hcc_end_get_pid(struct pid *pid);
void hcc_put_pid(struct pid *pid);

/* Foreign pidmaps */
int pidmap_map_read_lock(void);
void pidmap_map_read_unlock(void);
hcc_node_t pidmap_node(hcc_node_t node);
struct pid_namespace *node_pidmap(hcc_node_t node);

void pidmap_map_cleanup(struct hcc_namespace *hcc_ns);

void hcc_free_pidmap(struct upid *upid);

#elif defined(CONFIG_HCC_PROC)

static inline int pidmap_map_read_lock(void)
{
	return 0;
}

static inline void pidmap_map_read_unlock(void)
{
}

static inline hcc_node_t pidmap_node(hcc_node_t node)
{
	return hcc_node_online(node) ? node : HCC_NODE_ID_NONE;
}

static inline struct pid_namespace *node_pidmap(hcc_node_t node)
{
	return NULL;
}

#endif /* CONFIG_HCC_GPM */

#endif /* __HCC_PID_H__ */
