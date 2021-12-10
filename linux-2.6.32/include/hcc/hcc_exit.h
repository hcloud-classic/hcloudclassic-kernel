#ifndef __HCC_EXIT_H__
#define __HCC_EXIT_H__

struct task_struct;

#ifdef CONFIG_HCC_GPM

#include <linux/types.h>
#include <hcc/sys/types.h>

struct children_gdm_object;
enum pid_type;
struct siginfo;
struct rusage;

struct remote_child {
	struct list_head sibling;
	struct list_head thread_group;
	pid_t pid;
	pid_t tgid;
	pid_t pgid;
	pid_t sid;
	pid_t parent;
	pid_t real_parent;
	int ptraced;
	int exit_signal;
	long exit_state;
	hcc_node_t node;
};

/* do_wait() hook */
int hcc_do_wait(struct children_gdm_object *obj, struct wait_opts *wo);

/* Used by hcc_do_wait() */
int hcc_wait_task_zombie(struct wait_opts *wo,
			 struct remote_child *child);

/* do_notify_parent() hook */
int hcc_do_notify_parent(struct task_struct *task, struct siginfo *info);

/* Used by remote (zombie) child reparenting */
void notify_remote_child_reaper(pid_t zombie_pid,
				hcc_node_t zombie_location);

/* Delayed do_notify_parent() in release_task() */
int hcc_delayed_notify_parent(struct task_struct *leader);

/* exit_ptrace() hooks */
struct children_gdm_object *
hcc_prepare_exit_ptrace_task(struct task_struct *tracer,
			     struct task_struct *task)
	__acquires(tasklist_lock);
void hcc_finish_exit_ptrace_task(struct task_struct *task,
				 struct children_gdm_object *obj,
				 bool dead)
	__releases(tasklist_lock);

#endif /* CONFIG_HCC_GPM */

#ifdef CONFIG_HCC_PROC

/* exit_notify() hooks */

void *hcc_prepare_exit_notify(struct task_struct *task);
void hcc_finish_exit_notify(struct task_struct *task, int signal, void *cookie);

#endif /* CONFIG_HCC_PROC */

#endif /* __HCC_EXIT_H__ */
