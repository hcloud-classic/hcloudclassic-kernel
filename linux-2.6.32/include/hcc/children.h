#ifndef __HCC_CHILDREN_H__
#define __HCC_CHILDREN_H__

#ifdef CONFIG_HCC_GPM

#include <linux/types.h>
#include <hcc/sys/types.h>

struct children_gdm_object;
struct task_struct;
struct pid_namespace;
struct pid;

struct children_gdm_object *hcc_children_alloc(struct task_struct *task);
void hcc_children_share(struct task_struct *task);
void hcc_children_exit(struct task_struct *task);
void hcc_children_get(struct children_gdm_object *obj);
void hcc_children_put(struct children_gdm_object *obj);
int hcc_new_child(struct children_gdm_object *obj,
		  pid_t parent_pid,
		  struct task_struct *child);
void __hcc_set_child_pgid(struct children_gdm_object *obj,
			  pid_t pid, pid_t pgid);
void hcc_set_child_pgid(struct children_gdm_object *obj,
			struct task_struct *child);
int hcc_set_child_ptraced(struct children_gdm_object *obj,
			  struct task_struct *child, int ptraced);
void hcc_set_child_exit_signal(struct children_gdm_object *obj,
			       struct task_struct *child);
void hcc_set_child_exit_state(struct children_gdm_object *obj,
			      struct task_struct *child);
void hcc_set_child_location(struct children_gdm_object *obj,
			    struct task_struct *child);
void hcc_remove_child(struct children_gdm_object *obj,
		      struct task_struct *child);
void hcc_forget_original_remote_parent(struct task_struct *parent,
				       struct task_struct *reaper);
pid_t hcc_get_real_parent_tgid(struct task_struct *task,
			       struct pid_namespace *ns);
pid_t hcc_get_real_parent_pid(struct task_struct *task);
int __hcc_get_parent(struct children_gdm_object *obj, pid_t pid,
		     pid_t *parent_pid, pid_t *real_parent_pid);
int hcc_get_parent(struct children_gdm_object *obj, struct task_struct *child,
		     pid_t *parent_pid, pid_t *real_parent_pid);
struct children_gdm_object *hcc_children_writelock(pid_t tgid);
struct children_gdm_object *__hcc_children_writelock(struct task_struct *task);
struct children_gdm_object *hcc_children_writelock_nested(pid_t tgid);
struct children_gdm_object *hcc_children_readlock(pid_t tgid);
struct children_gdm_object *__hcc_children_readlock(struct task_struct *task);
struct children_gdm_object *
hcc_parent_children_writelock(struct task_struct *task,
			      pid_t *parent_tgid);
struct children_gdm_object *
hcc_parent_children_readlock(struct task_struct *task,
			     pid_t *parent_tgid);
void hcc_children_unlock(struct children_gdm_object *obj);
void hcc_update_self_exec_id(struct task_struct *task);
u32 hcc_get_real_parent_self_exec_id(struct task_struct *task,
				     struct children_gdm_object *obj);

/* fork() hooks */
int hcc_children_prepare_fork(struct task_struct *task,
			      struct pid *pid,
			      unsigned long clone_flags);
int hcc_children_fork(struct task_struct *task,
		      struct pid *pid,
		      unsigned long clone_flags);
void hcc_children_commit_fork(struct task_struct *task);
void hcc_children_abort_fork(struct task_struct *task);

/* exit()/release_task() hooks */
void hcc_reparent_to_local_child_reaper(struct task_struct *task);
void hcc_children_cleanup(struct task_struct *task);

/* de_thread() hooks */
struct children_gdm_object *
hcc_children_prepare_de_thread(struct task_struct *task);
void hcc_children_finish_de_thread(struct children_gdm_object *obj,
				   struct task_struct *task);

/* Used by hcc_prepare_exit_notify() and hcc_delayed_notify_parent() */
void hcc_update_parents(struct task_struct *task,
			struct children_gdm_object *parent_children_obj,
			pid_t parent, pid_t real_parent,
			hcc_node_t node);
/* Used by hcc_release_task() */
void hcc_unhash_process(struct task_struct *tsk);

#endif /* CONFIG_HCC_GPM */

#endif /* __HCC_CHILDREN_H__ */
