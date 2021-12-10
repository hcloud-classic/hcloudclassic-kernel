#ifndef __HCC_TASK_H__
#define __HCC_TASK_H__

#ifdef CONFIG_HCC_PROC

#include <linux/types.h>
#include <linux/rwsem.h>
#include <linux/kref.h>
#include <linux/rcupdate.h>
#include <hcc/sys/types.h>
#include <asm/cputime.h>

/** management of process than can or have migrated
 *  @author Innogrid HCC
 */

/* task gdm object */

struct task_struct;
struct pid;
#ifdef CONFIG_HCC_GPM
struct pid_gdm_object;
#endif

struct task_gdm_object {
	volatile long state;
	unsigned int flags;
	unsigned int ptrace;
	int exit_state;
	int exit_code, exit_signal;

	hcc_node_t node;
	u32 self_exec_id;
	int thread_group_empty;

	pid_t pid;
	pid_t parent;
	hcc_node_t parent_node;
	pid_t real_parent;
	pid_t real_parent_tgid;
	pid_t group_leader;

	uid_t uid;
	uid_t euid;
	gid_t egid;

	cputime_t utime, stime;

	unsigned int dumpable;

	/* The remaining fields are not shared */
#ifdef CONFIG_HCC_GPM
	struct pid_gdm_object *pid_obj;
#endif
	struct task_struct *task;

	struct rw_semaphore sem;
	int write_locked;

	int alive;
	struct kref kref;

	struct rcu_head rcu;
};

void hcc_task_get(struct task_gdm_object *obj);
void hcc_task_put(struct task_gdm_object *obj);
int hcc_task_alive(struct task_gdm_object *obj);
struct task_gdm_object *hcc_task_readlock(pid_t pid);
struct task_gdm_object *__hcc_task_readlock(struct task_struct *task);
struct task_gdm_object *hcc_task_create_writelock(pid_t pid);
struct task_gdm_object *hcc_task_writelock(pid_t pid);
struct task_gdm_object *__hcc_task_writelock(struct task_struct *task);
struct task_gdm_object *hcc_task_writelock_nested(pid_t pid);
struct task_gdm_object *__hcc_task_writelock_nested(struct task_struct *task);
void hcc_task_unlock(pid_t pid);
void __hcc_task_unlock(struct task_struct *task);
int hcc_task_alloc(struct task_struct *task, struct pid *pid);
void hcc_task_fill(struct task_struct *task, unsigned long clone_flags);
void hcc_task_commit(struct task_struct *task);
void hcc_task_abort(struct task_struct *task);
#ifdef CONFIG_HCC_GPM
void __hcc_task_free(struct task_struct *task);
#endif
void hcc_task_free(struct task_struct *task);

/* exit */
#ifdef CONFIG_HCC_GPM
int hcc_delay_release_task(struct task_struct *task);
#endif
void hcc_release_task(struct task_struct *task);

void __hcc_task_unlink(struct task_gdm_object *obj, int need_update);
void hcc_task_unlink(struct task_gdm_object *obj, int need_update);

#endif /* CONFIG_HCC_PROC */

#endif /* __HCC_TASK_H__ */
