#ifndef __KHCC_SEM__
#define __KHCC_SEM__

#define sc_semmni       sem_ctls[3]

int hcc_gipc_sem_newary(struct ipc_namespace *ns, struct sem_array *sma, int nsems);

void hcc_gipc_sem_freeary(struct ipc_namespace *ns,
			 struct kern_ipc_perm *ipcp);

void hcc_gipc_sem_wakeup_process(struct sem_queue *q, int error);

int hcc_gipc_sem_copy_semundo(unsigned long clone_flags,
			     struct task_struct *tsk);

struct sem_undo *hcc_gipc_sem_find_undo(struct sem_array* sma);

void hcc_gipc_sem_exit_sem(struct ipc_namespace *ns, struct task_struct * tsk);

int newary(struct ipc_namespace *ns, struct ipc_params *params);

int sem_lock(struct sem_array *sma, struct sembuf *sops,
			      int nsops);

struct sem_array *sem_obtain_object(struct ipc_namespace *ns, int id);

struct sem_array *sem_obtain_object_check(struct ipc_namespace *ns,
							int id);

void sem_unlock(struct sem_array *sma, int locknum);

/* caller is responsible to call kfree(q->undo) before if needed */
static inline void free_semqueue(struct sem_queue *q)
{
	if (q->sops)
		kfree(q->sops);
	kfree(q);
}

void local_freeary(struct ipc_namespace *ns, struct kern_ipc_perm *ipcp);

void __exit_sem_found(struct sem_array *sma, struct sem_undo *un);

#endif
