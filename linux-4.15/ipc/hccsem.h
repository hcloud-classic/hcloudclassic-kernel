#ifndef __HHCC_SEM__
#define __HHCC_SEM__
#define sc_semmni       sem_ctls[3]

#define SEM_GLOBAL_LOCK (-1)

int sem_lock(struct sem_array *sma, struct sembuf *sops, int nsops);
struct sem_array *sem_obtain_object_check(struct ipc_namespace *ns, int id);
struct sem_array *sem_obtain_object(struct ipc_namespace *ns, int id);
void __exit_sem_found(struct sem_array *sma, struct sem_undo *un);

static inline struct sem_array *local_sem_lock(struct ipc_namespace *ns, int id)
{
	struct kern_ipc_perm *ipcp = local_ipc_lock(&sem_ids(ns), id);

	if (IS_ERR(ipcp))
		return (struct sem_array *)ipcp;

	return container_of(ipcp, struct sem_array, sem_perm);
}

static inline void sem_unlock(struct sem_array *sma, int locknum)
{
	if (locknum == SEM_GLOBAL_LOCK)
	{
		unmerge_queues(sma);
		complexmode_tryleave(sma);
		ipc_unlock_object(&sma->sem_perm);
	}
	else
	{
		struct sem *sem = &sma->sems[locknum];
		spin_unlock(&sem->lock);
	}
}

static inline void local_sem_unlock(struct sem_array *sma)
{
	local_ipc_unlock(&(sma)->sem_perm);
}

#endif
