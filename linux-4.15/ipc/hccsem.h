#ifndef __HHCC_SEM__
#define __HHCC_SEM__
#define sc_semmni       sem_ctls[3]

#define SEM_GLOBAL_LOCK (-1)

int sem_lock(struct sem_array *sma, struct sembuf *sops, int nsops);
struct sem_array *sem_obtain_object_check(struct ipc_namespace *ns, int id);
struct sem_array *sem_obtain_object(struct ipc_namespace *ns, int id);
void __exit_sem_found(struct sem_array *sma, struct sem_undo *un);
#endif
