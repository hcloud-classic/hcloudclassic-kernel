#include <linux/sem.h>
#include <linux/lockdep.h>
#include <linux/security.h>
#include <linux/ipc_namespace.h>
#include <linux/ipc.h>


struct kmem_cache *semarray_object_cachep;

struct sem_array *create_local_sem(struct ipc_namespace *ns,
				   struct sem_array *received_sma)
{
	struct sem_array *sma;
	int size_sems;
	int retval;

	size_sems = received_sma->sem_nsems * sizeof (struct sem);
	sma = ipc_rcu_alloc(sizeof (*sma) + size_sems);
	if (!sma) {
		return ERR_PTR(-ENOMEM);
	}
	*sma = *received_sma;

	sma->sem_base = (struct sem *) &sma[1];
	memcpy(sma->sem_base, received_sma->sem_base, size_sems);

	retval = security_sem_alloc(sma);
	if (retval)
		goto err_putref;

	retval = local_ipc_reserveid(&sem_ids(ns), &sma->sem_perm, ns->sc_semmni);
	if (retval)
		goto err_security_free;

	INIT_LIST_HEAD(&sma->sem_pending);
	INIT_LIST_HEAD(&sma->list_id);
	INIT_LIST_HEAD(&sma->remote_sem_pending);

	sma->sem_perm.hccops = sem_ids(ns).hccops;
	local_sem_unlock(sma);

	return sma;

err_security_free:
	security_sem_free(sma);
err_putref:
	ipc_rcu_putref(sma);
	return ERR_PTR(retval);
}
