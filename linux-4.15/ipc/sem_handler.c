/** 
 * HCC  modules ipc sem_handler.c
 * 
 * All the code for sharing IPC semaphore accross the cluster
 */

#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/sem.h>

#ifdef CONFIG_HCC_IPC
#include "sem_handler.h"
#include "util.h"
#include "semarray_io_linker.h"
#endif

struct semhccops {
    /*Semaphore operation struct*/
	struct hccipc_ops hcc_ops;
	/* unique_id generator for sem_undo_list identifier */
	unique_id_root_t undo_list_unique_id_root;
};


static struct kern_ipc_perm *hcc_ipc_sem_lock(struct ipc_ids *ids, int id)
{
	semarray_object_t *sem_object;
	struct sem_array *sma;
	int index ;

	rcu_read_lock();

	index = ipcid_to_idx(id);

	if (!sem_object)
		goto error;

	sma = sem_object->local_sem;

	BUG_ON(!sma);

	mutex_lock(&sma->sem_perm.mutex);

	if (sma->sem_perm.deleted) {
		mutex_unlock(&sma->sem_perm.mutex);
		goto error;
	}

	return &(sma->sem_perm);

error:
	rcu_read_unlock();

	return ERR_PTR(-EINVAL);
}

static void hcc_ipc_sem_unlock(struct kern_ipc_perm *ipcp)
{
	int index, deleted = 0;

	index = ipcid_to_idx(ipcp->id);

	if (ipcp->deleted)
		deleted = 1;

	if (!deleted)
		mutex_unlock(&ipcp->mutex);

	rcu_read_unlock();
}

int hcc_ipc_sem_newary(struct ipc_namespace *ns, struct sem_array *sma)
{
	semarray_object_t *sem_object;
	long *key_index;
	int index ;

	BUG_ON(!sem_ids(ns).hccops);

	index = ipcid_to_idx(sma->sem_perm.id);



	BUG_ON(sem_object);

	sem_object = kmem_cache_alloc(semarray_object_cachep, GFP_KERNEL);
	if (!sem_object)
		return -ENOMEM;

	sem_object->local_sem = sma;
	sem_object->mobile_sem_base = NULL;
	sem_object->imported_sem = *sma;

	/* there are no pending objects for the moment */
	BUG_ON(!list_empty(&sma->sem_pending));
	BUG_ON(!list_empty(&sma->remote_sem_pending));

	INIT_LIST_HEAD(&sem_object->imported_sem.list_id);
	INIT_LIST_HEAD(&sem_object->imported_sem.sem_pending);
	INIT_LIST_HEAD(&sem_object->imported_sem.remote_sem_pending);

	_kddm_set_object(sem_ids(ns).hccops->data_kddm_set, index, sem_object);

	if (sma->sem_perm.key != IPC_PRIVATE)
	{
		//Find key and set the value
	}


	sma->sem_perm.hccops = sem_ids(ns).hccops;

	return 0;
}




static struct kern_ipc_perm *kcb_ipc_sem_findkey(struct ipc_ids *ids, key_t key)
{
	long *key_index;

// Key intdex search
	// key_index = ;

	if (key_index)
		id = *key_index;

	if (id != -1)
		return hcc_ipc_sem_lock(ids, id);

	return NULL;
}