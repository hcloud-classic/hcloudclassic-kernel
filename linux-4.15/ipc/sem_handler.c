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
// for hcc namespace
#include <hcc/namespace.h>
#endif

struct semhccops {
    /*Semaphore operation struct*/
	struct hccipc_ops hcc_ops;
	/* unique_id generator for sem_undo_list identifier */
	unique_id_root_t undo_list_unique_id_root;
};

// remote sem wake up info and msg
struct ipcsem_wakeup_msg {
	kerrighed_node_t requester;
	int sem_id;
	pid_t pid;
	int error;
};

static struct hcc_namespace *hcc_ns;
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


void handle_ipcsem_wakeup_process(struct rpc_desc *desc, void *_msg,
				  size_t size)
{
	struct ipcsem_wakeup_msg *msg = _msg;
	struct sem_array *sma;
	struct sem_queue *q, *tq;
	struct ipc_namespace *ns;


	struct hcc_namespace *ns;

	rcu_read_lock();
	ns = rcu_dereference(hcc_ns);
	if (ns)
		if (!atomic_add_unless(&ns->count, 1, 0))
			ns = NULL;
	rcu_read_unlock();
	BUG_ON(!ns);

// sma local lock implemention
// sma= xxx
	BUG_ON(IS_ERR(sma));

	list_for_each_entry_safe(q, tq, &sma->sem_pending, list) {
		/* compare to q->sleeper's pid instead of q->pid
		   because q->pid == q->sleeper's tgid */
		if (task_pid_knr(q->sleeper) == msg->pid) {
			list_del(&q->list);
			goto found;
		}
	}

	BUG();
found:
	q->status = 1; /* IN_WAKEUP; */

	BUG_ON(!q->sleeper);
	BUG_ON(q->pid != task_tgid_nr_ns(q->sleeper,
					 task_active_pid_ns(q->sleeper)));

	wake_up_process(q->sleeper);
	smp_wmb();
	q->status = msg->error;

	local_sem_unlock(sma);

	rpc_pack_type(desc, msg->error);

	put_ipc_ns(ns);
}