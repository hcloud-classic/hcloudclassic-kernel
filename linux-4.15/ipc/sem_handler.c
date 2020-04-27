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
#include "hccsem.h"
#endif

struct semhccops {
    /*Semaphore operation struct*/
	struct hccipc_ops hcc_ops;
	/* unique_id generator for sem_undo_list identifier */
	unique_id_root_t undo_list_unique_id_root;
};

// remote sem wake up info and msg
struct ipcsem_wakeup_msg {
	hcc_node_t requster;
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
static inline struct semundo_list_object * __create_semundo_proc_list(
	struct task_struct *task)
{
	unique_id_t undo_list_id;
	struct semundo_list_object *undo_list;
	struct ipc_namespace *ns;
	struct semhccops *semops;

	ns = task_nsproxy(task)->ipc_ns;
	if (!sem_ids(ns).hccops)
		return ERR_PTR(-EINVAL);

	semops = container_of(sem_ids(ns).hccops, struct semhccops, hccops);

	/* get a random id */
	undo_list_id = get_unique_id(&semops->undo_list_unique_id_root);


	BUG_ON(undo_list);

	undo_list = kzalloc(sizeof(struct semundo_list_object), GFP_KERNEL);
	if (!undo_list) {
		undo_list = ERR_PTR(-ENOMEM);
		goto err_alloc;
	}

	undo_list->id = undo_list_id;
	atomic_inc(&undo_list->refcnt);


	task->sysvsem.undo_list_id = undo_list_id;
exit:
	return undo_list;

err_alloc:
	goto exit;
}

int create_semundo_proc_list(struct task_struct *task)
{
	int r = 0;
	struct semundo_list_object *undo_list;

	BUG_ON(task->sysvsem.undo_list_id != UNIQUE_ID_NONE);

	undo_list_set = task_undolist_set(task);
	if (IS_ERR(undo_list_set)) {
		undo_list = ERR_PTR(PTR_ERR(undo_list_set));
		goto err;
	}

	undo_list = __create_semundo_proc_list(task);

	if (IS_ERR(undo_list)) {
		r = PTR_ERR(undo_list);
		goto err;
	}

	BUG_ON(atomic_read(&undo_list->refcnt) != 1);

err:
	return r;
}

static int __share_new_semundo(struct task_struct *task)
{
	int r = 0;
	struct semundo_list_object *undo_list;

	BUG_ON(current);
	BUG_ON(current->sysvsem.undo_list_id != UNIQUE_ID_NONE);

	undo_list_set = task_undolist_set(task);
	if (IS_ERR(undo_list_set)) {
		r = PTR_ERR(undo_list_set);
		goto exit;
	}

	undo_list = __create_semundo_proc_list(current);

	if (IS_ERR(undo_list)) {
		r = PTR_ERR(undo_list);
		goto exit;
	}

	task->sysvsem.undo_list_id = current->sysvsem.undo_list_id;
	atomic_inc(&undo_list->refcnt);

	BUG_ON(atomic_read(&undo_list->refcnt) != 2);

exit:
	return r;
}

int share_existing_semundo_proc_list(struct task_struct *task,
				     unique_id_t undo_list_id)
{
	int r = 0;
	struct semundo_list_object *undo_list;

	undo_list_set = task_undolist_set(task);
	if (IS_ERR(undo_list_set)) {
		r = PTR_ERR(undo_list_set);
		goto exit;
	}

	BUG_ON(undo_list_id == UNIQUE_ID_NONE);

// Undo list get function implementation
	// undo_list = 

	if (!undo_list) {
		r = -ENOMEM;
		goto exit_put;
	}

	task->sysvsem.undo_list_id = undo_list_id;
	atomic_inc(&undo_list->refcnt);

exit_put:
	return 0;
exit:
	return r;
}


int share_existing_semundo_proc_list(struct task_struct *task,
				     unique_id_t undo_list_id)
{
	int r = 0;
	struct semundo_list_object *undo_list;

	undo_list = task_undolist_set(task);

	BUG_ON(undo_list_id == UNIQUE_ID_NONE);

	if (!undo_list) {
		r = -ENOMEM;
		goto exit;
	}

	task->sysvsem.undo_list_id = undo_list_id;
	atomic_inc(&undo_list->refcnt);


exit:
	return r;
}

int hcc_ipc_sem_copy_semundo(unsigned long clone_flags,
			     struct task_struct *tsk)
{
	int r = 0;

	BUG_ON(!tsk);

	if (clone_flags & CLONE_SYSVSEM) {
		if (current->sysvsem.undo_list) {
			printk("ERROR: Do not support fork of process (%d - %s)"
			       "that had used semaphore before Hcloud-Classic was "
			       "started\n", tsk->tgid, tsk->comm);
			r = -EPERM;
			goto exit;
		}

		if (current->sysvsem.undo_list_id != UNIQUE_ID_NONE)
			r = share_existing_semundo_proc_list(
				tsk, current->sysvsem.undo_list_id);
		else
			r = __share_new_semundo(tsk);

	} else
		/* undolist will be only created when needed */
		tsk->sysvsem.undo_list_id = UNIQUE_ID_NONE;

	tsk->sysvsem.undo_list = NULL;

exit:
	return r;
}


int add_semundo_to_proc_list(struct semundo_list_object *undo_list, int semid)
{
	struct semundo_id *undo_id;
	int r = 0;
	BUG_ON(!undo_list);

#ifdef CONFIG_HCC_DEBUG
	/* WARNING: this is a paranoiac checking */
	for (undo_id = undo_list->list; undo_id; undo_id = undo_id->next) {
		if (undo_id->semid == semid) {
			printk("%p %p %d %d\n", undo_id,
			       undo_list, semid,
			       atomic_read(&undo_list->semcnt));
			BUG();
		}
	}
#endif

	undo_id = kmalloc(sizeof(struct semundo_id), GFP_KERNEL);
	if (!undo_id) {
		r = -ENOMEM;
		goto exit;
	}

	atomic_inc(&undo_list->semcnt);
	undo_id->semid = semid;
	undo_id->next = undo_list->list;
	undo_list->list = undo_id;
exit:
	return r;
}


struct sem_undo * hcc_ipc_sem_find_undo(struct sem_array* sma)
{
	struct sem_undo * undo;
	int r = 0;
	struct semundo_list_object *undo_list = NULL;
	unique_id_t undo_list_id;


	if (current->sysvsem.undo_list_id == UNIQUE_ID_NONE) {

		/* create a undolist if not yet allocated */

		if (IS_ERR(undo_list)) {
			undo = ERR_PTR(PTR_ERR(undo_list));
			goto exit;
		}

		BUG_ON(atomic_read(&undo_list->semcnt) != 0);

	} else {
		/* check in the undo list of the sma */
		list_for_each_entry(undo, &sma->list_id, list_id) {
			if (undo->proc_list_id ==
			    current->sysvsem.undo_list_id) {
				goto exit;
			}
		}
	}

	undo_list_id = current->sysvsem.undo_list_id;

	/* allocate one */
	undo = kzalloc(sizeof(struct sem_undo) +
		       sizeof(short)*(sma->sem_nsems), GFP_KERNEL);
	if (!undo) {
		undo = ERR_PTR(-ENOMEM);
		goto exit;
	}

	INIT_LIST_HEAD(&undo->list_proc);
	undo->proc_list_id = undo_list_id;
	undo->semid = sma->sem_perm.id;
	undo->semadj = (short *) &undo[1];

	list_add(&undo->list_id, &sma->list_id);

	/* reference it in the undo_list per process*/
	BUG_ON(undo_list_id == UNIQUE_ID_NONE);

	if (!undo_list) {
		r = -ENOMEM;
		goto exit_free_undo;
	}

	r = add_semundo_to_proc_list(undo_list, undo->semid);

exit_free_undo:
	if (r) {
		list_del(&undo->list_id);
		kfree(undo);
		undo = ERR_PTR(r);
	}

exit:
	return undo;
}

static inline void __remove_semundo_from_sem_list(struct ipc_namespace *ns,
						  int semid,
						  unique_id_t undo_list_id)
{
	struct sem_array *sma;
	struct sem_undo *un, *tu;

	sma = sem_obtain_object(ns, semid);
	sem_lock(sma,NULL,-1);
	if (IS_ERR(sma))
		return;

	list_for_each_entry_safe(un, tu, &sma->list_id, list_id) {
		if (un->proc_list_id == undo_list_id) {
			list_del(&un->list_id);
			__exit_sem_found(sma, un);

			kfree(un);
			goto exit_unlock;
		}
	}
	BUG();

exit_unlock:
	sem_unlock(sma);
}

void hcc_ipc_sem_wakeup_process(struct sem_queue *q, int error)
{
	struct ipcsem_wakeup_msg msg;
	struct rpc_desc *desc;

	msg.requester = hcc_node_id;
	msg.sem_id = q->semid;
	msg.pid = remote_sleeper_pid(q); /* q->pid contains the tgid */
	msg.error = error;

	/*RPC Type check, Packing, Unpacking implementation */
}


void hcc_ipc_sem_exit_sem(struct ipc_namespace *ns,
			  struct task_struct * task)
{
	unique_id_t undo_list_id;
	struct semundo_list_object * undo_list;
	struct semundo_id * undo_id, *next;

	if (task->sysvsem.undo_list_id == UNIQUE_ID_NONE)
		return;


	undo_list_id = task->sysvsem.undo_list_id;

	if (!atomic_dec_and_test(&undo_list->refcnt))
		return;
	for (undo_id = undo_list->list; undo_id; undo_id = next) {
		next = undo_id->next;
		__remove_semundo_from_sem_list(ns, undo_id->semid,
					       undo_list_id);
		kfree(undo_id);
	}
	undo_list->list = NULL;
	atomic_set(&undo_list->semcnt, 0);


	return;


}

void hcc_ipc_shm_destroy(struct ipc_namespace *ns, struct shmid_kernel *shp)
{
	struct kddm_set *mm_set;
	int index;
	key_t key;

	index = ipcid_to_idx(shp->shm_perm.id);
	key = shp->shm_perm.key;

	mm_set = shp->shm_file->f_dentry->d_inode->i_mapping->kddm_set;

	if (key != IPC_PRIVATE) {
		_grab_object_no_ft(shm_ids(ns).hccops->key_set, key);
		_remove_frozen_object(shm_ids(ns).hccops->key_set, key);
	}

	local_shm_unlock(shp);

	_remove_frozen_object(shm_ids(ns).hccops->data_set, index);
	_destroy_set(mm_set);

	hcc_ipc_rmid(&shm_ids(ns), index);
}





/*****************************************************************************/
/*                                                                           */
/*                              INITIALIZATION                               */
/*                                                                           */
/*****************************************************************************/
void sem_handler_init (void)
{
	semarray_object_cachep = kmem_cache_create("semarray_object",
						   sizeof(semarray_object_t),
						   0, SLAB_PANIC, NULL);

	register_io_linker(SEMARRAY_LINKER, &semarray_linker);
	register_io_linker(SEMKEY_LINKER, &semkey_linker);
	register_io_linker(SEMUNDO_LINKER, &semundo_linker);

	rpc_register_void(IPC_SEM_WAKEUP, handle_ipcsem_wakeup_process, 0);
}
