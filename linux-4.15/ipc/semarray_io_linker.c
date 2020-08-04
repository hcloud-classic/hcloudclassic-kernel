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



#define IN_WAKEUP 1

static inline void update_sem_queues(struct sem_array *sma,
				     struct sem_array *received_sma)
{
	struct sem_queue *q, *tq, *local_q;

	BUG_ON(!list_empty(&received_sma->sem_pending));

	list_for_each_entry_safe(q, tq, &received_sma->remote_sem_pending, list) {

		int is_local = 0;

		list_for_each_entry(local_q, &sma->sem_pending, list) {

			if (task_pid_knr(local_q->sleeper) == remote_sleeper_pid(q)) {
				is_local = 1;

				BUG_ON(q->undo && !local_q->undo);
				BUG_ON(local_q->undo && !q->undo);
				local_q->undo = q->undo;
				BUG_ON(q->status == IN_WAKEUP);
				BUG_ON(local_q->status != q->status);

				goto next;
			}
		}
	next:
		list_del(&q->list);
		if (is_local)
			free_semqueue(q);
		else
			list_add(&q->list, &sma->remote_sem_pending);
	}

	BUG_ON(!list_empty(&received_sma->remote_sem_pending));
}

static void update_local_sem(struct sem_array *local_sma,
			     struct sem_array *received_sma)
{
	int size_sems;

	size_sems = local_sma->sem_nsems * sizeof (struct sem);

	local_sma->sem_otime = received_sma->sem_otime;
	local_sma->sem_ctime = received_sma->sem_ctime;
	memcpy(local_sma->sem_base, received_sma->sem_base, size_sems);

	list_splice_init(&received_sma->list_id, &local_sma->list_id);

	update_sem_queues(local_sma, received_sma);
}

int semarray_alloc_object (struct gdm_obj * obj_entry,
			   struct gdm_set * set,
			   objid_t objid)
{
	semarray_object_t *sem_object;

	sem_object = kmem_cache_alloc(semarray_object_cachep, GFP_KERNEL);
	if (!sem_object)
		return -ENOMEM;

	sem_object->local_sem = NULL;
	sem_object->mobile_sem_base = NULL;
	obj_entry->object = sem_object;

	return 0;
}


int semarray_insert_object (struct gdm_obj * obj_entry,
			    struct gdm_set * set,
			    objid_t objid)
{
	semarray_object_t *sem_object;
	struct sem_array *sem;
	int r = 0;

	sem_object = obj_entry->object;
	BUG_ON(!sem_object);

	if (!sem_object->local_sem) {
		struct ipc_namespace *ns;

		ns = find_get_hcc_ipcns();
		BUG_ON(!ns);

		sem = create_local_sem(ns, &sem_object->imported_sem);
		sem_object->local_sem = sem;

		if (IS_ERR(sem)) {
			r = PTR_ERR(sem);
			BUG();
		}

		put_ipc_ns(ns);
	}

	if (!r)
		update_local_sem(sem_object->local_sem,
				 &sem_object->imported_sem);

	return r;
}


int semarray_invalidate_object (struct gdm_obj * obj_entry,
				struct gdm_set * set,
				objid_t objid)
{
	semarray_object_t *sem_object = obj_entry->object;
	struct sem_array *sma = sem_object->local_sem;
	struct sem_undo *un, *tu;
	struct sem_queue *q, *tq;
	BUG_ON(!list_empty(&sem_object->imported_sem.list_id));
	BUG_ON(!list_empty(&sem_object->imported_sem.sem_pending));
	BUG_ON(!list_empty(&sem_object->imported_sem.remote_sem_pending));
	list_for_each_entry_safe(un, tu, &sma->list_id, list_id) {
		list_del(&un->list_id);
		kfree(un);
	}
	list_for_each_entry_safe(q, tq, &sma->remote_sem_pending, list) {
		list_del(&q->list);
		free_semqueue(q);
	}
	return gdm_IO_KEEP_OBJECT;
}

int semarray_remove_object(void *object, struct gdm_set * set,
			   objid_t objid)
{
	semarray_object_t *sem_object;
	struct sem_array *sma;

	sem_object = object;
	if (sem_object) {
		struct ipc_namespace *ns;

		ns = find_get_hcc_ipcns();
		BUG_ON(!ns);

		sma = sem_object->local_sem;

		local_sem_lock(ns, sma->sem_perm.id);
		local_freeary(ns, &sma->sem_perm);

		kfree(sem_object->mobile_sem_base);
		sem_object->mobile_sem_base = NULL;
		kmem_cache_free(semarray_object_cachep, sem_object);

		put_ipc_ns(ns);
	}

	return 0;
}



static inline void __export_semarray(struct rpc_desc *desc,
				     const semarray_object_t *sem_object,
				     const struct sem_array* sma)
{
	rpc_pack(desc, 0, sma, sizeof(struct sem_array));
	rpc_pack(desc, 0, sma->sem_base, sma->sem_nsems * sizeof (struct sem));
}

static inline void __export_semundos(struct rpc_desc *desc,
				     const struct sem_array* sma)
{
	long nb_semundo = 0;
	struct sem_undo *un;

	list_for_each_entry(un, &sma->list_id, list_id)
		nb_semundo++;

	rpc_pack_type(desc, nb_semundo);

	list_for_each_entry(un, &sma->list_id, list_id) {
		BUG_ON(!list_empty(&un->list_proc));

		rpc_pack(desc, 0, un, sizeof(struct sem_undo) +
			 sma->sem_nsems * sizeof(short));
	}
}


static inline void __export_one_local_semqueue(struct rpc_desc *desc,
					       const struct sem_queue* q)
{
	struct sem_queue q2 = *q;
	q2.sleeper = (void*)((long)(task_pid_knr(q->sleeper)));
	rpc_pack_type(desc, q2);
	if (q->nsops)
		rpc_pack(desc, 0, q->sops,
			 q->nsops * sizeof(struct sembuf));

	if (q->undo) {
		BUG_ON(!list_empty(&q->undo->list_proc));
		rpc_pack_type(desc, q->undo->proc_list_id);
	}
}


static inline void __export_one_remote_semqueue(struct rpc_desc *desc,
						const struct sem_queue* q)
{
	rpc_pack(desc, 0, q, sizeof(struct sem_queue));
	if (q->nsops)
		rpc_pack(desc, 0, q->sops,
			 q->nsops * sizeof(struct sembuf));

	if (q->undo) {
		BUG_ON(!list_empty(&q->undo->list_proc));
		rpc_pack_type(desc, q->undo->proc_list_id);
	}
}