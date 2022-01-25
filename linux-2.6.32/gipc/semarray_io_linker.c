/*
 *  HCC/modules/ipc/semarray_io_linker.c
 *
 *  GDM SEM array Linker.
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/sem.h>
#include <linux/lockdep.h>
#include <linux/security.h>
#include <linux/ipc_namespace.h>
#include <linux/ipc.h>
#include <net/grpc/grpc.h>
#include <gdm/gdm.h>
#include <hcc/pid.h>

#include "gipc_handler.h"
#include "semarray_io_linker.h"
#include "util.h"
#include "hcc_sem.h"

struct kmem_cache *semarray_object_cachep;

/** Create a local instance of an remotly existing Semaphore.
 *
 *  @author Innogrid HCC
 */
static struct sem_array *create_local_sem(struct ipc_namespace *ns,
				   struct sem_array *received_sma)
{
	struct sem_array *sma;
	int size_sems;
	int retval;
	int i;

	size_sems = received_sma->sem_nsems * sizeof (struct sem);
	sma = ipc_rcu_alloc(sizeof (*sma) + size_sems);
	if (!sma) {
		return ERR_PTR(-ENOMEM);
	}
	*sma = *received_sma;

	sma->sem_base = (struct sem *) &sma[1];
	memcpy(sma->sem_base, received_sma->sem_base, size_sems);

	retval = security_sem_alloc(sma);
	if (retval) {
		ipc_rcu_putref(sma, ipc_rcu_free);
		goto out;
	}

	/*
	 * ipc_reserveid() locks msq
	 */
	retval = local_ipc_reserveid(&sem_ids(ns), &sma->sem_perm, ns->sc_semmni);
	if (retval) {
		ipc_rcu_putref(sma, sem_rcu_free);
		goto out;
	}

	for (i = 0; i < received_sma->sem_nsems; i++) {
		INIT_LIST_HEAD(&sma->sem_base[i].sem_pending);
		INIT_LIST_HEAD(&sma->sem_base[i].remote_sem_pending);
		spin_lock_init(&sma->sem_base[i].lock);
	}

	sma->complex_count = 0;
	INIT_LIST_HEAD(&sma->sem_pending);
	INIT_LIST_HEAD(&sma->list_id);
	INIT_LIST_HEAD(&sma->remote_sem_pending);

	sma->sem_perm.hcc_ops = sem_ids(ns).hcc_ops;
	sem_unlock(sma, -1);

	return sma;

out:
	return ERR_PTR(retval);
}

#define IN_WAKEUP 1

static inline void update_sem_queues(struct sem_array *sma,
				     struct sem_array *received_sma)
{
	struct sem_queue *q, *tq, *local_q;
	int i;

	BUG_ON(!list_empty(&received_sma->sem_pending));
	/* adding (to local sem) semqueues that are not local */
	list_for_each_entry_safe(q, tq, &received_sma->remote_sem_pending, list) {

		int is_local = 0;

		/* checking if the sem_queue is local */
		list_for_each_entry(local_q, &sma->sem_pending, list) {

			/* comparing local_q->pid to q->pid is not sufficient
			 *  as they contains only tgid, two or more threads
			 *  can be pending.
			 */
			if (task_pid_knr(local_q->sleeper) == remote_sleeper_pid(q)) {
				/* the sem_queue is local */
				is_local = 1;

				BUG_ON(q->undo && !local_q->undo);
				BUG_ON(local_q->undo && !q->undo);
				local_q->undo = q->undo;
				/* No need to update q->status, as it is done when
				   needed in handle_ipcsem_wake_up_process */
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

	/* sem_base */
	for (i = 0; i < received_sma->sem_nsems; i++) {
		BUG_ON(!list_empty(&received_sma->sem_base[i].sem_pending));
		/* adding (to local sem) semqueues that are not local */
		list_for_each_entry_safe(q, tq, &received_sma->sem_base[i].remote_sem_pending, list) {

			int is_local = 0;

			/* checking if the sem_queue is local */
			list_for_each_entry(local_q, &sma->sem_base[i].sem_pending, list) {

				/* comparing local_q->pid to q->pid is not sufficient
				*  as they contains only tgid, two or more threads
				*  can be pending.
				*/
				if (task_pid_knr(local_q->sleeper) == remote_sleeper_pid(q)) {
					/* the sem_queue is local */
					is_local = 1;

					BUG_ON(q->undo && !local_q->undo);
					BUG_ON(local_q->undo && !q->undo);
					local_q->undo = q->undo;
					/* No need to update q->status, as it is done when
					needed in handle_ipcsem_wake_up_process */
					BUG_ON(q->status == IN_WAKEUP);
					BUG_ON(local_q->status != q->status);

					goto sem_base_next;
				}
			}
		sem_base_next:
			list_del(&q->list);
			if (is_local)
				free_semqueue(q);
			else
				list_add(&q->list, &sma->sem_base[i].remote_sem_pending);
		}
		BUG_ON(!list_empty(&received_sma->sem_base[i].remote_sem_pending));
	}
}

/** Update a local instance of a remotly existing IPC semaphore.
 *
 *  @author Innogrid HCC
 */
static void update_local_sem(struct sem_array *local_sma,
			     struct sem_array *received_sma)
{
	int size_sems;

	size_sems = local_sma->sem_nsems * sizeof (struct sem);

	/* getting new values from received semaphore */
	local_sma->sem_otime = received_sma->sem_otime;
	local_sma->sem_ctime = received_sma->sem_ctime;
	local_sma->complex_count = received_sma->complex_count;
	memcpy(local_sma->sem_base, received_sma->sem_base, size_sems);

	/* updating sem_undos list */
	list_splice_init(&received_sma->list_id, &local_sma->list_id);

	/* updating semqueues list */
	update_sem_queues(local_sma, received_sma);
}

/*****************************************************************************/
/*                                                                           */
/*                         SEM Array GDM IO FUNCTIONS                       */
/*                                                                           */
/*****************************************************************************/

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



/** Handle a gdm set sem_array first touch
 *  @author Innogrid HCC
 *
 *  @param  obj_entry  Kddm object descriptor.
 *  @param  set       Kddm set descriptor
 *  @param  objid     Id of the object to create.
 *
 *  @return  0 if everything is ok. Negative value otherwise.
 */
int semarray_first_touch (struct gdm_obj * obj_entry,
			  struct gdm_set * set,
			  objid_t objid,
			  int flags)
{
	BUG(); // I should never get here !

	return 0;
}



/** Insert a new sem_array in local structures.
 *  @author Innogrid HCC
 *
 *  @param  obj_entry  Descriptor of the object to insert.
 *  @param  set       Kddm set descriptor
 *  @param  objid     Id of the object to insert.
 */
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

		ns = find_get_hcc_gipcns();
		BUG_ON(!ns);

		/* This is the first time the object is inserted locally.
		 * We need to allocate kernel sem_array structure.
		 */
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



/** Invalidate a gdm object semarray.
 *  @author Innogrid HCC
 *
 *  @param  obj_entry  Descriptor of the object to invalidate.
 *  @param  set       Kddm set descriptor
 *  @param  objid     Id of the object to invalidate
 */
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

	/* freeing the semundo list */
	list_for_each_entry_safe(un, tu, &sma->list_id, list_id) {
		list_del(&un->list_id);
		kfree(un);
	}

	/* freeing the remote semqueues */
	list_for_each_entry_safe(q, tq, &sma->remote_sem_pending, list) {
		list_del(&q->list);
		free_semqueue(q);
	}

	return GDM_IO_KEEP_OBJECT;
}

/** Handle a gdm semaphore remove.
 *  @author Innogrid HCC
 *
 *  @param  obj_entry  Descriptor of the object to remove.
 *  @param  set       Kddm set descriptor.
 *  @param  padeid    Id of the object to remove.
 */
int semarray_remove_object(void *object, struct gdm_set * set,
			   objid_t objid)
{
	semarray_object_t *sem_object;
	struct sem_array *sma;

	sem_object = object;
	if (sem_object) {
		struct ipc_namespace *ns;

		ns = find_get_hcc_gipcns();
		BUG_ON(!ns);

		sma = sem_object->local_sem;

		rcu_read_lock();
		sem_lock(sma, NULL, -1);
		/* sem_unlock() and rcu_read_ulock() will be called in local_freeary() */
		local_freeary(ns, &sma->sem_perm);

		kfree(sem_object->mobile_sem_base);
		sem_object->mobile_sem_base = NULL;
		kmem_cache_free(semarray_object_cachep, sem_object);

		put_ipc_ns(ns);
	}

	return 0;
}

static inline void __export_semarray(struct grpc_desc *desc,
				     const semarray_object_t *sem_object,
				     const struct sem_array* sma)
{
	grpc_pack(desc, 0, sma, sizeof(struct sem_array));
	grpc_pack(desc, 0, sma->sem_base, sma->sem_nsems * sizeof (struct sem));
}

static inline void __export_semundos(struct grpc_desc *desc,
				     const struct sem_array* sma)
{
	long nb_semundo = 0;
	struct sem_undo *un;

	list_for_each_entry(un, &sma->list_id, list_id)
		nb_semundo++;

	grpc_pack_type(desc, nb_semundo);

	list_for_each_entry(un, &sma->list_id, list_id) {
		BUG_ON(!list_empty(&un->list_proc));

		grpc_pack(desc, 0, un, sizeof(struct sem_undo) +
			 sma->sem_nsems * sizeof(short));
	}
}

static inline void __export_one_local_semqueue(struct grpc_desc *desc,
					       const struct sem_queue* q)
{
	/* Fill q2->sleeper with the pid (and not tgid) of q->sleeper
	   (needed to be thread aware) */
	struct sem_queue q2 = *q;

	/* Make remote_sleeper_pid(q2) equal to q->sleeper's pid */
	q2.sleeper = (void*)((long)(task_pid_knr(q->sleeper)));

	grpc_pack_type(desc, q2);
	if (q->nsops)
		grpc_pack(desc, 0, q->sops,
			 q->nsops * sizeof(struct sembuf));

	if (q->undo) {
		BUG_ON(!list_empty(&q->undo->list_proc));
		grpc_pack_type(desc, q->undo->proc_list_id);
	}
}

static inline void __export_one_remote_semqueue(struct grpc_desc *desc,
						const struct sem_queue* q)
{
	grpc_pack(desc, 0, q, sizeof(struct sem_queue));
	if (q->nsops)
		grpc_pack(desc, 0, q->sops,
			 q->nsops * sizeof(struct sembuf));

	if (q->undo) {
		BUG_ON(!list_empty(&q->undo->list_proc));
		grpc_pack_type(desc, q->undo->proc_list_id);
	}
}

static inline void __export_semqueues(struct grpc_desc *desc,
				      const struct sem_array* sma)
{
	struct sem_queue *q;
	long nb_sem_pending = 0;
	long nb_sem_base_pending;
	int i = 0;

	/* count local sem_pending */
	list_for_each_entry(q, &sma->sem_pending, list)
		nb_sem_pending++;

	/* count remote sem_pending */
	list_for_each_entry(q, &sma->remote_sem_pending, list)
		nb_sem_pending++;

	grpc_pack_type(desc, nb_sem_pending);

	/* send local sem_queues */
	list_for_each_entry(q, &sma->sem_pending, list)
		__export_one_local_semqueue(desc, q);

	/* send remote sem_queues */
	list_for_each_entry(q, &sma->remote_sem_pending, list)
		__export_one_remote_semqueue(desc, q);

	/* sem_base */
	for (i = 0; i < sma->sem_nsems; i++) {
		nb_sem_base_pending = 0;

		/* count local sem_pending */
		list_for_each_entry(q, &sma->sem_base[i].sem_pending, list)
			nb_sem_base_pending++;

		/* count remote sem_pending */
		list_for_each_entry(q, &sma->sem_base[i].remote_sem_pending, list)
			nb_sem_base_pending++;

		grpc_pack_type(desc, nb_sem_base_pending);

		/* send local sem_queues */
		list_for_each_entry(q, &sma->sem_base[i].sem_pending, list)
			__export_one_local_semqueue(desc, q);

		/* send remote sem_queues */
		list_for_each_entry(q, &sma->sem_base[i].remote_sem_pending, list)
			__export_one_remote_semqueue(desc, q);
	}
}

/** Export an object
 *  @author Innogrid HCC
 *
 *  @param  buffer    Buffer to export object data in.
 *  @param  object    The object to export data from.
 */
int semarray_export_object (struct grpc_desc *desc,
			    struct gdm_set *set,
			    struct gdm_obj *obj_entry,
			    objid_t objid,
			    int flags)
{
	semarray_object_t *sem_object;
	struct sem_array *sma;

	sem_object = obj_entry->object;
	sma = sem_object->local_sem;

	BUG_ON(!sma);

	__export_semarray(desc, sem_object, sma);
	__export_semundos(desc, sma);
	__export_semqueues(desc, sma);

	return 0;
}

static inline int __import_semarray(struct grpc_desc *desc,
				    semarray_object_t *sem_object)
{
	struct sem_array buffer;
	int size_sems;
	int i;

	grpc_unpack_type(desc, buffer);
	sem_object->imported_sem = buffer;

	size_sems = sem_object->imported_sem.sem_nsems * sizeof(struct sem);
	if (!sem_object->mobile_sem_base)
		sem_object->mobile_sem_base = kmalloc(size_sems, GFP_KERNEL);
	if (!sem_object->mobile_sem_base)
		return -ENOMEM;

	grpc_unpack(desc, 0, sem_object->mobile_sem_base, size_sems);
	sem_object->imported_sem.sem_base = sem_object->mobile_sem_base;

	for (i = 0; i < sem_object->imported_sem.sem_nsems; i++) {
		INIT_LIST_HEAD(&sem_object->imported_sem.sem_base[i].sem_pending);
		INIT_LIST_HEAD(&sem_object->imported_sem.sem_base[i].remote_sem_pending);
		spin_lock_init(&sem_object->imported_sem.sem_base[i].lock);
	}
	INIT_LIST_HEAD(&sem_object->imported_sem.sem_pending);
	INIT_LIST_HEAD(&sem_object->imported_sem.remote_sem_pending);
	INIT_LIST_HEAD(&sem_object->imported_sem.list_id);

	return 0;
}

static inline int __import_semundos(struct grpc_desc *desc,
				    struct sem_array *sma)
{
	struct sem_undo* undo;
	long nb_semundo, i;
	int size_undo;
	size_undo = sizeof(struct sem_undo) +
		sma->sem_nsems * sizeof(short);

	grpc_unpack_type(desc, nb_semundo);

	BUG_ON(!list_empty(&sma->list_id));

	for (i=0; i < nb_semundo; i++) {
		undo = kzalloc(size_undo, GFP_KERNEL);
		if (!undo)
			goto unalloc_undos;

		grpc_unpack(desc, 0, undo, size_undo);
		INIT_LIST_HEAD(&undo->list_id);
		INIT_LIST_HEAD(&undo->list_proc);

		undo->semadj = (short *) &undo[1];
		list_add(&undo->list_id, &sma->list_id);
	}

	return 0;

unalloc_undos:
	return -ENOMEM;
}

static inline void __unimport_semundos(struct sem_array *sma)
{
	struct sem_undo * un, *tu;

	list_for_each_entry_safe(un, tu, &sma->list_id, list_id) {
		list_del(&un->list_id);
		kfree(un);
	}
}

static inline int import_one_semqueue(struct grpc_desc *desc,
				      struct sem_array *sma, bool is_sem_base,
				      int sem_base_index)
{
	unique_id_t undo_proc_list_id;
	struct sem_undo* undo;
	int r = -ENOMEM;
	struct sem_queue *q = kmalloc(sizeof(struct sem_queue), GFP_KERNEL);
	if (!q)
		goto exit;

	grpc_unpack(desc, 0, q, sizeof(struct sem_queue));
	INIT_LIST_HEAD(&q->list);

	if (q->nsops) {
		q->sops = kzalloc(q->nsops * sizeof(struct sembuf),
				  GFP_KERNEL);
		if (!q->sops)
			goto unalloc_q;
		grpc_unpack(desc, 0, q->sops, q->nsops * sizeof(struct sembuf));
	}

	if (q->undo) {
		grpc_unpack_type(desc, undo_proc_list_id);

		list_for_each_entry(undo, &sma->list_id, list_id) {
			if (undo->proc_list_id == undo_proc_list_id) {
				q->undo = undo;
				goto undo_found;
			}
		}
	}

undo_found:
	r = 0;

	/* split between remote and local
	   queues is done in update_local_sem */
	if (is_sem_base)
		list_add(&q->list, &sma->sem_base[sem_base_index].remote_sem_pending);
	else
		list_add(&q->list, &sma->remote_sem_pending);

	BUG_ON(!q->sleeper);
	return r;

unalloc_q:
	kfree(q);

exit:
	return r;
}

static inline int __import_semqueues(struct grpc_desc *desc,
				     struct sem_array *sma)
{
	long nb_sem_pending;
	long nb_sem_base_pending;
	int i, j, r;

	r = grpc_unpack_type(desc, nb_sem_pending);
	if (r)
		goto err;

	BUG_ON(!list_empty(&sma->remote_sem_pending));

	for (i = 0; i < nb_sem_pending; i++) {
		r = import_one_semqueue(desc, sma, false, 0);
		if (r)
			goto err;
	}

#ifdef CONFIG_HCC_DEBUG
	{
		struct sem_queue *q;
		i = 0;
		list_for_each_entry(q, &sma->remote_sem_pending, list)
			i++;

		BUG_ON(nb_sem_pending != i);
	}
#endif

	/* sem_base */
	for (i = 0; i < sma->sem_nsems; i++) {
		r = grpc_unpack_type(desc, nb_sem_base_pending);
		if (r)
			goto err;

		BUG_ON(!list_empty(&sma->sem_base[i].remote_sem_pending));

		for (j = 0; j < nb_sem_base_pending; j++) {
			r = import_one_semqueue(desc, sma, true, i);
			if (r)
				goto err;
		}

#ifdef CONFIG_HCC_DEBUG
		{
			struct sem_queue *q;
			j = 0;
			list_for_each_entry(q, &sma->sem_base[i].remote_sem_pending, list)
				j++;

			BUG_ON(nb_sem_base_pending != j);
		}
#endif
	}

err:
	return r;
}

static inline void __unimport_semqueues(struct sem_array *sma)
{
	struct sem_queue *q, *tq;

	list_for_each_entry_safe(q, tq, &sma->remote_sem_pending, list) {
		list_del(&q->list);
		free_semqueue(q);
	}
}

/** Import an object
 *  @author Innogrid HCC
 *
 *  @param  object    The object to import data in.
 *  @param  buffer    Data to import in the object.
 */
int semarray_import_object (struct grpc_desc *desc,
			    struct gdm_set *set,
			    struct gdm_obj *obj_entry,
			    objid_t objid,
			    int flags)
{
	semarray_object_t *sem_object;
	int r = 0;
	sem_object = obj_entry->object;

	r = __import_semarray(desc, sem_object);
	if (r)
		goto err;

	r = __import_semundos(desc, &sem_object->imported_sem);
	if (r)
		goto unimport_semundos;

	r = __import_semqueues(desc, &sem_object->imported_sem);
	if (r)
		goto unimport_semqueues;

	goto err;

unimport_semqueues:
	__unimport_semqueues(&sem_object->imported_sem);

unimport_semundos:
	__unimport_semundos(&sem_object->imported_sem);

err:
	return r;
}

/****************************************************************************/

/* Init the semarray IO linker */
struct iolinker_struct semarray_linker = {
	first_touch:       semarray_first_touch,
	remove_object:     semarray_remove_object,
	invalidate_object: semarray_invalidate_object,
	insert_object:     semarray_insert_object,
	linker_name:       "semarray",
	linker_id:         SEMARRAY_LINKER,
	alloc_object:      semarray_alloc_object,
	export_object:     semarray_export_object,
	import_object:     semarray_import_object
};

/*****************************************************************************/
/*                                                                           */
/*                         SEMKEY GDM IO FUNCTIONS                          */
/*                                                                           */
/*****************************************************************************/

/* Init the sem key IO linker */
struct iolinker_struct semkey_linker = {
	linker_name:       "semkey",
	linker_id:         SEMKEY_LINKER,
};
