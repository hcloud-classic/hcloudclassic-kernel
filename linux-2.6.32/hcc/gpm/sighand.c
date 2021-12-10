/*
 *  hcc/gpm/sighand.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/rwsem.h>
#include <linux/unique_id.h>
#include <hcc/signal.h>
#include <hcc/pid.h>
#include <hcc/task.h>
#include <hcc/application.h>
#include <hcc/app_shared.h>
#include <hcc/ghost.h>
#include <hcc/ghost_helpers.h>
#include <hcc/action.h>
#include <net/grpc/grpc.h>
#include <gdm/gdm.h>

struct sighand_struct_gdm_object {
	struct sighand_struct *sighand;
	atomic_t count;
	int keep_on_remove;
	struct rw_semaphore remove_sem;
};

static struct kmem_cache *sighand_struct_gdm_obj_cachep;

/* Kddm set of 'struct sighand_struct' location */
static struct gdm_set *sighand_struct_gdm_set = NULL;

/* unique_id for sighand gdm objects */
static unique_id_root_t sighand_struct_id_root;

static struct sighand_struct_gdm_object *sighand_struct_gdm_object_alloc(void)
{
	struct sighand_struct_gdm_object *obj;

	obj = kmem_cache_alloc(sighand_struct_gdm_obj_cachep, GFP_KERNEL);
	if (obj) {
		obj->sighand = NULL;
		obj->keep_on_remove = 0;
		init_rwsem(&obj->remove_sem);
	}
	return obj;
}

static struct sighand_struct *sighand_struct_alloc(void)
{
	return kmem_cache_alloc(sighand_cachep, GFP_KERNEL);
}

static void sighand_struct_attach_object(struct sighand_struct *sig,
					 struct sighand_struct_gdm_object *obj,
					 objid_t objid)
{
	sig->hcc_objid = objid;
	sig->gdm_obj = obj;
	obj->sighand = sig;
}

/*
 * @author Innogrid HCC
 */
static int sighand_struct_alloc_object(struct gdm_obj *obj_entry,
				       struct gdm_set *set, objid_t objid)
{
	struct sighand_struct_gdm_object *obj;
	struct sighand_struct *sig;

	obj = sighand_struct_gdm_object_alloc();
	if (!obj)
		return -ENOMEM;

	sig = sighand_struct_alloc();
	if (!sig) {
		kmem_cache_free(sighand_struct_gdm_obj_cachep, obj);
		return -ENOMEM;
	}

	sighand_struct_attach_object(sig, obj, objid);

	obj_entry->object = obj;

	return 0;
}

/*
 * @author Innogrid HCC
 */
static int sighand_struct_first_touch(struct gdm_obj *obj_entry,
				      struct gdm_set *set, objid_t objid,
				      int flags)
{
	struct sighand_struct_gdm_object *obj;

	obj = sighand_struct_gdm_object_alloc();
	if (!obj)
		return -ENOMEM;
	atomic_set(&obj->count, 1);

	obj_entry->object = obj;

	return 0;
}

/*
 * @author Innogrid HCC
 */
static int sighand_struct_import_object(struct grpc_desc *desc,
					struct gdm_set *set,
					struct gdm_obj *obj_entry,
					objid_t objid,
					int flags)
{
	struct sighand_struct_gdm_object *obj = obj_entry->object;
	struct sighand_struct *dest;
	struct sighand_struct *tmp;
	int retval;

	tmp = kmem_cache_alloc(sighand_cachep, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	retval = grpc_unpack_type(desc, tmp->count);
	if (likely(!retval))
		retval = grpc_unpack_type(desc, tmp->action);
	if (likely(!retval))
		retval = grpc_unpack_type(desc, obj->count);

	if (likely(!retval)) {
		dest = obj->sighand;
		spin_lock_irq(&dest->siglock);
		/* This is safe since all changes are protected by grab, and
		 * no thread can hold a grab during import */
		atomic_set(&dest->count, atomic_read(&tmp->count));
		memcpy(dest->action, tmp->action, sizeof(dest->action));
		spin_unlock_irq(&dest->siglock);
	}

	kmem_cache_free(sighand_cachep, tmp);

	return retval;
}

/*
 * @author Innogrid HCC
 */
static int sighand_struct_export_object(struct grpc_desc *desc,
					struct gdm_set *set,
					struct gdm_obj *obj_entry,
					objid_t objid,
					int flags)
{
	struct sighand_struct_gdm_object *obj = obj_entry->object;
	struct sighand_struct *src;
	int retval;

	src = obj->sighand;
	retval = grpc_pack_type(desc, src->count);
	if (likely(!retval))
		retval = grpc_pack_type(desc, src->action);
	if (likely(!retval))
		retval = grpc_pack_type(desc, obj->count);

	return retval;
}

void hcc_sighand_pin(struct sighand_struct *sig)
{
	struct sighand_struct_gdm_object *obj = sig->gdm_obj;
	BUG_ON(!obj);
	down_read(&obj->remove_sem);
}

void hcc_sighand_unpin(struct sighand_struct *sig)
{
	struct sighand_struct_gdm_object *obj = sig->gdm_obj;
	BUG_ON(!obj);
	up_read(&obj->remove_sem);
}

static int sighand_struct_remove_object(void *object,
					struct gdm_set *set, objid_t objid)
{
	struct sighand_struct_gdm_object *obj = object;

	/* Ensure that no thread uses this sighand_struct copy */
	down_write(&obj->remove_sem);
	up_write(&obj->remove_sem);

	if (!obj->keep_on_remove) {
		BUG_ON(waitqueue_active(&obj->sighand->signalfd_wqh));
		kmem_cache_free(sighand_cachep, obj->sighand);
	}
	kmem_cache_free(sighand_struct_gdm_obj_cachep, obj);

	return 0;
}

static struct iolinker_struct sighand_struct_io_linker = {
	.first_touch   = sighand_struct_first_touch,
	.linker_name   = "sigh ",
	.linker_id     = SIGHAND_STRUCT_LINKER,
	.alloc_object  = sighand_struct_alloc_object,
	.export_object = sighand_struct_export_object,
	.import_object = sighand_struct_import_object,
	.remove_object = sighand_struct_remove_object,
};

/*
 * Get and lock a sighand structure for a given process
 * @author Innogrid HCC
 */
struct sighand_struct *hcc_sighand_readlock(objid_t id)
{
	struct sighand_struct_gdm_object *obj;

	obj = _gdm_get_object_no_ft(sighand_struct_gdm_set, id);
	if (!obj) {
		_gdm_put_object(sighand_struct_gdm_set, id);
		return NULL;
	}
	BUG_ON(!obj->sighand);

	return obj->sighand;
}

/*
 * Grab and lock a sighand structure for a given process
 * @author Innogrid HCC
 */
struct sighand_struct *hcc_sighand_writelock(objid_t id)
{
	struct sighand_struct_gdm_object *obj;

	obj = _gdm_grab_object_no_ft(sighand_struct_gdm_set, id);
	if (!obj) {
		_gdm_put_object(sighand_struct_gdm_set, id);
		return NULL;
	}
	BUG_ON(!obj->sighand);

	return obj->sighand;
}

/*
 * unlock a sighand structure for a given process
 * @author Innogrid HCC
 */
void hcc_sighand_unlock(objid_t id)
{
	_gdm_put_object(sighand_struct_gdm_set, id);
}

static
struct sighand_struct_gdm_object *
____hcc_sighand_alloc(struct sighand_struct *sig)
{
	struct sighand_struct_gdm_object *obj;
	unique_id_t id;

	id = get_unique_id(&sighand_struct_id_root);

	/* Create the sighand object */
	obj = _gdm_grab_object(sighand_struct_gdm_set, id);
	BUG_ON(!obj);
	/* Must be a first touch */
	BUG_ON(obj->sighand);
	sighand_struct_attach_object(sig, obj, id);

	return obj;
}

/*
 * Alloc a dedicated sighand_struct to task_struct task.
 * @author Innogrid HCC
 */
static void __hcc_sighand_alloc(struct task_struct *task,
				struct sighand_struct *sig)
{
	struct sighand_struct_gdm_object *obj;

	/*
	 * Exclude kernel threads and local pids from using sighand_struct gdm
	 * objects.
	 */
	/*
	 * At this stage, task->mm may point to the mm of a
	 * task being duplicated instead of the mm of task for which this struct
	 * is being allocated, but we only need to know whether it is NULL or
	 * not, which will be the same after copy_mm.
	 */
	if (!task->nsproxy->hcc_ns
	    || !(task_pid_knr(task) & GLOBAL_PID_MASK)
	    || (task->flags & PF_KTHREAD)) {
		BUG_ON(hcc_current);
		sig->hcc_objid = 0;
		sig->gdm_obj = NULL;
		return;
	}

	obj = ____hcc_sighand_alloc(sig);
	BUG_ON(!obj);
	hcc_sighand_unlock(sig->hcc_objid);
}

void hcc_sighand_alloc(struct task_struct *task, unsigned long clone_flags)
{
	struct sighand_struct *sig = task->sighand;

	if (hcc_current && !in_hcc_do_fork())
		/*
		 * This is a process migration or restart: sighand_struct is
		 * already setup.
		 */
		return;

	if (!hcc_current && (clone_flags & CLONE_SIGHAND))
		/* New thread: already done in copy_sighand() */
		return;

	__hcc_sighand_alloc(task, sig);
}

void hcc_sighand_alloc_unshared(struct task_struct *task,
				struct sighand_struct *sig)
{
	__hcc_sighand_alloc(task, sig);
}

struct sighand_struct *cr_sighand_alloc(void)
{
	struct sighand_struct_gdm_object *obj;
	struct sighand_struct *sig;

	sig = sighand_struct_alloc();
	if (!sig)
		return NULL;

	obj = ____hcc_sighand_alloc(sig);
	BUG_ON(!obj);

	return sig;
}

void cr_sighand_free(objid_t id)
{
	_gdm_remove_frozen_object(sighand_struct_gdm_set, id);
}

/* Assumes that the associated gdm object is write locked. */
void hcc_sighand_share(struct task_struct *task)
{
	struct sighand_struct_gdm_object *obj = task->sighand->gdm_obj;
	int count;

	count = atomic_inc_return(&obj->count);
}

objid_t hcc_sighand_exit(struct sighand_struct *sig)
{
	struct sighand_struct_gdm_object *obj = sig->gdm_obj;
	objid_t id = sig->hcc_objid;
	int count;

	if (!obj)
		return 0;

	hcc_sighand_writelock(id);
	count = atomic_dec_return(&obj->count);
	if (count == 0) {
		hcc_sighand_unlock(id);
		BUG_ON(obj->keep_on_remove);
		/* Free the gdm object but keep the sighand_struct so that
		 * __exit_sighand releases it properly. */
		obj->keep_on_remove = 1;
		_gdm_remove_object(sighand_struct_gdm_set, id);

		return 0;
	}

	return id;
}

void hcc_sighand_cleanup(struct sighand_struct *sig)
{
	objid_t locked_id;

	locked_id = hcc_sighand_exit(sig);
	__cleanup_sighand(sig);
	if (locked_id)
		hcc_sighand_unlock(locked_id);
}

/* GPM actions */

static int cr_export_later_sighand_struct(struct gpm_action *action,
					  ghost_t *ghost,
					  struct task_struct *task)
{
	int r;
	long key;

	BUG_ON(action->type != GPM_CHECKPOINT);
	BUG_ON(action->checkpoint.shared != CR_SAVE_LATER);

	key = (long)(task->sighand);

	r = ghost_write(ghost, &key, sizeof(long));
	if (r)
		goto err;

	/*
	 * WARNING, currently we do not really support sighand shared by
	 * several nodes.
	 */
	r = add_to_shared_objects_list(task->application,
				       SIGHAND_STRUCT, key, LOCAL_ONLY,
				       task, NULL, 0);

	if (r == -ENOKEY) /* the sighand_struct was already in the list. */
		r = 0;
err:
	return r;
}

int export_sighand_struct(struct gpm_action *action,
			  ghost_t *ghost, struct task_struct *tsk)
{
	int r;

	if (action->type == GPM_CHECKPOINT
	    && action->checkpoint.shared == CR_SAVE_LATER) {
		r = cr_export_later_sighand_struct(action, ghost, tsk);
		return r;
	}

	r = ghost_write(ghost, &tsk->sighand->hcc_objid,
			sizeof(tsk->sighand->hcc_objid));
	if (r)
		goto err_write;

	if (action->type == GPM_CHECKPOINT)
		r = ghost_write(ghost,
				&tsk->sighand->action,
				sizeof(tsk->sighand->action));

err_write:
	return r;
}

static int cr_link_to_sighand_struct(struct gpm_action *action,
				     ghost_t *ghost,
				     struct task_struct *tsk)
{
	int r;
	long key;
	struct sighand_struct *sig;

	r = ghost_read(ghost, &key, sizeof(long));
	if (r)
		goto err;

	sig = get_imported_shared_object(action->restart.app,
					 SIGHAND_STRUCT, key);

	if (!sig) {
		r = -E_CR_BADDATA;
		goto err;
	}
	hcc_sighand_writelock(sig->hcc_objid);

	atomic_inc(&sig->count);
	tsk->sighand = sig;

	hcc_sighand_share(tsk);
	hcc_sighand_unlock(sig->hcc_objid);
err:
	return r;
}

int import_sighand_struct(struct gpm_action *action,
			  ghost_t *ghost, struct task_struct *tsk)
{
	unsigned long hcc_objid;
	int r;

	if (action->type == GPM_CHECKPOINT
	    && action->restart.shared == CR_LINK_ONLY) {
		r = cr_link_to_sighand_struct(action, ghost, tsk);
		return r;
	}

	r = ghost_read(ghost, &hcc_objid, sizeof(hcc_objid));
	if (r)
		goto err_read;

	switch (action->type) {
	case GPM_MIGRATE:
		tsk->sighand = hcc_sighand_writelock(hcc_objid);
		BUG_ON(!tsk->sighand);
		hcc_sighand_unlock(hcc_objid);
		break;
	case GPM_REMOTE_CLONE:
		/*
		 * The structure will be partly copied when creating the
		 * active process.
		 */
		tsk->sighand = hcc_sighand_readlock(hcc_objid);
		BUG_ON(!tsk->sighand);
		hcc_sighand_unlock(hcc_objid);
		break;
	case GPM_CHECKPOINT:
		tsk->sighand = cr_sighand_alloc();
		hcc_objid = tsk->sighand->hcc_objid;

		r = ghost_read(ghost,
			       &tsk->sighand->action,
			       sizeof(tsk->sighand->action));
		if (r) {
			cr_sighand_free(hcc_objid);
			goto err_read;
		}
		atomic_set(&tsk->sighand->count, 1);

		hcc_sighand_unlock(hcc_objid);
		break;
	default:
		PANIC("Case not supported: %d\n", action->type);
	}

err_read:
	return r;
}

void unimport_sighand_struct(struct task_struct *task)
{
}

static int cr_export_now_sighand_struct(struct gpm_action *action,
					ghost_t *ghost,
					struct task_struct *task,
					union export_args *args)
{
	int r;
	r = export_sighand_struct(action, ghost, task);
	if (r)
		ckpt_err(action, r,
			 "Fail to save struct sighand_struct "
			 "of process %d (%s)",
			 task_pid_knr(task), task->comm);
	return r;
}


static int cr_import_now_sighand_struct(struct gpm_action *action,
					ghost_t *ghost,
					struct task_struct *fake,
					int local_only,
					void **returned_data,
					size_t *data_size)
{
	int r;
	BUG_ON(*returned_data != NULL);

	r = import_sighand_struct(action, ghost, fake);
	if (r) {
		ckpt_err(action, r,
			 "App %d - Fail to restore a struct sighand_struct",
			 action->restart.app->app_id);
		goto err;
	}

	*returned_data = fake->sighand;
err:
	return r;
}

static int cr_import_complete_sighand_struct(struct task_struct *fake,
					     void *_sig)
{
	unsigned long sighand_id;
	struct sighand_struct *sig = _sig;
	sighand_id = hcc_sighand_exit(sig);
	if (sighand_id)
		hcc_sighand_unlock(sighand_id);

	BUG_ON(atomic_read(&sig->count) <= 1);
	__cleanup_sighand(sig);

	return 0;
}

static int cr_delete_sighand_struct(struct task_struct *fake, void *_sig)
{
	unsigned long sighand_id;
	struct sighand_struct *sig = _sig;
	sighand_id = hcc_sighand_exit(sig);
	if (sighand_id)
		hcc_sighand_unlock(sighand_id);

	BUG_ON(atomic_read(&sig->count) != 1);
	__cleanup_sighand(sig);

	return 0;
}

struct shared_object_operations cr_shared_sighand_struct_ops = {
	.export_now        = cr_export_now_sighand_struct,
	.export_user_info  = NULL,
	.import_now        = cr_import_now_sighand_struct,
	.import_complete   = cr_import_complete_sighand_struct,
	.delete            = cr_delete_sighand_struct,
};

int gpm_sighand_start(void)
{
	unsigned long cache_flags = SLAB_PANIC;

#ifdef CONFIG_DEBUG_SLAB
	cache_flags |= SLAB_POISON;
#endif
	sighand_struct_gdm_obj_cachep = KMEM_CACHE(sighand_struct_gdm_object,
						    cache_flags);

	/*
	 * Objid 0 is reserved to mark a sighand_struct having not been
	 * linked to a gdm object yet.
	 */
	init_and_set_unique_id_root(&sighand_struct_id_root, 1);

	register_io_linker(SIGHAND_STRUCT_LINKER, &sighand_struct_io_linker);

	sighand_struct_gdm_set =
		create_new_gdm_set(gdm_def_ns,
				    SIGHAND_STRUCT_GDM_ID,
				    SIGHAND_STRUCT_LINKER,
				    GDM_UNIQUE_ID_DEF_OWNER,
				    0, 0);
	if (IS_ERR(sighand_struct_gdm_set))
		OOM;

	return 0;
}

void gpm_sighand_exit(void)
{
}
