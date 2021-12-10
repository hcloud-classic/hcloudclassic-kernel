/*
 *  hcc/gscheduler/global_lock.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/errno.h>
#include <linux/err.h>
#include <gdm/gdm.h>
#include <asm/system.h>

static struct gdm_set *lock_set;

#define ZERO_SIZE_LOCK_OBJECT	((void *) 0xe5e5e5e5)

/* Avoid using memory for 0-sized objects */
static int global_lock_alloc_object(struct gdm_obj *obj_entry,
				    struct gdm_set *set,
				    objid_t objid)
{
	obj_entry->object = ZERO_SIZE_LOCK_OBJECT;
	return 0;
}

/* Avoid a useless grpc_pack() ... */
static int global_lock_export_object(struct grpc_desc *desc,
				     struct gdm_set *set,
				     struct gdm_obj *obj_entry,
				     objid_t objid,
				     int flags)
{
	return 0;
}

/* ... and its useless grpc_unpack() counterpart */
static int global_lock_import_object(struct grpc_desc *desc,
				     struct gdm_set *set,
				     struct gdm_obj *obj_entry,
				     objid_t objid,
				     int flags)
{
	return 0;
}

/* Do not try kfree(ZERO_SIZE_LOCK_OBJECT) */
static int global_lock_remove_object(void *object,
				     struct gdm_set *set,
				     objid_t objid)
{
	return 0;
}

static struct iolinker_struct global_lock_io_linker = {
	.linker_name   = "global lock",
	.linker_id     = GLOBAL_LOCK_LINKER,
	.alloc_object  = global_lock_alloc_object,
	.export_object = global_lock_export_object,
	.import_object = global_lock_import_object,
	.remove_object = global_lock_remove_object
};

int global_lock_try_writelock(unsigned long lock_id)
{
	void *ret = _gdm_try_grab_object(lock_set, lock_id);
	int retval;

	if (likely(ret == ZERO_SIZE_LOCK_OBJECT))
		retval = 0;
	else if (likely(ret == ERR_PTR(-EBUSY)))
		retval = -EAGAIN;
	else if (!ret)
		retval = -ENOMEM;
	else
		retval = PTR_ERR(ret);

	return retval;
}

int global_lock_writelock(unsigned long lock_id)
{
	void *ret = _gdm_grab_object(lock_set, lock_id);
	int retval;

	if (likely(ret == ZERO_SIZE_LOCK_OBJECT))
		retval = 0;
	else if (!ret)
		retval = -ENOMEM;
	else
		retval = PTR_ERR(ret);

	return retval;
}

int global_lock_readlock(unsigned long lock_id)
{
	void *ret = _gdm_get_object(lock_set, lock_id);
	int retval;

	if (likely(ret == ZERO_SIZE_LOCK_OBJECT))
		retval = 0;
	else if (!ret)
		retval = -ENOMEM;
	else
		retval = PTR_ERR(ret);

	return retval;
}

void global_lock_unlock(unsigned long lock_id)
{
	_gdm_put_object(lock_set, lock_id);
}

int global_lock_start(void)
{
	register_io_linker(GLOBAL_LOCK_LINKER, &global_lock_io_linker);

	lock_set = create_new_gdm_set(gdm_def_ns, GLOBAL_LOCK_GDM_SET_ID,
				       GLOBAL_LOCK_LINKER,
				       GDM_RR_DEF_OWNER,
				       0, GDM_LOCAL_EXCLUSIVE);
	BUG_ON(!lock_set);
	if (IS_ERR(lock_set))
		return PTR_ERR(lock_set);

	return 0;
}

void global_lock_exit(void)
{
}
