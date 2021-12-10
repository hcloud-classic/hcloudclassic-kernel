/** Management of GDM objects.
 *  @file object.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/proc_fs.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/module.h>

#include <gdm/gdm.h>
#include <net/grpc/grpcid.h>
#include <net/grpc/grpc.h>
#include <gdm/object_server.h>
#include <gdm/object.h>
#include <gdm/io_linker.h>

atomic_t nr_master_objects = ATOMIC_INIT(0);
atomic_t nr_copy_objects = ATOMIC_INIT(0);
atomic_t nr_OBJ_STATE[NB_OBJ_STATE];

#define STATE_DEF(state) [OBJ_STATE_INDEX(state)] = #state

const char *state_name[NB_OBJ_STATE] = {
	STATE_DEF(INV_COPY),
	STATE_DEF(READ_COPY),
	STATE_DEF(INV_OWNER),
	STATE_DEF(READ_OWNER),
	STATE_DEF(WRITE_OWNER),
	STATE_DEF(WRITE_GHOST),
	STATE_DEF(WAIT_ACK_INV),
	STATE_DEF(WAIT_ACK_WRITE),
	STATE_DEF(WAIT_CHG_OWN_ACK),
	STATE_DEF(WAIT_OBJ_READ),
	STATE_DEF(WAIT_OBJ_WRITE),
	STATE_DEF(WAIT_OBJ_RM_DONE),
	STATE_DEF(WAIT_OBJ_RM_ACK),
	STATE_DEF(WAIT_OBJ_RM_ACK2),
	STATE_DEF(INV_FILLING),
};
EXPORT_SYMBOL(state_name);

struct kmem_cache *gdm_obj_cachep;



/** Init an object state.
 *  @author Innogrid HCC
 *
 *  @param obj_entry  Entry of the object to set the state.
 *  @param state      State to set the object with.
 */
static inline void set_object_state(struct gdm_set * set,
				    struct gdm_obj * obj_entry,
				    gdm_obj_state_t state)
{
	INC_STATE_COUNTER(state);

	obj_entry->flags = state |
		(obj_entry->flags & ~OBJECT_STATE_MASK);

	if (I_AM_OWNER(obj_entry)) {
		atomic_inc (&nr_master_objects);
		atomic_inc (&set->nr_masters);
	} else {
		atomic_inc (&nr_copy_objects);
		atomic_inc (&set->nr_copies);
	}
}



/** Modify an object dsm state.
 *  @author Innogrid HCC
 *
 *  @param obj_entry   Entry of the object to modify the dsm state.
 *  @param new_state   New state to set the object with.
 */
static void change_object_state (struct gdm_set *set,
				 struct gdm_obj * obj_entry,
				 objid_t objid,
				 gdm_obj_state_t new_state)
{
	DEC_STATE_COUNTER (OBJ_STATE(obj_entry));
	INC_STATE_COUNTER (new_state);

	if (I_AM_OWNER (obj_entry)) {
		atomic_dec(&nr_master_objects);
		atomic_dec(&set->nr_masters);
	}
	else {
		atomic_dec(&nr_copy_objects);
		atomic_dec(&set->nr_copies);
	}

	obj_entry->flags = new_state |
		(obj_entry->flags & ~OBJECT_STATE_MASK);

	if (I_AM_OWNER (obj_entry)) {
		atomic_inc(&nr_master_objects);
		atomic_inc(&set->nr_masters);
	}
	else {
		atomic_inc(&nr_copy_objects);
		atomic_inc(&set->nr_copies);
	}

	if (new_state & GDM_OWNER_OBJ)
		change_prob_owner(obj_entry, hcc_node_id);
}



/** Change an object state.
 *  @author Innogrid HCC
 *
 *  @param set        gdm set the object is hosted by.
 *  @param obj_entry  Entry of the object to change the state.
 *  @param objid      Id of the object to change the state.
 *  @param state      State to set the object with.
 */
void gdm_change_obj_state(struct gdm_set * set,
			   struct gdm_obj *obj_entry,
			   objid_t objid,
			   gdm_obj_state_t newState)
{
	if (!obj_entry)
		return;

	if (OBJ_STATE(obj_entry) != newState) {
		change_object_state(set, obj_entry, objid, newState);

		gdm_io_change_state(obj_entry, set, objid, newState);
	}
}



/** Alloc and init a gdm object.
 *  @author Innogrid HCC
 *
 *  @param set     Set to allocate the object in.
 *  @param objid   Id of the object to allocate.
 *
 *  @return  The newly allocated object.
 */
struct gdm_obj *alloc_gdm_obj_entry(struct gdm_set *set,
				      objid_t objid)
{
	struct gdm_obj * obj_entry ;

	obj_entry = kmem_cache_alloc(gdm_obj_cachep, GFP_KERNEL);
	if (obj_entry == NULL) {
		OOM;
		return NULL;
	}

	obj_entry->flags = 0;
	obj_entry->object = NULL;
	atomic_set(&obj_entry->count, 1);

	BUG_ON(set->def_owner < 0 ||
	       set->def_owner > GDM_MAX_DEF_OWNER);

	change_prob_owner(obj_entry, gdm_io_default_owner(set, objid));

	if (get_prob_owner(obj_entry) == hcc_node_id)
		set_object_state(set, obj_entry, INV_OWNER);
	else
		set_object_state(set, obj_entry, INV_COPY);

	atomic_set(&obj_entry->frozen_count, 0);
	atomic_set(&obj_entry->sleeper_count, 0);

	atomic_inc (&set->nr_entries);

	CLEAR_SET(COPYSET(obj_entry));
	CLEAR_SET(RMSET(obj_entry));

	init_waitqueue_head(&obj_entry->waiting_tsk);

	return obj_entry;
}

struct gdm_obj *dup_gdm_obj_entry(struct gdm_obj *src_obj)
{
	struct gdm_obj * obj_entry;

	BUG_ON(atomic_read(&src_obj->frozen_count) != 0);

	obj_entry = kmem_cache_alloc(gdm_obj_cachep, GFP_ATOMIC);
	if (obj_entry == NULL) {
		OOM;
		return NULL;
	}

	*obj_entry = *src_obj;

	atomic_set(&obj_entry->count, 1);
	CLEAR_OBJECT_PINNED(obj_entry);
	atomic_set(&obj_entry->sleeper_count, 0);
	init_waitqueue_head(&obj_entry->waiting_tsk);

	return obj_entry;
}

/** Remove a local object frame from a gdm set
 */
void free_gdm_obj_entry(struct gdm_set *set,
			 struct gdm_obj *obj_entry,
			 objid_t objid)
{
	BUG_ON(atomic_read(&obj_entry->frozen_count) != 0);
	BUG_ON(obj_entry_count(obj_entry) != 0);
	BUG_ON(TEST_OBJECT_LOCKED(obj_entry));

	/* Ask the IO linker to remove the object */
	if (obj_entry->object != NULL)
		gdm_io_remove_object(obj_entry->object, set, objid);

	atomic_dec(&set->nr_entries);

	kmem_cache_free(gdm_obj_cachep, obj_entry);
}



/*** Remove an object entry from a gdm set object table. ***/

int destroy_gdm_obj_entry (struct gdm_set *set,
			    struct gdm_obj *obj_entry,
			    objid_t objid,
			    int cluster_wide_remove)
{
	hcc_node_t default_owner = gdm_io_default_owner(set, objid);
	BUG_ON (object_frozen(obj_entry, set));

	ASSERT_OBJ_PATH_LOCKED(set, objid);

	/* Check if we are in a flush case i.e. cluster_wide_remove == 0
	 * or if we have a pending request on the object. In both cases, can
	 * cannot remove the object entry.
	 */
	if ((!cluster_wide_remove) ||
	    atomic_read (&obj_entry->sleeper_count)) {

		if (cluster_wide_remove && (default_owner == hcc_node_id))
			gdm_change_obj_state(set, obj_entry, objid, INV_OWNER);
		else {
			gdm_change_obj_state(set, obj_entry, objid, INV_COPY);
			if (cluster_wide_remove)
				change_prob_owner(obj_entry, default_owner);
		}

		wake_up (&obj_entry->waiting_tsk);
		gdm_io_remove_object_and_unlock (obj_entry, set, objid);
		goto exit;
	}

	if (I_AM_OWNER(obj_entry)) {
		atomic_dec(&nr_master_objects);
		atomic_dec(&set->nr_masters);
	} else {
		atomic_dec(&nr_copy_objects);
		atomic_dec(&set->nr_copies);
	}

	set->ops->remove_obj_entry(set, objid);

	put_gdm_obj_entry(set, obj_entry, objid);

	put_obj_entry_count(set, obj_entry, objid);
exit:
	return 0;
}



/*** Get an object entry from a gdm set. ***/

struct gdm_obj *__get_gdm_obj_entry (struct gdm_set *set,
				       objid_t objid)
{
	struct gdm_obj *obj_entry;

retry:
	gdm_obj_path_lock(set, objid);

	obj_entry = set->ops->lookup_obj_entry(set, objid);
	if (obj_entry) {
		if (TEST_AND_SET_OBJECT_LOCKED (obj_entry)) {
			gdm_obj_path_unlock (set, objid);
			while (TEST_OBJECT_LOCKED (obj_entry))
				cpu_relax();
			goto retry;
		}
	}
	else
		gdm_obj_path_unlock(set, objid);

	return obj_entry;
}



/*** Get or alloc an object entry from a gdm set. ***/

struct gdm_obj *__get_alloc_gdm_obj_entry (struct gdm_set *set,
					     objid_t objid)
{
	struct gdm_obj *obj_entry, *new_obj;

	/* Since we cannot allocate in a lock section, we need to
	 * pre-allocate an obj_entry and free it after the lock section if an
	 * object was already present in the table. Can do better with a cache
	 * of new objects (see radix tree code for instance).
	 */
retry:
	new_obj = alloc_gdm_obj_entry(set, objid);

	gdm_obj_path_lock(set, objid);

	obj_entry = set->ops->get_obj_entry(set, objid, new_obj);
	if (obj_entry && obj_entry != new_obj)
		put_obj_entry_count(set, new_obj, objid);
	else if (!obj_entry)
		obj_entry = new_obj;

	if (TEST_AND_SET_OBJECT_LOCKED (obj_entry)) {
		gdm_obj_path_unlock(set, objid);
		while (TEST_OBJECT_LOCKED (obj_entry))
			cpu_relax();
		goto retry;
	}

	return obj_entry;
}



/*** Insert a new object in a gdm set ***/

void gdm_insert_object(struct gdm_set * set,
			objid_t objid,
			struct gdm_obj * obj_entry,
			gdm_obj_state_t objectState)
{
	ASSERT_OBJ_PATH_LOCKED(set, objid);

	put_gdm_obj_entry(set, obj_entry, objid);

	if (set->ops->insert_object)
		set->ops->insert_object (set, objid, obj_entry);

	gdm_io_insert_object(obj_entry, set, objid);

	gdm_obj_path_lock(set, objid);

	gdm_change_obj_state(set, obj_entry, objid, objectState);

	if (objectState & GDM_OWNER_OBJ) {
		CLEAR_SET(COPYSET(obj_entry));
		ADD_TO_SET(COPYSET(obj_entry), hcc_node_id);
		ADD_TO_SET(RMSET(obj_entry), hcc_node_id);
	}
	if (OBJ_STATE(obj_entry) != WAIT_ACK_INV)
		wake_up_on_wait_object(obj_entry, set);
}



/*** Invalidate a local gdm object ***/

void gdm_invalidate_local_object_and_unlock(struct gdm_obj * obj_entry,
					     struct gdm_set * set,
					     objid_t objid,
					     gdm_obj_state_t state)
{
	BUG_ON(obj_entry->object == NULL);
	ASSERT_OBJ_PATH_LOCKED(set, objid);

	obj_entry = gdm_break_cow_object (set, obj_entry,objid,
					   GDM_BREAK_COW_INV);

	if (!obj_entry)
		goto done;

	/* Inform interface linkers to invalidate the object */
	gdm_change_obj_state(set, obj_entry, objid, INV_COPY);
	if (state != INV_COPY)
		gdm_change_obj_state(set, obj_entry, objid, state);

	CLEAR_SET(COPYSET(obj_entry));

	/* Ask the IO linker to invalidate the object */
	gdm_io_invalidate_object(obj_entry, set, objid);

done:
	put_gdm_obj_entry(set, obj_entry, objid);
}

/* Unlock, and make a process sleep until the corresponding
 * object is received.
 */
void __sleep_on_gdm_obj(struct gdm_set * set,
			 struct gdm_obj * obj_entry,
			 objid_t objid,
			 int flags)
{
	struct gdm_info_struct *gdm_info = current->gdm_info;
	wait_queue_t wait;
#ifdef CONFIG_HCC_GPM
	struct task_struct *hcc_cur = hcc_current;
#endif

#ifdef CONFIG_HCC_GPM
	if (hcc_cur)
		hcc_current = NULL;
#endif

	ASSERT_OBJ_PATH_LOCKED(set, objid);

	/* Increase sleeper count and enqueue the task in the obj wait queue */
	atomic_inc(&obj_entry->sleeper_count);
	CLEAR_OBJECT_PINNED(obj_entry);

	init_waitqueue_entry(&wait, current);

	add_wait_queue(&obj_entry->waiting_tsk, &wait);

	set_current_state(TASK_UNINTERRUPTIBLE);

	put_gdm_obj_entry(set, obj_entry, objid);

	if (gdm_info) {
		gdm_info->wait_obj = obj_entry;
		gdm_info->ns_id = set->ns->id;
		gdm_info->set_id = set->id;
		gdm_info->obj_id = objid;
	}

	schedule();

retry:
	gdm_obj_path_lock(set, objid);
	if (TEST_AND_SET_OBJECT_LOCKED (obj_entry)) {
		gdm_obj_path_unlock (set, objid);
		while (TEST_OBJECT_LOCKED (obj_entry))
			cpu_relax();
		goto retry;
	}

	if( (TEST_FAILURE_FLAG(obj_entry)) &&
	    !(flags & GDM_DONT_KILL) ){
		printk("sleep_on_object_and...:Should kill current: %d %s "
		       "(%ld:%ld)\n", current->pid, current->comm,
		       set->id, objid);
		do_exit(SIGSEGV);
		BUG();
	};

	if (gdm_info)
		gdm_info->wait_obj = NULL;

	remove_wait_queue(&obj_entry->waiting_tsk, &wait);

	/* If all tasks waiting for the object have been woken-up we can
	   release the object */
	if (atomic_dec_and_test(&obj_entry->sleeper_count))
		CLEAR_OBJECT_PINNED(obj_entry);

#ifdef CONFIG_HCC_GPM
	if (hcc_cur)
		hcc_current = hcc_cur;
#endif
}



/* Check if we need to sleep on a local exclusive set.
 */
int check_sleep_on_local_exclusive (struct gdm_set * set,
				    struct gdm_obj * obj_entry,
				    objid_t objid,
				    int flags)
{
	int res = 0;

	ASSERT_OBJ_PATH_LOCKED(set, objid);

	if (object_frozen(obj_entry, set) &&
	    (gdm_local_exclusive(set))) {
		sleep_on_gdm_obj(set, obj_entry, objid, flags);
		res = 1;
	}
	return res;
}



/** Indicate if an object is frozen, ie if it should not be modified.
 *  @author Innogrid HCC
 *
 *  @param obj_entry  Entry of the object to test.
 */
int object_frozen(struct gdm_obj * obj_entry,
		  struct gdm_set * set)
{
	return (atomic_read(&obj_entry->frozen_count) != 0);
}



/** Indicate if an object is frozen, ie if it should not be modified.
 *  @author Innogrid HCC
 *
 *  @param obj_entry  Entry of the object to test.
 */
int object_frozen_or_pinned(struct gdm_obj * obj_entry,
			    struct gdm_set * set)
{
	return ((atomic_read(&obj_entry->frozen_count) != 0) ||
		TEST_OBJECT_PINNED(obj_entry));
}



/** Freeze the given object.
 *  @author Innogrid HCC
 *
 *  @param obj_entry  Entry of the object to freeze.
 */
void set_object_frozen(struct gdm_obj * obj_entry,
		       struct gdm_set * set)
{
	atomic_inc(&obj_entry->frozen_count);
}



/** Object clear Frozen.
 *  @author Innogrid HCC
 *
 *  @param obj_entry  Entry of the object to warm.
 */
void object_clear_frozen(struct gdm_obj * obj_entry,
			 struct gdm_set * set)
{
	atomic_dec(&obj_entry->frozen_count);

	BUG_ON(atomic_read(&obj_entry->frozen_count) < 0);

	wake_up_on_wait_object(obj_entry, set);
}



void __for_each_gdm_object(struct gdm_set *set,
			    int(*f)(unsigned long, void *, void*),
			    void *data)
{
	int i;

	for (i = 0; i < NR_OBJ_ENTRY_LOCKS; i++)
		spin_lock(&(set->obj_lock[i]));

	set->ops->for_each_obj_entry(set, f, data);

	for (i = 0; i < NR_OBJ_ENTRY_LOCKS; i++)
		spin_unlock(&(set->obj_lock[i]));
}




void for_each_gdm_object(int ns_id,
			  gdm_set_id_t set_id,
			  int(*f)(unsigned long, void*, void*),
			  void *data)
{
	struct gdm_set *set;

	set = find_get_gdm_set (ns_id, set_id);
	if(!set)
		return;

	__for_each_gdm_object(set, f, data);

	put_gdm_set(set);
}
EXPORT_SYMBOL(for_each_gdm_object);


int init_gdm_objects (void)
{
	unsigned long cache_flags = SLAB_PANIC;
	int i ;

#ifdef CONFIG_DEBUG_SLAB
	cache_flags |= SLAB_POISON;
#endif
	gdm_obj_cachep = kmem_cache_create("gdm_obj", sizeof(struct gdm_obj),
					    16, cache_flags, NULL);

	for (i = 0; i < NB_OBJ_STATE; i++) {
		atomic_set(&nr_OBJ_STATE[i], 0);
	}

	return 0;
}
