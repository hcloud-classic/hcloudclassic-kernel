/** GDM remove object
 *  @file gdm_remove_object.c
 *
 *  Implementation of GDM remove object function.
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */
#include <linux/module.h>

#include <gdm/gdm.h>
#include <gdm/object_server.h>
#include "protocol_action.h"


static inline void wait_copies_remove_done(struct gdm_set *set,
					   struct gdm_obj *obj_entry,
					   objid_t objid)
{
	gdm_change_obj_state(set, obj_entry, objid,
			      WAIT_OBJ_RM_ACK);
sleep_again:
	__sleep_on_gdm_obj(set, obj_entry, objid, 0);
	/* We can be woken up by a put  */
	if (!SET_IS_EMPTY(RMSET(obj_entry)))
		goto sleep_again;
}



/** Remove an object cluster wide.
 *  @author Innogrid HCC
 *
 *  @param set        GDM set hosting the object.
 *  @param obj_entry  Object entry of the object to remove.
 *  @param objid      Identifier of the object to remove.
 *  @param frozen     Set to 1 if we remove a frozen object.
 *
 *  @return              0 if everything ok
 *                       Negative value if error.
 */
int generic_gdm_remove_object(struct gdm_set *set,
			       objid_t objid,
			       int remove_frozen)
{
	struct gdm_obj *obj_entry;
	int res = 0, need_wait;

	inc_remove_object_counter(set);

	obj_entry = __get_gdm_obj_entry(set, objid);
	if (likely(obj_entry != NULL))
		goto try_again;

	if (I_AM_DEFAULT_OWNER(set, objid))
		return 0;

	BUG_ON(remove_frozen);

	obj_entry = __get_alloc_gdm_obj_entry(set, objid);

try_again:
	switch (OBJ_STATE(obj_entry)) {
	case WAIT_OBJ_RM_ACK:
	case WAIT_OBJ_RM_ACK2:
	case WAIT_OBJ_RM_DONE:
		res = -EALREADY;
		break;

	case READ_COPY:
		if (object_frozen(obj_entry, set)) {
			__sleep_on_gdm_obj(set, obj_entry, objid, 0);
			goto try_again;
		}
		/* Fall through */

	case INV_COPY:
		gdm_change_obj_state(set, obj_entry, objid, WAIT_OBJ_RM_DONE);

		request_objects_remove_to_mgr(set, obj_entry, objid);
		CLEAR_SET (RMSET(obj_entry));

		/* Wait for remove ACK from object manager */
		__sleep_on_gdm_obj(set, obj_entry, objid, 0);

		destroy_gdm_obj_entry(set, obj_entry, objid, 1);
		goto exit_no_unlock;

	case WAIT_OBJ_READ:
	case WAIT_ACK_WRITE:
	case WAIT_OBJ_WRITE:
	case WAIT_CHG_OWN_ACK:
	case WAIT_ACK_INV:
	case INV_FILLING:
		__sleep_on_gdm_obj(set, obj_entry, objid, 0);
		goto try_again;

	case INV_OWNER:
	case READ_OWNER:
	case WRITE_OWNER:
	case WRITE_GHOST:
		if (remove_frozen &&
		    (atomic_read(&obj_entry->frozen_count) == 1) ) {
			object_clear_frozen(obj_entry, set);
			remove_frozen = 0;
		}
		if (object_frozen(obj_entry, set)) {
			__sleep_on_gdm_obj(set, obj_entry, objid, 0);
			goto try_again;
		}

		need_wait = request_copies_remove(set, obj_entry, objid,
						  hcc_node_id);
		if (need_wait)
			wait_copies_remove_done(set, obj_entry, objid);

		destroy_gdm_obj_entry(set, obj_entry, objid, 1);
		goto exit_no_unlock;

	default:
		STATE_MACHINE_ERROR(set->id, objid, obj_entry);
		break;
	}

	put_gdm_obj_entry(set, obj_entry, objid);
exit_no_unlock:

	return res;
}

int _gdm_remove_object(struct gdm_set *set, objid_t objid)
{
	return generic_gdm_remove_object(set, objid, 0);
}
EXPORT_SYMBOL(_gdm_remove_object);

int gdm_remove_object(struct gdm_ns *ns, gdm_set_id_t set_id, objid_t objid)
{
	struct gdm_set *set;
	int res;

	set = _find_get_gdm_set (ns, set_id);
	res = generic_gdm_remove_object(set, objid, 0);
	put_gdm_set(set);

	return res;
}
EXPORT_SYMBOL(gdm_remove_object);

int _gdm_remove_frozen_object(struct gdm_set *set, objid_t objid)
{
	return generic_gdm_remove_object(set, objid, 1);
}
EXPORT_SYMBOL(_gdm_remove_frozen_object);

int gdm_remove_frozen_object(struct gdm_ns *ns, gdm_set_id_t set_id,
			      objid_t objid)
{
	struct gdm_set *set;
	int res;

	set = _find_get_gdm_set (ns, set_id);
	res = generic_gdm_remove_object(set, objid, 1);
	put_gdm_set(set);

	return res;
}
EXPORT_SYMBOL(gdm_remove_frozen_object);
