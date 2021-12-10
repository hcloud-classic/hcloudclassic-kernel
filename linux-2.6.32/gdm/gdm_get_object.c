/** GDM get object
 *  @file gdm_get_object.c
 *
 *  Implementation of GDM get object function.
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */
#include <linux/module.h>

#include <gdm/gdm.h>
#include <gdm/object_server.h>
#include "protocol_action.h"


/** Place a copy of a given object in local physical memory.
 *  @author Innogrid HCC
 *
 *  @param set        GDM set hosting the object.
 *  @param obj_entry  Object entry of the object to get.
 *  @param objid      Identifier of the object to get.
 *  @param flags      Sync / Async request, FT or not, etc...
 *
 *  @return        Address of the object if found.
 *                 NULL if the object does not exist.
 *                 Negative value if error.
 *
 *  A object is retreived from a remote node owning a copy. If there is
 *  no copy in the cluster and the NO_FT flag is not set,
 *  the object is created by the IO Linker. Otherwise NULL is returned.
 */
void *generic_gdm_get_object(struct gdm_set *set,
			      objid_t objid,
			      int flags)
{
	struct gdm_obj *obj_entry;
	void *object = NULL;

	inc_get_object_counter (set);

	obj_entry = __get_alloc_gdm_obj_entry(set, objid);

try_again:
	switch (OBJ_STATE(obj_entry)) {
	case INV_COPY:
		request_object_on_read(set, obj_entry, objid, flags);
		gdm_change_obj_state(set, obj_entry, objid, WAIT_OBJ_READ);
		/* Fall through */

	case WAIT_ACK_WRITE:
	case WAIT_OBJ_WRITE:
	case WAIT_OBJ_READ:
	case INV_FILLING:
		if (flags & GDM_ASYNC_REQ)
			goto exit_no_freeze;

		sleep_on_gdm_obj(set, obj_entry, objid, flags);

		if ((flags & GDM_NO_FT_REQ) &&
		    ((OBJ_STATE(obj_entry) == INV_COPY) ||
		     (OBJ_STATE(obj_entry) == INV_OWNER)))
			goto exit;

		if (!(OBJ_STATE(obj_entry) & GDM_READ_OBJ)) {
			/* Argh, object has been invalidated before we
			   woke up. */
			goto try_again;
		}
		break;

	case WAIT_CHG_OWN_ACK:
	case READ_COPY:
	case READ_OWNER:
	case WRITE_OWNER:
	case WAIT_ACK_INV:
		break;

	case WAIT_OBJ_RM_DONE:
	case WAIT_OBJ_RM_ACK:
	case WAIT_OBJ_RM_ACK2:
		sleep_on_gdm_obj(set, obj_entry, objid, flags);
		goto try_again;

	case WRITE_GHOST:
		gdm_change_obj_state(set, obj_entry, objid, WRITE_OWNER);
		break;

	case INV_OWNER:          /* First Touch */
		if (flags & GDM_NO_FT_REQ)
			goto exit;

		/*** The object can be created on the local node  ***/
		if (object_first_touch(set, obj_entry, objid,
				       READ_OWNER, flags) != 0)
			BUG();
		break;

	default:
		STATE_MACHINE_ERROR(set->id, objid, obj_entry);
		break;
	}

exit:
	if (flags & GDM_ASYNC_REQ)
		goto exit_no_freeze;

	if (check_sleep_on_local_exclusive(set, obj_entry, objid, flags))
		goto try_again;
	if (!(flags & GDM_NO_FREEZE))
		set_object_frozen(obj_entry, set);

exit_no_freeze:
	object = obj_entry->object;
	put_gdm_obj_entry(set, obj_entry, objid);

	return object;
}



void *_gdm_get_object(struct gdm_set *set, objid_t objid)
{
	return generic_gdm_get_object(set, objid, 0);
}
EXPORT_SYMBOL(_gdm_get_object);

void *gdm_get_object(struct gdm_ns *ns, gdm_set_id_t set_id, objid_t objid)
{
	struct gdm_set *set;
	void *obj;

	set = _find_get_gdm_set (ns, set_id);
	obj = generic_gdm_get_object(set, objid, 0);
	put_gdm_set(set);

	return obj;
}
EXPORT_SYMBOL(gdm_get_object);



void *_fgdm_get_object(struct gdm_set *set, objid_t objid, int flags)
{
	return generic_gdm_get_object(set, objid, flags);
}
EXPORT_SYMBOL(_fgdm_get_object);

void *fgdm_get_object(struct gdm_ns *ns, gdm_set_id_t set_id,
			objid_t objid, int flags)
{
	struct gdm_set *set;
	void *obj;

	set = _find_get_gdm_set (ns, set_id);
	obj = generic_gdm_get_object(set, objid, flags);
	put_gdm_set(set);

	return obj;
}
EXPORT_SYMBOL(fgdm_get_object);



void *_async_gdm_get_object(struct gdm_set *set, objid_t objid)
{
	return generic_gdm_get_object(set, objid, GDM_ASYNC_REQ);
}
EXPORT_SYMBOL(_async_gdm_get_object);

void *async_gdm_get_object(struct gdm_ns *ns, gdm_set_id_t set_id,
			    objid_t objid)
{
	struct gdm_set *set;
	void *obj;

	set = _find_get_gdm_set (ns, set_id);
	obj = generic_gdm_get_object(set, objid, GDM_ASYNC_REQ);
	put_gdm_set(set);

	return obj;
}
EXPORT_SYMBOL(async_gdm_get_object);



void *_gdm_get_object_no_ft(struct gdm_set *set, objid_t objid)
{
	return generic_gdm_get_object(set, objid, GDM_NO_FT_REQ);
}
EXPORT_SYMBOL(_gdm_get_object_no_ft);

void *gdm_get_object_no_ft(struct gdm_ns *ns, gdm_set_id_t set_id,
			    objid_t objid)
{
	struct gdm_set *set;
	void *obj;

	set = _find_get_gdm_set (ns, set_id);
	obj = generic_gdm_get_object(set, objid, GDM_NO_FT_REQ);
	put_gdm_set(set);

	return obj;
}
EXPORT_SYMBOL(gdm_get_object_no_ft);



void *_gdm_get_object_manual_ft(struct gdm_set *set, objid_t objid)
{
	return generic_gdm_get_object(set, objid, GDM_NO_FT_REQ |
				       GDM_SEND_OWNERSHIP);
}
EXPORT_SYMBOL(_gdm_get_object_manual_ft);

void *gdm_get_object_manual_ft(struct gdm_ns *ns, gdm_set_id_t set_id,
				objid_t objid)
{
	struct gdm_set *set;
	void *obj;

	set = _find_get_gdm_set (ns, set_id);
	obj = generic_gdm_get_object(set, objid, GDM_NO_FT_REQ |
				      GDM_SEND_OWNERSHIP);
	put_gdm_set(set);

	return obj;
}
EXPORT_SYMBOL(gdm_get_object_manual_ft);



void *_gdm_get_object_no_lock(struct gdm_set *set, objid_t objid)
{
	return generic_gdm_get_object(set, objid, GDM_NO_FREEZE);
}
EXPORT_SYMBOL(_gdm_get_object_no_lock);

void *gdm_get_object_no_lock(struct gdm_ns *ns, gdm_set_id_t set_id,
			      objid_t objid)
{
	struct gdm_set *set;
	void *obj;

	set = _find_get_gdm_set (ns, set_id);
	obj = generic_gdm_get_object(set, objid, GDM_NO_FREEZE);
	put_gdm_set(set);

	return obj;
}
EXPORT_SYMBOL(gdm_get_object_no_lock);
